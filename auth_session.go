package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type authSessionStruct struct {
	id         string
	userId     string
	secretHash []byte
	createdAt  time.Time
}

func (authSession *authSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, authSession.secretHash)
	return hashEqual
}

func (server *serverStruct) getAuthSession(authSessionId string) (authSessionStruct, error) {
	authSessions := []authSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return authSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, created_at FROM auth_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{authSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				createdAt := time.Unix(stmt.ColumnInt64(2), 0)

				authSession := authSessionStruct{
					id:         authSessionId,
					userId:     userId,
					secretHash: secretHash,
					createdAt:  createdAt,
				}

				authSessions = append(authSessions, authSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return authSessionStruct{}, fmt.Errorf("failed to select from auth_session table: %s", err.Error())
	}

	if len(authSessions) < 1 {
		return authSessionStruct{}, errItemNotFound
	}

	return authSessions[0], nil
}

var errInvalidAuthSessionToken = errors.New("invalid auth session token")

func (server *serverStruct) validateAuthSessionToken(authSessionToken string) (authSessionStruct, error) {
	authSessionId, authSessionSecret, err := parseSessionToken(authSessionToken)
	if err != nil {
		return authSessionStruct{}, errInvalidAuthSessionToken
	}

	authSession, err := server.getAuthSession(authSessionId)
	if errors.Is(err, errItemNotFound) {
		return authSessionStruct{}, errInvalidAuthSessionToken
	}
	if err != nil {
		return authSessionStruct{}, fmt.Errorf("failed to get auth session: %s", err.Error())
	}

	secretValid := authSession.compareSecretAgainstHash(authSessionSecret)
	if !secretValid {
		return authSessionStruct{}, errInvalidAuthSessionToken
	}

	return authSession, nil
}

const authSessionTokenCookieName = "auth_session_token"

func (server *serverStruct) validateRequestAuthSessionToken(r *http.Request) (authSessionStruct, string, error) {
	authSessionTokenCookie, err := r.Cookie(authSessionTokenCookieName)
	if err != nil {
		return authSessionStruct{}, "", errInvalidAuthSessionToken
	}
	authSessionToken := authSessionTokenCookie.Value

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return authSessionStruct{}, "", errInvalidAuthSessionToken
	}
	if err != nil {
		return authSessionStruct{}, "", fmt.Errorf("failed to validate auth session token: %s", err.Error())
	}

	return authSession, authSessionToken, nil
}

func (server *serverStruct) setBlankAuthSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, authSessionTokenCookieName)
}

func (server *serverStruct) deleteAuthSession(authSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM auth_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{authSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from auth_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) deleteUserAuthSessions(userId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM auth_session WHERE user_id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to delete from auth_session table: %s", err.Error())
	}
	return nil
}
