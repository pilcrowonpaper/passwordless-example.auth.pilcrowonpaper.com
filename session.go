package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type sessionStruct struct {
	id         string
	userId     string
	secretHash []byte
	createdAt  time.Time
}

func (session *sessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, session.secretHash)
	return hashEqual
}

func generateSessionSecret() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret
}

func hashSessionSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createSessionToken(sessionId string, sessionSecret []byte) string {
	encodedSessionSecret := base64.StdEncoding.EncodeToString(sessionSecret)
	sessionToken := sessionId + "." + encodedSessionSecret
	return sessionToken
}

const sessionTokenCookieName = "session_token"

func (server *serverStruct) setBlankSessionTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sessionTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) createSession(userId string) (sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	session := sessionStruct{
		id:         id,
		userId:     userId,
		secretHash: secretHash,
		createdAt:  nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				session.id,
				session.userId,
				session.secretHash,
				session.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return sessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	return session, secret, nil
}

func (server *serverStruct) getSession(sessionId string) (sessionStruct, error) {
	sessions := []sessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, created_at FROM session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{sessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				createdAt := time.Unix(stmt.ColumnInt64(2), 0)

				session := sessionStruct{
					id:         sessionId,
					userId:     userId,
					secretHash: secretHash,
					createdAt:  createdAt,
				}

				sessions = append(sessions, session)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to select from session table: %s", err.Error())
	}

	if len(sessions) < 1 {
		return sessionStruct{}, errItemNotFound
	}

	return sessions[0], nil
}

var errInvalidSessionToken = errors.New("invalid session token")

func (server *serverStruct) validateSessionToken(sessionToken string) (sessionStruct, error) {
	sessionTokenParts := strings.Split(sessionToken, ".")
	if len(sessionTokenParts) != 2 {
		return sessionStruct{}, errInvalidSessionToken
	}
	sessionId := sessionTokenParts[0]
	encodedSessionSecret := sessionTokenParts[1]
	sessionSecret, err := base64.StdEncoding.DecodeString(encodedSessionSecret)
	if err != nil {
		return sessionStruct{}, errInvalidSessionToken
	}

	session, err := server.getSession(sessionId)
	if errors.Is(err, errItemNotFound) {
		return sessionStruct{}, errInvalidSessionToken
	}
	if err != nil {
		return sessionStruct{}, fmt.Errorf("failed to get session: %s", err.Error())
	}

	sessionSecretValid := session.compareSecretAgainstHash(sessionSecret)
	if !sessionSecretValid {
		return sessionStruct{}, errInvalidSessionToken
	}

	return session, nil
}

func (server *serverStruct) validateRequestSessionToken(r *http.Request) (sessionStruct, string, error) {
	sessionTokenCookie, err := r.Cookie(sessionTokenCookieName)
	if err != nil {
		return sessionStruct{}, "", errInvalidSessionToken
	}
	sessionToken := sessionTokenCookie.Value

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return sessionStruct{}, "", errInvalidSessionToken
	}
	if err != nil {
		return sessionStruct{}, "", fmt.Errorf("failed to validate session token: %s", err.Error())
	}

	return session, sessionToken, nil
}

func (server *serverStruct) deleteSession(sessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{sessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) deleteUserSessions(userId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM session WHERE user_id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if err != nil {
		return fmt.Errorf("failed to delete from session table: %s", err.Error())
	}
	return nil
}
