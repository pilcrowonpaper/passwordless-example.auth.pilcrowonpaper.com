package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/webauthn"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passkeyDeletionSessionStruct struct {
	id               string
	authSessionId    string
	secretHash       []byte
	passkeyId        string
	identityVerified bool
	createdAt        time.Time
}

func (passkeyDeletionSession *passkeyDeletionSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passkeyDeletionSession.secretHash)
	return hashEqual
}

func (server *serverStruct) createPasskeyDeletionSession(authSessionId string, passkeyId string) (passkeyDeletionSessionStruct, []byte, identityVerificationSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyDeletionSessionId := generateItemId()
	passkeyDeletionSessionSecret := generateSessionSecret()
	passkeyDeletionSessionSecretHash := hashSessionSecret(passkeyDeletionSessionSecret)

	passkeyDeletionSession := passkeyDeletionSessionStruct{
		id:            passkeyDeletionSessionId,
		authSessionId: authSessionId,
		secretHash:    passkeyDeletionSessionSecretHash,
		passkeyId:     passkeyId,
		createdAt:     nowSecondPrecision,
	}

	identityVerificationSessionId := generateItemId()
	identityVerificationSessionSecret := generateSessionSecret()
	identityVerificationSessionSecretHash := hashSessionSecret(identityVerificationSessionSecret)
	identityVerificationSessionPasskeyVerificationChallenge := webauthn.GenerateChallenge()

	identityVerificationSession := identityVerificationSessionStruct{
		id:                           identityVerificationSessionId,
		authSessionId:                authSessionId,
		secretHash:                   identityVerificationSessionSecretHash,
		verifyingAction:              identityVerificationSessionVerifyingActionPasskeyDeletion,
		verifyingActionId:            passkeyDeletionSession.id,
		passkeyVerificationChallenge: identityVerificationSessionPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_deletion_session (id, auth_session_id, secret_hash, passkey_id, created_at) VALUES (?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeyDeletionSession.id,
				passkeyDeletionSession.authSessionId,
				passkeyDeletionSession.secretHash,
				passkeyDeletionSession.passkeyId,
				passkeyDeletionSession.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into passkey_deletion_session table: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO identity_verification_session (id, auth_session_id, secret_hash, verifying_action, verifying_action_id, passkey_verification_challenge, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				identityVerificationSession.id,
				identityVerificationSession.authSessionId,
				identityVerificationSession.secretHash,
				identityVerificationSession.verifyingAction,
				identityVerificationSession.verifyingActionId,
				identityVerificationSession.passkeyVerificationChallenge,
				identityVerificationSession.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into identity_verification_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkeyDeletionSession, passkeyDeletionSessionSecret, identityVerificationSession, identityVerificationSessionSecret, nil
}

func (server *serverStruct) getPasskeyDeletionSession(passkeyDeletionSessionId string) (passkeyDeletionSessionStruct, error) {
	passkeyDeletionSessions := []passkeyDeletionSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyDeletionSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, passkey_id, identity_verified, created_at FROM passkey_deletion_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeyDeletionSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				authSessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				passkeyId := stmt.ColumnText(2)

				identityVerified := stmt.ColumnBool(3)

				createdAt := time.Unix(stmt.ColumnInt64(4), 0)

				passkeyDeletionSession := passkeyDeletionSessionStruct{
					id:               passkeyDeletionSessionId,
					authSessionId:    authSessionId,
					secretHash:       secretHash,
					passkeyId:        passkeyId,
					identityVerified: identityVerified,
					createdAt:        createdAt,
				}

				passkeyDeletionSessions = append(passkeyDeletionSessions, passkeyDeletionSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyDeletionSessionStruct{}, fmt.Errorf("failed to select from passkey_deletion_session table: %s", err.Error())
	}

	if len(passkeyDeletionSessions) < 1 {
		return passkeyDeletionSessionStruct{}, errItemNotFound
	}

	passkeDeletion := passkeyDeletionSessions[0]

	if time.Since(passkeDeletion.createdAt) >= time.Hour {
		return passkeyDeletionSessionStruct{}, errItemNotFound
	}

	return passkeDeletion, nil
}

var errInvalidPasskeyDeletionSessionToken = errors.New("invalid passkey deletion session token")

func (server *serverStruct) validatePasskeyDeletionSessionToken(passkeyDeletionSessionToken string) (passkeyDeletionSessionStruct, error) {
	passkeyDeletionSessionId, passkeyDeletionSessionSecret, err := parseSessionToken(passkeyDeletionSessionToken)
	if err != nil {
		return passkeyDeletionSessionStruct{}, errInvalidPasskeyDeletionSessionToken
	}

	passkeyDeletionSession, err := server.getPasskeyDeletionSession(passkeyDeletionSessionId)
	if errors.Is(err, errItemNotFound) {
		return passkeyDeletionSessionStruct{}, errInvalidPasskeyDeletionSessionToken
	}
	if err != nil {
		return passkeyDeletionSessionStruct{}, fmt.Errorf("failed to get passkey deletion session: %s", err.Error())
	}

	secretValid := passkeyDeletionSession.compareSecretAgainstHash(passkeyDeletionSessionSecret)
	if !secretValid {
		return passkeyDeletionSessionStruct{}, errInvalidPasskeyDeletionSessionToken
	}

	return passkeyDeletionSession, nil
}

const passkeyDeletionSessionTokenCookieName = "passkey_deletion_session_token"

func (server *serverStruct) validateRequestPasskeyDeletionSessionToken(r *http.Request) (passkeyDeletionSessionStruct, string, error) {
	passkeyDeletionSessionTokenCookie, err := r.Cookie(passkeyDeletionSessionTokenCookieName)
	if err != nil {
		return passkeyDeletionSessionStruct{}, "", errInvalidPasskeyDeletionSessionToken
	}
	passkeyDeletionSessionToken := passkeyDeletionSessionTokenCookie.Value

	passkeyDeletionSession, err := server.validatePasskeyDeletionSessionToken(passkeyDeletionSessionToken)
	if errors.Is(err, errInvalidPasskeyDeletionSessionToken) {
		return passkeyDeletionSessionStruct{}, "", errInvalidPasskeyDeletionSessionToken
	}
	if err != nil {
		return passkeyDeletionSessionStruct{}, "", fmt.Errorf("failed to validate passkey deletion session token: %s", err.Error())
	}

	return passkeyDeletionSession, passkeyDeletionSessionToken, nil
}

func (server *serverStruct) setBlankPasskeyDeletionSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, passkeyDeletionSessionTokenCookieName)
}

func (server *serverStruct) completePasskeyDeletion(passkeyDeletionSessionId string) (string, error) {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	passkeyNames := []string{}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey WHERE id = (SELECT passkey_id FROM passkey_deletion_session WHERE id = ?) RETURNING name", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			passkeyName := stmt.ColumnText(0)
			passkeyNames = append(passkeyNames, passkeyName)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from passkey table: %s", err.Error())
	}
	if len(passkeyNames) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", errItemNotFound
	}
	passkeyName := passkeyNames[0]

	err = sqlitex.Execute(databaseWriteConnection, `DELETE FROM passkey_deletion_session WHERE id = ?`, &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from passkey_deletion_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkeyName, nil
}

func (server *serverStruct) deletePasskeyDeletionSession(passkeyDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_deletion_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from passkey_deletion_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	if affectedCount < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return errItemNotFound
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE verifying_action = 'passkey_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from identity_verification_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return nil
}
