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

type accountDeletionSessionStruct struct {
	id               string
	authSessionId    string
	secretHash       []byte
	identityVerified bool
	createdAt        time.Time
}

func (accountDeletionSession *accountDeletionSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, accountDeletionSession.secretHash)
	return hashEqual
}

func (server *serverStruct) createAccountDeletionSession(authSessionId string) (accountDeletionSessionStruct, []byte, identityVerificationSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	accountDeletionSessionId := generateItemId()
	accountDeletionSessionSecret := generateSessionSecret()
	accountDeletionSessionSecretHash := hashSessionSecret(accountDeletionSessionSecret)

	accountDeletionSession := accountDeletionSessionStruct{
		id:            accountDeletionSessionId,
		authSessionId: authSessionId,
		secretHash:    accountDeletionSessionSecretHash,
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
		verifyingAction:              identityVerificationSessionVerifyingActionAccountDeletion,
		verifyingActionId:            accountDeletionSession.id,
		passkeyVerificationChallenge: identityVerificationSessionPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO account_deletion_session (id, auth_session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				accountDeletionSession.id,
				accountDeletionSession.authSessionId,
				accountDeletionSession.secretHash,
				accountDeletionSession.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into account_deletion_session table: %s", err.Error())
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
			return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into identity_verification_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return accountDeletionSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return accountDeletionSession, accountDeletionSessionSecret, identityVerificationSession, identityVerificationSessionSecret, nil
}

func (server *serverStruct) getAccountDeletionSession(accountDeletionSessionId string) (accountDeletionSessionStruct, error) {
	accountDeletionSessions := []accountDeletionSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, identity_verified, created_at FROM account_deletion_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				authSessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				identityVerified := stmt.ColumnBool(2)

				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				accountDeletionSession := accountDeletionSessionStruct{
					id:               accountDeletionSessionId,
					secretHash:       secretHash,
					authSessionId:    authSessionId,
					identityVerified: identityVerified,
					createdAt:        createdAt,
				}

				accountDeletionSessions = append(accountDeletionSessions, accountDeletionSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to select from account_deletion_session table: %s", err.Error())
	}

	if len(accountDeletionSessions) < 1 {
		return accountDeletionSessionStruct{}, errItemNotFound
	}

	accountDeletionSession := accountDeletionSessions[0]

	if time.Since(accountDeletionSession.createdAt) >= time.Hour {
		return accountDeletionSessionStruct{}, errItemNotFound
	}

	return accountDeletionSession, nil
}

var errInvalidAccountDeletionSessionToken = errors.New("invalid account deletion session token")

func (server *serverStruct) validateAccountDeletionSessionToken(accountDeletionSessionToken string) (accountDeletionSessionStruct, error) {
	accountDeletionSessionId, accountDeletionSessionSecret, err := parseSessionToken(accountDeletionSessionToken)
	if err != nil {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}

	accountDeletionSession, err := server.getAccountDeletionSession(accountDeletionSessionId)
	if errors.Is(err, errItemNotFound) {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}
	if err != nil {
		return accountDeletionSessionStruct{}, fmt.Errorf("failed to validate account deletion session: %s", err.Error())
	}

	secretValid := accountDeletionSession.compareSecretAgainstHash(accountDeletionSessionSecret)
	if !secretValid {
		return accountDeletionSessionStruct{}, errInvalidAccountDeletionSessionToken
	}

	return accountDeletionSession, nil
}

const accountDeletionSessionTokenCookieName = "account_deletion_session_token"

func (server *serverStruct) validateRequestAccountDeletionSessionToken(r *http.Request) (accountDeletionSessionStruct, string, error) {
	accountDeletionSessionTokenCookie, err := r.Cookie(accountDeletionSessionTokenCookieName)
	if err != nil {
		return accountDeletionSessionStruct{}, "", errInvalidAccountDeletionSessionToken
	}
	accountDeletionSessionToken := accountDeletionSessionTokenCookie.Value

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return accountDeletionSessionStruct{}, "", errInvalidAccountDeletionSessionToken
	}
	if err != nil {
		return accountDeletionSessionStruct{}, "", fmt.Errorf("failed to validate account deletion session token: %s", err.Error())
	}

	return accountDeletionSession, accountDeletionSessionToken, nil
}

func (server *serverStruct) setBlankAccountDeletionSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, accountDeletionSessionTokenCookieName)
}

func (server *serverStruct) completeAccountDeletion(accountDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`DELETE FROM user WHERE id IN (
SELECT auth_session.user_id FROM account_deletion_session
INNER JOIN auth_session ON account_deletion_session.auth_session_id = auth_session.id
WHERE account_deletion_session.id = ?
AND account_deletion_session.identity_verified = 1
)`,
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionSessionId},
		},
	)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from user table: %s", err.Error())
	}
	deletedUserCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if deletedUserCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) deleteAccountDeletionSession(accountDeletionSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM account_deletion_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from account_deletion_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE verifying_action = 'account_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionSessionId},
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
