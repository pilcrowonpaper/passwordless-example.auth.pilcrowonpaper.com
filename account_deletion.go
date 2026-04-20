package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"passwordless-example.auth.pilcrowonpaper.com/webauthn"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type accountDeletionStruct struct {
	id               string
	sessionId        string
	secretHash       []byte
	identityVerified bool
	createdAt        time.Time
}

func (accountDeletion *accountDeletionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, accountDeletion.secretHash)
	return hashEqual
}

func (server *serverStruct) createAccountDeletion(sessionId string) (accountDeletionStruct, []byte, identityVerificationStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	accountDeletionId := generateItemId()
	accountDeletionSecret := generateSessionSecret()
	accountDeletionSecretHash := hashSessionSecret(accountDeletionSecret)

	accountDeletion := accountDeletionStruct{
		id:         accountDeletionId,
		sessionId:  sessionId,
		secretHash: accountDeletionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	identityVerificationId := generateItemId()
	identityVerificationSecret := generateSessionSecret()
	identityVerificationSecretHash := hashSessionSecret(identityVerificationSecret)
	identityVerificationPasskeyVerificationChallenge := webauthn.GenerateChallenge()

	identityVerification := identityVerificationStruct{
		id:                           identityVerificationId,
		sessionId:                    sessionId,
		secretHash:                   identityVerificationSecretHash,
		verifyingAction:              identityVerificationVerifyingActionAccountDeletion,
		verifyingActionId:            accountDeletion.id,
		passkeyVerificationChallenge: identityVerificationPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO account_deletion (id, session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				accountDeletion.id,
				accountDeletion.sessionId,
				accountDeletion.secretHash,
				accountDeletion.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into account_deletion table: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO identity_verification (id, session_id, secret_hash, verifying_action, verifying_action_id, passkey_verification_challenge, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				identityVerification.id,
				identityVerification.sessionId,
				identityVerification.secretHash,
				identityVerification.verifyingAction,
				identityVerification.verifyingActionId,
				identityVerification.passkeyVerificationChallenge,
				identityVerification.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into identity_verification table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return accountDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return accountDeletion, accountDeletionSecret, identityVerification, identityVerificationSecret, nil
}

func (server *serverStruct) getAccountDeletion(accountDeletionId string) (accountDeletionStruct, error) {
	accountDeletions := []accountDeletionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, identity_verified, created_at FROM account_deletion WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{accountDeletionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				identityVerified := stmt.ColumnBool(2)

				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				accountDeletion := accountDeletionStruct{
					id:               accountDeletionId,
					secretHash:       secretHash,
					sessionId:        sessionId,
					identityVerified: identityVerified,
					createdAt:        createdAt,
				}

				accountDeletions = append(accountDeletions, accountDeletion)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to select from account_deletion table: %s", err.Error())
	}

	if len(accountDeletions) < 1 {
		return accountDeletionStruct{}, errItemNotFound
	}

	accountDeletion := accountDeletions[0]

	if time.Since(accountDeletion.createdAt) >= time.Minute*60 {
		return accountDeletionStruct{}, errItemNotFound
	}

	return accountDeletion, nil
}

const accountDeletionTokenCookieName = "account_deletion_token"

func (server *serverStruct) setBlankAccountDeletionTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     accountDeletionTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

var errInvalidAccountDeletionToken = errors.New("invalid account deletion token")

func (server *serverStruct) validateAccountDeletionToken(accountDeletionToken string) (accountDeletionStruct, error) {
	accountDeletionTokenParts := strings.Split(accountDeletionToken, ".")
	if len(accountDeletionTokenParts) != 2 {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}
	accountDeletionId := accountDeletionTokenParts[0]
	encodedAccountDeletionSecret := accountDeletionTokenParts[1]
	accountDeletionSecret, err := base64.StdEncoding.DecodeString(encodedAccountDeletionSecret)
	if err != nil {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}

	accountDeletion, err := server.getAccountDeletion(accountDeletionId)
	if errors.Is(err, errItemNotFound) {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}
	if err != nil {
		return accountDeletionStruct{}, fmt.Errorf("failed to get account deletion: %s", err.Error())
	}

	accountDeletionSecretValid := accountDeletion.compareSecretAgainstHash(accountDeletionSecret)
	if !accountDeletionSecretValid {
		return accountDeletionStruct{}, errInvalidAccountDeletionToken
	}

	return accountDeletion, nil
}

func (server *serverStruct) validateRequestAccountDeletionToken(r *http.Request) (accountDeletionStruct, string, error) {
	accountDeletionTokenCookie, err := r.Cookie(accountDeletionTokenCookieName)
	if err != nil {
		return accountDeletionStruct{}, "", errInvalidAccountDeletionToken
	}
	accountDeletionToken := accountDeletionTokenCookie.Value

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return accountDeletionStruct{}, "", errInvalidAccountDeletionToken
	}
	if err != nil {
		return accountDeletionStruct{}, "", fmt.Errorf("failed to validate accountDeletion token: %s", err.Error())
	}

	return accountDeletion, accountDeletionToken, nil
}

func (server *serverStruct) completeAccountDeletionIdentityVerification(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE account_deletion SET identity_verified = 1 WHERE id = ? AND identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return errItemConflict
		}
		return fmt.Errorf("failed to update account_deletion table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'account_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return errItemConflict
		}
		return fmt.Errorf("failed to update identity_verification table: %s", err.Error())
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

func (server *serverStruct) completeAccountDeletion(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM user WHERE id IN (SELECT session.user_id FROM account_deletion INNER JOIN session ON account_deletion.session_id = session.id WHERE account_deletion.id = ? AND account_deletion.identity_verified = 1)", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
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

func (server *serverStruct) deleteAccountDeletion(accountDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM account_deletion WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from account_deletion table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'account_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{accountDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from identity_verification table: %s", err.Error())
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
