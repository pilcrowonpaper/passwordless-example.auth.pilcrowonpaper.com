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

type passkeyDeletionStruct struct {
	id               string
	sessionId        string
	secretHash       []byte
	passkeyId        string
	identityVerified bool
	createdAt        time.Time
}

func (passkeyDeletion *passkeyDeletionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passkeyDeletion.secretHash)
	return hashEqual
}

func (server *serverStruct) createPasskeyDeletion(sessionId string, passkeyId string) (passkeyDeletionStruct, []byte, identityVerificationStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyDeletionId := generateItemId()
	passkeyDeletionSecret := generateSessionSecret()
	passkeyDeletionSecretHash := hashSessionSecret(passkeyDeletionSecret)

	passkeyDeletion := passkeyDeletionStruct{
		id:         passkeyDeletionId,
		sessionId:  sessionId,
		secretHash: passkeyDeletionSecretHash,
		passkeyId:  passkeyId,
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
		verifyingAction:              identityVerificationVerifyingActionPasskeyDeletion,
		verifyingActionId:            passkeyDeletion.id,
		passkeyVerificationChallenge: identityVerificationPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_deletion (id, session_id, secret_hash, passkey_id, created_at) VALUES (?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeyDeletion.id,
				passkeyDeletion.sessionId,
				passkeyDeletion.secretHash,
				passkeyDeletion.passkeyId,
				passkeyDeletion.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into passkey_deletion table: %s", err.Error())
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
			return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into identity_verification table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyDeletionStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkeyDeletion, passkeyDeletionSecret, identityVerification, identityVerificationSecret, nil
}

func (server *serverStruct) getPasskeyDeletion(PasskeyDeletionId string) (passkeyDeletionStruct, error) {
	passkeyDeletions := []passkeyDeletionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyDeletionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, passkey_id, identity_verified, created_at FROM passkey_deletion WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{PasskeyDeletionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				passkeyId := stmt.ColumnText(2)

				identityVerified := stmt.ColumnBool(3)

				createdAt := time.Unix(stmt.ColumnInt64(4), 0)

				passkeyDeletion := passkeyDeletionStruct{
					id:               PasskeyDeletionId,
					sessionId:        sessionId,
					secretHash:       secretHash,
					passkeyId:        passkeyId,
					identityVerified: identityVerified,
					createdAt:        createdAt,
				}

				passkeyDeletions = append(passkeyDeletions, passkeyDeletion)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyDeletionStruct{}, fmt.Errorf("failed to select from passkey_deletion table: %s", err.Error())
	}

	if len(passkeyDeletions) < 1 {
		return passkeyDeletionStruct{}, errItemNotFound
	}

	return passkeyDeletions[0], nil
}

const passkeyDeletionTokenCookieName = "passkey_deletion_token"

func (server *serverStruct) setBlankPasskeyDeletionTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     passkeyDeletionTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

var errInvalidPasskeyDeletionToken = errors.New("invalid email address update token")

func (server *serverStruct) validatePasskeyDeletionToken(passkeyDeletionToken string) (passkeyDeletionStruct, error) {
	passkeyDeletionTokenParts := strings.Split(passkeyDeletionToken, ".")
	if len(passkeyDeletionTokenParts) != 2 {
		return passkeyDeletionStruct{}, errInvalidPasskeyDeletionToken
	}
	passkeyDeletionId := passkeyDeletionTokenParts[0]
	encodedPasskeyDeletionSecret := passkeyDeletionTokenParts[1]
	passkeyDeletionSecret, err := base64.StdEncoding.DecodeString(encodedPasskeyDeletionSecret)
	if err != nil {
		return passkeyDeletionStruct{}, errInvalidPasskeyDeletionToken
	}

	passkeyDeletion, err := server.getPasskeyDeletion(passkeyDeletionId)
	if errors.Is(err, errItemNotFound) {
		return passkeyDeletionStruct{}, errInvalidPasskeyDeletionToken
	}
	if err != nil {
		return passkeyDeletionStruct{}, fmt.Errorf("failed to get passkey: %s", err.Error())
	}

	passkeyDeletionSecretValid := passkeyDeletion.compareSecretAgainstHash(passkeyDeletionSecret)
	if !passkeyDeletionSecretValid {
		return passkeyDeletionStruct{}, errInvalidPasskeyDeletionToken
	}

	return passkeyDeletion, nil
}

func (server *serverStruct) validateRequestPasskeyDeletionToken(r *http.Request) (passkeyDeletionStruct, string, error) {
	passkeyDeletionTokenCookie, err := r.Cookie(passkeyDeletionTokenCookieName)
	if err != nil {
		return passkeyDeletionStruct{}, "", errInvalidPasskeyDeletionToken
	}
	passkeyDeletionToken := passkeyDeletionTokenCookie.Value

	passkeyDeletion, err := server.validatePasskeyDeletionToken(passkeyDeletionToken)
	if errors.Is(err, errInvalidPasskeyDeletionToken) {
		return passkeyDeletionStruct{}, "", errInvalidPasskeyDeletionToken
	}
	if err != nil {
		return passkeyDeletionStruct{}, "", fmt.Errorf("failed to validate passkeyDeletion token: %s", err.Error())
	}

	return passkeyDeletion, passkeyDeletionToken, nil
}

func (server *serverStruct) completePasskeyDeletionIdentityVerification(passkeyDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE passkey_deletion SET identity_verified = 1 WHERE id = ? AND identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
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
		return fmt.Errorf("failed to update passkey_deletion table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'passkey_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
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

func (server *serverStruct) completePasskeyDeletion(passkeyDeletionId string) (string, error) {
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
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey WHERE id = (SELECT passkey_id FROM passkey_deletion WHERE id = ?) RETURNING name", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
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

	err = sqlitex.Execute(databaseWriteConnection, `DELETE FROM passkey_deletion WHERE id = ?`, &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from passkey_deletion table: %s", err.Error())
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

func (server *serverStruct) deletePasskeyDeletion(passkeyDeletionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_deletion WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from passkey_deletion table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'passkey_deletion' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyDeletionId},
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
