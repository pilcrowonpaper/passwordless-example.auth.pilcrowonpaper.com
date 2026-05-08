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

type identityVerificationSessionStruct struct {
	id                           string
	authSessionId                string
	secretHash                   []byte
	verifyingAction              string
	verifyingActionId            string
	passkeyVerificationChallenge []byte
	emailCodeDefined             bool
	emailCode                    string
	createdAt                    time.Time
}

func (identityVerificationSession *identityVerificationSessionStruct) compareEmailCode(emailCode string) bool {
	if !identityVerificationSession.emailCodeDefined {
		return false
	}
	return constantTimeCompareStrings(emailCode, identityVerificationSession.emailCode)
}

const (
	identityVerificationSessionVerifyingActionEmailAddressUpdate  = "email_address_update"
	identityVerificationSessionVerifyingActionPasskeyRegistration = "passkey_registration"
	identityVerificationSessionVerifyingActionPasskeyDeletion     = "passkey_deletion"
	identityVerificationSessionVerifyingActionAccountDeletion     = "account_deletion"
)

func (identityVerificationSession *identityVerificationSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, identityVerificationSession.secretHash)
	return hashEqual
}

func (server *serverStruct) getIdentityVerificationSession(identityVerificationSessionId string) (identityVerificationSessionStruct, error) {
	identityVerificationSessions := []identityVerificationSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return identityVerificationSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, verifying_action, verifying_action_id, passkey_verification_challenge, email_code, created_at FROM identity_verification_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				authSessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				verifyingAction := stmt.ColumnText(2)

				verifyingActionId := stmt.ColumnText(3)

				passkeyVerificationChallenge := make([]byte, stmt.ColumnLen(4))
				stmt.ColumnBytes(4, passkeyVerificationChallenge)

				emailCodeDefined := false
				var emailCode string
				if !stmt.ColumnIsNull(5) {
					emailCodeDefined = true
					emailCode = stmt.ColumnText(5)
				}

				createdAt := time.Unix(stmt.ColumnInt64(6), 0)

				identityVerificationSession := identityVerificationSessionStruct{
					id:                           identityVerificationSessionId,
					authSessionId:                authSessionId,
					secretHash:                   secretHash,
					verifyingAction:              verifyingAction,
					verifyingActionId:            verifyingActionId,
					passkeyVerificationChallenge: passkeyVerificationChallenge,
					emailCodeDefined:             emailCodeDefined,
					emailCode:                    emailCode,
					createdAt:                    createdAt,
				}

				identityVerificationSessions = append(identityVerificationSessions, identityVerificationSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return identityVerificationSessionStruct{}, fmt.Errorf("failed to select from identity_verification_session table: %s", err.Error())
	}

	if len(identityVerificationSessions) < 1 {
		return identityVerificationSessionStruct{}, errItemNotFound
	}

	identityVerificationSession := identityVerificationSessions[0]

	if time.Since(identityVerificationSession.createdAt) >= time.Hour {
		return identityVerificationSessionStruct{}, errItemNotFound
	}

	return identityVerificationSession, nil
}

func (server *serverStruct) getIdentityVerificationSessionUserEmailAddress(identityVerificationSessionId string) (string, error) {
	userEmailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		`SELECT user.email_address FROM identity_verification_session
INNER JOIN auth_session ON identity_verification_session.auth_session_id = auth_session.id
INNER JOIN user ON auth_session.user_id = user.id
WHERE identity_verification_session.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)
				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from identity_verification_session table: %s", err.Error())
	}

	if len(userEmailAddresses) < 1 {
		return "", errItemNotFound
	}

	userEmailAddress := userEmailAddresses[0]

	return userEmailAddress, nil
}

var errInvalidIdentityVerificationSessionToken = errors.New("invalid identity verification session token")

func (server *serverStruct) validateIdentityVerificationSessionToken(identityVerificationSessionToken string) (identityVerificationSessionStruct, error) {
	identityVerificationSessionId, identityVerificationSessionSecret, err := parseSessionToken(identityVerificationSessionToken)
	if err != nil {
		return identityVerificationSessionStruct{}, errInvalidIdentityVerificationSessionToken
	}

	identityVerificationSession, err := server.getIdentityVerificationSession(identityVerificationSessionId)
	if errors.Is(err, errItemNotFound) {
		return identityVerificationSessionStruct{}, errInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		return identityVerificationSessionStruct{}, fmt.Errorf("failed to get identity verification session: %s", err.Error())
	}

	secretValid := identityVerificationSession.compareSecretAgainstHash(identityVerificationSessionSecret)
	if !secretValid {
		return identityVerificationSessionStruct{}, errInvalidIdentityVerificationSessionToken
	}

	return identityVerificationSession, nil
}

const identityVerificationSessionTokenCookieName = "identity_verification_session_token"

func (server *serverStruct) validateRequestIdentityVerificationSessionToken(r *http.Request) (identityVerificationSessionStruct, string, error) {
	identityVerificationSessionTokenCookie, err := r.Cookie(identityVerificationSessionTokenCookieName)
	if err != nil {
		return identityVerificationSessionStruct{}, "", errInvalidIdentityVerificationSessionToken
	}
	identityVerificationSessionToken := identityVerificationSessionTokenCookie.Value

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return identityVerificationSessionStruct{}, "", errInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		return identityVerificationSessionStruct{}, "", fmt.Errorf("failed to validate identity verification session token: %s", err.Error())
	}

	return identityVerificationSession, identityVerificationSessionToken, nil
}

func (server *serverStruct) setBlankIdentityVerificationSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, identityVerificationSessionTokenCookieName)
}

func (server *serverStruct) issueIdentityVerificationSessionEmailCode(identityVerificationSessionId string) (string, string, error) {
	emailCode := generateEmailCode()

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", "", fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	userEmailAddresses := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`SELECT user.email_address FROM identity_verification_session
INNER JOIN auth_session ON identity_verification_session.auth_session_id = auth_session.id
INNER JOIN user ON auth_session.user_id = user.id
WHERE identity_verification_session.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)
				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", "", fmt.Errorf("failed to select from identity_verification_session table: %s", err.Error())
	}
	if len(userEmailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", errItemNotFound
	}
	userEmailAddress := userEmailAddresses[0]

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification_session SET email_code = ? WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCode, identityVerificationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", "", fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return emailCode, userEmailAddress, nil
}

func (server *serverStruct) revokeIdentityVerificationSessionEmailCode(identityVerificationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification_session SET email_code = NULL WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeIdentityVerification(identityVerificationSessionId string, verifyingAction string) error {
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		err := server.completeIdentityVerificationForEmailAddressUpdate(identityVerificationSessionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete identity verification for email address update: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationSessionVerifyingActionPasskeyRegistration {
		err := server.completeIdentityVerificationForPasskeyRegistration(identityVerificationSessionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete identity verification for passkey registration: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		err := server.completeIdentityVerificationForPasskeyDeletion(identityVerificationSessionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete identity verification for passkey deletion: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		err := server.completeIdentityVerificationForAccountDeletion(identityVerificationSessionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete identity verification for account deletion: %s", err.Error())
		}
		return nil
	}
	return fmt.Errorf("unknown identity verification session verifying action '%s'", verifyingAction)
}

func (server *serverStruct) completeIdentityVerificationForEmailAddressUpdate(identityVerificationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE email_address_update_session SET identity_verified = 1 FROM identity_verification_session
WHERE email_address_update_session.id = identity_verification_session.verifying_action_id
AND identity_verification_session.id = ?
AND identity_verification_session.verifying_action = 'email_address_update'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
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
		return fmt.Errorf("failed to update email_address_update_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
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

func (server *serverStruct) completeIdentityVerificationForPasskeyRegistration(identityVerificationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE passkey_registration_session SET identity_verified = 1 FROM identity_verification_session
WHERE passkey_registration_session.id = identity_verification_session.verifying_action_id
AND identity_verification_session.id = ?
AND identity_verification_session.verifying_action = 'passkey_registration'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
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
		return fmt.Errorf("failed to update passkey_registration_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
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

func (server *serverStruct) completeIdentityVerificationForPasskeyDeletion(identityVerificationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE passkey_deletion_session SET identity_verified = 1 FROM identity_verification_session
WHERE passkey_deletion_session.id = identity_verification_session.verifying_action_id
AND identity_verification_session.id = ?
AND identity_verification_session.verifying_action = 'passkey_deletion'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
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
		return fmt.Errorf("failed to update passkey_deletion_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
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

func (server *serverStruct) completeIdentityVerificationForAccountDeletion(identityVerificationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE account_deletion_session SET identity_verified = 1 FROM identity_verification_session
WHERE account_deletion_session.id = identity_verification_session.verifying_action_id
AND identity_verification_session.id = ?
AND identity_verification_session.verifying_action = 'account_deletion'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationSessionId},
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
		return fmt.Errorf("failed to update account_deletion_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return fmt.Errorf("failed to update identity_verification_session table: %s", err.Error())
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
