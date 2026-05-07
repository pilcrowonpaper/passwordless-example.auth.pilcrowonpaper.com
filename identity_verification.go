package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type identityVerificationStruct struct {
	id                           string
	sessionId                    string
	secretHash                   []byte
	verifyingAction              string
	verifyingActionId            string
	passkeyVerificationChallenge []byte
	emailCodeDefined             bool
	emailCode                    string
	createdAt                    time.Time
}

func (identityVerification *identityVerificationStruct) compareEmailCode(emailCode string) bool {
	if !identityVerification.emailCodeDefined {
		return false
	}
	return constantTimeCompareStrings(emailCode, identityVerification.emailCode)
}

const (
	identityVerificationVerifyingActionEmailAddressUpdate  = "email_address_update"
	identityVerificationVerifyingActionPasskeyRegistration = "passkey_registration"
	identityVerificationVerifyingActionPasskeyDeletion     = "passkey_deletion"
	identityVerificationVerifyingActionAccountDeletion     = "account_deletion"
)

func (identityVerification *identityVerificationStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, identityVerification.secretHash)
	return hashEqual
}

func (identityVerification *identityVerificationStruct) comparePasskeyVerificationChallenge(challenge []byte) bool {
	return bytes.Equal(identityVerification.passkeyVerificationChallenge, challenge)
}

func (server *serverStruct) getIdentityVerification(identityVerificationId string) (identityVerificationStruct, error) {
	identityVerifications := []identityVerificationStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return identityVerificationStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, verifying_action, verifying_action_id, passkey_verification_challenge, email_code, created_at FROM identity_verification WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sessionId := stmt.ColumnText(0)

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

				identityVerification := identityVerificationStruct{
					id:                           identityVerificationId,
					sessionId:                    sessionId,
					secretHash:                   secretHash,
					verifyingAction:              verifyingAction,
					verifyingActionId:            verifyingActionId,
					passkeyVerificationChallenge: passkeyVerificationChallenge,
					emailCodeDefined:             emailCodeDefined,
					emailCode:                    emailCode,
					createdAt:                    createdAt,
				}

				identityVerifications = append(identityVerifications, identityVerification)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return identityVerificationStruct{}, fmt.Errorf("failed to select from identity_verification table: %s", err.Error())
	}

	if len(identityVerifications) < 1 {
		return identityVerificationStruct{}, errItemNotFound
	}

	identityVerification := identityVerifications[0]

	if time.Since(identityVerification.createdAt) >= time.Hour {
		return identityVerificationStruct{}, errItemNotFound
	}

	return identityVerification, nil
}

func (server *serverStruct) getIdentityVerificationUserEmailAddress(identityVerificationId string) (string, error) {
	userEmailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		`SELECT user.email_address FROM identity_verification
INNER JOIN session ON identity_verification.session_id = session.id
INNER JOIN user ON session.user_id = user.id
WHERE identity_verification.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)
				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from identity_verification table: %s", err.Error())
	}

	if len(userEmailAddresses) < 1 {
		return "", errItemNotFound
	}

	userEmailAddress := userEmailAddresses[0]

	return userEmailAddress, nil
}

var errInvalidIdentityVerificationToken = errors.New("invalid identity verification token")

func (server *serverStruct) validateIdentityVerificationToken(identityVerificationToken string) (identityVerificationStruct, error) {
	tokenParts := strings.Split(identityVerificationToken, ".")
	if len(tokenParts) != 2 {
		return identityVerificationStruct{}, errInvalidIdentityVerificationToken
	}
	identityVerificationId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return identityVerificationStruct{}, errInvalidIdentityVerificationToken
	}

	identityVerification, err := server.getIdentityVerification(identityVerificationId)
	if errors.Is(err, errItemNotFound) {
		return identityVerificationStruct{}, errInvalidIdentityVerificationToken
	}
	if err != nil {
		return identityVerificationStruct{}, fmt.Errorf("failed to get identity verification: %s", err.Error())
	}

	secretValid := identityVerification.compareSecretAgainstHash(secret)
	if !secretValid {
		return identityVerificationStruct{}, errInvalidIdentityVerificationToken
	}

	return identityVerification, nil
}

const identityVerificationTokenCookieName = "identity_verification_token"

func (server *serverStruct) validateRequestIdentityVerificationToken(r *http.Request) (identityVerificationStruct, string, error) {
	identityVerificationTokenCookie, err := r.Cookie(identityVerificationTokenCookieName)
	if err != nil {
		return identityVerificationStruct{}, "", errInvalidIdentityVerificationToken
	}
	identityVerificationToken := identityVerificationTokenCookie.Value

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return identityVerificationStruct{}, "", errInvalidIdentityVerificationToken
	}
	if err != nil {
		return identityVerificationStruct{}, "", fmt.Errorf("failed to validate identity verification token: %s", err.Error())
	}

	return identityVerification, identityVerificationToken, nil
}

func (server *serverStruct) setBlankIdentityVerificationTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     identityVerificationTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) issueIdentityVerificationEmailCode(identityVerificationId string) (string, string, error) {
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
		`SELECT user.email_address FROM identity_verification
INNER JOIN session ON identity_verification.session_id = session.id
INNER JOIN user ON session.user_id = user.id
WHERE identity_verification.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
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
		return "", "", fmt.Errorf("failed to select from identity_verification table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification SET email_code = ? WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCode, identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", fmt.Errorf("failed to update identity_verification table: %s", err.Error())
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

func (server *serverStruct) revokeIdentityVerificationEmailCode(identityVerificationId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification SET email_code = NULL WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update identity_verification table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeIdentityVerification(identityVerificationId string, verifyingAction string) error {
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		err := server.completeIdentityVerificationForEmailAddressUpdate(identityVerificationId)
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
	if verifyingAction == identityVerificationVerifyingActionPasskeyRegistration {
		err := server.completeIdentityVerificationForPasskeyRegistration(identityVerificationId)
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
	if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		err := server.completeIdentityVerificationForPasskeyDeletion(identityVerificationId)
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
	if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		err := server.completeIdentityVerificationForAccountDeletion(identityVerificationId)
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
	return fmt.Errorf("unknown identity verification verifying action '%s'", verifyingAction)
}

func (server *serverStruct) completeIdentityVerificationForEmailAddressUpdate(identityVerificationId string) error {
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
		`UPDATE email_address_update SET identity_verified = 1 FROM identity_verification
WHERE email_address_update.id = identity_verification.verifying_action_id
AND identity_verification.id = ?
AND identity_verification.verifying_action = 'email_address_update'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
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
		return fmt.Errorf("failed to update email_address_update table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
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

func (server *serverStruct) completeIdentityVerificationForPasskeyRegistration(identityVerificationId string) error {
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
		`UPDATE passkey_registration SET identity_verified = 1 FROM identity_verification
WHERE passkey_registration.id = identity_verification.verifying_action_id
AND identity_verification.id = ?
AND identity_verification.verifying_action = 'passkey_registration'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
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
		return fmt.Errorf("failed to update passkey_registration table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
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

func (server *serverStruct) completeIdentityVerificationForPasskeyDeletion(identityVerificationId string) error {
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
		`UPDATE passkey_deletion SET identity_verified = 1 FROM identity_verification
WHERE passkey_deletion.id = identity_verification.verifying_action_id
AND identity_verification.id = ?
AND identity_verification.verifying_action = 'passkey_deletion'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
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

func (server *serverStruct) completeIdentityVerificationForAccountDeletion(identityVerificationId string) error {
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
		`UPDATE account_deletion SET identity_verified = 1 FROM identity_verification
WHERE account_deletion.id = identity_verification.verifying_action_id
AND identity_verification.id = ?
AND identity_verification.verifying_action = 'account_deletion'`, &sqlitex.ExecOptions{
			Args: []any{identityVerificationId},
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
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
