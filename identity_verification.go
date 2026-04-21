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
	emailCodeHashDefined         bool
	emailCodeHash                []byte
	emailCodeSaltDefined         bool
	emailCodeSalt                []byte
	createdAt                    time.Time
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
		"SELECT session_id, secret_hash, verifying_action, verifying_action_id, passkey_verification_challenge, email_code_hash, email_code_salt, created_at FROM identity_verification WHERE id = ?",
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

				emailCodeHashDefined := false
				var emailCodeHash []byte
				if !stmt.ColumnIsNull(5) {
					emailCodeHashDefined = true
					emailCodeHash = make([]byte, stmt.ColumnLen(5))
					stmt.ColumnBytes(5, emailCodeHash)
				}

				emailCodeSaltDefined := false
				var emailCodeSalt []byte
				if !stmt.ColumnIsNull(6) {
					emailCodeSaltDefined = true
					emailCodeSalt = make([]byte, stmt.ColumnLen(6))
					stmt.ColumnBytes(6, emailCodeSalt)
				}

				createdAt := time.Unix(stmt.ColumnInt64(7), 0)

				identityVerification := identityVerificationStruct{
					id:                           identityVerificationId,
					sessionId:                    sessionId,
					secretHash:                   secretHash,
					verifyingAction:              verifyingAction,
					verifyingActionId:            verifyingActionId,
					passkeyVerificationChallenge: passkeyVerificationChallenge,
					emailCodeHashDefined:         emailCodeHashDefined,
					emailCodeHash:                emailCodeHash,
					emailCodeSaltDefined:         emailCodeSaltDefined,
					emailCodeSalt:                emailCodeSalt,
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

	if time.Since(identityVerification.createdAt) >= time.Minute*60 {
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
				emailAddress := stmt.ColumnText(0)
				userEmailAddresses = append(userEmailAddresses, emailAddress)
				return nil
			},
		})
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
	emailCodeSalt := generateHashingSalt()
	emailCodeHash := server.hashEmailCode(emailCode, emailCodeSalt)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", "", fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification SET email_code_hash = ?, email_code_salt = ? WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCodeHash, emailCodeSalt, identityVerificationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return "", "", errItemConflict
		}
		return "", "", fmt.Errorf("failed to update email_address_update table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	if affectedCount < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", errItemNotFound
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
				emailAddress := stmt.ColumnText(0)
				userEmailAddresses = append(userEmailAddresses, emailAddress)
				return nil
			},
		})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", fmt.Errorf("failed to update email_address_update table: %s", err.Error())
	}
	if len(userEmailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return "", "", fmt.Errorf("expected user to exist")
	}
	userEmailAddress := userEmailAddresses[0]

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
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE identity_verification SET email_code_hash = NULL, email_code_salt = NULL WHERE id = ?", &sqlitex.ExecOptions{
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

func (server *serverStruct) completeIdentityVerification(verifyingAction string, verifyingActionId string) error {
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		err := server.completeEmailAddressUpdateIdentityVerification(verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete email address update identity verification: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationVerifyingActionPasskeyRegistration {
		err := server.completePasskeyRegistrationIdentityVerification(verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete passkey registration identity verification: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		err := server.completePasskeyDeletionIdentityVerification(verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete passkey deletion identity verification: %s", err.Error())
		}
		return nil
	}
	if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		err := server.completeAccountDeletionIdentityVerification(verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return errItemNotFound
		}
		if errors.Is(err, errItemConflict) {
			return errItemConflict
		}
		if err != nil {
			return fmt.Errorf("failed to complete account deletion identity verification: %s", err.Error())
		}
		return nil
	}
	return fmt.Errorf("unknown identity verification verifying action '%s'", verifyingAction)
}
