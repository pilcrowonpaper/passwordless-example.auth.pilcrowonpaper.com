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

type emailAddressUpdateStruct struct {
	id                                     string
	sessionId                              string
	secretHash                             []byte
	identityVerified                       bool
	newEmailAddress                        string
	newEmailAddressDefined                 bool
	newEmailAddressVerificationCode        string
	newEmailAddressVerificationCodeDefined bool
	createdAt                              time.Time
}

func (emailAddressUpdate *emailAddressUpdateStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, emailAddressUpdate.secretHash)
	return hashEqual
}

func (emailAddressUpdate *emailAddressUpdateStruct) compareNewEmailAddressVerificationCode(newEmailAddressVerificationCode string) bool {
	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		return false
	}
	return constantTimeCompareStrings(newEmailAddressVerificationCode, emailAddressUpdate.newEmailAddressVerificationCode)
}

func (server *serverStruct) createEmailAddressUpdate(sessionId string) (emailAddressUpdateStruct, []byte, identityVerificationStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	emailAddressUpdateId := generateItemId()
	emailAddressUpdateSecret := generateSessionSecret()
	emailAddressUpdateSecretHash := hashSessionSecret(emailAddressUpdateSecret)

	emailAddressUpdate := emailAddressUpdateStruct{
		id:         emailAddressUpdateId,
		sessionId:  sessionId,
		secretHash: emailAddressUpdateSecretHash,
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
		verifyingAction:              identityVerificationVerifyingActionEmailAddressUpdate,
		verifyingActionId:            emailAddressUpdate.id,
		passkeyVerificationChallenge: identityVerificationPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO email_address_update (id, session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				emailAddressUpdate.id,
				emailAddressUpdate.sessionId,
				emailAddressUpdate.secretHash,
				emailAddressUpdate.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into email_address_update table: %s", err.Error())
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
			return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into identity_verification table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return emailAddressUpdateStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return emailAddressUpdate, emailAddressUpdateSecret, identityVerification, identityVerificationSecret, nil
}

func (server *serverStruct) getEmailAddressUpdate(emailAddressUpdateId string) (emailAddressUpdateStruct, error) {
	emailAddressUpdates := []emailAddressUpdateStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, identity_verified, new_email_address, new_email_address_verification_code, created_at FROM email_address_update WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				identityVerified := stmt.ColumnBool(2)

				var newEmailAddress string
				newEmailAddressDefined := false
				if !stmt.ColumnIsNull(3) {
					newEmailAddress = stmt.ColumnText(3)
					newEmailAddressDefined = true
				}

				var newEmailAddressVerificationCode string
				newEmailAddressVerificationCodeDefined := false
				if !stmt.ColumnIsNull(4) {
					newEmailAddressVerificationCode = stmt.ColumnText(4)
					newEmailAddressVerificationCodeDefined = true
				}

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				emailAddressUpdate := emailAddressUpdateStruct{
					id:                                     emailAddressUpdateId,
					sessionId:                              sessionId,
					secretHash:                             secretHash,
					identityVerified:                       identityVerified,
					newEmailAddress:                        newEmailAddress,
					newEmailAddressDefined:                 newEmailAddressDefined,
					newEmailAddressVerificationCode:        newEmailAddressVerificationCode,
					newEmailAddressVerificationCodeDefined: newEmailAddressVerificationCodeDefined,
					createdAt:                              createdAt,
				}

				emailAddressUpdates = append(emailAddressUpdates, emailAddressUpdate)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to select from email_address_update table: %s", err.Error())
	}

	if len(emailAddressUpdates) < 1 {
		return emailAddressUpdateStruct{}, errItemNotFound
	}

	emailAddressUpdate := emailAddressUpdates[0]

	if time.Since(emailAddressUpdate.createdAt) >= time.Minute*60 {
		return emailAddressUpdateStruct{}, errItemNotFound
	}

	return emailAddressUpdate, nil
}

const emailAddressUpdateTokenCookieName = "email_address_update_token"

func (server *serverStruct) setBlankEmailAddressUpdateTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     emailAddressUpdateTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

var errInvalidEmailAddressUpdateToken = errors.New("invalid email address update token")

func (server *serverStruct) validateEmailAddressUpdateToken(emailAddressUpdateToken string) (emailAddressUpdateStruct, error) {
	emailAddressUpdateTokenParts := strings.Split(emailAddressUpdateToken, ".")
	if len(emailAddressUpdateTokenParts) != 2 {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateId := emailAddressUpdateTokenParts[0]
	encodedEmailAddressUpdateSecret := emailAddressUpdateTokenParts[1]
	emailAddressUpdateSecret, err := base64.StdEncoding.DecodeString(encodedEmailAddressUpdateSecret)
	if err != nil {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}

	emailAddressUpdate, err := server.getEmailAddressUpdate(emailAddressUpdateId)
	if errors.Is(err, errItemNotFound) {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateStruct{}, fmt.Errorf("failed to get email address update: %s", err.Error())
	}

	emailAddressUpdateSecretValid := emailAddressUpdate.compareSecretAgainstHash(emailAddressUpdateSecret)
	if !emailAddressUpdateSecretValid {
		return emailAddressUpdateStruct{}, errInvalidEmailAddressUpdateToken
	}

	return emailAddressUpdate, nil
}

func (server *serverStruct) validateRequestEmailAddressUpdateToken(r *http.Request) (emailAddressUpdateStruct, string, error) {
	emailAddressUpdateTokenCookie, err := r.Cookie(emailAddressUpdateTokenCookieName)
	if err != nil {
		return emailAddressUpdateStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	emailAddressUpdateToken := emailAddressUpdateTokenCookie.Value

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return emailAddressUpdateStruct{}, "", errInvalidEmailAddressUpdateToken
	}
	if err != nil {
		return emailAddressUpdateStruct{}, "", fmt.Errorf("failed to validate emailAddressUpdate token: %s", err.Error())
	}

	return emailAddressUpdate, emailAddressUpdateToken, nil
}

func (server *serverStruct) completeEmailAddressUpdateIdentityVerification(emailAddressUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update SET identity_verified = 1 WHERE id = ? AND identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'email_address_update' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
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

func (server *serverStruct) setEmailAddressUpdateNewEmailAddress(emailAddressUpdateId string, newEmailAddress string) (string, error) {
	newEmailAddressVerificationCode := generateEmailAddressVerificationCode()

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE email_address_update SET new_email_address = ?, new_email_address_verification_code = ? WHERE id = ? AND new_email_address IS NULL", &sqlitex.ExecOptions{
		Args: []any{newEmailAddress, newEmailAddressVerificationCode, emailAddressUpdateId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", fmt.Errorf("failed to update email_address_update table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return "", errItemNotFound
	}
	return newEmailAddressVerificationCode, nil
}

func (server *serverStruct) completeEmailAddressUpdate(emailAddressUpdateId string) (string, error) {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return "", fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	oldEmailAddresses := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`SELECT user.email_address FROM email_address_update
INNER JOIN session ON email_address_update.session_id = session.id
INNER JOIN user ON session.user_id = user.id
WHERE email_address_update.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				oldEmailAddress := stmt.ColumnText(0)

				oldEmailAddresses = append(oldEmailAddresses, oldEmailAddress)
				return nil
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to select from email_address_update table: %s", err.Error())
	}

	if len(oldEmailAddresses) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", errItemNotFound
	}
	oldEmailAddress := oldEmailAddresses[0]

	userIds := []string{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`UPDATE user SET email_address = email_address_update.new_email_address FROM session
INNER JOIN email_address_update ON session.id = email_address_update.session_id
WHERE user.id = session.user_id
AND email_address_update.id = ?
AND email_address_update.new_email_address IS NOT NULL
AND email_address_update.identity_verified = 1
RETURNING user.id`,
		&sqlitex.ExecOptions{
			Args: []any{emailAddressUpdateId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)
				userIds = append(userIds, userId)
				return nil
			},
		})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return "", errItemConflict
		}
		return "", fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", errItemNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from email_address_update table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_code_signin WHERE user_id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to delete from signin table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, `UPDATE identity_verification SET email_code_hash = NULL, email_code_salt = NULL FROM session 
WHERE identity_verification.session_id = session.id
AND session.user_id = ?`, &sqlitex.ExecOptions{
		Args: []any{userId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return "", fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return "", fmt.Errorf("failed to update identity_verification table: %s", err.Error())
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

	return oldEmailAddress, nil
}

func (server *serverStruct) deleteEmailAddressUpdate(emailAddressUpdateId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_address_update WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from email_address_update table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'email_address_update' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddressUpdateId},
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
