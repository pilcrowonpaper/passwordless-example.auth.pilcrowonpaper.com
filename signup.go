package main

import (
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

type signupStruct struct {
	id                           string
	secretHash                   []byte
	targetUserId                 string
	emailAddress                 string
	emailAddressVerificationCode string
	emailAddressVerified         bool
	createdAt                    time.Time
}

func (signup *signupStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, signup.secretHash)
	return hashEqual
}

func (signup *signupStruct) compareEmailAddressVerificationCode(emailAddressVerificationCode string) bool {
	return constantTimeCompareStrings(emailAddressVerificationCode, signup.emailAddressVerificationCode)
}

const signupTokenCookieName = "signup_token"

func (server *serverStruct) setBlankSignupTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     signupTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

var errInvalidSignupToken = errors.New("invalid signup token")

func (server *serverStruct) createSignup(emailAddress string) (signupStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()
	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	targetUserId := generateItemId()

	emailAddressVerificationCode := generateEmailAddressVerificationCode()

	signup := signupStruct{
		id:                           id,
		secretHash:                   secretHash,
		targetUserId:                 targetUserId,
		emailAddress:                 emailAddress,
		emailAddressVerificationCode: emailAddressVerificationCode,
		emailAddressVerified:         false,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return signupStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO signup (id, secret_hash, target_user_id, email_address, email_address_verification_code, created_at) VALUES (?, ?, ?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{signup.id, signup.secretHash, signup.targetUserId, signup.emailAddress, signup.emailAddressVerificationCode, signup.createdAt.Unix()},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return signupStruct{}, nil, errItemConflict
	}
	if err != nil {
		return signupStruct{}, nil, fmt.Errorf("failed to insert into signup table: %s", err.Error())
	}

	return signup, secret, nil
}

func (server *serverStruct) getSignup(signupId string) (signupStruct, error) {
	signups := []signupStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT secret_hash, target_user_id, email_address, email_address_verification_code, email_address_verified, created_at FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			secretHash := make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, secretHash)

			targetUserId := stmt.ColumnText(1)

			emailAddress := stmt.ColumnText(2)

			emailAddressVerificationCode := stmt.ColumnText(3)

			emailAddressVerified := stmt.ColumnBool(4)

			createdAt := time.Unix(stmt.ColumnInt64(5), 0)

			signup := signupStruct{
				id:                           signupId,
				secretHash:                   secretHash,
				targetUserId:                 targetUserId,
				emailAddress:                 emailAddress,
				emailAddressVerificationCode: emailAddressVerificationCode,
				emailAddressVerified:         emailAddressVerified,
				createdAt:                    createdAt,
			}

			signups = append(signups, signup)

			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to select from signup table: %s", err.Error())
	}

	if len(signups) < 1 {
		return signupStruct{}, errItemNotFound
	}
	signup := signups[0]

	if time.Since(signup.createdAt) >= time.Hour*24 {
		return signupStruct{}, errItemNotFound
	}

	return signup, nil
}

func (server *serverStruct) validateSignupToken(signupToken string) (signupStruct, error) {
	tokenParts := strings.Split(signupToken, ".")
	if len(tokenParts) != 2 {
		return signupStruct{}, errInvalidSignupToken
	}
	signupId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return signupStruct{}, errInvalidSignupToken
	}

	signup, err := server.getSignup(signupId)
	if errors.Is(err, errItemNotFound) {
		return signupStruct{}, errInvalidSignupToken
	}
	if err != nil {
		return signupStruct{}, fmt.Errorf("failed to get signup: %s", err.Error())
	}

	secretValid := signup.compareSecretAgainstHash(secret)
	if !secretValid {
		return signupStruct{}, errInvalidSignupToken
	}

	return signup, nil
}

func (server *serverStruct) validateRequestSignupToken(r *http.Request) (signupStruct, string, error) {
	signupTokenCookie, err := r.Cookie(signupTokenCookieName)
	if err != nil {
		return signupStruct{}, "", errInvalidSignupToken
	}
	signupToken := signupTokenCookie.Value

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return signupStruct{}, "", errInvalidSignupToken
	}
	if err != nil {
		return signupStruct{}, "", fmt.Errorf("failed to validate signup token: %s", err.Error())
	}

	return signup, signupToken, nil
}

func (server *serverStruct) setSignupAsEmailAddressVerified(signupId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE signup SET email_address_verified = 1 WHERE id = ? AND email_address_verified = 0", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update signup table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeSignup(signupId string) (userStruct, sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	sessionId := generateItemId()
	sessionSecret := generateSessionSecret()
	sessionSecretHash := hashSessionSecret(sessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	users := []userStruct{}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO user (id, email_address, created_at) SELECT signup.target_user_id, signup.email_address, ? FROM signup WHERE id = ? AND email_address_verified = 1 RETURNING id, email_address", &sqlitex.ExecOptions{
		Args: []any{nowSecondPrecision.Unix(), signupId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := stmt.ColumnText(0)
			emailAddress := stmt.ColumnText(1)
			user := userStruct{
				id:           id,
				emailAddress: emailAddress,
				createdAt:    nowSecondPrecision,
			}
			users = append(users, user)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, sessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(users) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, errItemNotFound
	}
	user := users[0]

	session := sessionStruct{
		id:         sessionId,
		userId:     user.id,
		secretHash: sessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{session.id, session.userId, session.secretHash, session.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return user, session, sessionSecret, nil
}

func (server *serverStruct) completeSignupWithPasskeyRegistration(signupId string, signupPasskeyRegistrationId string, passkeyName string) (userStruct, passkeyStruct, sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyId := generateItemId()

	sessionId := generateItemId()
	sessionSecret := generateSessionSecret()
	sessionSecretHash := hashSessionSecret(sessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	users := []userStruct{}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO user (id, email_address, created_at) SELECT signup.target_user_id, signup.email_address, ? FROM signup WHERE id = ? AND email_address_verified = 1 RETURNING id, email_address", &sqlitex.ExecOptions{
		Args: []any{nowSecondPrecision.Unix(), signupId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := stmt.ColumnText(0)
			emailAddress := stmt.ColumnText(1)

			user := userStruct{
				id:           id,
				emailAddress: emailAddress,
				createdAt:    nowSecondPrecision,
			}
			users = append(users, user)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(users) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, errItemNotFound
	}
	user := users[0]

	passkeys := []passkeyStruct{}
	err = sqlitex.Execute(databaseWriteConnection, `INSERT INTO passkey (id, user_id, webauthn_credential_id, signature_algorithm, public_key, webauthn_authenticator_id, name, created_at)
SELECT ?, ?, passkey_webauthn_credential_id, passkey_signature_algorithm, passkey_public_key, passkey_webauthn_authenticator_id, ?, ? FROM signup_passkey_registration
WHERE id = ?
RETURNING webauthn_credential_id, signature_algorithm, public_key, webauthn_authenticator_id, name`, &sqlitex.ExecOptions{
		Args: []any{passkeyId, user.id, passkeyName, nowSecondPrecision.Unix(), signupPasskeyRegistrationId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			webauthnCredentialId := make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, webauthnCredentialId)

			signatureAlgorithm := stmt.ColumnText(1)

			publicKey := make([]byte, stmt.ColumnLen(2))
			stmt.ColumnBytes(2, publicKey)

			webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(3))
			stmt.ColumnBytes(3, webauthnAuthenticatorId)

			name := stmt.ColumnText(4)

			passkey := passkeyStruct{
				id:                      passkeyId,
				userId:                  user.id,
				webauthnCredentialId:    webauthnCredentialId,
				signatureAlgorithm:      signatureAlgorithm,
				publicKey:               publicKey,
				webauthnAuthenticatorId: webauthnAuthenticatorId,
				name:                    name,
				createdAt:               nowSecondPrecision,
			}
			passkeys = append(passkeys, passkey)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into passkey table: %s", err.Error())
	}
	if len(passkeys) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, errItemNotFound
	}
	passkey := passkeys[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}

	session := sessionStruct{
		id:         sessionId,
		userId:     user.id,
		secretHash: sessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{session.id, session.userId, session.secretHash, session.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, sessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return user, passkey, session, sessionSecret, nil
}

func (server *serverStruct) deleteSignup(signupId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
