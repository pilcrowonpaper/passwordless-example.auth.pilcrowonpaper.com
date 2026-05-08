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

type signupSessionStruct struct {
	id                                    string
	secretHash                            []byte
	targetUserId                          string
	emailAddress                          string
	emailAddressVerificationCode          string
	emailAddressVerified                  bool
	passkeyWebauthnCredentialIdDefined    bool
	passkeyWebauthnCredentialId           []byte
	passkeyCOSEPublicKeyDefined           bool
	passkeyCOSEPublicKey                  []byte
	passkeyWebauthnAuthenticatorIdDefined bool
	passkeyWebauthnAuthenticatorId        []byte
	createdAt                             time.Time
}

func (signupSession *signupSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, signupSession.secretHash)
	return hashEqual
}

func (signupSession *signupSessionStruct) compareEmailAddressVerificationCode(emailAddressVerificationCode string) bool {
	return constantTimeCompareStrings(emailAddressVerificationCode, signupSession.emailAddressVerificationCode)
}

func (server *serverStruct) createSignupSession(emailAddress string) (signupSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()
	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	targetUserId := generateItemId()

	emailAddressVerificationCode := generateEmailAddressVerificationCode()

	signupSession := signupSessionStruct{
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
		return signupSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO signup_session (id, secret_hash, target_user_id, email_address, email_address_verification_code, created_at) VALUES (?, ?, ?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{signupSession.id, signupSession.secretHash, signupSession.targetUserId, signupSession.emailAddress, signupSession.emailAddressVerificationCode, signupSession.createdAt.Unix()},
	})
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return signupSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return signupSessionStruct{}, nil, fmt.Errorf("failed to insert into signup_session table: %s", err.Error())
	}

	return signupSession, secret, nil
}

func (server *serverStruct) getSignupSession(signupSessionId string) (signupSessionStruct, error) {
	signupSessions := []signupSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT secret_hash, target_user_id, email_address, email_address_verification_code, email_address_verified, passkey_webauthn_credential_id, passkey_cose_public_key, passkey_webauthn_authenticator_id, created_at FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			secretHash := make([]byte, stmt.ColumnLen(0))
			stmt.ColumnBytes(0, secretHash)

			targetUserId := stmt.ColumnText(1)

			emailAddress := stmt.ColumnText(2)

			emailAddressVerificationCode := stmt.ColumnText(3)

			emailAddressVerified := stmt.ColumnBool(4)

			passkeyWebauthnCredentialIdDefined := false
			var passkeyWebauthnCredentialId []byte
			if !stmt.ColumnIsNull(5) {
				passkeyWebauthnCredentialIdDefined = true
				passkeyWebauthnCredentialId = make([]byte, stmt.ColumnLen(5))
				stmt.ColumnBytes(5, passkeyWebauthnCredentialId)
			}

			passkeyCOSEPublicKeyDefined := false
			var passkeyCOSEPublicKey []byte
			if !stmt.ColumnIsNull(6) {
				passkeyCOSEPublicKeyDefined = true
				passkeyCOSEPublicKey = make([]byte, stmt.ColumnLen(6))
				stmt.ColumnBytes(6, passkeyCOSEPublicKey)
			}

			passkeyWebauthnAuthenticatorIdDefined := false
			var passkeyWebauthnAuthenticatorId []byte
			if !stmt.ColumnIsNull(7) {
				passkeyWebauthnAuthenticatorIdDefined = true
				passkeyWebauthnAuthenticatorId = make([]byte, stmt.ColumnLen(7))
				stmt.ColumnBytes(7, passkeyWebauthnAuthenticatorId)
			}

			createdAt := time.Unix(stmt.ColumnInt64(8), 0)

			signupSession := signupSessionStruct{
				id:                                    signupSessionId,
				secretHash:                            secretHash,
				targetUserId:                          targetUserId,
				emailAddress:                          emailAddress,
				emailAddressVerificationCode:          emailAddressVerificationCode,
				emailAddressVerified:                  emailAddressVerified,
				passkeyWebauthnCredentialIdDefined:    passkeyWebauthnCredentialIdDefined,
				passkeyWebauthnCredentialId:           passkeyWebauthnCredentialId,
				passkeyCOSEPublicKeyDefined:           passkeyCOSEPublicKeyDefined,
				passkeyCOSEPublicKey:                  passkeyCOSEPublicKey,
				passkeyWebauthnAuthenticatorIdDefined: passkeyWebauthnAuthenticatorIdDefined,
				passkeyWebauthnAuthenticatorId:        passkeyWebauthnAuthenticatorId,
				createdAt:                             createdAt,
			}

			signupSessions = append(signupSessions, signupSession)

			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to select from signup_session table: %s", err.Error())
	}

	if len(signupSessions) < 1 {
		return signupSessionStruct{}, errItemNotFound
	}
	signupSession := signupSessions[0]

	if time.Since(signupSession.createdAt) >= time.Hour*24 {
		return signupSessionStruct{}, errItemNotFound
	}

	return signupSession, nil
}

var errInvalidSignupSessionToken = errors.New("invalid signup session token")

func (server *serverStruct) validateSignupSessionToken(signupSessionToken string) (signupSessionStruct, error) {
	signupSessionId, signupSessionSecret, err := parseSessionToken(signupSessionToken)
	if err != nil {
		return signupSessionStruct{}, errInvalidSignupSessionToken
	}

	signupSession, err := server.getSignupSession(signupSessionId)
	if errors.Is(err, errItemNotFound) {
		return signupSessionStruct{}, errInvalidSignupSessionToken
	}
	if err != nil {
		return signupSessionStruct{}, fmt.Errorf("failed to get signup session: %s", err.Error())
	}

	secretValid := signupSession.compareSecretAgainstHash(signupSessionSecret)
	if !secretValid {
		return signupSessionStruct{}, errInvalidSignupSessionToken
	}

	return signupSession, nil
}

const signupSessionTokenCookieName = "signup_session_token"

func (server *serverStruct) validateRequestSignupSessionToken(r *http.Request) (signupSessionStruct, string, error) {
	signupSessionTokenCookie, err := r.Cookie(signupSessionTokenCookieName)
	if err != nil {
		return signupSessionStruct{}, "", errInvalidSignupSessionToken
	}
	signupSessionToken := signupSessionTokenCookie.Value

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return signupSessionStruct{}, "", errInvalidSignupSessionToken
	}
	if err != nil {
		return signupSessionStruct{}, "", fmt.Errorf("failed to validate signup session token: %s", err.Error())
	}

	return signupSession, signupSessionToken, nil
}

func (server *serverStruct) setBlankSignupSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, signupSessionTokenCookieName)
}

func (server *serverStruct) setSignupSessionAsEmailAddressVerified(signupSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE signup_session SET email_address_verified = 1 WHERE id = ? AND email_address_verified = 0", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update signup_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) setSignupSessionPasskeyWebauthnCredential(signupSessionId string, passkeyWebauthnCredentialId []byte, passkeyCOSEPublicKey []byte, passkeyWebauthnAuthenticatorId []byte) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "UPDATE signup_session SET passkey_webauthn_credential_id = ?, passkey_cose_public_key = ?, passkey_webauthn_authenticator_id = ? WHERE id = ? AND passkey_webauthn_credential_id IS NULL", &sqlitex.ExecOptions{
		Args: []any{passkeyWebauthnCredentialId, passkeyCOSEPublicKey, passkeyWebauthnAuthenticatorId, signupSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update signup_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completeSignupWithoutPasskeyRegistration(signupSessionId string) (userStruct, authSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	authSessionId := generateItemId()
	authSessionSecret := generateSessionSecret()
	authSessionSecretHash := hashSessionSecret(authSessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	users := []userStruct{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO user (id, email_address, created_at)
SELECT target_user_id, email_address, ? FROM signup_session
WHERE id = ?
AND email_address_verified = 1
AND passkey_webauthn_credential_id IS NULL
RETURNING id, email_address`, &sqlitex.ExecOptions{
			Args: []any{nowSecondPrecision.Unix(), signupSessionId},
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
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, authSessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(users) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, errItemNotFound
	}
	user := users[0]

	authSession := authSessionStruct{
		id:         authSessionId,
		userId:     user.id,
		secretHash: authSessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO auth_session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{authSession.id, authSession.userId, authSession.secretHash, authSession.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into auth_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to delete from signup_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return user, authSession, authSessionSecret, nil
}

func (server *serverStruct) completeSignupWithPasskeyRegistration(signupSessionId string, passkeyName string) (userStruct, passkeyStruct, authSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyId := generateItemId()

	authSessionId := generateItemId()
	authSessionSecret := generateSessionSecret()
	authSessionSecretHash := hashSessionSecret(authSessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	users := []userStruct{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO user (id, email_address, created_at)
SELECT target_user_id, email_address, ? FROM signup_session
WHERE id = ?
AND email_address_verified = 1
AND passkey_webauthn_credential_id IS NOT NULL
RETURNING id, email_address`,
		&sqlitex.ExecOptions{
			Args: []any{nowSecondPrecision.Unix(), signupSessionId},
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
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into user table: %s", err.Error())
	}

	if len(users) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, errItemNotFound
	}
	user := users[0]

	passkeys := []passkeyStruct{}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO passkey (id, user_id, webauthn_credential_id, cose_public_key, webauthn_authenticator_id, name, created_at)
SELECT ?, ?, passkey_webauthn_credential_id, passkey_cose_public_key, passkey_webauthn_authenticator_id, ?, ? FROM signup_session
WHERE id = ?
RETURNING webauthn_credential_id, cose_public_key, webauthn_authenticator_id, name`,
		&sqlitex.ExecOptions{
			Args: []any{passkeyId, user.id, passkeyName, nowSecondPrecision.Unix(), signupSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				webauthnCredentialId := make([]byte, stmt.ColumnLen(0))
				stmt.ColumnBytes(0, webauthnCredentialId)

				cosePublicKey := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, cosePublicKey)

				webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, webauthnAuthenticatorId)

				name := stmt.ColumnText(3)

				passkey := passkeyStruct{
					id:                      passkeyId,
					userId:                  user.id,
					webauthnCredentialId:    webauthnCredentialId,
					cosePublicKey:           cosePublicKey,
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
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, errItemConflict
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into passkey table: %s", err.Error())
	}
	if len(passkeys) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, errItemNotFound
	}
	passkey := passkeys[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to delete from signup_session table: %s", err.Error())
	}

	authSession := authSessionStruct{
		id:         authSessionId,
		userId:     user.id,
		secretHash: authSessionSecretHash,
		createdAt:  nowSecondPrecision,
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO auth_session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{authSession.id, authSession.userId, authSession.secretHash, authSession.createdAt.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to insert into auth_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return userStruct{}, passkeyStruct{}, authSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return user, passkey, authSession, authSessionSecret, nil
}

func (server *serverStruct) deleteSignupSession(signupSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from signup_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
