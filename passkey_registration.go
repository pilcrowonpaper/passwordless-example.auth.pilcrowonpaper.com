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

type passkeyRegistrationSessionStruct struct {
	id                                    string
	authSessionId                         string
	secretHash                            []byte
	identityVerified                      bool
	passkeyCOSEPublicKey                  []byte
	passkeyCOSEPublicKeyDefined           bool
	passkeyWebauthnCredentialId           []byte
	passkeyWebauthnCredentialIdDefined    bool
	passkeyWebauthnAuthenticatorId        []byte
	passkeyWebauthnAuthenticatorIdDefined bool
	createdAt                             time.Time
}

func (passkeyRegistrationSession *passkeyRegistrationSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passkeyRegistrationSession.secretHash)
	return hashEqual
}

func (server *serverStruct) createPasskeyRegistrationSession(authSessionId string) (passkeyRegistrationSessionStruct, []byte, identityVerificationSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyRegistrationSessionId := generateItemId()
	passkeyRegistrationSessionSecret := generateSessionSecret()
	passkeyRegistrationSessionSecretHash := hashSessionSecret(passkeyRegistrationSessionSecret)

	passkeyRegistrationSession := passkeyRegistrationSessionStruct{
		id:            passkeyRegistrationSessionId,
		authSessionId: authSessionId,
		secretHash:    passkeyRegistrationSessionSecretHash,
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
		verifyingAction:              identityVerificationSessionVerifyingActionPasskeyRegistration,
		verifyingActionId:            passkeyRegistrationSession.id,
		passkeyVerificationChallenge: identityVerificationSessionPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_registration_session (id, auth_session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeyRegistrationSession.id,
				passkeyRegistrationSession.authSessionId,
				passkeyRegistrationSession.secretHash,
				passkeyRegistrationSession.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into passkey_registration_session table: %s", err.Error())
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
			return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to insert into identity_verification_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyRegistrationSessionStruct{}, nil, identityVerificationSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkeyRegistrationSession, passkeyRegistrationSessionSecret, identityVerificationSession, identityVerificationSessionSecret, nil
}

func (server *serverStruct) getPasskeyRegistrationSession(passkeyRegistrationSessionId string) (passkeyRegistrationSessionStruct, error) {
	passkeyRegistrationSessions := []passkeyRegistrationSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyRegistrationSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT auth_session_id, secret_hash, identity_verified, passkey_cose_public_key, passkey_webauthn_credential_id, passkey_webauthn_authenticator_id, created_at FROM passkey_registration_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeyRegistrationSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				authSessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				identityVerified := stmt.ColumnBool(2)

				passkeyCOSEPublicKeyDefined := false
				var passkeyCOSEPublicKey []byte
				if !stmt.ColumnIsNull(3) {
					passkeyCOSEPublicKey = make([]byte, stmt.ColumnLen(3))
					stmt.ColumnBytes(3, passkeyCOSEPublicKey)
					passkeyCOSEPublicKeyDefined = true
				}

				passkeyWebauthnCredentialIdDefined := false
				var passkeyWebauthnCredentialId []byte
				if !stmt.ColumnIsNull(4) {
					passkeyWebauthnCredentialId = make([]byte, stmt.ColumnLen(4))
					stmt.ColumnBytes(4, passkeyWebauthnCredentialId)
					passkeyWebauthnCredentialIdDefined = true
				}

				passkeyWebauthnAuthenticatorIdDefined := false
				var passkeyWebauthnAuthenticatorId []byte
				if !stmt.ColumnIsNull(5) {
					passkeyWebauthnAuthenticatorId = make([]byte, stmt.ColumnLen(5))
					stmt.ColumnBytes(5, passkeyWebauthnAuthenticatorId)
					passkeyWebauthnAuthenticatorIdDefined = true
				}

				createdAt := time.Unix(stmt.ColumnInt64(6), 0)

				passkeyRegistrationSession := passkeyRegistrationSessionStruct{
					id:                                    passkeyRegistrationSessionId,
					authSessionId:                         authSessionId,
					secretHash:                            secretHash,
					identityVerified:                      identityVerified,
					passkeyCOSEPublicKey:                  passkeyCOSEPublicKey,
					passkeyCOSEPublicKeyDefined:           passkeyCOSEPublicKeyDefined,
					passkeyWebauthnCredentialId:           passkeyWebauthnCredentialId,
					passkeyWebauthnCredentialIdDefined:    passkeyWebauthnCredentialIdDefined,
					passkeyWebauthnAuthenticatorId:        passkeyWebauthnAuthenticatorId,
					passkeyWebauthnAuthenticatorIdDefined: passkeyWebauthnAuthenticatorIdDefined,
					createdAt:                             createdAt,
				}

				passkeyRegistrationSessions = append(passkeyRegistrationSessions, passkeyRegistrationSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyRegistrationSessionStruct{}, fmt.Errorf("failed to select from passkey_registration_session table: %s", err.Error())
	}

	if len(passkeyRegistrationSessions) < 1 {
		return passkeyRegistrationSessionStruct{}, errItemNotFound
	}

	passkeyRegistrationSession := passkeyRegistrationSessions[0]

	if time.Since(passkeyRegistrationSession.createdAt) >= time.Hour {
		return passkeyRegistrationSessionStruct{}, errItemNotFound
	}

	return passkeyRegistrationSession, nil
}

var errInvalidPasskeyRegistrationSessionToken = errors.New("invalid passkey registration session token")

func (server *serverStruct) validatePasskeyRegistrationSessionToken(passkeyRegistrationSessionToken string) (passkeyRegistrationSessionStruct, error) {
	passkeyRegistrationSessionId, passkeyRegistrationSessionSecret, err := parseSessionToken(passkeyRegistrationSessionToken)
	if err != nil {
		return passkeyRegistrationSessionStruct{}, errInvalidPasskeyRegistrationSessionToken
	}

	passkeyRegistrationSession, err := server.getPasskeyRegistrationSession(passkeyRegistrationSessionId)
	if errors.Is(err, errItemNotFound) {
		return passkeyRegistrationSessionStruct{}, errInvalidPasskeyRegistrationSessionToken
	}
	if err != nil {
		return passkeyRegistrationSessionStruct{}, fmt.Errorf("failed to get passkey registration session: %s", err.Error())
	}

	secretValid := passkeyRegistrationSession.compareSecretAgainstHash(passkeyRegistrationSessionSecret)
	if !secretValid {
		return passkeyRegistrationSessionStruct{}, errInvalidPasskeyRegistrationSessionToken
	}

	return passkeyRegistrationSession, nil
}

const passkeyRegistrationSessionTokenCookieName = "passkey_registration_session_token"

func (server *serverStruct) validateRequestPasskeyRegistrationSessionToken(r *http.Request) (passkeyRegistrationSessionStruct, string, error) {
	passkeyRegistrationSessionTokenCookie, err := r.Cookie(passkeyRegistrationSessionTokenCookieName)
	if err != nil {
		return passkeyRegistrationSessionStruct{}, "", errInvalidPasskeyRegistrationSessionToken
	}
	passkeyRegistrationSessionToken := passkeyRegistrationSessionTokenCookie.Value

	passkeyRegistrationSession, err := server.validatePasskeyRegistrationSessionToken(passkeyRegistrationSessionToken)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		return passkeyRegistrationSessionStruct{}, "", errInvalidPasskeyRegistrationSessionToken
	}
	if err != nil {
		return passkeyRegistrationSessionStruct{}, "", fmt.Errorf("failed to validate passkey registration session token: %s", err.Error())
	}

	return passkeyRegistrationSession, passkeyRegistrationSessionToken, nil
}

func (server *serverStruct) setBlankPasskeyRegistrationSessionTokenCookie(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, passkeyRegistrationSessionTokenCookieName)
}

func (server *serverStruct) setPasskeyRegistrationSessionPasskeyWebauthnCredential(passkeyRegistrationSessionId string, webauthnCredentialId []byte, cosePublicKey []byte, webauthnAuthenticatorId []byte) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, `UPDATE passkey_registration_session
SET passkey_cose_public_key = ?, passkey_webauthn_credential_id = ?, passkey_webauthn_authenticator_id = ?
WHERE id = ? AND passkey_cose_public_key IS NULL AND passkey_webauthn_credential_id IS NULL AND passkey_webauthn_authenticator_id IS NULL`, &sqlitex.ExecOptions{
		Args: []any{cosePublicKey, webauthnCredentialId, webauthnAuthenticatorId, passkeyRegistrationSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update passkey_registration_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

const maxPasskeyCountLimit = 10

func (server *serverStruct) completePasskeyRegistration(passkeyRegistrationSessionId string, passkeyName string) (passkeyStruct, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyId := generateItemId()

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyStruct{}, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return passkeyStruct{}, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	passkeyCount := 0
	err = sqlitex.Execute(databaseWriteConnection, `SELECT count(*) FROM passkey
WHERE user_id = (
SELECT auth_session.user_id FROM passkey_registration_session
INNER JOIN auth_session ON passkey_registration_session.auth_session_id = auth_session.id
WHERE passkey_registration_session.id = ?
)`, &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			passkeyCount = stmt.ColumnInt(0)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}
	if passkeyCount >= maxPasskeyCountLimit {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, errItemConflict
	}

	passkeys := []passkeyStruct{}
	err = sqlitex.Execute(databaseWriteConnection, `INSERT INTO passkey (id, user_id, webauthn_credential_id, cose_public_key, webauthn_authenticator_id, name, created_at)
SELECT ?, auth_session.user_id, passkey_registration_session.passkey_webauthn_credential_id, passkey_registration_session.passkey_cose_public_key, passkey_registration_session.passkey_webauthn_authenticator_id, ?, ? FROM passkey_registration_session
INNER JOIN auth_session ON passkey_registration_session.auth_session_id = auth_session.id
WHERE passkey_registration_session.id = ?
AND passkey_registration_session.passkey_webauthn_credential_id IS NOT NULL
AND passkey_registration_session.passkey_cose_public_key IS NOT NULL
AND passkey_registration_session.passkey_webauthn_authenticator_id IS NOT NULL
AND passkey_registration_session.identity_verified = 1
RETURNING user_id, webauthn_credential_id, cose_public_key, webauthn_authenticator_id, name`, &sqlitex.ExecOptions{
		Args: []any{passkeyId, passkeyName, nowSecondPrecision.Unix(), passkeyRegistrationSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userId := stmt.ColumnText(0)

			webauthnCredentialId := make([]byte, stmt.ColumnLen(1))
			stmt.ColumnBytes(1, webauthnCredentialId)

			cosePublicKey := make([]byte, stmt.ColumnLen(2))
			stmt.ColumnBytes(2, cosePublicKey)

			webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(3))
			stmt.ColumnBytes(3, webauthnAuthenticatorId)

			name := stmt.ColumnText(4)

			passkey := passkeyStruct{
				id:                   passkeyId,
				userId:               userId,
				webauthnCredentialId: webauthnCredentialId,
				cosePublicKey:        cosePublicKey,
				name:                 name,
				createdAt:            nowSecondPrecision,
			}
			passkeys = append(passkeys, passkey)
			return nil
		},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return passkeyStruct{}, errItemConflict
		}
		return passkeyStruct{}, fmt.Errorf("failed to insert into passkey table: %s", err.Error())
	}
	if len(passkeys) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, errItemNotFound
	}
	passkey := passkeys[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_registration_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, fmt.Errorf("failed to delete from passkey_registration_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkey, nil
}

func (server *serverStruct) deletePasskeyRegistrationSession(passkeyRegistrationSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_registration_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from passkey_registration_session table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification_session WHERE verifying_action = 'passkey_registration' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationSessionId},
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
