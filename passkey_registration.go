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

type passkeyRegistrationStruct struct {
	id                                    string
	sessionId                             string
	secretHash                            []byte
	identityVerified                      bool
	passkeySignatureAlgorithm             string
	passkeySignatureAlgorithmDefined      bool
	passkeyPublicKey                      []byte
	passkeyPublicKeyDefined               bool
	passkeyWebauthnCredentialId           []byte
	passkeyWebauthnCredentialIdDefined    bool
	passkeyWebauthnAuthenticatorId        []byte
	passkeyWebauthnAuthenticatorIdDefined bool
	createdAt                             time.Time
}

func (passkeyRegistration *passkeyRegistrationStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, passkeyRegistration.secretHash)
	return hashEqual
}

func (server *serverStruct) createPasskeyRegistration(sessionId string) (passkeyRegistrationStruct, []byte, identityVerificationStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	passkeyRegistrationId := generateItemId()
	passkeyRegistrationSecret := generateSessionSecret()
	passkeyRegistrationSecretHash := hashSessionSecret(passkeyRegistrationSecret)

	passkeyRegistration := passkeyRegistrationStruct{
		id:         passkeyRegistrationId,
		sessionId:  sessionId,
		secretHash: passkeyRegistrationSecretHash,
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
		verifyingAction:              identityVerificationVerifyingActionPasskeyRegistration,
		verifyingActionId:            passkeyRegistration.id,
		passkeyVerificationChallenge: identityVerificationPasskeyVerificationChallenge,
		createdAt:                    nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_registration (id, session_id, secret_hash, created_at) VALUES (?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeyRegistration.id,
				passkeyRegistration.sessionId,
				passkeyRegistration.secretHash,
				passkeyRegistration.createdAt.Unix(),
			},
		},
	)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into passkey_registration table: %s", err.Error())
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
			return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to insert into identity_verification table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyRegistrationStruct{}, nil, identityVerificationStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	return passkeyRegistration, passkeyRegistrationSecret, identityVerification, identityVerificationSecret, nil
}

func (server *serverStruct) getPasskeyRegistration(passkeyRegistrationId string) (passkeyRegistrationStruct, error) {
	passkeyRegistrations := []passkeyRegistrationStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyRegistrationStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT session_id, secret_hash, identity_verified, passkey_signature_algorithm, passkey_public_key, passkey_webauthn_credential_id, passkey_webauthn_authenticator_id, created_at FROM passkey_registration WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeyRegistrationId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				sessionId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				identityVerified := stmt.ColumnBool(2)

				passkeySignatureAlgorithmDefined := false
				var passkeySignatureAlgorithm string
				if !stmt.ColumnIsNull(3) {
					passkeySignatureAlgorithm = stmt.ColumnText(3)
					passkeySignatureAlgorithmDefined = true
				}

				passkeyPublicKeyDefined := false
				var passkeyPublicKey []byte
				if !stmt.ColumnIsNull(4) {
					passkeyPublicKey = make([]byte, stmt.ColumnLen(4))
					stmt.ColumnBytes(4, passkeyPublicKey)
					passkeyPublicKeyDefined = true
				}

				passkeyWebauthnCredentialIdDefined := false
				var passkeyWebauthnCredentialId []byte
				if !stmt.ColumnIsNull(5) {
					passkeyWebauthnCredentialId = make([]byte, stmt.ColumnLen(5))
					stmt.ColumnBytes(5, passkeyWebauthnCredentialId)
					passkeyWebauthnCredentialIdDefined = true
				}

				passkeyWebauthnAuthenticatorIdDefined := false
				var passkeyWebauthnAuthenticatorId []byte
				if !stmt.ColumnIsNull(6) {
					passkeyWebauthnAuthenticatorId = make([]byte, stmt.ColumnLen(6))
					stmt.ColumnBytes(6, passkeyWebauthnAuthenticatorId)
					passkeyWebauthnAuthenticatorIdDefined = true
				}

				createdAt := time.Unix(stmt.ColumnInt64(7), 0)

				passkeyRegistration := passkeyRegistrationStruct{
					id:                                    passkeyRegistrationId,
					sessionId:                             sessionId,
					secretHash:                            secretHash,
					identityVerified:                      identityVerified,
					passkeySignatureAlgorithm:             passkeySignatureAlgorithm,
					passkeySignatureAlgorithmDefined:      passkeySignatureAlgorithmDefined,
					passkeyPublicKey:                      passkeyPublicKey,
					passkeyPublicKeyDefined:               passkeyPublicKeyDefined,
					passkeyWebauthnCredentialId:           passkeyWebauthnCredentialId,
					passkeyWebauthnCredentialIdDefined:    passkeyWebauthnCredentialIdDefined,
					passkeyWebauthnAuthenticatorId:        passkeyWebauthnAuthenticatorId,
					passkeyWebauthnAuthenticatorIdDefined: passkeyWebauthnAuthenticatorIdDefined,
					createdAt:                             createdAt,
				}

				passkeyRegistrations = append(passkeyRegistrations, passkeyRegistration)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyRegistrationStruct{}, fmt.Errorf("failed to select from passkey_registration table: %s", err.Error())
	}

	if len(passkeyRegistrations) < 1 {
		return passkeyRegistrationStruct{}, errItemNotFound
	}

	return passkeyRegistrations[0], nil
}

const passkeyRegistrationTokenCookieName = "passkey_registration_token"

func (server *serverStruct) setBlankPasskeyRegistrationTokenCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     passkeyRegistrationTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

var errInvalidPasskeyRegistrationToken = errors.New("invalid passkey registration token")

func (server *serverStruct) validatePasskeyRegistrationToken(passkeyRegistrationToken string) (passkeyRegistrationStruct, error) {
	passkeyRegistrationTokenParts := strings.Split(passkeyRegistrationToken, ".")
	if len(passkeyRegistrationTokenParts) != 2 {
		return passkeyRegistrationStruct{}, errInvalidPasskeyRegistrationToken
	}
	passkeyRegistrationId := passkeyRegistrationTokenParts[0]
	encodedPasskeyRegistrationSecret := passkeyRegistrationTokenParts[1]
	passkeyRegistrationSecret, err := base64.StdEncoding.DecodeString(encodedPasskeyRegistrationSecret)
	if err != nil {
		return passkeyRegistrationStruct{}, errInvalidPasskeyRegistrationToken
	}

	passkeyRegistration, err := server.getPasskeyRegistration(passkeyRegistrationId)
	if errors.Is(err, errItemNotFound) {
		return passkeyRegistrationStruct{}, errInvalidPasskeyRegistrationToken
	}
	if err != nil {
		return passkeyRegistrationStruct{}, fmt.Errorf("failed to get passkey registration: %s", err.Error())
	}

	passkeyRegistrationSecretValid := passkeyRegistration.compareSecretAgainstHash(passkeyRegistrationSecret)
	if !passkeyRegistrationSecretValid {
		return passkeyRegistrationStruct{}, errInvalidPasskeyRegistrationToken
	}

	return passkeyRegistration, nil
}

func (server *serverStruct) validateRequestPasskeyRegistrationToken(r *http.Request) (passkeyRegistrationStruct, string, error) {
	passkeyRegistrationTokenCookie, err := r.Cookie(passkeyRegistrationTokenCookieName)
	if err != nil {
		return passkeyRegistrationStruct{}, "", errInvalidPasskeyRegistrationToken
	}
	passkeyRegistrationToken := passkeyRegistrationTokenCookie.Value

	passkeyRegistration, err := server.validatePasskeyRegistrationToken(passkeyRegistrationToken)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		return passkeyRegistrationStruct{}, "", errInvalidPasskeyRegistrationToken
	}
	if err != nil {
		return passkeyRegistrationStruct{}, "", fmt.Errorf("failed to validate passkeyRegistration token: %s", err.Error())
	}

	return passkeyRegistration, passkeyRegistrationToken, nil
}

func (server *serverStruct) setPasskeyRegistrationPasskeyWebauthnCredential(passkeyRegistrationId string, webauthnCredentialId []byte, signatureAlgorithm string, publicKey []byte, webauthnAuthenticatorId []byte) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, `UPDATE passkey_registration
SET passkey_signature_algorithm = ?, passkey_public_key = ?, passkey_webauthn_credential_id = ?, passkey_webauthn_authenticator_id = ?
WHERE id = ? AND passkey_signature_algorithm IS NULL AND passkey_public_key IS NULL AND passkey_webauthn_credential_id IS NULL AND passkey_webauthn_authenticator_id IS NULL`, &sqlitex.ExecOptions{
		Args: []any{signatureAlgorithm, publicKey, webauthnCredentialId, webauthnAuthenticatorId, passkeyRegistrationId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to update passkey_registration table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completePasskeyRegistrationIdentityVerification(passkeyRegistrationId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "UPDATE passkey_registration SET identity_verified = 1 WHERE id = ? AND identity_verified = 0", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'passkey_registration' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
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

const maxPasskeyCountLimit = 10

func (server *serverStruct) completePasskeyRegistration(passkeyRegistrationId string, passkeyName string) (passkeyStruct, error) {
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
SELECT session.user_id FROM passkey_registration
INNER JOIN session ON passkey_registration.session_id = session.id
WHERE passkey_registration.id = ?
)`, &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
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
	err = sqlitex.Execute(databaseWriteConnection, `INSERT INTO passkey (id, user_id, webauthn_credential_id, signature_algorithm, public_key, webauthn_authenticator_id, name, created_at)
SELECT ?, session.user_id, passkey_registration.passkey_webauthn_credential_id, passkey_registration.passkey_signature_algorithm, passkey_registration.passkey_public_key, passkey_registration.passkey_webauthn_authenticator_id, ?, ? FROM passkey_registration
INNER JOIN session ON passkey_registration.session_id = session.id
WHERE passkey_registration.id = ?
AND passkey_registration.passkey_webauthn_credential_id IS NOT NULL
AND passkey_registration.passkey_signature_algorithm IS NOT NULL
AND passkey_registration.passkey_public_key IS NOT NULL
AND passkey_registration.passkey_webauthn_authenticator_id IS NOT NULL
AND passkey_registration.identity_verified = 1
RETURNING user_id, webauthn_credential_id, signature_algorithm, public_key, webauthn_authenticator_id, name`, &sqlitex.ExecOptions{
		Args: []any{passkeyId, passkeyName, nowSecondPrecision.Unix(), passkeyRegistrationId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userId := stmt.ColumnText(0)

			webauthnCredentialId := make([]byte, stmt.ColumnLen(1))
			stmt.ColumnBytes(1, webauthnCredentialId)

			signatureAlgorithm := stmt.ColumnText(2)

			publicKey := make([]byte, stmt.ColumnLen(3))
			stmt.ColumnBytes(3, publicKey)

			webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(4))
			stmt.ColumnBytes(4, webauthnAuthenticatorId)

			name := stmt.ColumnText(5)

			passkey := passkeyStruct{
				id:                   passkeyId,
				userId:               userId,
				webauthnCredentialId: webauthnCredentialId,
				signatureAlgorithm:   signatureAlgorithm,
				publicKey:            publicKey,
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_registration WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return passkeyStruct{}, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return passkeyStruct{}, fmt.Errorf("failed to delete from passkey_registration table: %s", err.Error())
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

func (server *serverStruct) deletePasskeyRegistration(passkeyRegistrationId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_registration WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from passkey_registration table: %s", err.Error())
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

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM identity_verification WHERE verifying_action = 'passkey_registration' AND verifying_action_id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeyRegistrationId},
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
