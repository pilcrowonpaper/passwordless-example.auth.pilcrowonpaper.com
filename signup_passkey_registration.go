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

type signupPasskeyRegistrationStruct struct {
	id                             string
	signupId                       string
	passkeySignatureAlgorithm      string
	passkeyPublicKey               []byte
	passkeyWebauthnCredentialId    []byte
	passkeyWebauthnAuthenticatorId []byte
	createdAt                      time.Time
}

func (server *serverStruct) createSignupPasskeyRegistration(signupId string, passkeySignatureAlgorithm string, passkeyPublicKey []byte, passkeyWebauthnCredentialId []byte, passkeyWebauthnAuthenticatorId []byte) (signupPasskeyRegistrationStruct, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	signupPasskeyRegistration := signupPasskeyRegistrationStruct{
		id:                             id,
		signupId:                       signupId,
		passkeySignatureAlgorithm:      passkeySignatureAlgorithm,
		passkeyPublicKey:               passkeyPublicKey,
		passkeyWebauthnCredentialId:    passkeyWebauthnCredentialId,
		passkeyWebauthnAuthenticatorId: passkeyWebauthnAuthenticatorId,
		createdAt:                      nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return signupPasskeyRegistrationStruct{}, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO signup_passkey_registration (id, signup_id, passkey_signature_algorithm, passkey_public_key, passkey_webauthn_credential_id, passkey_webauthn_authenticator_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				signupPasskeyRegistration.id,
				signupPasskeyRegistration.signupId,
				signupPasskeyRegistration.passkeySignatureAlgorithm,
				signupPasskeyRegistration.passkeyPublicKey,
				signupPasskeyRegistration.passkeyWebauthnCredentialId,
				signupPasskeyRegistration.passkeyWebauthnAuthenticatorId,
				signupPasskeyRegistration.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return signupPasskeyRegistrationStruct{}, errItemConflict
	}
	if err != nil {
		return signupPasskeyRegistrationStruct{}, fmt.Errorf("failed to insert into signup_passkey_registration table: %s", err.Error())
	}

	return signupPasskeyRegistration, nil
}

func (server *serverStruct) getSignupPasskeyRegistration(signupPasskeyRegistrationId string) (signupPasskeyRegistrationStruct, error) {
	signupPasskeyRegistrations := []signupPasskeyRegistrationStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return signupPasskeyRegistrationStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT signup_id, passkey_signature_algorithm, passkey_public_key, passkey_webauthn_credential_id, passkey_webauthn_authenticator_id, created_at FROM signup_passkey_registration WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{signupPasskeyRegistrationId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				signupId := stmt.ColumnText(0)

				passkeySignatureAlgorithm := stmt.ColumnText(1)

				passkeyPublicKey := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, passkeyPublicKey)

				passkeyWebauthnCredentialId := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, passkeyWebauthnCredentialId)

				passkeyWebauthnAuthenticatorId := make([]byte, stmt.ColumnLen(4))
				stmt.ColumnBytes(4, passkeyWebauthnAuthenticatorId)

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				signupPasskeyRegistration := signupPasskeyRegistrationStruct{
					id:                             signupPasskeyRegistrationId,
					signupId:                       signupId,
					passkeySignatureAlgorithm:      passkeySignatureAlgorithm,
					passkeyPublicKey:               passkeyPublicKey,
					passkeyWebauthnCredentialId:    passkeyWebauthnCredentialId,
					passkeyWebauthnAuthenticatorId: passkeyWebauthnAuthenticatorId,
					createdAt:                      createdAt,
				}

				signupPasskeyRegistrations = append(signupPasskeyRegistrations, signupPasskeyRegistration)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return signupPasskeyRegistrationStruct{}, fmt.Errorf("failed to select from signup_passkey_registration table: %s", err.Error())
	}

	if len(signupPasskeyRegistrations) < 1 {
		return signupPasskeyRegistrationStruct{}, errItemNotFound
	}

	return signupPasskeyRegistrations[0], nil
}

const signupPasskeyRegistrationIdCookieName = "signup_passkey_registration_id"

func (server *serverStruct) setBlankSignupPasskeyRegistrationIdCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     signupPasskeyRegistrationIdCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) getRequestSignupPasskeyRegistration(r *http.Request) (signupPasskeyRegistrationStruct, error) {
	signupPasskeyRegistrationIdCookie, err := r.Cookie(signupPasskeyRegistrationIdCookieName)
	if err != nil {
		return signupPasskeyRegistrationStruct{}, errItemNotFound
	}
	signupPasskeyRegistrationId := signupPasskeyRegistrationIdCookie.Value

	signupPasskeyRegistration, err := server.getSignupPasskeyRegistration(signupPasskeyRegistrationId)
	if errors.Is(err, errItemNotFound) {
		return signupPasskeyRegistrationStruct{}, errItemNotFound
	}
	if err != nil {
		return signupPasskeyRegistrationStruct{}, fmt.Errorf("failed to get signup passkey registration: %s", err.Error())
	}

	return signupPasskeyRegistration, nil
}

func (server *serverStruct) deleteSignupPasskeyRegistration(signupPasskeyRegistrationId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup_passkey_registration WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{signupPasskeyRegistrationId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from signup_passkey_registration table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
