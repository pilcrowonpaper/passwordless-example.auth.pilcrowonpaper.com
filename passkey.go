package main

import (
	"context"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

func verifyPasskeyNamePattern(passkeyName string) bool {
	if len(passkeyName) < 1 && len(passkeyName) > 50 {
		return false
	}
	// Printable ASCII excluding double quotes
	for _, char := range passkeyName {
		if char < ' ' || char > '~' {
			return false
		}
		if char == '"' {
			return false
		}
	}
	if passkeyName[0] == ' ' || passkeyName[len(passkeyName)-1] == ' ' {
		return false
	}
	return true
}

type passkeyStruct struct {
	id                      string
	userId                  string
	webauthnCredentialId    []byte
	cosePublicKey           []byte
	webauthnAuthenticatorId []byte
	name                    string
	createdAt               time.Time
}

func (server *serverStruct) getPasskey(passkeyId string) (passkeyStruct, error) {
	passkeys := []passkeyStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, webauthn_credential_id,  cose_public_key, webauthn_authenticator_id, name, created_at FROM passkey WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeyId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				webauthnCredentialId := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, webauthnCredentialId)

				cosePublicKey := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, cosePublicKey)

				webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, webauthnAuthenticatorId)

				name := stmt.ColumnText(4)

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				passkey := passkeyStruct{
					id:                      passkeyId,
					userId:                  userId,
					webauthnCredentialId:    webauthnCredentialId,
					cosePublicKey:           cosePublicKey,
					webauthnAuthenticatorId: webauthnAuthenticatorId,
					name:                    name,
					createdAt:               createdAt,
				}

				passkeys = append(passkeys, passkey)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyStruct{}, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	if len(passkeys) < 1 {
		return passkeyStruct{}, errItemNotFound
	}

	return passkeys[0], nil
}

func (server *serverStruct) getPasskeyByWebauthnCredentialId(webauthnCredentialId []byte) (passkeyStruct, error) {
	passkeys := []passkeyStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeyStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT id, user_id, cose_public_key, webauthn_authenticator_id, name, created_at FROM passkey WHERE webauthn_credential_id = ?",
		&sqlitex.ExecOptions{
			Args: []any{webauthnCredentialId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id := stmt.ColumnText(0)

				userId := stmt.ColumnText(1)

				cosePublicKey := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, cosePublicKey)

				webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, webauthnAuthenticatorId)

				name := stmt.ColumnText(4)

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				passkey := passkeyStruct{
					id:                      id,
					userId:                  userId,
					webauthnCredentialId:    webauthnCredentialId,
					cosePublicKey:           cosePublicKey,
					webauthnAuthenticatorId: webauthnAuthenticatorId,
					name:                    name,
					createdAt:               createdAt,
				}

				passkeys = append(passkeys, passkey)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeyStruct{}, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	if len(passkeys) < 1 {
		return passkeyStruct{}, errItemNotFound
	}

	return passkeys[0], nil
}

func (server *serverStruct) getUserPasskeys(userId string) ([]passkeyStruct, error) {
	passkeys := []passkeyStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT id, webauthn_credential_id, cose_public_key, webauthn_authenticator_id, name, created_at FROM passkey WHERE user_id = ?",
		&sqlitex.ExecOptions{
			Args: []any{userId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id := stmt.ColumnText(0)

				webauthnCredentialId := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, webauthnCredentialId)

				cosePublicKey := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, cosePublicKey)

				webauthnAuthenticatorId := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, webauthnAuthenticatorId)

				name := stmt.ColumnText(4)

				createdAt := time.Unix(stmt.ColumnInt64(5), 0)

				passkey := passkeyStruct{
					id:                      id,
					userId:                  userId,
					webauthnCredentialId:    webauthnCredentialId,
					cosePublicKey:           cosePublicKey,
					webauthnAuthenticatorId: webauthnAuthenticatorId,
					name:                    name,
					createdAt:               createdAt,
				}

				passkeys = append(passkeys, passkey)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return nil, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	return passkeys, nil
}

func (server *serverStruct) getUserPasskeyWebauthnCredentialIds(userId string) ([][]byte, error) {
	webauthnCredentialIds := [][]byte{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT webauthn_credential_id FROM passkey WHERE user_id = ?",
		&sqlitex.ExecOptions{
			Args: []any{userId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				webauthnCredentialId := make([]byte, stmt.ColumnLen(0))
				stmt.ColumnBytes(0, webauthnCredentialId)

				webauthnCredentialIds = append(webauthnCredentialIds, webauthnCredentialId)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return nil, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	return webauthnCredentialIds, nil
}

func (server *serverStruct) checkPasskeyWebauthnCredentialIdAvailability(webauthnCredentialId []byte) (bool, error) {
	count := 0

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT count(*) FROM passkey WHERE webauthn_credential_id = ?",
		&sqlitex.ExecOptions{
			Args: []any{webauthnCredentialId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				count = stmt.ColumnInt(0)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return false, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	return count < 1, nil
}

func (server *serverStruct) getUserPasskeyCount(userId string) (int, error) {
	passkeyCount := 0

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return 0, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT count(*) FROM passkey WHERE user_id = ?",
		&sqlitex.ExecOptions{
			Args: []any{userId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				passkeyCount = stmt.ColumnInt(0)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return 0, fmt.Errorf("failed to select from passkey table: %s", err.Error())
	}

	return passkeyCount, nil
}
