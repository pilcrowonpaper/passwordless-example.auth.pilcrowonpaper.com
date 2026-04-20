package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"passwordless-example.auth.pilcrowonpaper.com/webauthn"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passkeySigninStruct struct {
	id        string
	challenge []byte
	createdAt time.Time
}

func (passkeySignin *passkeySigninStruct) compareChallenge(challenge []byte) bool {
	return bytes.Equal(passkeySignin.challenge, challenge)
}

func (server *serverStruct) createPasskeySignin() (passkeySigninStruct, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	challenge := webauthn.GenerateChallenge()

	passkeySignin := passkeySigninStruct{
		id:        id,
		challenge: challenge,
		createdAt: nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeySigninStruct{}, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_signin (id, challenge, created_at) VALUES (?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeySignin.id,
				passkeySignin.challenge,
				passkeySignin.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passkeySigninStruct{}, errItemConflict
	}
	if err != nil {
		return passkeySigninStruct{}, fmt.Errorf("failed to insert into passkey_signin table: %s", err.Error())
	}

	return passkeySignin, nil
}

func (server *serverStruct) getPasskeySignin(passkeySigninId string) (passkeySigninStruct, error) {
	passkeySignins := []passkeySigninStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeySigninStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT challenge, created_at FROM passkey_signin WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeySigninId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				challenge := make([]byte, stmt.ColumnLen(0))
				stmt.ColumnBytes(0, challenge)

				createdAt := time.Unix(stmt.ColumnInt64(1), 0)

				passkeySignin := passkeySigninStruct{
					id:        passkeySigninId,
					challenge: challenge,
					createdAt: createdAt,
				}

				passkeySignins = append(passkeySignins, passkeySignin)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeySigninStruct{}, fmt.Errorf("failed to select from passkey_signin table: %s", err.Error())
	}

	if len(passkeySignins) < 1 {
		return passkeySigninStruct{}, errItemNotFound
	}

	passkeySignin := passkeySignins[0]

	if time.Since(passkeySignin.createdAt) >= time.Minute*60 {
		return passkeySigninStruct{}, errItemNotFound
	}

	return passkeySignin, nil
}

func (server *serverStruct) deletePasskeySignin(passkeySigninId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_signin WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeySigninId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from passkey_signin table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completePasskeySignin(passkeySigninId string, userId string) (sessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	sessionId := generateItemId()

	sessionSecret := generateSessionSecret()
	sessionSecretHash := hashSessionSecret(sessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return sessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return sessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_signin WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeySigninId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to delete from passkey_signin table: %s", err.Error())
	}
	if databaseWriteConnection.Changes() < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, errItemNotFound
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{sessionId, userId, sessionSecretHash, nowSecondPrecision.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return sessionStruct{}, nil, errItemConflict
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	session := sessionStruct{
		id:         sessionId,
		userId:     userId,
		secretHash: sessionSecretHash,
		createdAt:  nowSecondPrecision,
	}
	return session, sessionSecret, nil
}
