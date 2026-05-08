package main

import (
	"context"
	"fmt"
	"time"

	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/webauthn"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type passkeySigninAttemptStruct struct {
	id        string
	challenge []byte
	createdAt time.Time
}

func (server *serverStruct) createPasskeySigninAttempt() (passkeySigninAttemptStruct, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	challenge := webauthn.GenerateChallenge()

	passkeySigninAttempt := passkeySigninAttemptStruct{
		id:        id,
		challenge: challenge,
		createdAt: nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return passkeySigninAttemptStruct{}, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO passkey_signin_attempt (id, challenge, created_at) VALUES (?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				passkeySigninAttempt.id,
				passkeySigninAttempt.challenge,
				passkeySigninAttempt.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return passkeySigninAttemptStruct{}, errItemConflict
	}
	if err != nil {
		return passkeySigninAttemptStruct{}, fmt.Errorf("failed to insert into passkey_signin_attempt table: %s", err.Error())
	}

	return passkeySigninAttempt, nil
}

func (server *serverStruct) getPasskeySigninAttempt(passkeySigninAttemptId string) (passkeySigninAttemptStruct, error) {
	passkeySigninAttempts := []passkeySigninAttemptStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return passkeySigninAttemptStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT challenge, created_at FROM passkey_signin_attempt WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{passkeySigninAttemptId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				challenge := make([]byte, stmt.ColumnLen(0))
				stmt.ColumnBytes(0, challenge)

				createdAt := time.Unix(stmt.ColumnInt64(1), 0)

				passkeySigninAttempt := passkeySigninAttemptStruct{
					id:        passkeySigninAttemptId,
					challenge: challenge,
					createdAt: createdAt,
				}

				passkeySigninAttempts = append(passkeySigninAttempts, passkeySigninAttempt)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return passkeySigninAttemptStruct{}, fmt.Errorf("failed to select from passkey_signin_attempt table: %s", err.Error())
	}

	if len(passkeySigninAttempts) < 1 {
		return passkeySigninAttemptStruct{}, errItemNotFound
	}

	passkeySigninAttempt := passkeySigninAttempts[0]

	if time.Since(passkeySigninAttempt.createdAt) >= time.Hour {
		return passkeySigninAttemptStruct{}, errItemNotFound
	}

	return passkeySigninAttempt, nil
}

func (server *serverStruct) deletePasskeySigninAttempt(passkeySigninAttemptId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_signin_attempt WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeySigninAttemptId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from passkey_signin_attempt table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}

func (server *serverStruct) completePasskeySignin(passkeySigninAttemptId string, userId string) (authSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	authSessionId := generateItemId()

	authSessionSecret := generateSessionSecret()
	authSessionSecretHash := hashSessionSecret(authSessionSecret)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return authSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return authSessionStruct{}, nil, fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_signin_attempt WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{passkeySigninAttemptId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to delete from passkey_signin_attempt table: %s", err.Error())
	}
	if databaseWriteConnection.Changes() < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, errItemNotFound
	}

	err = sqlitex.Execute(databaseWriteConnection, "INSERT INTO auth_session (id, user_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", &sqlitex.ExecOptions{
		Args: []any{authSessionId, userId, authSessionSecretHash, nowSecondPrecision.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return authSessionStruct{}, nil, errItemConflict
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to insert into auth_session table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	server.databaseWriteConnectionPool.Put(databaseWriteConnection)

	session := authSessionStruct{
		id:         authSessionId,
		userId:     userId,
		secretHash: authSessionSecretHash,
		createdAt:  nowSecondPrecision,
	}
	return session, authSessionSecret, nil
}
