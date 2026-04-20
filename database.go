package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var errItemNotFound = errors.New("item not found")
var errItemConflict = errors.New("item conflict")

func setUpDatabase() error {
	currentSchemaHash := sha256.Sum256([]byte(schemaSQLScript))

	databaseConnection, err := sqlite.OpenConn(databaseFilename, sqlite.OpenCreate, sqlite.OpenReadWrite)
	if err != nil {
		return fmt.Errorf("failed to create database file: %s\n", err.Error())
	}

	err = sqlitex.ExecuteTransient(databaseConnection, "PRAGMA foreign_keys = ON", nil)
	if err != nil {
		return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
	}

	latestSchemaMatch, err := checkLatestSchema(databaseConnection, currentSchemaHash[:])
	databaseConnection.Close()
	if err != nil {
		return fmt.Errorf("failed to check latest schema: %s\n", err.Error())
	}

	if latestSchemaMatch {
		return nil
	}

	// Reset database file
	databaseFile, err := os.Create(databaseFilename)
	databaseFile.Close()
	if err != nil {
		return fmt.Errorf("failed to open database file: %s\n", err.Error())
	}

	databaseConnection, err = sqlite.OpenConn(databaseFilename, sqlite.OpenCreate, sqlite.OpenReadWrite)
	if err != nil {
		return fmt.Errorf("failed to create database file: %s\n", err.Error())
	}

	err = sqlitex.Execute(databaseConnection, "BEGIN", nil)
	if err != nil {
		databaseConnection.Close()
		return fmt.Errorf("failed to begin transaction: %s\n", err.Error())
	}

	err = sqlitex.ExecuteTransient(databaseConnection, "CREATE TABLE _database (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL) STRICT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseConnection, "ROLLBACK", nil)
		databaseConnection.Close()
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to execute schema script: %s", err.Error())
	}

	err = sqlitex.ExecuteTransient(databaseConnection, "INSERT INTO _database (key, value) VALUES ('schema_hash', ?)", &sqlitex.ExecOptions{
		Args: []any{base64.StdEncoding.EncodeToString(currentSchemaHash[:])},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseConnection, "ROLLBACK", nil)
		databaseConnection.Close()
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to execute schema script: %s", err.Error())
	}

	err = sqlitex.ExecuteScript(databaseConnection, schemaSQLScript, nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseConnection, "ROLLBACK", nil)
		databaseConnection.Close()
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to execute schema script: %s", err.Error())
	}

	err = sqlitex.Execute(databaseConnection, "COMMIT", nil)
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseConnection, "ROLLBACK", nil)
		databaseConnection.Close()
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to commit transaction: %s", err.Error())
	}

	databaseConnection.Close()

	return nil
}

func checkLatestSchema(databaseConnection *sqlite.Conn, currentSchemaHash []byte) (bool, error) {
	databaseTableIds := []int{}
	err := sqlitex.ExecuteTransient(databaseConnection, "SELECT rowid FROM sqlite_schema WHERE type = 'table' AND name = '_database'", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			databaseTableIds = append(databaseTableIds, stmt.ColumnInt(0))
			return nil
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to create from sqlite_schema table: %s", err.Error())
	}
	if len(databaseTableIds) < 1 {
		return false, nil
	}

	schemaHashes := [][]byte{}
	err = sqlitex.ExecuteTransient(databaseConnection, "SELECT value FROM _database WHERE key = 'schema_hash'", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			encodedSchemaHash := stmt.ColumnText(0)
			schemaHash, err := base64.StdEncoding.DecodeString(encodedSchemaHash)
			if err != nil {
				return fmt.Errorf("failed to decode schema hash: %s", err.Error())
			}
			schemaHashes = append(schemaHashes, schemaHash)
			return nil
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to create from _db table: %s", err.Error())
	}
	if len(schemaHashes) < 1 {
		return false, nil
	}
	latestSchemaHash := schemaHashes[0]

	schemaHashMatch := slices.Compare(currentSchemaHash, latestSchemaHash) == 0

	return schemaHashMatch, nil
}

func (server *serverStruct) cleanDatabase() error {
	now := time.Now()
	userCreatedThreshold := now.Add(24 * time.Hour * -1)
	signupCreationThreshold := now.Add(60 * time.Minute * -1)
	passkeySigninCreationThreshold := now.Add(60 * time.Minute * -1)

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "BEGIN IMMEDIATE", nil)
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to begin transaction: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM user WHERE created_at <= ?", &sqlitex.ExecOptions{
		Args: []any{userCreatedThreshold.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from user table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM signup WHERE created_at <= ?", &sqlitex.ExecOptions{
		Args: []any{signupCreationThreshold.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from signup table: %s", err.Error())
	}

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM passkey_signin WHERE created_at <= ?", &sqlitex.ExecOptions{
		Args: []any{passkeySigninCreationThreshold.Unix()},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return fmt.Errorf("failed to delete from signup table: %s", err.Error())
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
