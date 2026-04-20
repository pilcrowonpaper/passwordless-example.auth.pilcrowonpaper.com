package main

import (
	"context"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type userStruct struct {
	id           string
	emailAddress string
	createdAt    time.Time
}

func (server *serverStruct) checkUserEmailAddressAvailability(emailAddress string) (bool, error) {
	userIds := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return false, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseReadConnection, "SELECT id FROM user WHERE email_address = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddress},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userIds = append(userIds, stmt.ColumnText(0))
			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return false, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	emailAddressAvailable := len(userIds) < 1
	return emailAddressAvailable, nil
}

func (server *serverStruct) getUser(userId string) (userStruct, error) {
	users := []userStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseReadConnection, "SELECT email_address, created_at FROM user WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{userId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			emailAddress := stmt.ColumnText(0)
			createdAt := time.Unix(stmt.ColumnInt64(1), 0)

			user := userStruct{
				id:           userId,
				emailAddress: emailAddress,
				createdAt:    createdAt,
			}

			users = append(users, user)
			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)

	if err != nil {
		return userStruct{}, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	if len(users) < 1 {
		return userStruct{}, errItemNotFound
	}

	return users[0], nil
}

func (server *serverStruct) getUserByEmailAddress(emailAddress string) (userStruct, error) {
	users := []userStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}

	err = sqlitex.Execute(databaseReadConnection, "SELECT id, created_at FROM user WHERE email_address = ?", &sqlitex.ExecOptions{
		Args: []any{emailAddress},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id := stmt.ColumnText(0)
			createdAt := time.Unix(stmt.ColumnInt64(1), 0)

			user := userStruct{
				id:           id,
				emailAddress: emailAddress,
				createdAt:    createdAt,
			}

			users = append(users, user)
			return nil
		},
	})
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return userStruct{}, fmt.Errorf("failed to select from user table: %s", err.Error())
	}

	if len(users) < 1 {
		return userStruct{}, errItemNotFound
	}

	return users[0], nil
}
