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

type emailCodeSigninSessionStruct struct {
	id         string
	userId     string
	secretHash []byte
	emailCode  string
	createdAt  time.Time
}

func (emailCodeSigninSession *emailCodeSigninSessionStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, emailCodeSigninSession.secretHash)
	return hashEqual
}

func (emailCodeSigninSession *emailCodeSigninSessionStruct) compareEmailCode(emailCode string) bool {
	return constantTimeCompareStrings(emailCode, emailCodeSigninSession.emailCode)
}

func (server *serverStruct) createEmailCodeSigninSessionFromUserEmailAddress(userEmailAddress string) (emailCodeSigninSessionStruct, []byte, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailCode := generateEmailCode()

	userIds := []string{}
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return emailCodeSigninSessionStruct{}, nil, fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		`INSERT INTO email_code_signin_session (id, user_id, secret_hash, email_code, created_at)
SELECT ?, user.id, ?, ?, ? FROM user
WHERE user.email_address = ?
RETURNING user_id`,
		&sqlitex.ExecOptions{
			Args: []any{
				id,
				secretHash,
				emailCode,
				nowSecondPrecision.Unix(),
				userEmailAddress,
			},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)
				userIds = append(userIds, userId)
				return nil
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return emailCodeSigninSessionStruct{}, nil, errItemConflict
	}
	if err != nil {
		return emailCodeSigninSessionStruct{}, nil, fmt.Errorf("failed to insert into email_code_signin_session table: %s", err.Error())
	}
	if len(userIds) < 1 {
		return emailCodeSigninSessionStruct{}, nil, errItemNotFound
	}

	emailCodeSigninSession := emailCodeSigninSessionStruct{
		id:         id,
		userId:     userIds[0],
		secretHash: secretHash,
		emailCode:  emailCode,
		createdAt:  nowSecondPrecision,
	}

	return emailCodeSigninSession, secret, nil
}

func (server *serverStruct) getEmailCodeSigninSession(emailCodeSigninSessionId string) (emailCodeSigninSessionStruct, error) {
	emailCodeSigninSessions := []emailCodeSigninSessionStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return emailCodeSigninSessionStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, email_code, created_at FROM email_code_signin_session WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailCodeSigninSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				emailCode := stmt.ColumnText(2)

				createdAt := time.Unix(stmt.ColumnInt64(3), 0)

				emailCodeSigninSession := emailCodeSigninSessionStruct{
					id:         emailCodeSigninSessionId,
					userId:     userId,
					secretHash: secretHash,
					emailCode:  emailCode,
					createdAt:  createdAt,
				}

				emailCodeSigninSessions = append(emailCodeSigninSessions, emailCodeSigninSession)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return emailCodeSigninSessionStruct{}, fmt.Errorf("failed to select from email_code_signin_session table: %s", err.Error())
	}

	if len(emailCodeSigninSessions) < 1 {
		return emailCodeSigninSessionStruct{}, errItemNotFound
	}

	emailCodeSigninSession := emailCodeSigninSessions[0]

	if time.Since(emailCodeSigninSession.createdAt) >= time.Hour {
		return emailCodeSigninSessionStruct{}, errItemNotFound
	}
	return emailCodeSigninSession, nil
}

func (server *serverStruct) getEmailCodeSigninSessionUserEmailAddress(emailCodeSigninSessionId string) (string, error) {
	userEmailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user.email_address FROM email_code_signin_session INNER JOIN user ON email_code_signin_session.user_id = user.id WHERE email_code_signin_session.id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailCodeSigninSessionId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userEmailAddress := stmt.ColumnText(0)

				userEmailAddresses = append(userEmailAddresses, userEmailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from email_code_signin_session table: %s", err.Error())
	}

	if len(userEmailAddresses) < 1 {
		return "", errItemNotFound
	}

	userEmailAddress := userEmailAddresses[0]

	return userEmailAddress, nil
}

var errInvalidEmailCodeSigninSessionToken = errors.New("invalid email code signin session token")

func (server *serverStruct) validateEmailCodeSigninSessionToken(emailCodeSigninSessionToken string) (emailCodeSigninSessionStruct, error) {
	emailCodeSigninSessionId, emailCodeSigninSessionSecret, err := parseSessionToken(emailCodeSigninSessionToken)
	if err != nil {
		return emailCodeSigninSessionStruct{}, errInvalidEmailCodeSigninSessionToken
	}

	emailCodeSigninSession, err := server.getEmailCodeSigninSession(emailCodeSigninSessionId)
	if errors.Is(err, errItemNotFound) {
		return emailCodeSigninSessionStruct{}, errInvalidEmailCodeSigninSessionToken
	}
	if err != nil {
		return emailCodeSigninSessionStruct{}, fmt.Errorf("failed to get email code signin session: %s", err.Error())
	}

	secretValid := emailCodeSigninSession.compareSecretAgainstHash(emailCodeSigninSessionSecret)
	if !secretValid {
		return emailCodeSigninSessionStruct{}, errInvalidEmailCodeSigninSessionToken
	}

	return emailCodeSigninSession, nil
}

const emailCodeSigninSessionTokenCookieName = "email_code_signin_session_token"

func (server *serverStruct) validateRequestEmailCodeSigninSessionToken(r *http.Request) (emailCodeSigninSessionStruct, string, error) {
	emailCodeSigninSessionTokenCookie, err := r.Cookie(emailCodeSigninSessionTokenCookieName)
	if err != nil {
		return emailCodeSigninSessionStruct{}, "", errInvalidEmailCodeSigninSessionToken
	}
	emailCodeSigninSessionToken := emailCodeSigninSessionTokenCookie.Value

	emailCodeSigninSession, err := server.validateEmailCodeSigninSessionToken(emailCodeSigninSessionToken)
	if errors.Is(err, errInvalidEmailCodeSigninSessionToken) {
		return emailCodeSigninSessionStruct{}, "", errInvalidEmailCodeSigninSessionToken
	}
	if err != nil {
		return emailCodeSigninSessionStruct{}, "", fmt.Errorf("failed to validate email code signin session token: %s", err.Error())
	}

	return emailCodeSigninSession, emailCodeSigninSessionToken, nil
}

func (server *serverStruct) setBlankEmailCodeSigninSessionToken(w http.ResponseWriter) {
	server.setBlankSessionTokenCookie(w, emailCodeSigninSessionTokenCookieName)
}

func (server *serverStruct) completeEmailCodeSigninSession(emailCodeSigninSessionId string) (authSessionStruct, []byte, error) {
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

	userIds := []string{}
	err = sqlitex.Execute(databaseWriteConnection, `INSERT INTO auth_session (id, user_id, secret_hash, created_at)
SELECT ?, user_id, ?, ? FROM email_code_signin_session WHERE id = ?
RETURNING user_id`, &sqlitex.ExecOptions{
		Args: []any{authSessionId, authSessionSecretHash, nowSecondPrecision.Unix(), emailCodeSigninSessionId},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userId := stmt.ColumnText(0)
			userIds = append(userIds, userId)
			return nil
		},
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
	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, errItemNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_code_signin_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCodeSigninSessionId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return authSessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return authSessionStruct{}, nil, fmt.Errorf("failed to delete from emailCodeSigninSession table: %s", err.Error())
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

func (server *serverStruct) deleteEmailCodeSigninSession(emailCodeSigninSessionId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_code_signin_session WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCodeSigninSessionId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from email_code_signin_session table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
