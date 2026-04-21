package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type emailCodeSigninStruct struct {
	id            string
	userId        string
	secretHash    []byte
	emailCodeHash []byte
	emailCodeSalt []byte
	createdAt     time.Time
}

func (emailCodeSignin *emailCodeSigninStruct) compareSecretAgainstHash(secret []byte) bool {
	hashed := hashSessionSecret(secret)
	hashEqual := constantTimeCompare(hashed, emailCodeSignin.secretHash)
	return hashEqual
}

func (server *serverStruct) createEmailCodeSignin(userId string) (emailCodeSigninStruct, []byte, string, error) {
	nowSecondPrecision := getCurrentTimeSecondPrecision()

	id := generateItemId()

	secret := generateSessionSecret()
	secretHash := hashSessionSecret(secret)

	emailCode := generateEmailCode()
	emailCodeSalt := generateHashingSalt()
	emailCodeHash := server.hashEmailCode(emailCode, emailCodeSalt)

	emailCodeSignin := emailCodeSigninStruct{
		id:            id,
		userId:        userId,
		secretHash:    secretHash,
		emailCodeHash: emailCodeHash,
		emailCodeSalt: emailCodeSalt,
		createdAt:     nowSecondPrecision,
	}

	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return emailCodeSigninStruct{}, nil, "", fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseWriteConnection,
		"INSERT INTO email_code_signin (id, user_id, secret_hash, email_code_hash, email_code_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		&sqlitex.ExecOptions{
			Args: []any{
				emailCodeSignin.id,
				emailCodeSignin.userId,
				emailCodeSignin.secretHash,
				emailCodeSignin.emailCodeHash,
				emailCodeSignin.emailCodeSalt,
				emailCodeSignin.createdAt.Unix(),
			},
		},
	)
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
		return emailCodeSigninStruct{}, nil, "", errItemConflict
	}
	if err != nil {
		return emailCodeSigninStruct{}, nil, "", fmt.Errorf("failed to insert into email_code_signin table: %s", err.Error())
	}

	return emailCodeSignin, secret, emailCode, nil
}

func (server *serverStruct) getEmailCodeSignin(emailCodeSigninId string) (emailCodeSigninStruct, error) {
	emailCodeSignins := []emailCodeSigninStruct{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return emailCodeSigninStruct{}, fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user_id, secret_hash, email_code_hash, email_code_salt, created_at FROM email_code_signin WHERE id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailCodeSigninId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				userId := stmt.ColumnText(0)

				secretHash := make([]byte, stmt.ColumnLen(1))
				stmt.ColumnBytes(1, secretHash)

				emailCodeHash := make([]byte, stmt.ColumnLen(2))
				stmt.ColumnBytes(2, emailCodeHash)

				emailCodeSalt := make([]byte, stmt.ColumnLen(3))
				stmt.ColumnBytes(3, emailCodeSalt)

				createdAt := time.Unix(stmt.ColumnInt64(4), 0)

				emailCodeSignin := emailCodeSigninStruct{
					id:            emailCodeSigninId,
					userId:        userId,
					secretHash:    secretHash,
					emailCodeSalt: emailCodeSalt,
					emailCodeHash: emailCodeHash,
					createdAt:     createdAt,
				}

				emailCodeSignins = append(emailCodeSignins, emailCodeSignin)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return emailCodeSigninStruct{}, fmt.Errorf("failed to select from email_code_signin table: %s", err.Error())
	}

	if len(emailCodeSignins) < 1 {
		return emailCodeSigninStruct{}, errItemNotFound
	}

	emailCodeSignin := emailCodeSignins[0]

	if time.Since(emailCodeSignin.createdAt) >= time.Minute*60 {
		return emailCodeSigninStruct{}, errItemNotFound
	}
	return emailCodeSignin, nil
}

var errInvalidEmailCodeSigninToken = errors.New("invalid email code signin token")

func (server *serverStruct) validateEmailCodeSigninToken(emailCodeSigninToken string) (emailCodeSigninStruct, error) {
	tokenParts := strings.Split(emailCodeSigninToken, ".")
	if len(tokenParts) != 2 {
		return emailCodeSigninStruct{}, errInvalidEmailCodeSigninToken
	}
	emailCodeSigninId := tokenParts[0]
	encodedSecret := tokenParts[1]
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return emailCodeSigninStruct{}, errInvalidEmailCodeSigninToken
	}

	emailCodeSignin, err := server.getEmailCodeSignin(emailCodeSigninId)
	if errors.Is(err, errItemNotFound) {
		return emailCodeSigninStruct{}, errInvalidEmailCodeSigninToken
	}
	if err != nil {
		return emailCodeSigninStruct{}, fmt.Errorf("failed to get email code signin: %s", err.Error())
	}

	secretValid := emailCodeSignin.compareSecretAgainstHash(secret)
	if !secretValid {
		return emailCodeSigninStruct{}, errInvalidEmailCodeSigninToken
	}

	return emailCodeSignin, nil
}

const emailCodeSigninTokenCookieName = "email_code_signin_token"

func (server *serverStruct) setBlankEmailCodeSigninToken(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     emailCodeSigninTokenCookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

func (server *serverStruct) validateRequestEmailCodeSigninToken(r *http.Request) (emailCodeSigninStruct, string, error) {
	emailCodeSigninTokenCookie, err := r.Cookie(emailCodeSigninTokenCookieName)
	if err != nil {
		return emailCodeSigninStruct{}, "", errInvalidEmailCodeSigninToken
	}
	emailCodeSigninToken := emailCodeSigninTokenCookie.Value

	emailCodeSignin, err := server.validateEmailCodeSigninToken(emailCodeSigninToken)
	if errors.Is(err, errInvalidEmailCodeSigninToken) {
		return emailCodeSigninStruct{}, "", errInvalidEmailCodeSigninToken
	}
	if err != nil {
		return emailCodeSigninStruct{}, "", fmt.Errorf("failed to validate email code signin token: %s", err.Error())
	}

	return emailCodeSignin, emailCodeSigninToken, nil
}

func (server *serverStruct) getEmailCodeSigninUserEmailAddress(emailCodeSigninId string) (string, error) {
	emailAddresses := []string{}

	databaseReadConnection, err := server.databaseReadConnectionPool.Take(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to take database read connection: %s", err.Error())
	}
	err = sqlitex.Execute(
		databaseReadConnection,
		"SELECT user.email_address from email_code_signin INNER JOIN user ON email_code_signin.user_id = user.id WHERE email_code_signin.id = ?",
		&sqlitex.ExecOptions{
			Args: []any{emailCodeSigninId},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				emailAddress := stmt.ColumnText(0)

				emailAddresses = append(emailAddresses, emailAddress)
				return nil
			},
		},
	)
	server.databaseReadConnectionPool.Put(databaseReadConnection)
	if err != nil {
		return "", fmt.Errorf("failed to select from email_code_signin table: %s", err.Error())
	}

	if len(emailAddresses) < 1 {
		return "", errItemNotFound
	}

	emailAddress := emailAddresses[0]

	return emailAddress, nil
}

func (server *serverStruct) completeEmailCodeSignin(emailCodeSigninId string) (sessionStruct, []byte, error) {
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

	userIds := []string{}
	err = sqlitex.Execute(databaseWriteConnection, `INSERT INTO session (id, user_id, secret_hash, created_at)
SELECT ?, user_id, ?, ? FROM email_code_signin WHERE id = ?
RETURNING user_id`, &sqlitex.ExecOptions{
		Args: []any{sessionId, sessionSecretHash, nowSecondPrecision.Unix(), emailCodeSigninId},
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
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}

		if sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintUnique || sqlite.ErrCode(err).ToPrimary() == sqlite.ResultConstraintForeignKey {
			return sessionStruct{}, nil, errItemConflict
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to insert into session table: %s", err.Error())
	}
	if len(userIds) < 1 {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, errItemNotFound
	}
	userId := userIds[0]

	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_code_signin WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCodeSigninId},
	})
	if err != nil {
		rollbackErr := sqlitex.Execute(databaseWriteConnection, "ROLLBACK", nil)
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		if rollbackErr != nil {
			return sessionStruct{}, nil, fmt.Errorf("failed to rollback transaction: %s", rollbackErr.Error())
		}
		return sessionStruct{}, nil, fmt.Errorf("failed to delete from emailCodeSignin table: %s", err.Error())
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

func (server *serverStruct) deleteEmailCodeSignin(emailCodeSigninId string) error {
	databaseWriteConnection, err := server.databaseWriteConnectionPool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("failed to take database write connection: %s", err.Error())
	}
	err = sqlitex.Execute(databaseWriteConnection, "DELETE FROM email_code_signin WHERE id = ?", &sqlitex.ExecOptions{
		Args: []any{emailCodeSigninId},
	})
	if err != nil {
		server.databaseWriteConnectionPool.Put(databaseWriteConnection)
		return fmt.Errorf("failed to delete from email_code_signin table: %s", err.Error())
	}
	affectedCount := databaseWriteConnection.Changes()
	server.databaseWriteConnectionPool.Put(databaseWriteConnection)
	if affectedCount < 1 {
		return errItemNotFound
	}
	return nil
}
