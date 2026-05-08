package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func generateSessionSecret() []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret
}

func hashSessionSecret(secret []byte) []byte {
	secretHash := sha256.Sum256(secret)
	return secretHash[:]
}

func createSessionToken(sessionId string, sessionSecret []byte) string {
	encodedSessionSecret := base64.StdEncoding.EncodeToString(sessionSecret)
	sessionToken := sessionId + "." + encodedSessionSecret
	return sessionToken
}

func (server *serverStruct) setBlankSessionTokenCookie(w http.ResponseWriter, cookieName string) {
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
		Secure:   server.https(),
	}
	http.SetCookie(w, cookie)
}

func parseSessionToken(sessionToken string) (string, []byte, error) {
	sessionTokenParts := strings.Split(sessionToken, ".")
	if len(sessionTokenParts) != 2 {
		return "", nil, errors.New("invalid part count")
	}
	sessionId := sessionTokenParts[0]
	encodedSessionSecret := sessionTokenParts[1]
	sessionSecret, err := base64.StdEncoding.DecodeString(encodedSessionSecret)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode secret: %s", err.Error())
	}

	return sessionId, sessionSecret, nil
}
