package main

import (
	"crypto/rand"
	"encoding/base32"
)

func generateItemId() string {
	idBytes := make([]byte, 10)
	rand.Read(idBytes)
	verificationCode := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").EncodeToString(idBytes)
	return verificationCode
}

func generateLongItemId() string {
	idBytes := make([]byte, 20)
	rand.Read(idBytes)
	verificationCode := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").EncodeToString(idBytes)
	return verificationCode
}
