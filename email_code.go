package main

import (
	"crypto/rand"
	"encoding/base32"
)

func generateEmailCode() string {
	emailCodeBytes := make([]byte, 5)
	rand.Read(emailCodeBytes)
	emailCode := base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").EncodeToString(emailCodeBytes)
	return emailCode
}

func formatEmailCode(code string) string {
	stringBytes := make([]byte, 9)
	stringBytes[0] = code[0]
	stringBytes[1] = code[1]
	stringBytes[2] = code[2]
	stringBytes[3] = code[3]
	stringBytes[4] = '-'
	stringBytes[5] = code[4]
	stringBytes[6] = code[5]
	stringBytes[7] = code[6]
	stringBytes[8] = code[7]
	return string(stringBytes)
}
