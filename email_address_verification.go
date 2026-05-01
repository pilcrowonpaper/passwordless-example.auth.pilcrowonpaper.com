package main

import (
	"crypto/rand"
	"encoding/binary"
)

func generateEmailAddressVerificationCode() string {
	for {
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)
		randomUint := binary.BigEndian.Uint32(randomBytes)
		randomUint >>= 5
		if randomUint < 100_000_000 {
			stringBytes := make([]byte, 8)
			stringBytes[0] = byte((randomUint/10_000_000)%10 + '0')
			stringBytes[1] = byte((randomUint/1_000_000)%10 + '0')
			stringBytes[2] = byte((randomUint/100_000)%10 + '0')
			stringBytes[3] = byte((randomUint/10_000)%10 + '0')
			stringBytes[4] = byte((randomUint/1_000)%10 + '0')
			stringBytes[5] = byte((randomUint/100)%10 + '0')
			stringBytes[6] = byte((randomUint/10)%10 + '0')
			stringBytes[7] = byte((randomUint)%10 + '0')
			return string(stringBytes)
		}
	}
}

func formatEmailAddressVerificationCode(verificationCode string) string {
	stringBytes := make([]byte, 9)
	stringBytes[0] = verificationCode[0]
	stringBytes[1] = verificationCode[1]
	stringBytes[2] = verificationCode[2]
	stringBytes[3] = verificationCode[3]
	stringBytes[4] = '-'
	stringBytes[5] = verificationCode[4]
	stringBytes[6] = verificationCode[5]
	stringBytes[7] = verificationCode[6]
	stringBytes[8] = verificationCode[7]
	return string(stringBytes)
}
