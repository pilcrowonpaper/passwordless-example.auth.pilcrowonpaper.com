package main

import "crypto/rand"

func generateHashingSalt() []byte {
	saltBytes := make([]byte, 32)
	rand.Read(saltBytes)
	return saltBytes
}
