package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
)

func parseECDSASEC1PublicKey(curve elliptic.Curve, sec1PublicKey []byte) (*ecdsa.PublicKey, error) {
	if len(sec1PublicKey) < 1 {
		return nil, errors.New("invalid length")
	}
	if sec1PublicKey[0] == 0x02 || sec1PublicKey[0] == 0x03 {
		publicKey, err := parseECDSASEC1CompressedPublicKey(curve, sec1PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse compressed public key: %s", err.Error())
		}
		return publicKey, nil
	}
	if sec1PublicKey[0] == 0x04 {
		publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, sec1PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse uncompressed public key: %s", err.Error())
		}
		return publicKey, nil
	}
	return nil, errors.New("invalid leading byte")
}

func parseECDSASEC1CompressedPublicKey(curve elliptic.Curve, sec1PublicKey []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, sec1PublicKey)
	if x == nil {
		return nil, errors.New("failed to unmarshall compressed public key")
	}
	publicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return publicKey, nil
}
