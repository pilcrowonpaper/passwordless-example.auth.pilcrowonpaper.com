package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Supports:
// - Ed25519
// - ES256 (P-256)
// - RS256 (2048 bits, e=65537)
//
// Assumes the COSE public key encoding strictly follows the Web Authentication API and CTAP 2.1.
func verifyCOSEPublicKey(cosePublicKey []byte) (int, error) {
	// We dont' have to fully parse the CBOR because:
	// 1. The CTAP 2.1 canonical CBOR encoding ensures a strict map field order.
	// 2. The WebAuthn specification states that only the fields required by the algorithm should be included.

	if len(cosePublicKey) < 1 {
		return 0, fmt.Errorf("invalid major type")
	}
	if cosePublicKey[0]>>5 != 5 {
		return 0, fmt.Errorf("expected map major type")
	}
	if (cosePublicKey[0] & 0x1f) >= 24 {
		return 0, fmt.Errorf("cbor map too large")
	}
	mapSize := int(cosePublicKey[0] & 0x1f)
	if mapSize < 1 {
		return 0, fmt.Errorf("invalid map size")
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x01 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x27 {
			return 0, fmt.Errorf("expected algorithm of eddsa")
		}
		if len(cosePublicKey) < 42 {
			return 0, fmt.Errorf("invalid eddsa public key size")
		}
		if mapSize != 4 {
			return 0, fmt.Errorf("invalid eddsa public key cbor map size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x06 {
			return 0, fmt.Errorf("expected curve of ed25519")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return 0, fmt.Errorf("expected x to be a 32-byte binary string")
		}

		return 42, nil
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x02 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x26 {
			return 0, fmt.Errorf("expected algorithm of es256")
		}
		if mapSize != 5 {
			return 0, fmt.Errorf("invalid es256 public key cbor map size")
		}
		if len(cosePublicKey) < 77 {
			return 0, fmt.Errorf("invalid es256 public key size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x01 {
			return 0, fmt.Errorf("expected curve of p-256")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return 0, fmt.Errorf("expected x to be a 32-byte binary string")
		}
		x := new(big.Int)
		x.SetBytes(cosePublicKey[10:42])
		if cosePublicKey[42] != 0x22 || cosePublicKey[43] != 0x58 || cosePublicKey[44] != 32 {
			return 0, fmt.Errorf("expected y to be a 32-byte binary string")
		}
		y := new(big.Int)
		y.SetBytes(cosePublicKey[45:77])

		// elliptic.Curve.IsOnCurve() is deprecated but similar method doesn't exist in the standard library.
		// We don't need to check that nQ = O because the property holds for all points on P-256.
		// See SEC 1 section 3.2.2.1.
		// TODO: Is this required? We don't do a strict check for Ed25519
		publicKeyValid := elliptic.P256().IsOnCurve(x, y)
		if !publicKeyValid {
			return 0, fmt.Errorf("invalid public key")
		}

		return 77, nil
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x03 {
		if mapSize < 2 || len(cosePublicKey) < 7 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x39 || cosePublicKey[5] != 0x01 || cosePublicKey[6] != 0x00 {
			return 0, fmt.Errorf("expected algorithm of rs256")
		}
		if mapSize != 4 {
			return 0, fmt.Errorf("invalid rs256 public key cbor map size")
		}
		if len(cosePublicKey) < 272 {
			return 0, fmt.Errorf("invalid rs256 public key size")
		}
		// TODO: Support other key sizes?
		if cosePublicKey[7] != 0x20 || cosePublicKey[8] != 0x59 || cosePublicKey[9] != 0x01 || cosePublicKey[10] != 0x00 {
			return 0, fmt.Errorf("expected n to be a 256-byte binary string")
		}
		if cosePublicKey[11]>>7 != 1 {
			return 0, fmt.Errorf("expected n to be 2048 bit")
		}
		// TODO: Support other public exponents?
		if cosePublicKey[267] != 0x21 || cosePublicKey[268] != 0x43 || cosePublicKey[269] != 0x01 || cosePublicKey[270] != 0x00 || cosePublicKey[271] != 0x01 {
			return 0, fmt.Errorf("expected e of 65537")
		}
		return 272, nil
	}
	return 0, fmt.Errorf("unknown key type")
}

func VerifyAssertionSignatureWithCOSEPublicKey(cosePublicKey []byte, signature []byte, authenticatorData []byte, clientDataJSON []byte) (bool, error) {
	message := CreateAssertionSignatureMessage(authenticatorData, clientDataJSON)

	if len(cosePublicKey) < 1 {
		return false, fmt.Errorf("invalid major type")
	}
	if cosePublicKey[0]>>5 != 5 {
		return false, fmt.Errorf("expected map major type")
	}
	if (cosePublicKey[0] & 0x1f) >= 24 {
		return false, fmt.Errorf("cbor map too large")
	}
	mapSize := int(cosePublicKey[0] & 0x1f)
	if mapSize < 1 {
		return false, fmt.Errorf("invalid map size")
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x01 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x27 {
			return false, fmt.Errorf("expected algorithm of eddsa")
		}
		if len(cosePublicKey) != 42 {
			return false, fmt.Errorf("invalid eddsa public key size")
		}
		if mapSize != 4 {
			return false, fmt.Errorf("invalid eddsa public key cbor map size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x06 {
			return false, fmt.Errorf("expected curve of ed25519")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return false, fmt.Errorf("expected x to be a 32-byte binary string")
		}
		x := cosePublicKey[10:42]

		signatureValid := ed25519.Verify(x, message, signature)

		return signatureValid, nil
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x02 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x26 {
			return false, fmt.Errorf("expected algorithm of es256")
		}
		if mapSize != 5 {
			return false, fmt.Errorf("invalid es256 public key cbor map size")
		}
		if len(cosePublicKey) != 77 {
			return false, fmt.Errorf("invalid es256 public key size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x01 {
			return false, fmt.Errorf("expected curve of p-256")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return false, fmt.Errorf("expected x to be a 32-byte binary string")
		}
		x := new(big.Int)
		x.SetBytes(cosePublicKey[10:42])
		if cosePublicKey[42] != 0x22 || cosePublicKey[43] != 0x58 || cosePublicKey[44] != 32 {
			return false, fmt.Errorf("expected y to be a 32-byte binary string")
		}
		y := new(big.Int)
		y.SetBytes(cosePublicKey[45:77])

		// TODO: validate public key?

		publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		messageHash := sha256.Sum256(message)
		signatureValid := ecdsa.VerifyASN1(publicKey, messageHash[:], signature)

		return signatureValid, nil
	}

	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x03 {
		if mapSize < 2 || len(cosePublicKey) < 7 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x39 || cosePublicKey[5] != 0x01 || cosePublicKey[6] != 0x00 {
			return false, fmt.Errorf("expected algorithm of rs256")
		}
		if mapSize != 4 {
			return false, fmt.Errorf("invalid rs256 public key cbor map size")
		}
		if len(cosePublicKey) != 272 {
			return false, fmt.Errorf("invalid rs256 public key size")
		}
		// TODO: Support other key sizes?
		if cosePublicKey[7] != 0x20 || cosePublicKey[8] != 0x59 || cosePublicKey[9] != 0x01 || cosePublicKey[10] != 0x00 {
			return false, fmt.Errorf("expected n to be a 256-byte binary string")
		}
		n := new(big.Int)
		n.SetBytes(cosePublicKey[11:267])
		if n.BitLen() != 2048 {
			return false, fmt.Errorf("expected n to be 2048 bits")
		}
		// TODO: Support other public exponents?
		if cosePublicKey[267] != 0x21 || cosePublicKey[268] != 0x43 || cosePublicKey[269] != 0x01 || cosePublicKey[270] != 0x00 || cosePublicKey[271] != 0x01 {
			return false, fmt.Errorf("expected e of 65537")
		}

		publicKey := &rsa.PublicKey{N: n, E: 65537}
		messageHash := sha256.Sum256(message)
		err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, messageHash[:], signature)
		if err != nil {
			return false, nil
		}
		return true, nil
	}

	return false, fmt.Errorf("unknown key type")
}
