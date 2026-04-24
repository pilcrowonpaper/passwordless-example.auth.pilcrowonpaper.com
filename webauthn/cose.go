package webauthn

import (
	"fmt"
	"math/big"
)

// Supports:
// - Ed25519
// - ES256 (P-256)
// - RS256 (2048 bits, e=65537)
//
// Assumes the COSE public key encoding strictly follows the Web Authentication API and CTAP 2.1.
func parseCBORCOSEPublicKey(cosePublicKey []byte) (any, int, error) {
	if len(cosePublicKey) < 1 {
		return nil, 0, fmt.Errorf("invalid major type")
	}
	if cosePublicKey[0]>>5 != 5 {
		return nil, 0, fmt.Errorf("expected map major type")
	}
	if (cosePublicKey[0] & 0x1f) >= 24 {
		return nil, 0, fmt.Errorf("cbor map too large")
	}
	mapSize := int(cosePublicKey[0] & 0x1f)
	if mapSize < 1 {
		return nil, 0, fmt.Errorf("invalid map size")
	}
	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x01 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x27 {
			return nil, 0, fmt.Errorf("expected algorithm of eddsa")
		}
		if len(cosePublicKey) != 42 {
			return nil, 0, fmt.Errorf("invalid eddsa public key size")
		}
		if mapSize != 4 {
			return nil, 0, fmt.Errorf("invalid eddsa public key cbor map size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x06 {
			return nil, 0, fmt.Errorf("expected curve of ed25519")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return nil, 0, fmt.Errorf("expected x to be a 32-byte binary string")
		}
		x := cosePublicKey[10:42]

		publicKey := &EdDSACOSEPublicKeyStruct{x}
		return publicKey, 42, nil
	}
	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x02 {
		if mapSize < 2 || len(cosePublicKey) < 5 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x26 {
			return nil, 0, fmt.Errorf("expected algorithm of es256")
		}
		if mapSize != 5 {
			return nil, 0, fmt.Errorf("invalid es256 public key cbor map size")
		}
		if len(cosePublicKey) != 77 {
			return nil, 0, fmt.Errorf("invalid es256 public key size")
		}
		if cosePublicKey[5] != 0x20 || cosePublicKey[6] != 0x01 {
			return nil, 0, fmt.Errorf("expected curve of p-256")
		}
		if cosePublicKey[7] != 0x21 || cosePublicKey[8] != 0x58 || cosePublicKey[9] != 32 {
			return nil, 0, fmt.Errorf("expected x to be a 32-byte binary string")
		}
		x := new(big.Int)
		x.SetBytes(cosePublicKey[10:42])
		if cosePublicKey[42] != 0x22 || cosePublicKey[43] != 0x58 || cosePublicKey[44] != 32 {
			return nil, 0, fmt.Errorf("expected y to be a 32-byte binary string")
		}
		y := new(big.Int)
		y.SetBytes(cosePublicKey[45:77])

		publicKey := &ES256COSEPublicKeyStruct{x, y}
		return publicKey, 77, nil
	}
	if len(cosePublicKey) > 2 && cosePublicKey[1] == 0x01 && cosePublicKey[2] == 0x03 {
		if mapSize < 2 || len(cosePublicKey) < 7 || cosePublicKey[3] != 0x03 || cosePublicKey[4] != 0x39 || cosePublicKey[5] != 0x01 || cosePublicKey[6] != 0x00 {
			return nil, 0, fmt.Errorf("expected algorithm of rs256")
		}
		if mapSize != 4 {
			return nil, 0, fmt.Errorf("invalid rs256 public key cbor map size")
		}
		if len(cosePublicKey) != 272 {
			return nil, 0, fmt.Errorf("invalid rs256 public key size")
		}
		// TODO: Support other key sizes?
		if cosePublicKey[7] != 0x20 || cosePublicKey[8] != 0x59 || cosePublicKey[9] != 0x01 || cosePublicKey[10] != 0x00 {
			return nil, 0, fmt.Errorf("expected n to be a 256-byte binary string")
		}
		n := new(big.Int)
		n.SetBytes(cosePublicKey[11:267])
		// TODO: Support other public exponents?
		if cosePublicKey[267] != 0x21 || cosePublicKey[268] != 0x43 || cosePublicKey[269] != 0x01 || cosePublicKey[270] != 0x00 || cosePublicKey[271] != 0x01 {
			return nil, 0, fmt.Errorf("expected e of 65537")
		}
		publicKey := &RS256COSEPublicKeyStruct{n, 65537}
		return publicKey, 272, nil
	}
	return nil, 0, fmt.Errorf("unknown key type")
}

type ES256COSEPublicKeyStruct struct {
	X *big.Int
	Y *big.Int
}

type RS256COSEPublicKeyStruct struct {
	N *big.Int
	E int
}

type EdDSACOSEPublicKeyStruct struct {
	X []byte
}
