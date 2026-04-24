package webauthn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/pilcrowonpaper/go-json"
)

func ParseAuthenticatorData(authenticatorDataBytes []byte) (AuthenticatorStruct, error) {
	if len(authenticatorDataBytes) < 32 {
		return AuthenticatorStruct{}, errors.New("invalid relying party id")
	}
	relyingPartyId := authenticatorDataBytes[:32]

	if len(authenticatorDataBytes) < 33 {
		return AuthenticatorStruct{}, errors.New("invalid flags")
	}

	userPresent := authenticatorDataBytes[32]&0x01 == 1
	userVerified := (authenticatorDataBytes[32]>>2)&0x1 == 1
	backupEligible := (authenticatorDataBytes[32]>>3)&0x1 == 1
	backedUp := (authenticatorDataBytes[32]>>4)&0x1 == 1
	attestedCredentialDataIncluded := (authenticatorDataBytes[32]>>6)&0x1 == 1
	extensionDataIncluded := (authenticatorDataBytes[32]>>7)&0x1 == 1

	if extensionDataIncluded {
		return AuthenticatorStruct{}, errors.New("extension data included")
	}

	if len(authenticatorDataBytes) < 37 {
		return AuthenticatorStruct{}, errors.New("invalid sign count")
	}

	signCount := binary.BigEndian.Uint32(authenticatorDataBytes[33:])

	var attestedCredentialData AttestedCredentialStruct
	attestedCredentialDataSize := 0
	if attestedCredentialDataIncluded {
		if len(authenticatorDataBytes) < 53 {
			return AuthenticatorStruct{}, errors.New("invalid aaguid")
		}
		aaguid := authenticatorDataBytes[37:53]
		if len(authenticatorDataBytes) < 55 {
			return AuthenticatorStruct{}, errors.New("invalid credential id length")
		}
		credentialIdLength := int(binary.BigEndian.Uint16(authenticatorDataBytes[53:]))
		if len(authenticatorDataBytes) < 55+credentialIdLength {
			return AuthenticatorStruct{}, errors.New("invalid credential id")
		}
		if credentialIdLength > 1023 {
			return AuthenticatorStruct{}, errors.New("invalid credential id size")
		}
		credentialId := authenticatorDataBytes[55 : 55+credentialIdLength]

		cosePublicKey, cborCosePublicKeySize, err := parseCBORCOSEPublicKey(authenticatorDataBytes[55+credentialIdLength:])
		if err != nil {
			errInvalidOrUnknownPublicKey := &InvalidOrUnknownCOSEPublicKeyErrorStruct{err}
			return AuthenticatorStruct{}, errInvalidOrUnknownPublicKey
		}

		attestedCredentialData = AttestedCredentialStruct{
			AAGUID:        aaguid,
			CredentialId:  credentialId,
			COSEPublicKey: cosePublicKey,
		}
		attestedCredentialDataSize = 18 + credentialIdLength + cborCosePublicKeySize
	}

	if len(authenticatorDataBytes) != 37+attestedCredentialDataSize {
		return AuthenticatorStruct{}, errors.New("left over bytes")
	}

	authenticator := AuthenticatorStruct{
		RelyingPartyIdHash:        relyingPartyId,
		UserPresent:               userPresent,
		UserVerified:              userVerified,
		BackupEligible:            backupEligible,
		BackedUp:                  backedUp,
		SignCount:                 signCount,
		AttestedCredentialDefined: attestedCredentialDataIncluded,
		AttestedCredential:        attestedCredentialData,
	}

	return authenticator, nil
}

type AuthenticatorStruct struct {
	RelyingPartyIdHash        []byte
	UserPresent               bool
	UserVerified              bool
	BackupEligible            bool
	BackedUp                  bool
	SignCount                 uint32
	AttestedCredentialDefined bool
	AttestedCredential        AttestedCredentialStruct
}

func (authenticatorData *AuthenticatorStruct) CompareRelyingPartyIdAgainstHash(relyingPartyId string) bool {
	hashed := sha256.Sum256([]byte(relyingPartyId))
	hashEqual := subtle.ConstantTimeCompare(hashed[:], authenticatorData.RelyingPartyIdHash) == 1
	return hashEqual
}

type AttestedCredentialStruct struct {
	AAGUID        []byte
	CredentialId  []byte
	COSEPublicKey any
}

const AAGUIDSize = 16

type InvalidOrUnknownCOSEPublicKeyErrorStruct struct {
	COSEPublicKeyParsingError error
}

func (errInvalidOrUnknownCOSEPublicKeyError *InvalidOrUnknownCOSEPublicKeyErrorStruct) Error() string {
	return fmt.Sprintf("invalid or unknown cose public key: %s", errInvalidOrUnknownCOSEPublicKeyError.COSEPublicKeyParsingError.Error())
}

func GenerateChallenge() []byte {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	return challenge
}

func CreateAssertionSignatureMessage(authenticatorData []byte, clientDataJSON []byte) []byte {
	message := make([]byte, len(authenticatorData)+32)
	copy(message, authenticatorData)
	clientDataJSONHash := sha256.Sum256(clientDataJSON)
	copy(message[len(authenticatorData):], clientDataJSONHash[:])
	return message
}

const (
	ClientTypeWebauthnGet    = "webauthn.get"
	ClientTypeWebauthnCreate = "webauthn.create"
)

func ParseClientDataJSON(clientDataJSON []byte) (ClientStruct, error) {
	clientDataJSONObject, err := json.ParseObject(string(clientDataJSON))
	if err != nil {
		return ClientStruct{}, fmt.Errorf("failed to parse json object: %s", err.Error())
	}

	clientType, err := clientDataJSONObject.GetString("type")
	if err != nil {
		return ClientStruct{}, fmt.Errorf("failed to get 'type' string value: %s", err.Error())
	}
	if clientType != ClientTypeWebauthnGet && clientType != ClientTypeWebauthnCreate {
		return ClientStruct{}, fmt.Errorf("invalid client type")
	}

	encodedChallenge, err := clientDataJSONObject.GetString("challenge")
	if err != nil {
		return ClientStruct{}, fmt.Errorf("failed to get 'challenge' string value: %s", err.Error())
	}
	challenge, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedChallenge)
	if err != nil {
		return ClientStruct{}, fmt.Errorf("failed to decode base64url challenge: %s", err.Error())
	}

	origin, err := clientDataJSONObject.GetString("origin")
	if err != nil {
		return ClientStruct{}, fmt.Errorf("failed to get 'origin' string value: %s", err.Error())
	}

	crossOrigin := false
	if clientDataJSONObject.Has("cross_origin") {
		crossOriginValue, err := clientDataJSONObject.GetBool("cross_origin")
		if err != nil {
			return ClientStruct{}, fmt.Errorf("failed to get 'cross_origin' bool value: %s", err.Error())
		}
		crossOrigin = crossOriginValue
	}

	client := ClientStruct{
		Type:        clientType,
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: crossOrigin,
	}

	return client, nil
}

type ClientStruct struct {
	Type        string
	Challenge   []byte
	Origin      string
	CrossOrigin bool
}
