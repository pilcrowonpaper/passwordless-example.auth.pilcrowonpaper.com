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

func ParseAssertionAuthenticatorData(authenticatorDataBytes []byte) (AssertionAuthenticatorDataStruct, error) {
	if len(authenticatorDataBytes) < 32 {
		return AssertionAuthenticatorDataStruct{}, errors.New("invalid relying party id")
	}
	relyingPartyId := authenticatorDataBytes[:32]

	if len(authenticatorDataBytes) < 33 {
		return AssertionAuthenticatorDataStruct{}, errors.New("invalid flags")
	}

	userPresent := authenticatorDataBytes[32]&0x01 == 1
	userVerified := (authenticatorDataBytes[32]>>2)&0x1 == 1
	backupEligible := (authenticatorDataBytes[32]>>3)&0x1 == 1
	backedUp := (authenticatorDataBytes[32]>>4)&0x1 == 1
	attestedCredentialDataDefined := (authenticatorDataBytes[32]>>6)&0x1 == 1

	if len(authenticatorDataBytes) < 37 {
		return AssertionAuthenticatorDataStruct{}, errors.New("invalid sign count")
	}

	signCount := binary.BigEndian.Uint32(authenticatorDataBytes[33:])

	if attestedCredentialDataDefined {
		return AssertionAuthenticatorDataStruct{}, errors.New("attestation credential data defined")
	}

	authenticatorData := AssertionAuthenticatorDataStruct{
		RelyingPartyIdHash: relyingPartyId,
		UserPresent:        userPresent,
		UserVerified:       userVerified,
		BackupEligible:     backupEligible,
		BackedUp:           backedUp,
		SignCount:          signCount,
	}

	return authenticatorData, nil
}

type AssertionAuthenticatorDataStruct struct {
	RelyingPartyIdHash []byte
	UserPresent        bool
	UserVerified       bool
	BackupEligible     bool
	BackedUp           bool
	SignCount          uint32
}

func (assertionAuthenticatorData *AssertionAuthenticatorDataStruct) CompareRelyingPartyIdAgainstHash(relyingPartyId string) bool {
	hashed := sha256.Sum256([]byte(relyingPartyId))
	hashEqual := subtle.ConstantTimeCompare(hashed[:], assertionAuthenticatorData.RelyingPartyIdHash) == 1
	return hashEqual
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
	ClientDataTypeWebauthnGet    = "webauthn.get"
	ClientDataTypeWebauthnCreate = "webauthn.create"
)

func ParseClientDataJSON(clientDataJSON []byte) (ClientDataStruct, error) {
	clientDataJSONObject, err := json.ParseObject(string(clientDataJSON))
	if err != nil {
		return ClientDataStruct{}, fmt.Errorf("failed to parse json object: %s", err.Error())
	}

	clientDataType, err := clientDataJSONObject.GetString("type")
	if err != nil {
		return ClientDataStruct{}, fmt.Errorf("failed to get 'type' string value: %s", err.Error())
	}
	if clientDataType != ClientDataTypeWebauthnGet && clientDataType != ClientDataTypeWebauthnCreate {
		return ClientDataStruct{}, fmt.Errorf("invalid client data type")
	}

	encodedChallenge, err := clientDataJSONObject.GetString("challenge")
	if err != nil {
		return ClientDataStruct{}, fmt.Errorf("failed to get 'challenge' string value: %s", err.Error())
	}
	challenge, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedChallenge)
	if err != nil {
		return ClientDataStruct{}, fmt.Errorf("failed to decode base64url challenge: %s", err.Error())
	}

	origin, err := clientDataJSONObject.GetString("origin")
	if err != nil {
		return ClientDataStruct{}, fmt.Errorf("failed to get 'origin' string value: %s", err.Error())
	}

	crossOrigin := false
	if clientDataJSONObject.Has("cross_origin") {
		crossOriginValue, err := clientDataJSONObject.GetBool("cross_origin")
		if err != nil {
			return ClientDataStruct{}, fmt.Errorf("failed to get 'cross_origin' bool value: %s", err.Error())
		}
		crossOrigin = crossOriginValue
	}

	clientData := ClientDataStruct{
		Type:        clientDataType,
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: crossOrigin,
	}

	return clientData, nil
}

type ClientDataStruct struct {
	Type        string
	Challenge   []byte
	Origin      string
	CrossOrigin bool
}

const AuthenticatorIdSize = 16
