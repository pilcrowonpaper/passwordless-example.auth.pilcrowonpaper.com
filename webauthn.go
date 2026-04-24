package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/webauthn"
)

func (server *serverStruct) validatePasskeyRegistrationWebauthnAuthenticator(webauthnAuthenticator webauthn.AuthenticatorStruct) (passkeyRegistrationWebauthnAuthenticatorStruct, error) {
	if !webauthnAuthenticator.AttestedCredentialDefined {
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, fmt.Errorf("attested credential not defined")
	}
	if !webauthnAuthenticator.UserPresent {
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, fmt.Errorf("user not present")
	}
	if !webauthnAuthenticator.UserVerified {
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, fmt.Errorf("user not verified")
	}
	if !webauthnAuthenticator.BackupEligible && webauthnAuthenticator.BackedUp {
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, fmt.Errorf("invalid backup state")
	}
	relyingPartyIdMatched := webauthnAuthenticator.CompareRelyingPartyIdAgainstHash(server.webauthnRelyingPartyId)
	if !relyingPartyIdMatched {
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, fmt.Errorf("invalid relying party id hash")
	}

	credentialId := webauthnAuthenticator.AttestedCredential.CredentialId
	authenticatorId := webauthnAuthenticator.AttestedCredential.AAGUID

	var passkeySignatureAlgorithm string
	var passkeyPublicKey []byte
	switch cosePublicKey := webauthnAuthenticator.AttestedCredential.COSEPublicKey.(type) {
	case *webauthn.EdDSACOSEPublicKeyStruct:
		// The public key size is validated by webauthn.ParseAuthenticatorData().
		passkeySignatureAlgorithm = passkeySignatureAlgorithmEd25519
		passkeyPublicKey = cosePublicKey.X
	case *webauthn.ES256COSEPublicKeyStruct:
		// elliptic.Curve.IsOnCurve() is deprecated but similar method doesn't exist in the standard library.
		// We don't need to check that nQ = O because the property holds for all points on P-256.
		// See SEC 1 section 3.2.2.1.
		if !elliptic.P256().IsOnCurve(cosePublicKey.X, cosePublicKey.Y) {
			return passkeyRegistrationWebauthnAuthenticatorStruct{}, errInvalidOrUnsupportedWebauthnPublicKey
		}
		passkeySignatureAlgorithm = passkeySignatureAlgorithmECDSAP256SHA256
		passkeyPublicKey = elliptic.MarshalCompressed(elliptic.P256(), cosePublicKey.X, cosePublicKey.Y)
	case *webauthn.RS256COSEPublicKeyStruct:
		if cosePublicKey.N.BitLen() != 2048 || cosePublicKey.E != 65537 {
			return passkeyRegistrationWebauthnAuthenticatorStruct{}, errInvalidOrUnsupportedWebauthnPublicKey
		}
		passkeySignatureAlgorithm = passkeySignatureAlgorithmRSASSAPKCS1V15SHA256
		passkeyPublicKey = x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: cosePublicKey.N, E: cosePublicKey.E})
	default:
		return passkeyRegistrationWebauthnAuthenticatorStruct{}, errInvalidOrUnsupportedWebauthnPublicKey
	}

	validatedResult := passkeyRegistrationWebauthnAuthenticatorStruct{
		credentialId:              credentialId,
		authenticatorId:           authenticatorId,
		passkeySignatureAlgorithm: passkeySignatureAlgorithm,
		passkeyPublicKey:          passkeyPublicKey,
	}

	return validatedResult, nil
}

type passkeyRegistrationWebauthnAuthenticatorStruct struct {
	credentialId              []byte
	authenticatorId           []byte
	passkeySignatureAlgorithm string
	passkeyPublicKey          []byte
}

var errInvalidOrUnsupportedWebauthnPublicKey = errors.New("invalid or unsupported webauthn public key")

func (server *serverStruct) validatePasskeyVerificationWebauthnAuthenticator(webauthnAuthenticator webauthn.AuthenticatorStruct) error {
	if webauthnAuthenticator.AttestedCredentialDefined {
		return fmt.Errorf("attested credential defined")
	}
	if !webauthnAuthenticator.UserPresent {
		return fmt.Errorf("user not present")
	}
	if !webauthnAuthenticator.UserVerified {
		return fmt.Errorf("user not verified")
	}
	if !webauthnAuthenticator.BackupEligible && webauthnAuthenticator.BackedUp {
		return fmt.Errorf("invalid backup state")
	}
	relyingPartyIdMatched := webauthnAuthenticator.CompareRelyingPartyIdAgainstHash(server.webauthnRelyingPartyId)
	if !relyingPartyIdMatched {
		return fmt.Errorf("invalid relying party id hash")
	}

	return nil
}

func (server *serverStruct) validatePasskeyVerificationWebauthnClient(webauthnClient webauthn.ClientStruct, challenge []byte) error {
	if webauthnClient.Type != webauthn.ClientTypeWebauthnGet {
		return fmt.Errorf("invalid client type")
	}
	if webauthnClient.Origin != server.origin {
		return fmt.Errorf("invalid origin")
	}
	if !bytes.Equal(webauthnClient.Challenge, challenge) {
		return fmt.Errorf("invalid challenge")
	}
	if webauthnClient.CrossOrigin {
		return fmt.Errorf("cross origin")
	}

	return nil
}

func (server *serverStruct) verifyPasskeyVerificationWebauthnSignature(
	webauthnAuthenticatorData []byte,
	webauthnClientDataJSON []byte,
	webauthnSignature []byte,
	passkey passkeyStruct,
) (bool, error) {
	signatureMessage := webauthn.CreateAssertionSignatureMessage(webauthnAuthenticatorData, webauthnClientDataJSON)

	signatureValid := false
	switch passkey.signatureAlgorithm {
	case passkeySignatureAlgorithmEd25519:
		if len(passkey.publicKey) != ed25519.PublicKeySize {
			return false, fmt.Errorf("invalid ed25519 public key size")
		}
		signatureValid = ed25519.Verify(ed25519.PublicKey(passkey.publicKey), signatureMessage, webauthnSignature)
	case passkeySignatureAlgorithmECDSAP256SHA256:
		ecdsaPublicKey, err := parseECDSASEC1CompressedPublicKey(elliptic.P256(), passkey.publicKey)
		if err != nil {
			return false, fmt.Errorf("failed to parse ecdsa compressed sec1 public key: %s", err.Error())
		}

		messageHash := sha256.Sum256(signatureMessage)
		signatureValid = ecdsa.VerifyASN1(ecdsaPublicKey, messageHash[:], webauthnSignature)
	case passkeySignatureAlgorithmRSASSAPKCS1V15SHA256:
		rsaPublicKey, err := x509.ParsePKCS1PublicKey(passkey.publicKey)
		if err != nil {
			return false, fmt.Errorf("failed to rsa pkcs1 public key: %s", err.Error())
		}

		messageHash := sha256.Sum256(signatureMessage)
		err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, messageHash[:], webauthnSignature)
		signatureValid = err == nil
	default:
		return false, fmt.Errorf("unknown public key algorithm '%s'", passkey.signatureAlgorithm)
	}

	return signatureValid, nil
}
