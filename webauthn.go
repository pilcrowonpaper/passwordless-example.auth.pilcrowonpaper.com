package main

import (
	"bytes"
	"fmt"

	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/webauthn"
)

func (server *serverStruct) validatePasskeyRegistrationWebauthnAuthenticator(webauthnAuthenticator webauthn.AuthenticatorStruct) error {
	if !webauthnAuthenticator.AttestedCredentialDefined {
		return fmt.Errorf("attested credential not defined")
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

	if webauthnAuthenticator.CredentialProtectionPolicy != webauthn.CredentialProtectionPolicyUndefined && webauthnAuthenticator.CredentialProtectionPolicy != webauthn.CredentialProtectionPolicyUserVerificationRequired {
		return fmt.Errorf("invalid credential protection policy")
	}

	return nil
}

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

	if webauthnAuthenticator.CredentialProtectionPolicy != webauthn.CredentialProtectionPolicyUndefined {
		return fmt.Errorf("invalid credential protection policy")
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
