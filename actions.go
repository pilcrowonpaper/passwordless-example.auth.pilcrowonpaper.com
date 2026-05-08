package main

import (
	"errors"
	"fmt"

	"github.com/pilcrowonpaper/passwordless-example.auth.pilcrowonpaper.com/webauthn"
)

const (
	actionStartSignup                              = "start_signup"
	actionCancelSignup                             = "cancel_signup"
	actionSendSignupEmailAddressVerificationCode   = "send_signup_email_address_verification_code"
	actionVerifySignupEmailAddressVerificationCode = "verify_signup_email_address_verification_code"
	actionCompleteSignupWithoutPasskeyRegistration = "complete_signup_without_passkey_registration"
	actionSetSignupPasskeyWebauthnCredential       = "set_signup_passkey_webauthn_credential"
	actionSetSignupPasskeyName                     = "set_signup_passkey_name"

	actionStartEmailCodeSignin           = "start_email_code_signin"
	actionCancelEmailCodeSignin          = "cancel_email_code_signin"
	actionSendEmailCodeSigninEmailCode   = "send_email_code_signin_email_code"
	actionVerifyEmailCodeSigninEmailCode = "verify_email_code_signin_email_code"

	actionStartPasskeySignin                   = "start_passkey_signin"
	actionCancelPasskeySignin                  = "cancel_passkey_signin"
	actionVerifyPasskeySigninWebauthnSignature = "verify_passkey_signin_webauthn_signature"

	actionSignOut           = "sign_out"
	actionSignOutAllDevices = "sign_out_all_devices"

	actionGetWebauthnCredentialIds = "get_webauthn_credential_ids"

	actionCancelIdentityVerification                         = "cancel_identity_verification"
	actionVerifyIdentityVerificationPasskeyWebauthnSignature = "verify_identity_verification_passkey_webauthn_signature"
	actionIssueIdentityVerificationEmailCode                 = "issue_identity_verification_email_code"
	actionRevokeIdentityVerificationEmailCode                = "revoke_identity_verification_email_code"
	actionSendIdentityVerificationEmailCode                  = "send_identity_verification_email_code"
	actionVerifyIdentityVerificationEmailCode                = "verify_identity_verification_email_code"

	actionStartEmailAddressUpdate                                 = "start_email_address_update"
	actionCancelEmailAddressUpdate                                = "cancel_email_address_update"
	actionSetEmailAddressUpdateNewEmailAddress                    = "set_email_address_update_new_email_address"
	actionSendEmailAddressUpdateNewEmailAddressVerificationCode   = "send_email_address_update_new_email_address_verification_code"
	actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode = "verify_email_address_update_new_email_address_verification_code"

	actionStartPasskeyRegistration                        = "start_passkey_registration"
	actionCancelPasskeyRegistration                       = "cancel_passkey_registration"
	actionSetPasskeyRegistrationPasskeyWebauthnCredential = "set_passkey_registration_passkey_webauthn_credential"
	actionSetPasskeyRegistrationPasskeyName               = "set_passkey_registration_passkey_name"

	actionStartPasskeyDeletion   = "start_passkey_deletion"
	actionCancelPasskeyDeletion  = "cancel_passkey_deletion"
	actionConfirmPasskeyDeletion = "confirm_passkey_deletion"

	actionStartAccountDeletion   = "start_account_deletion"
	actionCancelAccountDeletion  = "cancel_account_deletion"
	actionConfirmAccountDeletion = "confirm_account_deletion"
)

func (server *serverStruct) startSignupAction(requestId string, clientIPAddress string, emailAddress string) (string, string) {
	const (
		errorCodeInvalidEmailAddress     = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed = "email_address_already_used"
		errorCodeRateLimited             = "rate_limited"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	emailAddressValid := verifyAccountIdentifierEmailAddressPattern(emailAddress)
	if !emailAddressValid {
		return "", errorCodeInvalidEmailAddress
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	signup, signupSecret, err := server.createSignup(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupStartedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	signupToken := createSessionToken(signup.id, signupSecret)

	return signupToken, ""
}

func (server *serverStruct) cancelSignupAction(requestId string, clientIPAddress string, signupToken string) string {
	const (
		errorCodeInvalidSignupToken = "invalid_signup_token"
		errorCodeConflict           = "conflict"
		errorCodeUnexpectedError    = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSignup(signup.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signup: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendSignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupToken string) string {
	const (
		errorCodeInvalidSignupToken          = "invalid_signup_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if signup.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(signup.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendSignupEmailAddressVerificationCodeEmail(signup.emailAddress, signup.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signup.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifySignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupToken string, verificationCode string) string {
	const (
		errorCodeInvalidSignupToken          = "invalid_signup_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeIncorrectVerificationCode   = "incorrect_verification_code"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if signup.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(signup.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	emailAddressVerificationCodeValid := signup.compareEmailAddressVerificationCode(verificationCode)
	if !emailAddressVerificationCodeValid {
		server.logSignupEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)
		return errorCodeIncorrectVerificationCode
	}

	err = server.setSignupAsEmailAddressVerified(signup.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup as email address verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logSignupEmailAddressVerifiedRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress)

	return ""
}

func (server *serverStruct) completeSignupWithoutPasskeyRegistrationAction(requestId string, clientIPAddress string, signupToken string) (string, string) {
	const (
		errorCodeInvalidSignupToken           = "invalid_signup_token"
		errorCodeEmailAddressNotVerified      = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialSet = "passkey_webauthn_credential_set"
		errorCodeEmailAddressAlreadyUsed      = "email_address_already_used"
		errorCodeUnexpectedError              = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return "", errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !signup.emailAddressVerified {
		return "", errorCodeEmailAddressNotVerified
	}
	if signup.passkeyWebauthnCredentialIdDefined {
		return "", errorCodePasskeyWebauthnCredentialSet
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	user, session, sessionSecret, err := server.completeSignupWithoutPasskeyRegistration(signup.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedWithoutPasskeyRegistrationRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress, user.id, session.id)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) setSignupPasskeyWebauthnCredentialAction(
	requestId string,
	clientIPAddress string,
	signupToken string,
	webauthnAuthenticatorData []byte,
) string {
	const (
		errorCodeInvalidSignupToken                  = "invalid_signup_token"
		errorCodeEmailAddressNotVerified             = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialAlreadySet = "passkey_webauthn_credential_already_set"
		errorCodeInvalidWebauthnAuthenticatorData    = "invalid_webauthn_authenticator_data"
		errorCodeInvalidOrUnsupportedPublicKey       = "invalid_or_unsupported_public_key"
		errorCodeWebauthnCredentialIdAlreadyUsed     = "webauthn_credential_id_already_used"
		errorCodeConflict                            = "conflict"
		errorCodeUnexpectedError                     = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	if !signup.emailAddressVerified {
		return errorCodeEmailAddressNotVerified
	}
	if signup.passkeyWebauthnCredentialIdDefined {
		return errorCodePasskeyWebauthnCredentialAlreadySet
	}

	if signup.passkeyCOSEPublicKeyDefined {
		errorMessage := "signup passkey cose public key defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if signup.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "signup passkey webauthn authenticator id defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	webauthnAuthenticator, err := webauthn.ParseAuthenticatorData(webauthnAuthenticatorData)
	if _, ok := err.(*webauthn.InvalidOrUnknownCOSEPublicKeyErrorStruct); ok {
		return errorCodeInvalidOrUnsupportedPublicKey
	}
	if err != nil {
		return errorCodeInvalidWebauthnAuthenticatorData
	}

	err = server.validatePasskeyRegistrationWebauthnAuthenticator(webauthnAuthenticator)
	if err != nil {
		return errorCodeInvalidWebauthnAuthenticatorData
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(webauthnAuthenticator.AttestedCredential.CredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return errorCodeWebauthnCredentialIdAlreadyUsed
	}

	err = server.setSignupPasskeyWebauthnCredential(
		signup.id,
		webauthnAuthenticator.AttestedCredential.CredentialId,
		webauthnAuthenticator.AttestedCredential.COSEPublicKey,
		webauthnAuthenticator.AttestedCredential.AAGUID,
	)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setSignupPasskeyNameAction(requestId string, clientIPAddress string, signupToken string, passkeyName string) (string, string) {
	const (
		errorCodeInvalidSignupToken              = "invalid_signup_token"
		errorCodeEmailAddressNotVerified         = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialNotSet = "passkey_webauthn_credential_not_set"
		errorCodeInvalidPasskeyName              = "invalid_passkey_name"
		errorCodeWebauthnCredentialIdAlreadyUsed = "webauthn_credential_id_already_used"
		errorCodeEmailAddressAlreadyUsed         = "email_address_already_used"
		errorCodeConflict                        = "conflict"
		errorCodeUnexpectedError                 = "unexpected_error"
	)

	signup, err := server.validateSignupToken(signupToken)
	if errors.Is(err, errInvalidSignupToken) {
		return "", errorCodeInvalidSignupToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !signup.emailAddressVerified {
		return "", errorCodeEmailAddressNotVerified
	}
	if !signup.passkeyWebauthnCredentialIdDefined {
		return "", errorCodePasskeyWebauthnCredentialNotSet
	}

	if !signup.passkeyCOSEPublicKeyDefined {
		errorMessage := "signup passkey cose public key not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !signup.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "signup passkey webauthn authenticator id not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passkeyNameValid := verifyPasskeyNamePattern(passkeyName)
	if !passkeyNameValid {
		return "", errorCodeInvalidPasskeyName
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(signup.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(signup.passkeyWebauthnCredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return "", errorCodeWebauthnCredentialIdAlreadyUsed
	}

	user, passkey, session, sessionSecret, err := server.completeSignupWithPasskeyRegistration(signup.id, passkeyName)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup with passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedWithPasskeyRegistrationRequestEvent(requestId, clientIPAddress, signup.id, signup.emailAddress, user.id, passkey.id, session.id)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) startPasskeySigninAction(requestId string, clientIPAddress string) (string, []byte, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	passkeySignin, err := server.createPasskeySignin()
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeySignin, errorMessage)
		return "", nil, errorCodeUnexpectedError
	}

	server.logPasskeySigninStartedRequestEvent(requestId, clientIPAddress, passkeySignin.id)

	return passkeySignin.id, passkeySignin.challenge, ""
}

func (server *serverStruct) cancelPasskeySigninAction(requestId string, clientIPAddress string, passkeySigninToken string) string {
	const (
		errorCodePasskeySigninNotFound = "passkey_signin_not_found"
		errorCodeConflict              = "conflict"
		errorCodeUnexpectedError       = "unexpected_error"
	)

	passkeySignin, err := server.getPasskeySignin(passkeySigninToken)
	if errors.Is(err, errItemNotFound) {
		return errorCodePasskeySigninNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey sign in token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeySignin, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deletePasskeySignin(passkeySignin.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeySignin, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) verifyPasskeySigninWebauthnSignatureAction(
	requestId string,
	clientIPAddress string,
	passkeySigninId string,
	webauthnCredentialId []byte,
	webauthnAuthenticatorData []byte,
	webauthnClientDataJSON []byte,
	webauthnSignature []byte,
) (string, string) {
	const (
		errorCodePasskeySigninNotFound            = "passkey_signin_not_found"
		errorCodePasskeyNotFound                  = "passkey_not_found"
		errorCodeInvalidWebauthnAuthenticatorData = "invalid_webauthn_authenticator_data"
		errorCodeInvalidWebauthnClientDataJSON    = "invalid_webauthn_client_data_json"
		errorCodeInvalidWebauthnSignature         = "invalid_webauthn_signature"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
	)

	passkeySignin, err := server.getPasskeySignin(passkeySigninId)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodePasskeySigninNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey sign in token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passkey, err := server.getPasskeyByWebauthnCredentialId(webauthnCredentialId)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodePasskeyNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey by webauthn credential id: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	webauthnAuthenticator, err := webauthn.ParseAuthenticatorData(webauthnAuthenticatorData)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}
	err = server.validatePasskeyVerificationWebauthnAuthenticator(webauthnAuthenticator)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}

	webauthnClient, err := webauthn.ParseClientDataJSON(webauthnClientDataJSON)
	if err != nil {
		return "", errorCodeInvalidWebauthnClientDataJSON
	}
	err = server.validatePasskeyVerificationWebauthnClient(webauthnClient, passkeySignin.challenge)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}

	signatureValid, err := webauthn.VerifyAssertionSignatureWithCOSEPublicKey(
		passkey.cosePublicKey,
		webauthnSignature,
		webauthnAuthenticatorData,
		webauthnClientDataJSON,
	)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify assertion signature with cose public key: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !signatureValid {
		server.logPasskeySigninSignatureVerificationFailedRequestEvent(requestId, clientIPAddress, passkeySignin.id, passkey.id, passkey.userId)
		return "", errorCodeInvalidWebauthnSignature
	}

	session, sessionSecret, err := server.completePasskeySignin(passkeySignin.id, passkey.userId)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasskeySigninCompletedRequestEvent(requestId, clientIPAddress, passkeySignin.id, passkey.id, passkey.userId, session.id)

	user, err := server.getUser(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	err = server.sendSignedInNotificationEmail(user.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypeSignedInNotification)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) startEmailCodeSigninAction(requestId string, clientIPAddress string, emailAddress string) (string, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUserNotFound        = "user_not_found"
		errorCodeRateLimited         = "rate_limited"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	emailAddressValid := verifyAccountIdentifierEmailAddressPattern(emailAddress)
	if !emailAddressValid {
		return "", errorCodeInvalidEmailAddress
	}

	user, err := server.getUserByEmailAddress(emailAddress)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeUserNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user by email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailCodeSignin, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(user.emailAddress)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	emailCodeSignin, emailCodeSigninSecret, err := server.createEmailCodeSigninFromUserEmailAddress(user.emailAddress)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email code signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailCodeSignin, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailCodeSigninStartedRequestEvent(requestId, clientIPAddress, emailCodeSignin.id, emailCodeSignin.userId, user.emailAddress)

	err = server.sendSigninEmailCode(user.emailAddress, emailCodeSignin.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signin email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailCodeSignin, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypeSigninEmailCode)

	sessionToken := createSessionToken(emailCodeSignin.id, emailCodeSigninSecret)

	return sessionToken, ""
}

func (server *serverStruct) cancelEmailCodeSigninAction(requestId string, clientIPAddress string, emailCodeSigninToken string) string {
	const (
		errorCodeInvalidEmailCodeSigninToken = "invalid_email_code_signin_token"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	emailCodeSignin, err := server.validateEmailCodeSigninToken(emailCodeSigninToken)
	if errors.Is(err, errInvalidEmailCodeSigninToken) {
		return errorCodeInvalidEmailCodeSigninToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailCodeSignin, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteEmailCodeSignin(emailCodeSignin.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email code signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailCodeSignin, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendEmailCodeSigninEmailCodeAction(requestId string, clientIPAddress string, emailCodeSigninToken string) string {
	const (
		errorCodeInvalidEmailCodeSigninToken = "invalid_email_code_signin_token"
		errorCodeConflict                    = "conflict"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	emailCodeSignin, err := server.validateEmailCodeSigninToken(emailCodeSigninToken)
	if errors.Is(err, errInvalidEmailCodeSigninToken) {
		return errorCodeInvalidEmailCodeSigninToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getEmailCodeSigninUserEmailAddress(emailCodeSignin.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email code signin user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(userEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendSigninEmailCode(userEmailAddress, emailCodeSignin.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signin email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeSigninEmailCode)

	return ""
}

func (server *serverStruct) verifyEmailCodeSigninEmailCodeAction(requestId string, clientIPAddress string, emailCodeSigninToken string, emailCode string) (string, string) {
	const (
		errorCodeInvalidEmailCodeSigninToken = "invalid_email_code_signin_token"
		errorCodeIncorrectEmailCode          = "incorrect_email_code"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
		errorCodeRateLimited                 = "rate_limited"
	)

	emailCodeSignin, err := server.validateEmailCodeSigninToken(emailCodeSigninToken)
	if errors.Is(err, errInvalidEmailCodeSigninToken) {
		return "", errorCodeInvalidEmailCodeSigninToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getEmailCodeSigninUserEmailAddress(emailCodeSignin.id)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email code singin user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userEmailCodeVerificationAuthenticationRateLimit.Consume(emailCodeSignin.userId)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	emailCodeCorrect := emailCodeSignin.compareEmailCode(emailCode)
	if !emailCodeCorrect {
		server.logEmailCodeSigninEmailCodeVerificationFailedRequestEvent(requestId, clientIPAddress, emailCodeSignin.id, emailCodeSignin.userId, userEmailAddress)
		return "", errorCodeIncorrectEmailCode
	}

	session, sessionSecret, err := server.completeEmailCodeSignin(emailCodeSignin.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email code signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailCodeSigninCompletedRequestEvent(requestId, clientIPAddress, emailCodeSignin.id, emailCodeSignin.userId, userEmailAddress, session.id)

	err = server.sendSignedInNotificationEmail(userEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeSignedInNotification)

	sessionToken := createSessionToken(session.id, sessionSecret)

	return sessionToken, ""
}

func (server *serverStruct) signOutAction(requestId string, clientIPAddress string, sessionToken string) string {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSession(session.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) signOutAllDevicesAction(requestId string, clientIPAddress string, sessionToken string) string {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteUserSessions(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user sessions: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) getWebauthnCredentialIdsAction(requestId string, clientIPAddress string, sessionToken string) ([][]byte, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return nil, errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionGetWebauthnCredentialIds, errorMessage)
		return nil, errorCodeUnexpectedError
	}

	passkeys, err := server.getUserPasskeys(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionGetWebauthnCredentialIds, errorMessage)
		return nil, errorCodeUnexpectedError
	}

	webauthnCredentialIds := [][]byte{}
	for _, passkey := range passkeys {
		webauthnCredentialIds = append(webauthnCredentialIds, passkey.webauthnCredentialId)
	}

	return webauthnCredentialIds, ""
}

func (server *serverStruct) cancelIdentityVerificationAction(requestId string, clientIPAddress string, sessionToken string, identityVerificationToken string) (string, string) {
	const (
		errorCodeInvalidSessionToken              = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken = "invalid_identity_verification_token"
		errorCodeSessionMismatch                  = "session_mismatch"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return "", errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return "", errorCodeSessionMismatch
	}

	switch identityVerification.verifyingAction {
	case identityVerificationVerifyingActionEmailAddressUpdate:
		err = server.deleteEmailAddressUpdate(identityVerification.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete email address update: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationVerifyingActionPasskeyRegistration:
		err = server.deletePasskeyRegistration(identityVerification.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete passkey registration: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationVerifyingActionPasskeyDeletion:
		err = server.deletePasskeyDeletion(identityVerification.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete passkey deletion: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationVerifyingActionAccountDeletion:
		err = server.deleteAccountDeletion(identityVerification.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete account deletion: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	default:
		errorMessage := fmt.Sprintf("unknown identity verification verifying action '%s'", identityVerification.verifyingAction)
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	return identityVerification.verifyingAction, ""
}

func (server *serverStruct) verifyIdentityVerificationPasskeyWebauthnSignatureAction(
	requestId string,
	clientIPAddress string,
	sessionToken string,
	identityVerificationToken string,
	webauthnCredentialId []byte,
	webauthnAuthenticatorData []byte,
	webauthnClientDataJSON []byte,
	webauthnSignature []byte,
) (string, string) {
	const (
		errorCodeInvalidSessionToken                  = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken     = "invalid_identity_verification_token"
		errorCodeSessionMismatch                      = "session_mismatch"
		errorCodeIdentityVerificationAlreadyCompleted = "identity_verification_already_completed"
		errorCodePasskeyNotFound                      = "passkey_not_found"
		errorCodeUserMismatch                         = "user_mismatch"
		errorCodeInvalidWebauthnAuthenticatorData     = "invalid_webauthn_authenticator_data"
		errorCodeInvalidWebauthnClientDataJSON        = "invalid_webauthn_client_data_json"
		errorCodeInvalidWebauthnSignature             = "invalid_webauthn_signature"
		errorCodeConflict                             = "conflict"
		errorCodeUnexpectedError                      = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return "", errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return "", errorCodeSessionMismatch
	}

	passkey, err := server.getPasskeyByWebauthnCredentialId(webauthnCredentialId)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodePasskeyNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey by webauthn credential id: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if passkey.userId != session.userId {
		return "", errorCodeUserMismatch
	}

	webauthnAuthenticator, err := webauthn.ParseAuthenticatorData(webauthnAuthenticatorData)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}
	err = server.validatePasskeyVerificationWebauthnAuthenticator(webauthnAuthenticator)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}

	webauthnClient, err := webauthn.ParseClientDataJSON(webauthnClientDataJSON)
	if err != nil {
		return "", errorCodeInvalidWebauthnClientDataJSON
	}
	err = server.validatePasskeyVerificationWebauthnClient(webauthnClient, identityVerification.passkeyVerificationChallenge)
	if err != nil {
		return "", errorCodeInvalidWebauthnAuthenticatorData
	}

	signatureValid, err := webauthn.VerifyAssertionSignatureWithCOSEPublicKey(
		passkey.cosePublicKey,
		webauthnSignature,
		webauthnAuthenticatorData,
		webauthnClientDataJSON,
	)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to verify assertion signature with cose public key: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !signatureValid {
		server.logIdentityVerificationPasskeyWebauthnSignatureVerificationFailedRequestEvent(
			requestId,
			clientIPAddress,
			session.id,
			session.userId,
			identityVerification.id,
			identityVerification.verifyingAction,
			identityVerification.verifyingActionId,
			passkey.id,
		)
		return "", errorCodeInvalidWebauthnSignature
	}

	err = server.completeIdentityVerification(identityVerification.id, identityVerification.verifyingAction)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update identity verification: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logIdentityVerificationPasskeyVerificationCompletedRequestEvent(requestId, clientIPAddress, session.id, session.userId, identityVerification.id, identityVerification.verifyingAction, identityVerification.verifyingActionId, passkey.id)

	return identityVerification.verifyingAction, ""
}

func (server *serverStruct) issueIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, sessionToken string, identityVerificationToken string) string {
	const (
		errorCodeInvalidSessionToken              = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken = "invalid_identity_verification_token"
		errorCodeSessionMismatch                  = "session_mismatch"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
		errorCodeRateLimited                      = "rate_limited"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	rateLimitAllowed := server.userEmailRateLimit.Consume(session.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	emailCode, userEmailAddress, err := server.issueIdentityVerificationEmailCode(identityVerification.id)
	if errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create identity verification email code verification: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logIdentityVerificationEmailCodeIssuedRequestEvent(
		requestId,
		clientIPAddress,
		session.id,
		session.userId,
		identityVerification.id,
		identityVerification.verifyingAction,
		identityVerification.verifyingActionId,
		userEmailAddress,
	)

	err = server.sendIdentityVerificationEmailCode(userEmailAddress, emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send identity verification email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeIdentityVerificationEmailCode)

	return ""
}

func (server *serverStruct) revokeIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, sessionToken string, identityVerificationToken string) string {
	const (
		errorCodeInvalidSessionToken              = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken = "invalid_identity_verification_token"
		errorCodeSessionMismatch                  = "session_mismatch"
		errorCodeEmailCodeNotIssued               = "email_code_not_issued"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
		errorCodeRateLimited                      = "rate_limited"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !identityVerification.emailCodeDefined {
		return errorCodeEmailCodeNotIssued
	}

	err = server.revokeIdentityVerificationEmailCode(identityVerification.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to revoke identity verification email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, sessionToken string, identityVerificationToken string) string {
	const (
		errorCodeInvalidSessionToken              = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken = "invalid_identity_verification_token"
		errorCodeSessionMismatch                  = "session_mismatch"
		errorCodeEmailCodeNotIssued               = "email_code_not_issued"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
		errorCodeRateLimited                      = "rate_limited"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return errorCodeSessionMismatch
	}

	if !identityVerification.emailCodeDefined {
		return errorCodeEmailCodeNotIssued
	}

	userEmailAddress, err := server.getIdentityVerificationUserEmailAddress(identityVerification.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get identity verification user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userEmailRateLimit.Consume(session.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	server.logIdentityVerificationEmailCodeIssuedRequestEvent(
		requestId,
		clientIPAddress,
		session.id,
		session.userId,
		identityVerification.id,
		identityVerification.verifyingAction,
		identityVerification.verifyingActionId,
		userEmailAddress,
	)

	err = server.sendIdentityVerificationEmailCode(userEmailAddress, identityVerification.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send identity verification email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeIdentityVerificationEmailCode)

	return ""
}

func (server *serverStruct) verifyIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, sessionToken string, identityVerificationToken string, emailCode string) (string, string) {
	const (
		errorCodeInvalidSessionToken              = "invalid_session_token"
		errorCodeInvalidIdentityVerificationToken = "invalid_identity_verification_token"
		errorCodeSessionMismatch                  = "session_mismatch"
		errorCodeEmailCodeNotIssued               = "email_code_not_issued"
		errorCodeIncorrectEmailCode               = "incorrect_email_code"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
		errorCodeRateLimited                      = "rate_limited"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerification, err := server.validateIdentityVerificationToken(identityVerificationToken)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		return "", errorCodeInvalidIdentityVerificationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getIdentityVerificationUserEmailAddress(identityVerification.id)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get identity verification user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerification.sessionId != session.id {
		return "", errorCodeSessionMismatch
	}

	if !identityVerification.emailCodeDefined {
		return "", errorCodeEmailCodeNotIssued
	}

	rateLimitAllowed := server.userEmailCodeVerificationAuthenticationRateLimit.Consume(session.userId)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	emailCodeCorrect := identityVerification.compareEmailCode(emailCode)
	if !emailCodeCorrect {
		server.logIdentityVerificationEmailCodeVerificationFailedRequestEvent(
			requestId,
			clientIPAddress,
			session.id,
			session.userId,
			identityVerification.id,
			identityVerification.verifyingAction,
			identityVerification.verifyingActionId,
			userEmailAddress,
		)
		return "", errorCodeIncorrectEmailCode
	}

	err = server.completeIdentityVerification(identityVerification.id, identityVerification.verifyingAction)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update identity verification: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logIdentityVerificationEmailCodeVerificationCompletedRequestEvent(
		requestId,
		clientIPAddress,
		session.id,
		session.userId,
		identityVerification.id,
		identityVerification.verifyingAction,
		identityVerification.verifyingActionId,
		userEmailAddress,
	)

	return identityVerification.verifyingAction, ""
}

func (server *serverStruct) startEmailAddressUpdateAction(requestId string, clientIPAddress string, sessionToken string) (string, string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	emailAddressUpdate, emailAddressUpdateSecret, identityVerification, identityVerificationSecret, err := server.createEmailAddressUpdate(session.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateStartedRequestEvent(requestId, clientIPAddress, session.id, session.userId, emailAddressUpdate.id, identityVerification.id)

	emailAddressUpdateToken := createSessionToken(emailAddressUpdate.id, emailAddressUpdateSecret)
	identityVerificationToken := createSessionToken(identityVerification.id, identityVerificationSecret)

	return emailAddressUpdateToken, identityVerificationToken, ""
}

func (server *serverStruct) cancelEmailAddressUpdateAction(requestId string, clientIPAddress string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeIdentityNotVerified            = "identity_not_verified"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdate.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deleteEmailAddressUpdate(emailAddressUpdate.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddressAction(requestId string, clientIPAddress string, sessionToken string, emailAddressUpdateToken string, newEmailAddress string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeIdentityNotVerified            = "identity_not_verified"
		errorCodeNewEmailAddressAlreadySet      = "new_email_address_already_set"
		errorCodeInvalidEmailAddress            = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdate.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressAlreadySet
	}

	if !verifyAccountIdentifierEmailAddressPattern(newEmailAddress) {
		return errorCodeInvalidEmailAddress
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	newEmailAddressVerificationCode, err := server.setEmailAddressUpdateNewEmailAddress(emailAddressUpdate.id, newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update new email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(newEmailAddress, newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, sessionToken string, emailAddressUpdateToken string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeIdentityNotVerified            = "identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdate.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}
	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(emailAddressUpdate.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddressUpdate.newEmailAddress, emailAddressUpdate.newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, emailAddressUpdate.newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, sessionToken string, emailAddressUpdateToken string, verificationCode string) string {
	const (
		errorCodeInvalidSessionToken            = "invalid_session_token"
		errorCodeInvalidEmailAddressUpdateToken = "invalid_email_address_update_token"
		errorCodeSessionMismatch                = "session_mismatch"
		errorCodeIdentityNotVerified            = "identity_not_verified"
		errorCodeNewEmailAddressNotSet          = "new_email_address_not_set"
		errorCodeIncorrectVerificationCode      = "incorrect_verification_code"
		errorCodeEmailAddressAlreadyUsed        = "email_address_already_used"
		errorCodeRateLimited                    = "rate_limited"
		errorCodeConflict                       = "conflict"
		errorCodeUnexpectedError                = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdate, err := server.validateEmailAddressUpdateToken(emailAddressUpdateToken)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		return errorCodeInvalidEmailAddressUpdateToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdate.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdate.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !emailAddressUpdate.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}

	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(emailAddressUpdate.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	verificationCodeCorrect := emailAddressUpdate.compareNewEmailAddressVerificationCode(verificationCode)
	if !verificationCodeCorrect {
		server.logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, session.id, session.userId, emailAddressUpdate.id, emailAddressUpdate.newEmailAddress)
		return errorCodeIncorrectVerificationCode
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddressUpdate.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	oldUserEmailAddress, err := server.completeEmailAddressUpdate(emailAddressUpdate.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateCompletedRequestEvent(requestId, clientIPAddress, session.id, session.userId, emailAddressUpdate.id, emailAddressUpdate.newEmailAddress)

	err = server.sendEmailAddressUpdatedNotificationEmail(oldUserEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, oldUserEmailAddress, emailTypeEmailAddressUpdatedNotification)

	return ""
}

func (server *serverStruct) startPasskeyRegistrationAction(requestId string, clientIPAddress string, sessionToken string) (string, string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodePasskeyLimitReached = "passkey_limit_reached"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	userPasskeyCount, err := server.getUserPasskeyCount(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkey count: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}
	if userPasskeyCount >= maxPasskeyCountLimit {
		return "", "", errorCodePasskeyLimitReached
	}

	passkeyRegistration, passkeyRegistrationSecret, identityVerification, identityVerificationSecret, err := server.createPasskeyRegistration(session.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logPasskeyRegistrationStartedRequestEvent(requestId, clientIPAddress, session.id, session.userId, identityVerification.id, passkeyRegistration.id)

	passkeyRegistrationToken := createSessionToken(passkeyRegistration.id, passkeyRegistrationSecret)
	identityVerificationToken := createSessionToken(identityVerification.id, identityVerificationSecret)

	return passkeyRegistrationToken, identityVerificationToken, ""
}

func (server *serverStruct) cancelPasskeyRegistrationAction(requestId string, clientIPAddress string, sessionToken string, passkeyRegistrationToken string) string {
	const (
		errorCodeInvalidSessionToken             = "invalid_session_token"
		errorCodeInvalidPasskeyRegistrationToken = "invalid_passkey_registration_token"
		errorCodeSessionMismatch                 = "session_mismatch"
		errorCodeIdentityNotVerified             = "identity_not_verified"
		errorCodeConflict                        = "conflict"
		errorCodeUnexpectedError                 = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistration, err := server.validatePasskeyRegistrationToken(passkeyRegistrationToken)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		return errorCodeInvalidPasskeyRegistrationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	if passkeyRegistration.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistration.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deletePasskeyRegistration(passkeyRegistration.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasskeyRegistrationPasskeyWebauthnCredentialAction(
	requestId string,
	clientIPAddress string,
	sessionToken string,
	passkeyRegistrationToken string,
	webauthnAuthenticatorData []byte,
) string {
	const (
		errorCodeInvalidSessionToken                 = "invalid_session_token"
		errorCodeInvalidPasskeyRegistrationToken     = "invalid_passkey_registration_token"
		errorCodeSessionMismatch                     = "session_mismatch"
		errorCodeIdentityNotVerified                 = "identity_not_verified"
		errorCodePasskeyWebauthnCredentialAlreadySet = "webauthn_credential_already_set"
		errorCodeInvalidWebauthnAuthenticatorData    = "invalid_webauthn_authenticator_data"
		errorCodeInvalidOrUnsupportedPublicKey       = "invalid_or_unsupported_public_key"
		errorCodeWebauthnCredentialIdAlreadyUsed     = "webauthn_credential_id_already_used"
		errorCodeConflict                            = "conflict"
		errorCodeUnexpectedError                     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistration, err := server.validatePasskeyRegistrationToken(passkeyRegistrationToken)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		return errorCodeInvalidPasskeyRegistrationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyRegistration.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistration.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if passkeyRegistration.passkeyWebauthnCredentialIdDefined {
		return errorCodePasskeyWebauthnCredentialAlreadySet
	}

	webauthnAuthenticator, err := webauthn.ParseAuthenticatorData(webauthnAuthenticatorData)
	if _, ok := err.(*webauthn.InvalidOrUnknownCOSEPublicKeyErrorStruct); ok {
		return errorCodeInvalidOrUnsupportedPublicKey
	}
	if err != nil {
		return errorCodeInvalidWebauthnAuthenticatorData
	}

	err = server.validatePasskeyRegistrationWebauthnAuthenticator(webauthnAuthenticator)
	if err != nil {
		return errorCodeInvalidWebauthnAuthenticatorData
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(webauthnAuthenticator.AttestedCredential.CredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return errorCodeWebauthnCredentialIdAlreadyUsed
	}

	err = server.setPasskeyRegistrationPasskeyWebauthnCredential(
		passkeyRegistration.id,
		webauthnAuthenticator.AttestedCredential.CredentialId,
		webauthnAuthenticator.AttestedCredential.COSEPublicKey,
		webauthnAuthenticator.AttestedCredential.AAGUID,
	)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set passkey registration passkey webauthn credential: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasskeyRegistrationPasskeyNameAction(requestId string, clientIPAddress string, sessionToken string, passkeyRegistrationToken string, passkeyName string) string {
	const (
		errorCodeInvalidSessionToken             = "invalid_session_token"
		errorCodeInvalidPasskeyRegistrationToken = "invalid_passkey_registration_token"
		errorCodeSessionMismatch                 = "session_mismatch"
		errorCodeIdentityNotVerified             = "identity_not_verified"
		errorCodePasskeyWebauthnCredentialNotSet = "webauthn_credential_not_set"
		errorCodeInvalidPasskeyName              = "invalid_passkey_name"
		errorCodePasskeyLimitReached             = "passkey_limit_reached"
		errorCodeWebauthnCredentialIdAlreadyUsed = "webauthn_credential_id_already_used"
		errorCodeEmailAddressAlreadyUsed         = "email_address_already_used"
		errorCodeConflict                        = "conflict"
		errorCodeUnexpectedError                 = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistration, err := server.validatePasskeyRegistrationToken(passkeyRegistrationToken)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		return errorCodeInvalidPasskeyRegistrationToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyRegistration.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistration.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !passkeyRegistration.passkeyWebauthnCredentialIdDefined {
		return errorCodePasskeyWebauthnCredentialNotSet
	}

	passkeyNameValid := verifyPasskeyNamePattern(passkeyName)
	if !passkeyNameValid {
		return errorCodeInvalidPasskeyName
	}

	if !passkeyRegistration.passkeyCOSEPublicKeyDefined {
		errorMessage := "signup passkey registration passkey cose public key not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if !passkeyRegistration.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "signup passkey registration passkey webauthn authenticator id not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	userPasskeyCount, err := server.getUserPasskeyCount(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkey count: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if userPasskeyCount >= maxPasskeyCountLimit {
		return errorCodePasskeyLimitReached
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(passkeyRegistration.passkeyWebauthnCredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return errorCodeWebauthnCredentialIdAlreadyUsed
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	passkey, err := server.completePasskeyRegistration(passkeyRegistration.id, passkeyName)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasskeyRegistrationCompletedRequestEvent(requestId, clientIPAddress, session.id, session.userId, passkeyRegistration.id, passkey.id)

	err = server.sendPasskeyRegisteredNotificationEmail(user.emailAddress, passkey.name)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send passkey registered notification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasskeyRegisteredNotification)

	return ""
}

func (server *serverStruct) startPasskeyDeletionAction(requestId string, clientIPAddress string, sessionToken string, passkeyId string) (string, string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodePasskeyNotFound     = "passkey_not_found"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	passkey, err := server.getPasskey(passkeyId)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodePasskeyNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	passkeyDeletion, passkeyDeletionSecret, identityVerification, identityVerificationSecret, err := server.createPasskeyDeletion(session.id, passkey.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logPasskeyDeletionStartedRequestEvent(requestId, clientIPAddress, session.id, session.userId, passkeyDeletion.id, passkeyDeletion.passkeyId, identityVerification.id)

	passkeyDeletionToken := createSessionToken(passkeyDeletion.id, passkeyDeletionSecret)
	identityVerificationToken := createSessionToken(identityVerification.id, identityVerificationSecret)

	return passkeyDeletionToken, identityVerificationToken, ""
}

func (server *serverStruct) cancelPasskeyDeletionAction(requestId string, clientIPAddress string, sessionToken string, passkeyDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidPasskeyDeletionToken = "invalid_passkey_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeIdentityNotVerified         = "identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyDeletion, err := server.validatePasskeyDeletionToken(passkeyDeletionToken)
	if errors.Is(err, errInvalidPasskeyDeletionToken) {
		return errorCodeInvalidPasskeyDeletionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if passkeyDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !passkeyDeletion.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deletePasskeyDeletion(passkeyDeletion.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) confirmPasskeyDeletionAction(requestId string, clientIPAddress string, sessionToken string, passkeyDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidPasskeyDeletionToken = "invalid_passkey_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeIdentityNotVerified         = "identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyDeletion, err := server.validatePasskeyDeletionToken(passkeyDeletionToken)
	if errors.Is(err, errInvalidPasskeyDeletionToken) {
		return errorCodeInvalidPasskeyDeletionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !passkeyDeletion.identityVerified {
		return errorCodeIdentityNotVerified
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyName, err := server.completePasskeyDeletion(passkeyDeletion.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasskeyDeletionCompletedRequestEvent(requestId, clientIPAddress, session.id, session.userId, passkeyDeletion.id, passkeyDeletion.passkeyId)

	err = server.sendPasskeyDeletedNotificationEmail(user.emailAddress, passkeyName)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send passkey deleted notification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasskeyDeletedNotification)

	return ""
}

func (server *serverStruct) startAccountDeletionAction(requestId string, clientIPAddress string, sessionToken string) (string, string, string) {
	const (
		errorCodeInvalidSessionToken = "invalid_session_token"
		errorCodeConflict            = "conflict"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return "", "", errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	accountDeletion, accountDeletionSecret, identityVerification, identityVerificationSecret, err := server.createAccountDeletion(session.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logAccountDeletionStartedRequestEvent(requestId, clientIPAddress, session.id, session.userId, accountDeletion.id, identityVerification.id)

	accountDeletionToken := createSessionToken(accountDeletion.id, accountDeletionSecret)
	identityVerificationToken := createSessionToken(identityVerification.id, identityVerificationSecret)

	return accountDeletionToken, identityVerificationToken, ""
}

func (server *serverStruct) cancelAccountDeletionAction(requestId string, clientIPAddress string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeIdentityNotVerified         = "identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return errorCodeInvalidAccountDeletionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !accountDeletion.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deleteAccountDeletion(accountDeletion.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) confirmAccountDeletionAction(requestId string, clientIPAddress string, sessionToken string, accountDeletionToken string) string {
	const (
		errorCodeInvalidSessionToken         = "invalid_session_token"
		errorCodeInvalidAccountDeletionToken = "invalid_account_deletion_token"
		errorCodeSessionMismatch             = "session_mismatch"
		errorCodeIdentityNotVerified         = "identity_not_verified"
		errorCodeConflict                    = "conflict"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	session, err := server.validateSessionToken(sessionToken)
	if errors.Is(err, errInvalidSessionToken) {
		return errorCodeInvalidSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletion, err := server.validateAccountDeletionToken(accountDeletionToken)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		return errorCodeInvalidAccountDeletionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}
	if accountDeletion.sessionId != session.id {
		return errorCodeSessionMismatch
	}
	if !accountDeletion.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.completeAccountDeletion(accountDeletion.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionCompletedRequestEvent(requestId, clientIPAddress, session.id, session.userId, accountDeletion.id)

	return ""
}
