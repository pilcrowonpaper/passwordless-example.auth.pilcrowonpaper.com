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

	signupSession, signupSessionSecret, err := server.createSignupSession(emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create signup session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupStartedRequestEvent(requestId, clientIPAddress, signupSession.id, signupSession.emailAddress)

	err = server.sendSignupEmailAddressVerificationCodeEmail(signupSession.emailAddress, signupSession.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartSignup, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signupSession.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	signupSessionToken := createSessionToken(signupSession.id, signupSessionSecret)

	return signupSessionToken, ""
}

func (server *serverStruct) cancelSignupAction(requestId string, clientIPAddress string, signupSessionToken string) string {
	const (
		errorCodeInvalidSignupSessionToken = "invalid_signup_session_token"
		errorCodeConflict                  = "conflict"
		errorCodeUnexpectedError           = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteSignupSession(signupSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete signup session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelSignup, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendSignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupSessionToken string) string {
	const (
		errorCodeInvalidSignupSessionToken   = "invalid_signup_session_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if signupSession.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(signupSession.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendSignupEmailAddressVerificationCodeEmail(signupSession.emailAddress, signupSession.emailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signup email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, signupSession.emailAddress, emailTypeSignupEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifySignupEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, signupSessionToken string, verificationCode string) string {
	const (
		errorCodeInvalidSignupSessionToken   = "invalid_signup_session_token"
		errorCodeEmailAddressAlreadyVerified = "email_address_already_verified"
		errorCodeIncorrectVerificationCode   = "incorrect_verification_code"
		errorCodeRateLimited                 = "rate_limited"
		errorCodeUnexpectedError             = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if signupSession.emailAddressVerified {
		return errorCodeEmailAddressAlreadyVerified
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(signupSession.emailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	emailAddressVerificationCodeValid := signupSession.compareEmailAddressVerificationCode(verificationCode)
	if !emailAddressVerificationCodeValid {
		server.logSignupEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, signupSession.id, signupSession.emailAddress)
		return errorCodeIncorrectVerificationCode
	}

	err = server.setSignupSessionAsEmailAddressVerified(signupSession.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup session as email address verified: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logSignupEmailAddressVerifiedRequestEvent(requestId, clientIPAddress, signupSession.id, signupSession.emailAddress)

	return ""
}

func (server *serverStruct) completeSignupWithoutPasskeyRegistrationAction(requestId string, clientIPAddress string, signupSessionToken string) (string, string) {
	const (
		errorCodeInvalidSignupSessionToken    = "invalid_signup_session_token"
		errorCodeEmailAddressNotVerified      = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialSet = "passkey_webauthn_credential_set"
		errorCodeEmailAddressAlreadyUsed      = "email_address_already_used"
		errorCodeUnexpectedError              = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return "", errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !signupSession.emailAddressVerified {
		return "", errorCodeEmailAddressNotVerified
	}
	if signupSession.passkeyWebauthnCredentialIdDefined {
		return "", errorCodePasskeyWebauthnCredentialSet
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(signupSession.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	user, authSession, authSessionSecret, err := server.completeSignupWithoutPasskeyRegistration(signupSession.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedWithoutPasskeyRegistrationRequestEvent(requestId, clientIPAddress, signupSession.id, signupSession.emailAddress, user.id, authSession.id)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}

func (server *serverStruct) setSignupPasskeyWebauthnCredentialAction(
	requestId string,
	clientIPAddress string,
	signupSessionToken string,
	webauthnAuthenticatorData []byte,
) string {
	const (
		errorCodeInvalidSignupSessionToken           = "invalid_signup_session_token"
		errorCodeEmailAddressNotVerified             = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialAlreadySet = "passkey_webauthn_credential_already_set"
		errorCodeInvalidWebauthnAuthenticatorData    = "invalid_webauthn_authenticator_data"
		errorCodeInvalidOrUnsupportedPublicKey       = "invalid_or_unsupported_public_key"
		errorCodeWebauthnCredentialIdAlreadyUsed     = "webauthn_credential_id_already_used"
		errorCodeConflict                            = "conflict"
		errorCodeUnexpectedError                     = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	if !signupSession.emailAddressVerified {
		return errorCodeEmailAddressNotVerified
	}
	if signupSession.passkeyWebauthnCredentialIdDefined {
		return errorCodePasskeyWebauthnCredentialAlreadySet
	}

	if signupSession.passkeyCOSEPublicKeyDefined {
		errorMessage := "signup passkey cose public key defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if signupSession.passkeyWebauthnAuthenticatorIdDefined {
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

	err = server.setSignupSessionPasskeyWebauthnCredential(
		signupSession.id,
		webauthnAuthenticator.AttestedCredential.CredentialId,
		webauthnAuthenticator.AttestedCredential.COSEPublicKey,
		webauthnAuthenticator.AttestedCredential.AAGUID,
	)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set signup session passkey webauthn credential: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setSignupPasskeyNameAction(requestId string, clientIPAddress string, signupSessionToken string, passkeyName string) (string, string) {
	const (
		errorCodeInvalidSignupSessionToken       = "invalid_signup_session_token"
		errorCodeEmailAddressNotVerified         = "email_address_not_verified"
		errorCodePasskeyWebauthnCredentialNotSet = "passkey_webauthn_credential_not_set"
		errorCodeInvalidPasskeyName              = "invalid_passkey_name"
		errorCodeWebauthnCredentialIdAlreadyUsed = "webauthn_credential_id_already_used"
		errorCodeEmailAddressAlreadyUsed         = "email_address_already_used"
		errorCodeConflict                        = "conflict"
		errorCodeUnexpectedError                 = "unexpected_error"
	)

	signupSession, err := server.validateSignupSessionToken(signupSessionToken)
	if errors.Is(err, errInvalidSignupSessionToken) {
		return "", errorCodeInvalidSignupSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate signup session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if !signupSession.emailAddressVerified {
		return "", errorCodeEmailAddressNotVerified
	}
	if !signupSession.passkeyWebauthnCredentialIdDefined {
		return "", errorCodePasskeyWebauthnCredentialNotSet
	}

	if !signupSession.passkeyCOSEPublicKeyDefined {
		errorMessage := "signup passkey cose public key not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !signupSession.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "signup passkey webauthn authenticator id not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	passkeyNameValid := verifyPasskeyNamePattern(passkeyName)
	if !passkeyNameValid {
		return "", errorCodeInvalidPasskeyName
	}

	emailAddressAvailable, err := server.checkUserEmailAddressAvailability(signupSession.emailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !emailAddressAvailable {
		return "", errorCodeEmailAddressAlreadyUsed
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(signupSession.passkeyWebauthnCredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return "", errorCodeWebauthnCredentialIdAlreadyUsed
	}

	user, passkey, authSession, authSessionSecret, err := server.completeSignupWithPasskeyRegistration(signupSession.id, passkeyName)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete signup with passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetSignupPasskeyName, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logSignupCompletedWithPasskeyRegistrationRequestEvent(requestId, clientIPAddress, signupSession.id, signupSession.emailAddress, user.id, passkey.id, authSession.id)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}

func (server *serverStruct) startPasskeySigninAction(requestId string, clientIPAddress string) (string, []byte, string) {
	const (
		errorCodeInvalidEmailAddress = "invalid_email_address"
		errorCodeUnexpectedError     = "unexpected_error"
	)

	passkeySigninAttempt, err := server.createPasskeySigninAttempt()
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeySignin, errorMessage)
		return "", nil, errorCodeUnexpectedError
	}

	server.logPasskeySigninStartedRequestEvent(requestId, clientIPAddress, passkeySigninAttempt.id)

	return passkeySigninAttempt.id, passkeySigninAttempt.challenge, ""
}

func (server *serverStruct) cancelPasskeySigninAction(requestId string, clientIPAddress string, passkeySigninAttemptToken string) string {
	const (
		errorCodePasskeySigninAttemptNotFound = "passkey_signin_attempt_not_found"
		errorCodeConflict                     = "conflict"
		errorCodeUnexpectedError              = "unexpected_error"
	)

	passkeySigninAttempt, err := server.getPasskeySigninAttempt(passkeySigninAttemptToken)
	if errors.Is(err, errItemNotFound) {
		return errorCodePasskeySigninAttemptNotFound
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey sign in token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeySignin, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deletePasskeySigninAttempt(passkeySigninAttempt.id)
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
	passkeySigninAttemptId string,
	webauthnCredentialId []byte,
	webauthnAuthenticatorData []byte,
	webauthnClientDataJSON []byte,
	webauthnSignature []byte,
) (string, string) {
	const (
		errorCodePasskeySigninAttemptNotFound     = "passkey_signin_attempt_not_found"
		errorCodePasskeyNotFound                  = "passkey_not_found"
		errorCodeInvalidWebauthnAuthenticatorData = "invalid_webauthn_authenticator_data"
		errorCodeInvalidWebauthnClientDataJSON    = "invalid_webauthn_client_data_json"
		errorCodeInvalidWebauthnSignature         = "invalid_webauthn_signature"
		errorCodeConflict                         = "conflict"
		errorCodeUnexpectedError                  = "unexpected_error"
	)

	passkeySigninAttempt, err := server.getPasskeySigninAttempt(passkeySigninAttemptId)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodePasskeySigninAttemptNotFound
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
	err = server.validatePasskeyVerificationWebauthnClient(webauthnClient, passkeySigninAttempt.challenge)
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
		server.logPasskeySigninSignatureVerificationFailedRequestEvent(requestId, clientIPAddress, passkeySigninAttempt.id, passkey.id, passkey.userId)
		return "", errorCodeInvalidWebauthnSignature
	}

	authSession, authSessionSecret, err := server.completePasskeySignin(passkeySigninAttempt.id, passkey.userId)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logPasskeySigninCompletedRequestEvent(requestId, clientIPAddress, passkeySigninAttempt.id, passkey.id, passkey.userId, authSession.id)

	user, err := server.getUser(authSession.userId)
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

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
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

	emailCodeSigninSession, emailCodeSigninSessionSecret, err := server.createEmailCodeSigninSessionFromUserEmailAddress(user.emailAddress)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email code signin session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailCodeSignin, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailCodeSigninStartedRequestEvent(requestId, clientIPAddress, emailCodeSigninSession.id, emailCodeSigninSession.userId, user.emailAddress)

	err = server.sendSigninEmailCode(user.emailAddress, emailCodeSigninSession.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signin email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailCodeSignin, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypeSigninEmailCode)

	emailCodeSigninSessionToken := createSessionToken(emailCodeSigninSession.id, emailCodeSigninSessionSecret)

	return emailCodeSigninSessionToken, ""
}

func (server *serverStruct) cancelEmailCodeSigninAction(requestId string, clientIPAddress string, emailCodeSigninSessionToken string) string {
	const (
		errorCodeInvalidEmailCodeSigninSessionToken = "invalid_email_code_signin_session_token"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	emailCodeSigninSession, err := server.validateEmailCodeSigninSessionToken(emailCodeSigninSessionToken)
	if errors.Is(err, errInvalidEmailCodeSigninSessionToken) {
		return errorCodeInvalidEmailCodeSigninSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailCodeSignin, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteEmailCodeSigninSession(emailCodeSigninSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email code signin session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailCodeSignin, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendEmailCodeSigninEmailCodeAction(requestId string, clientIPAddress string, emailCodeSigninSessionToken string) string {
	const (
		errorCodeInvalidEmailCodeSigninSessionToken = "invalid_email_code_signin_session_token"
		errorCodeConflict                           = "conflict"
		errorCodeRateLimited                        = "rate_limited"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	emailCodeSigninSession, err := server.validateEmailCodeSigninSessionToken(emailCodeSigninSessionToken)
	if errors.Is(err, errInvalidEmailCodeSigninSessionToken) {
		return errorCodeInvalidEmailCodeSigninSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getEmailCodeSigninSessionUserEmailAddress(emailCodeSigninSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email code signin session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(userEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendSigninEmailCode(userEmailAddress, emailCodeSigninSession.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signin email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeSigninEmailCode)

	return ""
}

func (server *serverStruct) verifyEmailCodeSigninEmailCodeAction(requestId string, clientIPAddress string, emailCodeSigninSessionToken string, emailCode string) (string, string) {
	const (
		errorCodeInvalidEmailCodeSigninSessionToken = "invalid_email_code_signin_session_token"
		errorCodeIncorrectEmailCode                 = "incorrect_email_code"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
		errorCodeRateLimited                        = "rate_limited"
	)

	emailCodeSigninSession, err := server.validateEmailCodeSigninSessionToken(emailCodeSigninSessionToken)
	if errors.Is(err, errInvalidEmailCodeSigninSessionToken) {
		return "", errorCodeInvalidEmailCodeSigninSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email code signin session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getEmailCodeSigninSessionUserEmailAddress(emailCodeSigninSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email code signin session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userEmailCodeVerificationAuthenticationRateLimit.Consume(emailCodeSigninSession.userId)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	emailCodeCorrect := emailCodeSigninSession.compareEmailCode(emailCode)
	if !emailCodeCorrect {
		server.logEmailCodeSigninEmailCodeVerificationFailedRequestEvent(requestId, clientIPAddress, emailCodeSigninSession.id, emailCodeSigninSession.userId, userEmailAddress)
		return "", errorCodeIncorrectEmailCode
	}

	authSession, authSessionSecret, err := server.completeEmailCodeSigninSession(emailCodeSigninSession.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email code signin: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logEmailCodeSigninCompletedRequestEvent(requestId, clientIPAddress, emailCodeSigninSession.id, emailCodeSigninSession.userId, userEmailAddress, authSession.id)

	err = server.sendSignedInNotificationEmail(userEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send signed in email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeSignedInNotification)

	authSessionToken := createSessionToken(authSession.id, authSessionSecret)

	return authSessionToken, ""
}

func (server *serverStruct) signOutAction(requestId string, clientIPAddress string, authSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteAuthSession(authSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete auth session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOut, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) signOutAllDevicesAction(requestId string, clientIPAddress string, authSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	err = server.deleteUserAuthSessions(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete user auth sessions: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSignOutAllDevices, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) getWebauthnCredentialIdsAction(requestId string, clientIPAddress string, authSessionToken string) ([][]byte, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return nil, errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionGetWebauthnCredentialIds, errorMessage)
		return nil, errorCodeUnexpectedError
	}

	passkeys, err := server.getUserPasskeys(authSession.userId)
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

func (server *serverStruct) cancelIdentityVerificationAction(requestId string, clientIPAddress string, authSessionToken string, identityVerificationSessionToken string) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return "", errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
		return "", errorCodeSessionMismatch
	}

	switch identityVerificationSession.verifyingAction {
	case identityVerificationSessionVerifyingActionEmailAddressUpdate:
		err = server.deleteEmailAddressUpdateSession(identityVerificationSession.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete email address update session: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationSessionVerifyingActionPasskeyRegistration:
		err = server.deletePasskeyRegistrationSession(identityVerificationSession.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete passkey registration session: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationSessionVerifyingActionPasskeyDeletion:
		err = server.deletePasskeyDeletionSession(identityVerificationSession.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete passkey deletion session: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	case identityVerificationSessionVerifyingActionAccountDeletion:
		err = server.deleteAccountDeletionSession(identityVerificationSession.verifyingActionId)
		if errors.Is(err, errItemNotFound) {
			return "", errorCodeConflict
		}
		if err != nil {
			errorMessage := fmt.Sprintf("failed to delete account deletion session: %s", err.Error())
			server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
			return "", errorCodeUnexpectedError
		}
	default:
		errorMessage := fmt.Sprintf("unknown identity verification session verifying action '%s'", identityVerificationSession.verifyingAction)
		server.logActionInternalError(requestId, clientIPAddress, actionCancelIdentityVerification, errorMessage)
		return "", errorCodeUnexpectedError
	}

	return identityVerificationSession.verifyingAction, ""
}

func (server *serverStruct) verifyIdentityVerificationPasskeyWebauthnSignatureAction(
	requestId string,
	clientIPAddress string,
	authSessionToken string,
	identityVerificationSessionToken string,
	webauthnCredentialId []byte,
	webauthnAuthenticatorData []byte,
	webauthnClientDataJSON []byte,
	webauthnSignature []byte,
) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeIdentityVerificationAlreadyCompleted    = "identity_verification_already_completed"
		errorCodePasskeyNotFound                         = "passkey_not_found"
		errorCodeUserMismatch                            = "user_mismatch"
		errorCodeInvalidWebauthnAuthenticatorData        = "invalid_webauthn_authenticator_data"
		errorCodeInvalidWebauthnClientDataJSON           = "invalid_webauthn_client_data_json"
		errorCodeInvalidWebauthnSignature                = "invalid_webauthn_signature"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return "", errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
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

	if passkey.userId != authSession.userId {
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
	err = server.validatePasskeyVerificationWebauthnClient(webauthnClient, identityVerificationSession.passkeyVerificationChallenge)
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
			authSession.id,
			authSession.userId,
			identityVerificationSession.id,
			identityVerificationSession.verifyingAction,
			identityVerificationSession.verifyingActionId,
			passkey.id,
		)
		return "", errorCodeInvalidWebauthnSignature
	}

	err = server.completeIdentityVerification(identityVerificationSession.id, identityVerificationSession.verifyingAction)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update identity verification: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorMessage)
		return "", errorCodeUnexpectedError
	}

	server.logIdentityVerificationPasskeyVerificationCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, identityVerificationSession.id, identityVerificationSession.verifyingAction, identityVerificationSession.verifyingActionId, passkey.id)

	return identityVerificationSession.verifyingAction, ""
}

func (server *serverStruct) issueIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, authSessionToken string, identityVerificationSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
		errorCodeRateLimited                             = "rate_limited"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	rateLimitAllowed := server.userEmailRateLimit.Consume(authSession.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	emailCode, userEmailAddress, err := server.issueIdentityVerificationSessionEmailCode(identityVerificationSession.id)
	if errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to issue identity verification session email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logIdentityVerificationEmailCodeIssuedRequestEvent(
		requestId,
		clientIPAddress,
		authSession.id,
		authSession.userId,
		identityVerificationSession.id,
		identityVerificationSession.verifyingAction,
		identityVerificationSession.verifyingActionId,
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

func (server *serverStruct) revokeIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, authSessionToken string, identityVerificationSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeEmailCodeNotIssued                      = "email_code_not_issued"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
		errorCodeRateLimited                             = "rate_limited"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !identityVerificationSession.emailCodeDefined {
		return errorCodeEmailCodeNotIssued
	}

	err = server.revokeIdentityVerificationSessionEmailCode(identityVerificationSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to revoke identity verification session email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) sendIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, authSessionToken string, identityVerificationSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeEmailCodeNotIssued                      = "email_code_not_issued"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
		errorCodeRateLimited                             = "rate_limited"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}

	if !identityVerificationSession.emailCodeDefined {
		return errorCodeEmailCodeNotIssued
	}

	userEmailAddress, err := server.getIdentityVerificationSessionUserEmailAddress(identityVerificationSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get identity verification session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.userEmailRateLimit.Consume(authSession.userId)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	server.logIdentityVerificationEmailCodeIssuedRequestEvent(
		requestId,
		clientIPAddress,
		authSession.id,
		authSession.userId,
		identityVerificationSession.id,
		identityVerificationSession.verifyingAction,
		identityVerificationSession.verifyingActionId,
		userEmailAddress,
	)

	err = server.sendIdentityVerificationEmailCode(userEmailAddress, identityVerificationSession.emailCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send identity verification email code: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, userEmailAddress, emailTypeIdentityVerificationEmailCode)

	return ""
}

func (server *serverStruct) verifyIdentityVerificationEmailCodeAction(requestId string, clientIPAddress string, authSessionToken string, identityVerificationSessionToken string, emailCode string) (string, string) {
	const (
		errorCodeInvalidAuthSessionToken                 = "invalid_auth_session_token"
		errorCodeInvalidIdentityVerificationSessionToken = "invalid_identity_verification_session_token"
		errorCodeSessionMismatch                         = "session_mismatch"
		errorCodeEmailCodeNotIssued                      = "email_code_not_issued"
		errorCodeIncorrectEmailCode                      = "incorrect_email_code"
		errorCodeConflict                                = "conflict"
		errorCodeUnexpectedError                         = "unexpected_error"
		errorCodeRateLimited                             = "rate_limited"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	identityVerificationSession, err := server.validateIdentityVerificationSessionToken(identityVerificationSessionToken)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		return "", errorCodeInvalidIdentityVerificationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate identity verification session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	userEmailAddress, err := server.getIdentityVerificationSessionUserEmailAddress(identityVerificationSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get identity verification session user email address: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorMessage)
		return "", errorCodeUnexpectedError
	}

	if identityVerificationSession.authSessionId != authSession.id {
		return "", errorCodeSessionMismatch
	}

	if !identityVerificationSession.emailCodeDefined {
		return "", errorCodeEmailCodeNotIssued
	}

	rateLimitAllowed := server.userEmailCodeVerificationAuthenticationRateLimit.Consume(authSession.userId)
	if !rateLimitAllowed {
		return "", errorCodeRateLimited
	}

	emailCodeCorrect := identityVerificationSession.compareEmailCode(emailCode)
	if !emailCodeCorrect {
		server.logIdentityVerificationEmailCodeVerificationFailedRequestEvent(
			requestId,
			clientIPAddress,
			authSession.id,
			authSession.userId,
			identityVerificationSession.id,
			identityVerificationSession.verifyingAction,
			identityVerificationSession.verifyingActionId,
			userEmailAddress,
		)
		return "", errorCodeIncorrectEmailCode
	}

	err = server.completeIdentityVerification(identityVerificationSession.id, identityVerificationSession.verifyingAction)
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
		authSession.id,
		authSession.userId,
		identityVerificationSession.id,
		identityVerificationSession.verifyingAction,
		identityVerificationSession.verifyingActionId,
		userEmailAddress,
	)

	return identityVerificationSession.verifyingAction, ""
}

func (server *serverStruct) startEmailAddressUpdateAction(requestId string, clientIPAddress string, authSessionToken string) (string, string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	emailAddressUpdateSession, emailAddressUpdateSessionSecret, identityVerificationSession, identityVerificationSessionSecret, err := server.createEmailAddressUpdateSession(authSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id, identityVerificationSession.id)

	emailAddressUpdateSessionToken := createSessionToken(emailAddressUpdateSession.id, emailAddressUpdateSessionSecret)
	identityVerificationSessionToken := createSessionToken(identityVerificationSession.id, identityVerificationSessionSecret)

	return emailAddressUpdateSessionToken, identityVerificationSessionToken, ""
}

func (server *serverStruct) cancelEmailAddressUpdateAction(requestId string, clientIPAddress string, authSessionToken string, emailAddressUpdateSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken               = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateSessionToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                       = "session_mismatch"
		errorCodeIdentityNotVerified                   = "identity_not_verified"
		errorCodeConflict                              = "conflict"
		errorCodeUnexpectedError                       = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateSessionToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		return errorCodeInvalidEmailAddressUpdateSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdateSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deleteEmailAddressUpdateSession(emailAddressUpdateSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelEmailAddressUpdate, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setEmailAddressUpdateNewEmailAddressAction(requestId string, clientIPAddress string, authSessionToken string, emailAddressUpdateSessionToken string, newEmailAddress string) string {
	const (
		errorCodeInvalidAuthSessionToken               = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateSessionToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                       = "session_mismatch"
		errorCodeIdentityNotVerified                   = "identity_not_verified"
		errorCodeNewEmailAddressAlreadySet             = "new_email_address_already_set"
		errorCodeInvalidEmailAddress                   = "invalid_email_address"
		errorCodeEmailAddressAlreadyUsed               = "email_address_already_used"
		errorCodeRateLimited                           = "rate_limited"
		errorCodeConflict                              = "conflict"
		errorCodeUnexpectedError                       = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateSessionToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		return errorCodeInvalidEmailAddressUpdateSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdateSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if emailAddressUpdateSession.newEmailAddressDefined {
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

	newEmailAddressVerificationCode, err := server.setEmailAddressUpdateSessionNewEmailAddress(emailAddressUpdateSession.id, newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set email address update session new email address: %s", err.Error())
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

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, authSessionToken string, emailAddressUpdateSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken               = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateSessionToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                       = "session_mismatch"
		errorCodeIdentityNotVerified                   = "identity_not_verified"
		errorCodeNewEmailAddressNotSet                 = "new_email_address_not_set"
		errorCodeEmailAddressAlreadyUsed               = "email_address_already_used"
		errorCodeRateLimited                           = "rate_limited"
		errorCodeConflict                              = "conflict"
		errorCodeUnexpectedError                       = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateSessionToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		return errorCodeInvalidEmailAddressUpdateSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdateSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !emailAddressUpdateSession.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}
	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.unverifiedEmailAddressEmailRateLimit.Consume(emailAddressUpdateSession.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	err = server.sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddressUpdateSession.newEmailAddress, emailAddressUpdateSession.newEmailAddressVerificationCode)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update new email address verification code email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, emailAddressUpdateSession.newEmailAddress, emailTypeEmailAddressUpdateNewEmailAddressVerificationCode)

	return ""
}

func (server *serverStruct) verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId string, clientIPAddress string, authSessionToken string, emailAddressUpdateSessionToken string, verificationCode string) string {
	const (
		errorCodeInvalidAuthSessionToken               = "invalid_auth_session_token"
		errorCodeInvalidEmailAddressUpdateSessionToken = "invalid_email_address_update_session_token"
		errorCodeSessionMismatch                       = "session_mismatch"
		errorCodeIdentityNotVerified                   = "identity_not_verified"
		errorCodeNewEmailAddressNotSet                 = "new_email_address_not_set"
		errorCodeIncorrectVerificationCode             = "incorrect_verification_code"
		errorCodeEmailAddressAlreadyUsed               = "email_address_already_used"
		errorCodeRateLimited                           = "rate_limited"
		errorCodeConflict                              = "conflict"
		errorCodeUnexpectedError                       = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	emailAddressUpdateSession, err := server.validateEmailAddressUpdateSessionToken(emailAddressUpdateSessionToken)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		return errorCodeInvalidEmailAddressUpdateSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if emailAddressUpdateSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !emailAddressUpdateSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !emailAddressUpdateSession.newEmailAddressDefined {
		return errorCodeNewEmailAddressNotSet
	}

	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	rateLimitAllowed := server.emailAddressVerificationRateLimit.Consume(emailAddressUpdateSession.newEmailAddress)
	if !rateLimitAllowed {
		return errorCodeRateLimited
	}

	verificationCodeCorrect := emailAddressUpdateSession.compareNewEmailAddressVerificationCode(verificationCode)
	if !verificationCodeCorrect {
		server.logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id, emailAddressUpdateSession.newEmailAddress)
		return errorCodeIncorrectVerificationCode
	}

	newEmailAddressAvailable, err := server.checkUserEmailAddressAvailability(emailAddressUpdateSession.newEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check user email address availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}
	if !newEmailAddressAvailable {
		return errorCodeEmailAddressAlreadyUsed
	}

	oldUserEmailAddress, err := server.completeEmailAddressUpdate(emailAddressUpdateSession.id)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete email address update: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logEmailAddressUpdateCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, emailAddressUpdateSession.id, emailAddressUpdateSession.newEmailAddress)

	err = server.sendEmailAddressUpdatedNotificationEmail(oldUserEmailAddress)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send email address update email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, oldUserEmailAddress, emailTypeEmailAddressUpdatedNotification)

	return ""
}

func (server *serverStruct) startPasskeyRegistrationAction(requestId string, clientIPAddress string, authSessionToken string) (string, string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodePasskeyLimitReached     = "passkey_limit_reached"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	userPasskeyCount, err := server.getUserPasskeyCount(authSession.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkey count: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}
	if userPasskeyCount >= maxPasskeyCountLimit {
		return "", "", errorCodePasskeyLimitReached
	}

	passkeyRegistrationSession, passkeyRegistrationSessionSecret, identityVerificationSession, identityVerificationSessionSecret, err := server.createPasskeyRegistrationSession(authSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey registration session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyRegistration, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logPasskeyRegistrationStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, identityVerificationSession.id, passkeyRegistrationSession.id)

	passkeyRegistrationSessionToken := createSessionToken(passkeyRegistrationSession.id, passkeyRegistrationSessionSecret)
	identityVerificationSessionToken := createSessionToken(identityVerificationSession.id, identityVerificationSessionSecret)

	return passkeyRegistrationSessionToken, identityVerificationSessionToken, ""
}

func (server *serverStruct) cancelPasskeyRegistrationAction(requestId string, clientIPAddress string, authSessionToken string, passkeyRegistrationSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken                = "invalid_auth_session_token"
		errorCodeInvalidPasskeyRegistrationSessionToken = "invalid_passkey_registration_session_token"
		errorCodeSessionMismatch                        = "session_mismatch"
		errorCodeIdentityNotVerified                    = "identity_not_verified"
		errorCodeConflict                               = "conflict"
		errorCodeUnexpectedError                        = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistrationSession, err := server.validatePasskeyRegistrationSessionToken(passkeyRegistrationSessionToken)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		return errorCodeInvalidPasskeyRegistrationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey registration session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	if passkeyRegistrationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistrationSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deletePasskeyRegistrationSession(passkeyRegistrationSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete passkey registration session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyRegistration, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasskeyRegistrationPasskeyWebauthnCredentialAction(
	requestId string,
	clientIPAddress string,
	authSessionToken string,
	passkeyRegistrationSessionToken string,
	webauthnAuthenticatorData []byte,
) string {
	const (
		errorCodeInvalidAuthSessionToken                = "invalid_auth_session_token"
		errorCodeInvalidPasskeyRegistrationSessionToken = "invalid_passkey_registration_session_token"
		errorCodeSessionMismatch                        = "session_mismatch"
		errorCodeIdentityNotVerified                    = "identity_not_verified"
		errorCodePasskeyWebauthnCredentialAlreadySet    = "webauthn_credential_already_set"
		errorCodeInvalidWebauthnAuthenticatorData       = "invalid_webauthn_authenticator_data"
		errorCodeInvalidOrUnsupportedPublicKey          = "invalid_or_unsupported_public_key"
		errorCodeWebauthnCredentialIdAlreadyUsed        = "webauthn_credential_id_already_used"
		errorCodeConflict                               = "conflict"
		errorCodeUnexpectedError                        = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistrationSession, err := server.validatePasskeyRegistrationSessionToken(passkeyRegistrationSessionToken)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		return errorCodeInvalidPasskeyRegistrationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyRegistrationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistrationSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if passkeyRegistrationSession.passkeyWebauthnCredentialIdDefined {
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

	err = server.setPasskeyRegistrationSessionPasskeyWebauthnCredential(
		passkeyRegistrationSession.id,
		webauthnAuthenticator.AttestedCredential.CredentialId,
		webauthnAuthenticator.AttestedCredential.COSEPublicKey,
		webauthnAuthenticator.AttestedCredential.AAGUID,
	)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to set passkey registration session passkey webauthn credential: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) setPasskeyRegistrationPasskeyNameAction(requestId string, clientIPAddress string, authSessionToken string, passkeyRegistrationSessionToken string, passkeyName string) string {
	const (
		errorCodeInvalidAuthSessionToken                = "invalid_auth_session_token"
		errorCodeInvalidPasskeyRegistrationSessionToken = "invalid_passkey_registration_session_token"
		errorCodeSessionMismatch                        = "session_mismatch"
		errorCodeIdentityNotVerified                    = "identity_not_verified"
		errorCodePasskeyWebauthnCredentialNotSet        = "webauthn_credential_not_set"
		errorCodeInvalidPasskeyName                     = "invalid_passkey_name"
		errorCodePasskeyLimitReached                    = "passkey_limit_reached"
		errorCodeWebauthnCredentialIdAlreadyUsed        = "webauthn_credential_id_already_used"
		errorCodeEmailAddressAlreadyUsed                = "email_address_already_used"
		errorCodeConflict                               = "conflict"
		errorCodeUnexpectedError                        = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyRegistrationSession, err := server.validatePasskeyRegistrationSessionToken(passkeyRegistrationSessionToken)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		return errorCodeInvalidPasskeyRegistrationSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate email address update session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyRegistrationSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !passkeyRegistrationSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	if !passkeyRegistrationSession.passkeyWebauthnCredentialIdDefined {
		return errorCodePasskeyWebauthnCredentialNotSet
	}

	passkeyNameValid := verifyPasskeyNamePattern(passkeyName)
	if !passkeyNameValid {
		return errorCodeInvalidPasskeyName
	}

	if !passkeyRegistrationSession.passkeyCOSEPublicKeyDefined {
		errorMessage := "passkey registration session passkey cose public key not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if !passkeyRegistrationSession.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "passkey registration session passkey webauthn authenticator id not defined"
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	userPasskeyCount, err := server.getUserPasskeyCount(authSession.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkey count: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if userPasskeyCount >= maxPasskeyCountLimit {
		return errorCodePasskeyLimitReached
	}

	webauthnCredentialIdAvailable, err := server.checkPasskeyWebauthnCredentialIdAvailability(passkeyRegistrationSession.passkeyWebauthnCredentialId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to check passkey webauthn credential id availability: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}
	if !webauthnCredentialIdAvailable {
		return errorCodeWebauthnCredentialIdAlreadyUsed
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	passkey, err := server.completePasskeyRegistration(passkeyRegistrationSession.id, passkeyName)
	if errors.Is(err, errItemNotFound) || errors.Is(err, errItemConflict) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey registration: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasskeyRegistrationCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passkeyRegistrationSession.id, passkey.id)

	err = server.sendPasskeyRegisteredNotificationEmail(user.emailAddress, passkey.name)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send passkey registered notification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasskeyRegisteredNotification)

	return ""
}

func (server *serverStruct) startPasskeyDeletionAction(requestId string, clientIPAddress string, authSessionToken string, passkeyId string) (string, string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodePasskeyNotFound         = "passkey_not_found"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
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

	passkeyDeletionSession, passkeyDeletionSessionSecret, identityVerificationSession, identityVerificationSessionSecret, err := server.createPasskeyDeletionSession(authSession.id, passkey.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartPasskeyDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logPasskeyDeletionStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passkeyDeletionSession.id, passkeyDeletionSession.passkeyId, identityVerificationSession.id)

	passkeyDeletionSessionToken := createSessionToken(passkeyDeletionSession.id, passkeyDeletionSessionSecret)
	identityVerificationSessionToken := createSessionToken(identityVerificationSession.id, identityVerificationSessionSecret)

	return passkeyDeletionSessionToken, identityVerificationSessionToken, ""
}

func (server *serverStruct) cancelPasskeyDeletionAction(requestId string, clientIPAddress string, authSessionToken string, passkeyDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken            = "invalid_auth_session_token"
		errorCodeInvalidPasskeyDeletionSessionToken = "invalid_passkey_deletion_session_token"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeIdentityNotVerified                = "identity_not_verified"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyDeletionSession, err := server.validatePasskeyDeletionSessionToken(passkeyDeletionSessionToken)
	if errors.Is(err, errInvalidPasskeyDeletionSessionToken) {
		return errorCodeInvalidPasskeyDeletionSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if passkeyDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !passkeyDeletionSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deletePasskeyDeletionSession(passkeyDeletionSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete passkey deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) confirmPasskeyDeletionAction(requestId string, clientIPAddress string, authSessionToken string, passkeyDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken            = "invalid_auth_session_token"
		errorCodeInvalidPasskeyDeletionSessionToken = "invalid_passkey_deletion_session_token"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeIdentityNotVerified                = "identity_not_verified"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyDeletionSession, err := server.validatePasskeyDeletionSessionToken(passkeyDeletionSessionToken)
	if errors.Is(err, errInvalidPasskeyDeletionSessionToken) {
		return errorCodeInvalidPasskeyDeletionSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate passkey deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}
	if passkeyDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !passkeyDeletionSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	passkeyName, err := server.completePasskeyDeletion(passkeyDeletionSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete passkey deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logPasskeyDeletionCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, passkeyDeletionSession.id, passkeyDeletionSession.passkeyId)

	err = server.sendPasskeyDeletedNotificationEmail(user.emailAddress, passkeyName)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to send passkey deleted notification email: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logRequestEmail(requestId, clientIPAddress, user.emailAddress, emailTypePasskeyDeletedNotification)

	return ""
}

func (server *serverStruct) startAccountDeletionAction(requestId string, clientIPAddress string, authSessionToken string) (string, string, string) {
	const (
		errorCodeInvalidAuthSessionToken = "invalid_auth_session_token"
		errorCodeConflict                = "conflict"
		errorCodeUnexpectedError         = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return "", "", errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	accountDeletionSession, accountDeletionSessionSecret, identityVerificationSession, identityVerificationSessionSecret, err := server.createAccountDeletionSession(authSession.id)
	if errors.Is(err, errItemNotFound) {
		return "", "", errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create account deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionStartAccountDeletion, errorMessage)
		return "", "", errorCodeUnexpectedError
	}

	server.logAccountDeletionStartedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id, identityVerificationSession.id)

	accountDeletionSessionToken := createSessionToken(accountDeletionSession.id, accountDeletionSessionSecret)
	identityVerificationSessionToken := createSessionToken(identityVerificationSession.id, identityVerificationSessionSecret)

	return accountDeletionSessionToken, identityVerificationSessionToken, ""
}

func (server *serverStruct) cancelAccountDeletionAction(requestId string, clientIPAddress string, authSessionToken string, accountDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken            = "invalid_auth_session_token"
		errorCodeInvalidAccountDeletionSessionToken = "invalid_account_deletion_session_token"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeIdentityNotVerified                = "identity_not_verified"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return errorCodeInvalidAccountDeletionSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate account deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	if accountDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !accountDeletionSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.deleteAccountDeletionSession(accountDeletionSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to delete account deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionCancelAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	return ""
}

func (server *serverStruct) confirmAccountDeletionAction(requestId string, clientIPAddress string, authSessionToken string, accountDeletionSessionToken string) string {
	const (
		errorCodeInvalidAuthSessionToken            = "invalid_auth_session_token"
		errorCodeInvalidAccountDeletionSessionToken = "invalid_account_deletion_session_token"
		errorCodeSessionMismatch                    = "session_mismatch"
		errorCodeIdentityNotVerified                = "identity_not_verified"
		errorCodeConflict                           = "conflict"
		errorCodeUnexpectedError                    = "unexpected_error"
	)

	authSession, err := server.validateAuthSessionToken(authSessionToken)
	if errors.Is(err, errInvalidAuthSessionToken) {
		return errorCodeInvalidAuthSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate auth session token: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	accountDeletionSession, err := server.validateAccountDeletionSessionToken(accountDeletionSessionToken)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		return errorCodeInvalidAccountDeletionSessionToken
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate account deletion session: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}
	if accountDeletionSession.authSessionId != authSession.id {
		return errorCodeSessionMismatch
	}
	if !accountDeletionSession.identityVerified {
		return errorCodeIdentityNotVerified
	}

	err = server.completeAccountDeletion(accountDeletionSession.id)
	if errors.Is(err, errItemNotFound) {
		return errorCodeConflict
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to complete account deletion: %s", err.Error())
		server.logActionInternalError(requestId, clientIPAddress, actionConfirmAccountDeletion, errorMessage)
		return errorCodeUnexpectedError
	}

	server.logAccountDeletionCompletedRequestEvent(requestId, clientIPAddress, authSession.id, authSession.userId, accountDeletionSession.id)

	return ""
}
