package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/pilcrowonpaper/go-json"
)

func (server *serverStruct) actionRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	contentTypeHeader := r.Header.Get("Content-Type")
	if contentTypeHeader != "" {
		mediaType, mediaTypeParameters, err := mime.ParseMediaType(contentTypeHeader)
		if err != nil {
			w.WriteHeader(415)
			return
		}
		if mediaType != "application/json" {
			w.WriteHeader(415)
			return
		}
		charsetParameter, ok := mediaTypeParameters["charset"]
		if ok && strings.ToLower(charsetParameter) != "utf-8" {
			w.WriteHeader(415)
			return
		}
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	bodyJSONObject, err := json.ParseObject(string(bodyBytes))
	if err != nil {
		w.WriteHeader(400)
		return
	}

	actionName, err := bodyJSONObject.GetString("action")
	if err != nil {
		w.WriteHeader(400)
		return
	}
	values, err := bodyJSONObject.GetJSONObject("values")
	if err != nil {
		w.WriteHeader(400)
		return
	}

	if actionName == actionStartSignup {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		signupToken, errorCode := server.startSignupAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartSignup)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("signup_token", signupToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelSignup {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelSignupAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelSignup)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendSignupEmailAddressVerificationCode {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendSignupEmailAddressVerificationCodeAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSendSignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSendSignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifySignupEmailAddressVerificationCode {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifySignupEmailAddressVerificationCodeAction(requestId, signupToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifySignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifySignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionCompleteSignupWithoutPasskeyRegistration {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.completeSignupWithoutPasskeyRegistrationAction(requestId, signupToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCompleteSignupWithoutPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCompleteSignupWithoutPasskeyRegistration)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSetSignupPasskeyWebauthnCredential {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedPasskeyWebauthnCredentialId, err := values.GetString("passkey_webauthn_credential_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyWebauthnCredentialId, err := base64.StdEncoding.DecodeString(encodedPasskeyWebauthnCredentialId)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeySignatureAlgorithm, err := values.GetString("passkey_signature_algorithm")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedPasskeyPublicKey, err := values.GetString("passkey_public_key")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyPublicKey, err := base64.StdEncoding.DecodeString(encodedPasskeyPublicKey)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedPasskeyWebauthnAuthenticatorId, err := values.GetString("passkey_webauthn_authenticator_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyWebauthnAuthenticatorId, err := base64.StdEncoding.DecodeString(encodedPasskeyWebauthnAuthenticatorId)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		errorCode := server.setSignupPasskeyWebauthnCredentialAction(
			requestId,
			signupToken,
			passkeyWebauthnCredentialId,
			passkeySignatureAlgorithm,
			passkeyPublicKey,
			passkeyWebauthnAuthenticatorId,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetSignupPasskeyWebauthnCredential, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetSignupPasskeyWebauthnCredential)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetSignupPasskeyName {
		signupToken, err := values.GetString("signup_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyName, err := values.GetString("passkey_name")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.setSignupPasskeyNameAction(requestId, signupToken, passkeyName)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetSignupPasskeyName, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetSignupPasskeyName)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionStartPasskeySignin {
		passkeySigninId, challenge, errorCode := server.startPasskeySigninAction(requestId)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeySignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeySignin)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_signin_id", passkeySigninId)
		resultValuesJSONBuilder.AddString("challenge", base64.StdEncoding.EncodeToString(challenge))
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeySignin {
		passkeySigninId, err := values.GetString("passkey_signin_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}

		errorCode := server.cancelPasskeySigninAction(requestId, passkeySigninId)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeySignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeySignin)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasskeySigninWebauthnSignature {
		passkeySigninId, err := values.GetString("passkey_signin_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnCredentialId, err := values.GetString("webauthn_credential_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnCredentialId, err := base64.StdEncoding.DecodeString(encodedWebauthnCredentialId)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnAuthenticatorData, err := values.GetString("webauthn_authenticator_data")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnAuthenticatorData, err := base64.StdEncoding.DecodeString(encodedWebauthnAuthenticatorData)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnClientDataJSON, err := values.GetString("webauthn_client_data_json")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnClientDataJSON, err := base64.StdEncoding.DecodeString(encodedWebauthnClientDataJSON)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnSignature, err := values.GetString("webauthn_signature")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnSignature, err := base64.StdEncoding.DecodeString(encodedWebauthnSignature)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.verifyPasskeySigninWebauthnSignatureAction(
			requestId,
			passkeySigninId,
			webauthnCredentialId,
			webauthnAuthenticatorData,
			webauthnClientDataJSON,
			webauthnSignature,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyPasskeySigninWebauthnSignature, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyPasskeySigninWebauthnSignature)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionStartEmailCodeSignin {
		emailAddress, err := values.GetString("email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailCodeSigninToken, errorCode := server.startEmailCodeSigninAction(requestId, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartEmailCodeSignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartEmailCodeSignin)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_code_signin_token", emailCodeSigninToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailCodeSignin {
		emailCodeSigninToken, err := values.GetString("email_code_signin_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailCodeSigninAction(requestId, emailCodeSigninToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelEmailCodeSignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelEmailCodeSignin)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailCodeSigninEmailCode {
		emailCodeSigninToken, err := values.GetString("email_code_signin_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailCode, err := values.GetString("email_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		sessionToken, errorCode := server.verifyEmailCodeSigninEmailCodeAction(requestId, emailCodeSigninToken, emailCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyEmailCodeSigninEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyEmailCodeSigninEmailCode)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("session_token", sessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSignOut {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSignOut, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSignOut)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSignOutAllDevices {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAllDevices(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSignOutAllDevices, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSignOutAllDevices)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionCancelIdentityVerification {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationToken, err := values.GetString("identity_verification_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		cancelledAction, errorCode := server.cancelIdentityVerificationAction(requestId, sessionToken, identityVerificationToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionCancelIdentityVerification, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionCancelIdentityVerification)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("cancelled_action", cancelledAction)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionVerifyIdentityVerificationPasskeyWebauthnSignature {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationToken, err := values.GetString("identity_verification_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnCredentialId, err := values.GetString("webauthn_credential_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnCredentialId, err := base64.StdEncoding.DecodeString(encodedWebauthnCredentialId)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnAuthenticatorData, err := values.GetString("webauthn_authenticator_data")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnAuthenticatorData, err := base64.StdEncoding.DecodeString(encodedWebauthnAuthenticatorData)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnClientDataJSON, err := values.GetString("webauthn_client_data_json")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnClientDataJSON, err := base64.StdEncoding.DecodeString(encodedWebauthnClientDataJSON)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnSignature, err := values.GetString("webauthn_signature")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnSignature, err := base64.StdEncoding.DecodeString(encodedWebauthnSignature)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verifiedActon, errorCode := server.verifyIdentityVerificationPasskeyWebauthnSignatureAction(
			requestId,
			sessionToken,
			identityVerificationToken,
			webauthnCredentialId,
			webauthnAuthenticatorData,
			webauthnClientDataJSON,
			webauthnSignature,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyIdentityVerificationPasskeyWebauthnSignature)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("verified_action", verifiedActon)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionIssueIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationToken, err := values.GetString("identity_verification_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.issueIdentityVerificationEmailCodeAction(requestId, sessionToken, identityVerificationToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionIssueIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionIssueIdentityVerificationEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionRevokeIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationToken, err := values.GetString("identity_verification_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.revokeIdentityVerificationEmailCodeAction(
			requestId,
			sessionToken,
			identityVerificationToken,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionRevokeIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionRevokeIdentityVerificationEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationToken, err := values.GetString("identity_verification_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailCode, err := values.GetString("email_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verifiedAction, errorCode := server.verifyIdentityVerificationEmailCodeAction(
			requestId,
			sessionToken,
			identityVerificationToken,
			emailCode,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyIdentityVerificationEmailCode)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("verified_action", verifiedAction)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionStartEmailAddressUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, identityVerificationToken, errorCode := server.startEmailAddressUpdateAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartEmailAddressUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
		resultValuesJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailAddressUpdate {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailAddressUpdateAction(requestId, sessionToken, emailAddressUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartEmailAddressUpdate)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetEmailAddressUpdateNewEmailAddress {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newEmailAddress, err := values.GetString("new_email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setEmailAddressUpdateNewEmailAddressAction(requestId, sessionToken, emailAddressUpdateToken, newEmailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetEmailAddressUpdateNewEmailAddress, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetEmailAddressUpdateNewEmailAddress)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, sessionToken, emailAddressUpdateToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSendEmailAddressUpdateNewEmailAddressVerificationCode)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateToken, err := values.GetString("email_address_update_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, sessionToken, emailAddressUpdateToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasskeyRegistration {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationToken, identityVerificationToken, errorCode := server.startPasskeyRegistrationAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeyRegistration)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_registration_token", passkeyRegistrationToken)
		resultValuesJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeyRegistration {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationToken, err := values.GetString("passkey_registration_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasskeyRegistrationAction(requestId, sessionToken, passkeyRegistrationToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeyRegistration)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasskeyRegistrationPasskeyWebauthnCredential {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationToken, err := values.GetString("passkey_registration_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		signatureAlgorithm, err := values.GetString("signature_algorithm")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedPublicKey, err := values.GetString("public_key")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		publicKey, err := base64.StdEncoding.DecodeString(encodedPublicKey)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnCredentialId, err := values.GetString("webauthn_credential_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnCredentialId, err := base64.StdEncoding.DecodeString(encodedWebauthnCredentialId)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		encodedWebauthnAuthenticatorId, err := values.GetString("webauthn_authenticator_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnAuthenticatorId, err := base64.StdEncoding.DecodeString(encodedWebauthnAuthenticatorId)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setPasskeyRegistrationPasskeyWebauthnCredentialAction(
			requestId,
			sessionToken,
			passkeyRegistrationToken,
			webauthnCredentialId,
			signatureAlgorithm,
			publicKey,
			webauthnAuthenticatorId,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetPasskeyRegistrationPasskeyWebauthnCredential)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasskeyRegistrationPasskeyName {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationToken, err := values.GetString("passkey_registration_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyNameParam, err := values.GetString("passkey_name")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setPasskeyRegistrationPasskeyNameAction(requestId, sessionToken, passkeyRegistrationToken, passkeyNameParam)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionSetPasskeyRegistrationPasskeyName, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionSetPasskeyRegistrationPasskeyName)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasskeyDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyId, err := values.GetString("passkey_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionToken, identityVerificationToken, errorCode := server.startPasskeyDeletionAction(requestId, sessionToken, passkeyId)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeyDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_deletion_token", passkeyDeletionToken)
		resultValuesJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeyDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionToken, err := values.GetString("passkey_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasskeyDeletionAction(requestId, sessionToken, passkeyDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartPasskeyDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmPasskeyDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionToken, err := values.GetString("passkey_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmPasskeyDeletionAction(requestId, sessionToken, passkeyDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionConfirmPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionConfirmPasskeyDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, identityVerificationToken, errorCode := server.startAccountDeletionAction(requestId, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartAccountDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
		resultValuesJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, err := values.GetString("account_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelAccountDeletionAction(requestId, sessionToken, accountDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionStartAccountDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmAccountDeletion {
		sessionToken, err := values.GetString("session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionToken, err := values.GetString("account_deletion_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmAccountDeletionAction(requestId, sessionToken, accountDeletionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, actionConfirmAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, actionConfirmAccountDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	w.WriteHeader(400)
}

func writeActionErrorResult(w http.ResponseWriter, requestId string, errorCode string) {
	bodyJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
	bodyJSONBuilder.AddBool("ok", false)
	bodyJSONBuilder.AddString("request_id", requestId)
	bodyJSONBuilder.AddString("error_code", errorCode)
	bodyJSON := bodyJSONBuilder.Done()
	bodyJSONBytes := []byte(bodyJSON)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(bodyJSONBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	w.WriteHeader(200)

	w.Write(bodyJSONBytes)
}

func writeActionSuccessResult(w http.ResponseWriter, requestId string, valuesJSON string) {
	bodyJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
	bodyJSONBuilder.AddBool("ok", true)
	bodyJSONBuilder.AddString("request_id", requestId)
	bodyJSONBuilder.AddJSON("values", valuesJSON)
	bodyJSON := bodyJSONBuilder.Done()
	bodyJSONBytes := []byte(bodyJSON)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(bodyJSONBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	w.WriteHeader(200)

	w.Write(bodyJSONBytes)
}

func (server *serverStruct) homePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createHomePageHTML(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) accountPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeys, err := server.getUserPasskeys(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createAccountPageHTML(requestId, sessionToken, user, passkeys)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createSignUpPageHTML(requestId)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpVerifyEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupToken, err := server.validateRequestSignupToken(r)
	if errors.Is(err, errInvalidSignupToken) {
		server.setBlankSignupTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/register-passkey")
		w.WriteHeader(303)
		return
	}

	pageHTML := createSignUpVerifyEmailAddressPageHTML(requestId, signupToken, signup)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpRegisterPasskeyPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupToken, err := server.validateRequestSignupToken(r)
	if errors.Is(err, errInvalidSignupToken) {
		server.setBlankSignupTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	if signup.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/sign-up/register-passkey/set-passkey-name")
		w.WriteHeader(303)
		return
	}

	pageHTML := createSignUpRegisterPasskeyPage(requestId, signupToken, signup)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signUpRegisterPasskeySetPasskeyNamePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signup, signupToken, err := server.validateRequestSignupToken(r)
	if errors.Is(err, errInvalidSignupToken) {
		server.setBlankSignupTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signup.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	if !signup.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/sign-up/register-passkey")
		w.WriteHeader(303)
		return
	}

	passkeyNameSuggestion := ""
	if authenticatorName, ok := server.getWebauthnAuthenticatorName(signup.passkeyWebauthnAuthenticatorId); ok {
		passkeyNameSuggestion = authenticatorName
	}

	pageHTML := createSignUpRegisterPasskeySetPasskeyNamePage(requestId, signupToken, passkeyNameSuggestion)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signInPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeySignin, err := server.createPasskeySignin()
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey signin: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createSignInPage(requestId, passkeySignin)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) signInVerifyEmailCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	_, _, err := server.validateRequestSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailCodeSignin, emailCodeSigninToken, err := server.validateRequestEmailCodeSigninToken(r)
	if errors.Is(err, errInvalidEmailCodeSigninToken) {
		server.setBlankEmailCodeSigninToken(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email code signin token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createSignInVerifyEmailCodePage(requestId, emailCodeSigninToken, emailCodeSignin.emailAddress)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) verifyIdentityPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	identityVerification, identityVerificationToken, err := server.validateRequestIdentityVerificationToken(r)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		server.setBlankIdentityVerificationTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request identity verification token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if identityVerification.sessionId != session.id {
		server.setBlankIdentityVerificationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	passkeys, err := server.getUserPasskeys(session.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createVerifyIdentityPageHTML(requestId, sessionToken, identityVerificationToken, identityVerification, passkeys)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) verifyIdentityVerifyEmailCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	identityVerification, identityVerificationToken, err := server.validateRequestIdentityVerificationToken(r)
	if errors.Is(err, errInvalidIdentityVerificationToken) {
		server.setBlankIdentityVerificationTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request identity verification token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if identityVerification.sessionId != session.id {
		server.setBlankIdentityVerificationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !identityVerification.emailAddressDefined {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	pageHTML := createVerifyIdentityVerifyEmailCodePageHTML(requestId, sessionToken, identityVerificationToken, identityVerification.emailAddress)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updateEmailAddressSetNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdate, emailAddressUpdateToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdate.sessionId != session.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdate.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if emailAddressUpdate.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/verify-new-email-address")
		w.WriteHeader(303)
		return
	}

	pageHTML := createUpdateEmailAddressSetNewEmailAddressPageHTML(requestId, sessionToken, emailAddressUpdateToken)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) updateEmailAddressVerifyNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdate, emailAddressUpdateToken, err := server.validateRequestEmailAddressUpdateToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateToken) {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdate.sessionId != session.id {
		server.setBlankEmailAddressUpdateTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdate.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdate.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdate.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logActionError(requestId, errorMessage)

		server.setBlankEmailAddressUpdateTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createUpdateEmailAddressVerifyNewEmailAddressPageHTML(requestId, sessionToken, emailAddressUpdateToken, emailAddressUpdate.newEmailAddress)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) registerPasskeyCreatePasskeyPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyRegistration, passkeyRegistrationToken, err := server.validateRequestPasskeyRegistrationToken(r)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey registration token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyRegistration.sessionId != session.id {
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistration.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if passkeyRegistration.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/register-passkey/set-passkey-name")
		w.WriteHeader(303)
		return
	}
	if passkeyRegistration.passkeySignatureAlgorithmDefined || passkeyRegistration.passkeyPublicKeyDefined || passkeyRegistration.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "passkey registration webauthn credential partially set"
		server.logActionError(requestId, errorMessage)

		server.setBlankPasskeyRegistrationTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(session.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankSessionTokenCookie(w)
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeys, err := server.getUserPasskeys(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createRegisterPasskeyCreatePasskeyPageHTML(requestId, sessionToken, passkeyRegistrationToken, user, passkeys)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) registerPasskeySetPasskeyNamePageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyRegistration, passkeyRegistrationToken, err := server.validateRequestPasskeyRegistrationToken(r)
	if errors.Is(err, errInvalidPasskeyRegistrationToken) {
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey registration token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyRegistration.sessionId != session.id {
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistration.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if !passkeyRegistration.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/register-passkey/create-passkey")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistration.passkeySignatureAlgorithmDefined || !passkeyRegistration.passkeyPublicKeyDefined || !passkeyRegistration.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "passkey registration webauthn credential partially not set"
		server.logActionError(requestId, errorMessage)

		server.setBlankPasskeyRegistrationTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyNameSuggestion := ""
	if authenticatorName, ok := server.getWebauthnAuthenticatorName(passkeyRegistration.passkeyWebauthnAuthenticatorId); ok {
		passkeyNameSuggestion = authenticatorName
	}

	pageHTML := createRegisterPasskeySetPasskeyNamePageHTML(requestId, sessionToken, passkeyRegistrationToken, passkeyNameSuggestion)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) deletePasskeyConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyDeletion, passkeyDeletionToken, err := server.validateRequestPasskeyDeletionToken(r)
	if errors.Is(err, errInvalidPasskeyDeletionToken) {
		server.setBlankPasskeyDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey deletion token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyDeletion.sessionId != session.id {
		server.setBlankPasskeyDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyDeletion.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	passkey, err := server.getPasskey(passkeyDeletion.passkeyId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankPasskeyRegistrationTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageHTML := createDeletePasskeyConfirmPageHTML(requestId, sessionToken, passkeyDeletionToken, passkey.name)

	writePageHTMLResponse(w, 200, pageHTML)
}

func (server *serverStruct) deleteAccountConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string) {
	session, sessionToken, err := server.validateRequestSessionToken(r)
	if errors.Is(err, errInvalidSessionToken) {
		server.setBlankSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request session token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletion, accountDeletionToken, err := server.validateRequestAccountDeletionToken(r)
	if errors.Is(err, errInvalidAccountDeletionToken) {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion token: %s", err.Error())
		server.logActionError(requestId, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletion.sessionId != session.id {
		server.setBlankAccountDeletionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !accountDeletion.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	pageHTML := createDeleteAccountConfirmPageHTML(requestId, sessionToken, accountDeletionToken)

	writePageHTMLResponse(w, 200, pageHTML)
}

func writePageHTMLResponse(w http.ResponseWriter, statusCode int, pageHTML string) {
	pageHTMLBytes := []byte(pageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(pageHTMLBytes)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(statusCode)
	w.Write(pageHTMLBytes)
}
