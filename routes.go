package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/pilcrowonpaper/go-json"

	_ "embed"
)

const (
	routeHomePage                                    = "home_page"
	routeAccountPage                                 = "account_page"
	routeSignUpPage                                  = "sign_up_page"
	routeSignUpVerifyEmailAddressPage                = "sign_up_verify_email_address_page"
	routeSignUpRegisterPasskeyPage                   = "sign_up_register_passkey_page"
	routeSignUpRegisterPasskeySetPasskeyNamePage     = "sign_up_register_passkey_set_passkey_name_page"
	routeSignInPage                                  = "sign_in_page"
	routeSignInVerifyEmailCodePage                   = "sign_in_verify_email_code_page"
	routeVerifyIdentityPage                          = "verify_identity_page"
	routeVerifyIdentityVerifyEmailCodePage           = "verify_identity_verify_email_code_page"
	routeUpdateEmailAddressSetNewEmailAddressPage    = "update_email_address_set_new_email_address_page"
	routeUpdateEmailAddressVerifyNewEmailAddressPage = "update_email_address_verify_new_email_address_page"
	routeDeleteAccountConfirmPage                    = "delete_account_confirm_page"
	routeRegisterPasskeyCreatePasskeyPage            = "register_passkey_create_passkey_page"
	routeRegisterPasskeySetPasskeyNamePage           = "register_passkey_set_passkey_name_page"
	routeDeletePasskeyConfirmPage                    = "delete_passkey_confirm_page"
)

func (server *serverStruct) actionRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	if secFetchSite != "same-origin" {
		w.WriteHeader(403)
		return
	}

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
		signupSessionToken, errorCode := server.startSignupAction(requestId, clientIPAddress, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartSignup)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("signup_session_token", signupSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelSignup {
		signupSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelSignupAction(requestId, clientIPAddress, signupSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelSignup, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelSignup)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendSignupEmailAddressVerificationCode {
		signupSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendSignupEmailAddressVerificationCodeAction(requestId, clientIPAddress, signupSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendSignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifySignupEmailAddressVerificationCode {
		signupSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifySignupEmailAddressVerificationCodeAction(requestId, clientIPAddress, signupSessionToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifySignupEmailAddressVerificationCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionCompleteSignupWithoutPasskeyRegistration {
		signupSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.completeSignupWithoutPasskeyRegistrationAction(requestId, clientIPAddress, signupSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCompleteSignupWithoutPasskeyRegistration)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSetSignupPasskeyWebauthnCredential {
		signupSessionToken, err := values.GetString("signup_session_token")
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

		errorCode := server.setSignupPasskeyWebauthnCredentialAction(
			requestId,
			clientIPAddress,
			signupSessionToken,
			webauthnAuthenticatorData,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetSignupPasskeyWebauthnCredential)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetSignupPasskeyName {
		signupSessionToken, err := values.GetString("signup_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyName, err := values.GetString("passkey_name")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.setSignupPasskeyNameAction(requestId, clientIPAddress, signupSessionToken, passkeyName)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetSignupPasskeyName, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetSignupPasskeyName)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionStartPasskeySignin {
		passkeySigninAttemptId, challenge, errorCode := server.startPasskeySigninAction(requestId, clientIPAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeySignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeySignin)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_signin_attempt_id", passkeySigninAttemptId)
		resultValuesJSONBuilder.AddString("webauthn_challenge", base64.StdEncoding.EncodeToString(challenge))
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeySignin {
		passkeySigninAttemptId, err := values.GetString("passkey_signin_attempt_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}

		errorCode := server.cancelPasskeySigninAction(requestId, clientIPAddress, passkeySigninAttemptId)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeySignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeySignin)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyPasskeySigninWebauthnSignature {
		passkeySigninAttemptId, err := values.GetString("passkey_signin_attempt_id")
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
		authSessionToken, errorCode := server.verifyPasskeySigninWebauthnSignatureAction(
			requestId,
			clientIPAddress,
			passkeySigninAttemptId,
			webauthnCredentialId,
			webauthnAuthenticatorData,
			webauthnClientDataJSON,
			webauthnSignature,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyPasskeySigninWebauthnSignature)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
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
		emailCodeSigninSessionToken, errorCode := server.startEmailCodeSigninAction(requestId, clientIPAddress, emailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartEmailCodeSignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartEmailCodeSignin)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_code_signin_session_token", emailCodeSigninSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailCodeSignin {
		emailCodeSigninSessionToken, err := values.GetString("email_code_signin_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailCodeSigninAction(requestId, clientIPAddress, emailCodeSigninSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelEmailCodeSignin, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelEmailCodeSignin)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendEmailCodeSigninEmailCode {
		emailCodeSigninSessionToken, err := values.GetString("email_code_signin_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendEmailCodeSigninEmailCodeAction(requestId, clientIPAddress, emailCodeSigninSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendEmailCodeSigninEmailCode)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailCodeSigninEmailCode {
		emailCodeSigninSessionToken, err := values.GetString("email_code_signin_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailCode, err := values.GetString("email_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authSessionToken, errorCode := server.verifyEmailCodeSigninEmailCodeAction(requestId, clientIPAddress, emailCodeSigninSessionToken, emailCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyEmailCodeSigninEmailCode)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("auth_session_token", authSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionSignOut {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSignOut, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSignOut)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSignOutAllDevices {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.signOutAllDevicesAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSignOutAllDevices, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSignOutAllDevices)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionGetWebauthnCredentialIds {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		webauthnCredentialIds, errorCode := server.getWebauthnCredentialIdsAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionGetWebauthnCredentialIds, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionGetWebauthnCredentialIds)

		webauthnCredentialIdsJSONBuilder := json.NewArrayBuilder(json.MinimalStringCharacterEscapingBehavior)
		for _, webauthnCredentialId := range webauthnCredentialIds {
			encodedWebauthnCredentialId := base64.StdEncoding.EncodeToString(webauthnCredentialId)
			webauthnCredentialIdsJSONBuilder.AddString(encodedWebauthnCredentialId)
		}
		webauthnCredentialIdsJSON := webauthnCredentialIdsJSONBuilder.Done()

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddJSON("webauthn_credential_ids", webauthnCredentialIdsJSON)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelIdentityVerification {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		cancelledAction, errorCode := server.cancelIdentityVerificationAction(requestId, clientIPAddress, sessionToken, identityVerificationSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionCancelIdentityVerification, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionCancelIdentityVerification)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("cancelled_action", cancelledAction)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionVerifyIdentityVerificationPasskeyWebauthnSignature {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
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
			clientIPAddress,
			sessionToken,
			identityVerificationSessionToken,
			webauthnCredentialId,
			webauthnAuthenticatorData,
			webauthnClientDataJSON,
			webauthnSignature,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyIdentityVerificationPasskeyWebauthnSignature)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("verified_action", verifiedActon)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionIssueIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.issueIdentityVerificationEmailCodeAction(requestId, clientIPAddress, sessionToken, identityVerificationSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionIssueIdentityVerificationEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionRevokeIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.revokeIdentityVerificationEmailCodeAction(
			requestId,
			clientIPAddress,
			sessionToken,
			identityVerificationSessionToken,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionRevokeIdentityVerificationEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendIdentityVerificationEmailCodeAction(
			requestId,
			clientIPAddress,
			sessionToken,
			identityVerificationSessionToken,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendIdentityVerificationEmailCode)

		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyIdentityVerificationEmailCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		identityVerificationSessionToken, err := values.GetString("identity_verification_session_token")
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
			clientIPAddress,
			sessionToken,
			identityVerificationSessionToken,
			emailCode,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyIdentityVerificationEmailCode)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("verified_action", verifiedAction)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionStartEmailAddressUpdate {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, identityVerificationSessionToken, errorCode := server.startEmailAddressUpdateAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartEmailAddressUpdate)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
		resultValuesJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelEmailAddressUpdate {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelEmailAddressUpdateAction(requestId, clientIPAddress, sessionToken, emailAddressUpdateSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartEmailAddressUpdate, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartEmailAddressUpdate)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetEmailAddressUpdateNewEmailAddress {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		newEmailAddress, err := values.GetString("new_email_address")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setEmailAddressUpdateNewEmailAddressAction(requestId, clientIPAddress, sessionToken, emailAddressUpdateSessionToken, newEmailAddress)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetEmailAddressUpdateNewEmailAddress)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSendEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.sendEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, clientIPAddress, sessionToken, emailAddressUpdateSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSendEmailAddressUpdateNewEmailAddressVerificationCode)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		emailAddressUpdateSessionToken, err := values.GetString("email_address_update_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		verificationCode, err := values.GetString("verification_code")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.verifyEmailAddressUpdateNewEmailAddressVerificationCodeAction(requestId, clientIPAddress, sessionToken, emailAddressUpdateSessionToken, verificationCode)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionVerifyEmailAddressUpdateNewEmailAddressVerificationCode)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasskeyRegistration {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationSessionToken, identityVerificationSessionToken, errorCode := server.startPasskeyRegistrationAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeyRegistration)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_registration_session_token", passkeyRegistrationSessionToken)
		resultValuesJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeyRegistration {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationSessionToken, err := values.GetString("passkey_registration_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasskeyRegistrationAction(requestId, clientIPAddress, sessionToken, passkeyRegistrationSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeyRegistration, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeyRegistration)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasskeyRegistrationPasskeyWebauthnCredential {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationSessionToken, err := values.GetString("passkey_registration_session_token")
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
		errorCode := server.setPasskeyRegistrationPasskeyWebauthnCredentialAction(
			requestId,
			clientIPAddress,
			sessionToken,
			passkeyRegistrationSessionToken,
			webauthnAuthenticatorData,
		)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyWebauthnCredential)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionSetPasskeyRegistrationPasskeyName {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyRegistrationSessionToken, err := values.GetString("passkey_registration_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyNameParam, err := values.GetString("passkey_name")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.setPasskeyRegistrationPasskeyNameAction(requestId, clientIPAddress, sessionToken, passkeyRegistrationSessionToken, passkeyNameParam)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionSetPasskeyRegistrationPasskeyName)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartPasskeyDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyId, err := values.GetString("passkey_id")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionSessionToken, identityVerificationSessionToken, errorCode := server.startPasskeyDeletionAction(requestId, clientIPAddress, sessionToken, passkeyId)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeyDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("passkey_deletion_session_token", passkeyDeletionSessionToken)
		resultValuesJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelPasskeyDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionSessionToken, err := values.GetString("passkey_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelPasskeyDeletionAction(requestId, clientIPAddress, sessionToken, passkeyDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartPasskeyDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmPasskeyDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		passkeyDeletionSessionToken, err := values.GetString("passkey_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmPasskeyDeletionAction(requestId, clientIPAddress, sessionToken, passkeyDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionConfirmPasskeyDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionConfirmPasskeyDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionStartAccountDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, identityVerificationSessionToken, errorCode := server.startAccountDeletionAction(requestId, clientIPAddress, sessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartAccountDeletion)

		resultValuesJSONBuilder := json.NewObjectBuilder(json.MinimalStringCharacterEscapingBehavior)
		resultValuesJSONBuilder.AddString("account_deletion_session_token", accountDeletionSessionToken)
		resultValuesJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
		resultValuesJSON := resultValuesJSONBuilder.Done()
		writeActionSuccessResult(w, requestId, resultValuesJSON)
		return
	}

	if actionName == actionCancelAccountDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, err := values.GetString("account_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.cancelAccountDeletionAction(requestId, clientIPAddress, sessionToken, accountDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionStartAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionStartAccountDeletion)
		writeActionSuccessResult(w, requestId, "{}")
		return
	}

	if actionName == actionConfirmAccountDeletion {
		sessionToken, err := values.GetString("auth_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		accountDeletionSessionToken, err := values.GetString("account_deletion_session_token")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		errorCode := server.confirmAccountDeletionAction(requestId, clientIPAddress, sessionToken, accountDeletionSessionToken)
		if errorCode != "" {
			server.logActionErrorResult(requestId, clientIPAddress, actionConfirmAccountDeletion, errorCode)
			writeActionErrorResult(w, requestId, errorCode)
			return
		}
		server.logActionSuccessResult(requestId, clientIPAddress, actionConfirmAccountDeletion)
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

//go:embed frontend_assets/home.css
var homePageStylesheet string

func (server *serverStruct) homePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeHomePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Passwordless auth example"
	bodyHTML := `<h1>Passwordless auth example</h1>
<p>This an example website that implements email code sign-in and passkeys following best practices. All accounts older than 24 hours are automatically deleted at midnight (UTC).</p>
<div id="auth">
	<a href="/sign-in" class="block-button">Sign in</a>
	<a href="/sign-up" class="block-button">Create an account</a>
</div>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, "", homePageStylesheet, "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/account.js
var accountPageScript string

//go:embed frontend_assets/account.css
var accountPageStylesheet string

func (server *serverStruct) accountPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeAccountPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeAccountPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeys, err := server.getUserPasskeys(user.id)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeAccountPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyListHTML := ""
	if len(passkeys) > 0 {
		passkeyListHTMLBuilder := strings.Builder{}
		passkeyListHTMLBuilder.WriteString(`<ul id="passkeys-list">`)
		for _, passkey := range passkeys {
			listItemHTML := fmt.Sprintf(`<li><p>%s</p><button class="delete-passkey-button link-button" data-passkey-id="%s">Delete</button></li>`, html.EscapeString(passkey.name), html.EscapeString(passkey.id))
			passkeyListHTMLBuilder.WriteString(listItemHTML)
		}
		passkeyListHTMLBuilder.WriteString("</ul>")

		passkeyListHTML = passkeyListHTMLBuilder.String()
	}

	registerPasskeyButtonHTML := ""
	if len(passkeys) < maxPasskeyCountLimit {
		registerPasskeyButtonHTML = `<button id="register-passkey-button" class="block-button">Register passkey</button>`
	}

	pageTitle := "My account | Passwordless auth example"
	bodyHTMLTemplate := `<h1>My account</h1>
<section>
	<h2>Account information</h2>
	<p id="account-info-user-id">User ID: %s</p>
	<p id="account-info-email-address">Email address: %s</p>
	<button id="update-email-address-button" class="block-button">Update email address</button>
</section>
<section>
	<h2>Passkeys</h2>
	<p id="passkeys-description">Passkeys are secure login credentials stored on your device, password manager, or security key that allow you to sign in using your device PIN or biometrics.</p>
	%s
	%s
</section>
<section>
	<h2>Sign out</h2>
	<div id="sign-out-controls">
		<button id="sign-out-button" class="block-button">Sign out</button>
		<button id="sign-out-all-devices-button" class="link-button">Sign out of all devices</button>
	</div>
</section>
<section>
	<h2>Delete your account</h2>
	<p id="delete-account-description">Deleting your account will permanently remove all your data. Some logs (including your IP address and email address) may be retained for up to 90 days.</p>
	<button id="delete-account-button" class="block-button">Delete account</button>
</section>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.id), html.EscapeString(user.emailAddress), passkeyListHTML, registerPasskeyButtonHTML)

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, accountPageScript, accountPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_up.js
var signUpPageScript string

//go:embed frontend_assets/sign_up.css
var signUpPageStylesheet string

func (server *serverStruct) signUpPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}
	pageTitle := "Create an account | Passwordless auth example"
	bodyHTML := `<h1>Create an account</h1>
<p>All accounts older than 24 hours are permanently deleted at midnight UTC each day.
For security purposes, logs (which may include your IP address and email address) are retained for up to 90 days.
These logs are processed and stored by <a href="https://cloudflare.com">Cloudflare</a> and <a href="https://railway.com">Railway</a>.
We do not share or sell this data to any third parties.</p>
<p>The email address must be lowercase and no more than 100 characters long.</p>
<form id="sign-up-form">
	<label for="sign-up-form-email-address-input">Email address</label>
	<input id="sign-up-form-email-address-input" name="email_address" type="email" required maxlength="100" />
	<button id="sign-up-form-submit-button">Continue</button>
</form>
<a id="sign-in-link" href="/sign-in" class="link-button">Sign in with an existing account</a>`

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpPageScript, signUpPageStylesheet, "")

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_up_verify_email_address.js
var signUpVerifyEmailAddressPageScript string

//go:embed frontend_assets/sign_up_verify_email_address.css
var signUpVerifyEmailAddressPageStylesheet string

func (server *serverStruct) signUpVerifyEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpVerifyEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signupSession, signupSessionToken, err := server.validateRequestSignupSessionToken(r)
	if errors.Is(err, errInvalidSignupSessionToken) {
		server.setBlankSignupSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpVerifyEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if signupSession.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/register-passkey")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Verify your email address | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Verify your email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" autocomplete="one-time-code" required />
	<button id="verify-verification-code-form-submit-button">Verify email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signupSession.emailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("signup_session_token", signupSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpVerifyEmailAddressPageScript, signUpVerifyEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_up_register_passkey.js
var signUpRegisterPasskeyScript string

//go:embed frontend_assets/sign_up_register_passkey.css
var signUpRegisterPasskeyStylesheet string

func (server *serverStruct) signUpRegisterPasskeyPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpRegisterPasskeyPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signupSession, signupSessionToken, err := server.validateRequestSignupSessionToken(r)
	if errors.Is(err, errInvalidSignupSessionToken) {
		server.setBlankSignupSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpRegisterPasskeyPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signupSession.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	if signupSession.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/sign-up/register-passkey/set-passkey-name")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Register a passkey | Passwordless auth example"

	bodyHTML := `<h1>Register a passkey</h1>
<p>Passkeys are secure login credentials stored on your device, password manager, or security key that allow you to sign in using your device PIN or biometrics.</p>
<div id="controls">
	<button id="create-passkey-button" class="block-button">Create a passkey</button>
	<button id="skip-button" class="link-button">Skip</button>
</div>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("signup_session_token", signupSessionToken)
	pageDataJSONBuilder.AddString("signup_target_user_id", signupSession.targetUserId)
	pageDataJSONBuilder.AddString("signup_email_address", signupSession.emailAddress)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpRegisterPasskeyScript, signUpRegisterPasskeyStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_up_register_passkey_set_passkey_name.js
var signUpRegisterPasskeySetPasskeyNameScript string

func (server *serverStruct) signUpRegisterPasskeySetPasskeyNamePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpRegisterPasskeySetPasskeyNamePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	signupSession, signupSessionToken, err := server.validateRequestSignupSessionToken(r)
	if errors.Is(err, errInvalidSignupSessionToken) {
		server.setBlankSignupSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-up")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request signup session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignUpRegisterPasskeySetPasskeyNamePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if !signupSession.emailAddressVerified {
		w.Header().Set("Location", "/sign-up/verify-email-address")
		w.WriteHeader(303)
		return
	}

	if !signupSession.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/sign-up/register-passkey")
		w.WriteHeader(303)
		return
	}

	passkeyNameSuggestion := ""
	if authenticatorName, ok := server.getWebauthnAuthenticatorName(signupSession.passkeyWebauthnAuthenticatorId); ok {
		passkeyNameSuggestion = authenticatorName
	}

	pageTitle := "Name your passkey | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Name your passkey</h1>
<p>Give your passkey a name so you can easily recognize and manage it later. The name must contain only standard characters (excluding double quotes) and must be 50 characters or fewer.</p>
<form id="set-passkey-name-form">
	<label for="set-passkey-name-form-name-input">Passkey name</label>
	<input id="set-passkey-name-form-name-input" name="passkey_name" required value="%s" />
	<button id="set-passkey-name-form-submit-button">Complete</button>
</form>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(passkeyNameSuggestion))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("signup_session_token", signupSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signUpRegisterPasskeySetPasskeyNameScript, "", pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_in.js
var signInPageScript string

//go:embed frontend_assets/sign_in.css
var signInPageStylesheet string

func (server *serverStruct) signInPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeySigninAttempt, err := server.createPasskeySigninAttempt()
	if err != nil {
		errorMessage := fmt.Sprintf("failed to create passkey signin: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Sign in | Passwordless auth example"

	bodyHTML := `<h1>Sign in</h1>
<form id="sign-in-with-email-code-form">
	<label for="sign-in-with-email-code-form-email-address-input">Email address (lowercase)</label>
	<input id="sign-in-with-email-code-form-email-address-input" name="email_address" type="email" autocomplete="webauthn" required maxlength="100" />
	<button id="sign-in-with-email-code-form-submit-button">Continue</button>
</form>
<button id="sign-in-with-passkey-button" class="link-button">Sign in with passkeys</button>
<div id="links">
	<a id="create-account-link" href="/sign-up" class="link-button">Create a new account</a>
</div>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("passkey_signin_attempt_id", passkeySigninAttempt.id)
	pageDataJSONBuilder.AddString("passkey_signin_webauthn_challenge", base64.StdEncoding.EncodeToString(passkeySigninAttempt.challenge))
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signInPageScript, signInPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/sign_in_verify_email_code.js
var signInVerifyEmailCodePageScript string

//go:embed frontend_assets/sign_in_verify_email_code.css
var signInVerifyEmailCodePageStylesheet string

func (server *serverStruct) signInVerifyEmailCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	_, _, err := server.validateRequestAuthSessionToken(r)
	if err == nil {
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !errors.Is(err, errInvalidAuthSessionToken) {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailCodeSigninSession, emailCodeSigninSessionToken, err := server.validateRequestEmailCodeSigninSessionToken(r)
	if errors.Is(err, errInvalidEmailCodeSigninSessionToken) {
		server.setBlankEmailCodeSigninSessionToken(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email code signin session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	userEmailAddress, err := server.getEmailCodeSigninSessionUserEmailAddress(emailCodeSigninSession.id)
	if errors.Is(err, errItemNotFound) {
		server.setBlankEmailCodeSigninSessionToken(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get email code signin session user email address: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeSignInVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Sign in with email code | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Sign in with email code</h1>
<p>We sent a one-time code to %s.</p>
<form id="verify-email-code-form">
	<label for="verify-email-code-form-email-code-input">Code</label>
	<input id="verify-email-code-form-email-code-input" name="email_code" autocomplete="one-time-code" required/>
	<button id="verify-email-code-form-submit-button">Continue</button>
</form>
<div id="controls">
	<button id="resend-email-code-button" class="link-button">Resend email code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(userEmailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("email_code_signin_session_token", emailCodeSigninSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, signInVerifyEmailCodePageScript, signInVerifyEmailCodePageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/verify_identity.js
var verifyIdentityPageScript string

//go:embed frontend_assets/verify_identity.css
var verifyIdentityPageStylesheet string

func (server *serverStruct) verifyIdentityPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	identityVerificationSession, identityVerificationSessionToken, err := server.validateRequestIdentityVerificationSessionToken(r)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		server.setBlankIdentityVerificationSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request identity verification session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if identityVerificationSession.authSessionId != authSession.id {
		server.setBlankIdentityVerificationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	passkeyCount, err := server.getUserPasskeyCount(authSession.userId)
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user passkeys: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your identity | Passwordless auth example"

	var controlsHTML string
	if passkeyCount > 0 {
		controlsHTML = `<div id="controls">
	<button id="verify-with-passkey-button" class="block-button">Verify with passkeys</button>
	<button id="verify-with-email-code-button" class="link-button">Verify with email code</button>
</div>`
	} else {
		controlsHTML = `<div id="controls">
	<button id="verify-with-email-code-button" class="block-button">Verify with email code</button>
</div>`
	}

	bodyHTMLTemplate := `<h1>Verify your identity</h1>
<p>Verify your identity to continue.</p>
<div id="controls">%s</div>
<button id="cancel-button" class="link-button">Cancel</button>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, controlsHTML)

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
	pageDataJSONBuilder.AddString("identity_verification_passkey_verification_challenge", base64.StdEncoding.EncodeToString(identityVerificationSession.passkeyVerificationChallenge))
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, verifyIdentityPageScript, verifyIdentityPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/verify_identity_verify_email_code.js
var verifyIdentityVerifyEmailCodePageScript string

//go:embed frontend_assets/verify_identity_verify_email_code.css
var verifyIdentityVerifyEmailCodePageStylesheet string

func (server *serverStruct) verifyIdentityVerifyEmailCodePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	identityVerificationSession, identityVerificationSessionToken, err := server.validateRequestIdentityVerificationSessionToken(r)
	if errors.Is(err, errInvalidIdentityVerificationSessionToken) {
		server.setBlankIdentityVerificationSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request identity verification session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if identityVerificationSession.authSessionId != authSession.id {
		server.setBlankIdentityVerificationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}

	if !identityVerificationSession.emailCodeDefined {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	userEmailAddress, err := server.getIdentityVerificationSessionUserEmailAddress(identityVerificationSession.id)
	if errors.Is(err, errItemNotFound) {
		server.setBlankIdentityVerificationSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get identity verification session user email address: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeVerifyIdentityVerifyEmailCodePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify identity with email code | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Verify identity with email code</h1>
<p>We sent a one-time code to %s.</p>
<form id="verify-email-code-form">
	<label for="verify-email-code-form-email-code-input">Code</label>
	<input id="verify-email-code-form-email-code-input" name="email_code" autocomplete="one-time-code" required/>
	<button id="verify-email-code-form-submit-button">Continue</button>
</form>
<div id="controls">
	<button id="resend-email-code-button" class="link-button">Resend email code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(userEmailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("identity_verification_session_token", identityVerificationSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, verifyIdentityVerifyEmailCodePageScript, verifyIdentityVerifyEmailCodePageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/update_email_address_set_new_email_address.js
var updateEmailAddressSetNewEmailAddressPageScript string

//go:embed frontend_assets/update_email_address_set_new_email_address.css
var updateEmailAddressSetNewEmailAddressPageStylesheet string

func (server *serverStruct) updateEmailAddressSetNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressSetNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdateSession, emailAddressUpdateSessionToken, err := server.validateRequestEmailAddressUpdateSessionToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		server.setBlankEmailAddressUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressSetNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		server.setBlankEmailAddressUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdateSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if emailAddressUpdateSession.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address/verify-new-email-address")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Set your new email address | Passwordless auth example"

	bodyHTML := `<h1>Set your new email address</h1>
<form id="set-new-email-address-form">
	<label for="set-new-email-address-form-new-email-address-input">New email address</label>
	<input id="set-new-email-address-form-new-email-address-input" name="new_email_address" type="email" required maxlength="100" />
	<button id="set-new-email-address-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updateEmailAddressSetNewEmailAddressPageScript, updateEmailAddressSetNewEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/update_email_address_verify_new_email_address.js
var updateEmailAddressVerifyNewEmailAddressPageScript string

//go:embed frontend_assets/update_email_address_verify_new_email_address.css
var updateEmailAddressVerifyNewEmailAddressPageStylesheet string

func (server *serverStruct) updateEmailAddressVerifyNewEmailAddressPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	emailAddressUpdateSession, emailAddressUpdateSessionToken, err := server.validateRequestEmailAddressUpdateSessionToken(r)
	if errors.Is(err, errInvalidEmailAddressUpdateSessionToken) {
		server.setBlankEmailAddressUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request email address update session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if emailAddressUpdateSession.authSessionId != authSession.id {
		server.setBlankEmailAddressUpdateSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !emailAddressUpdateSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdateSession.newEmailAddressDefined {
		w.Header().Set("Location", "/update-email-address")
		w.WriteHeader(303)
		return
	}

	if !emailAddressUpdateSession.newEmailAddressVerificationCodeDefined {
		errorMessage := "new email address verification code not defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeUpdateEmailAddressVerifyNewEmailAddressPage, errorMessage)

		server.setBlankEmailAddressUpdateSessionTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Verify your new email address | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Verify your new email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" autocomplete="one-time-code" required />
	<button id="verify-verification-code-form-submit-button">Update email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(emailAddressUpdateSession.newEmailAddress))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("email_address_update_session_token", emailAddressUpdateSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, updateEmailAddressVerifyNewEmailAddressPageScript, updateEmailAddressVerifyNewEmailAddressPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/register_passkey_create_passkey.js
var registerPasskeyCreatePasskeyPageScript string

//go:embed frontend_assets/register_passkey_create_passkey.css
var registerPasskeyCreatePasskeyPageStylesheet string

func (server *serverStruct) registerPasskeyCreatePasskeyPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyRegistrationSession, passkeyRegistrationSessionToken, err := server.validateRequestPasskeyRegistrationSessionToken(r)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey registration session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyRegistrationSession.authSessionId != authSession.id {
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistrationSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if passkeyRegistrationSession.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/register-passkey/set-passkey-name")
		w.WriteHeader(303)
		return
	}
	if passkeyRegistrationSession.passkeyCOSEPublicKeyDefined {
		errorMessage := "passkey registration session passkey cose public key defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)

		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}
	if passkeyRegistrationSession.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "passkey registration session passkey webauthn authenticator id defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)

		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	user, err := server.getUser(authSession.userId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankAuthSessionTokenCookie(w)
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get user: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeleteAccountConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Create a passkey | Passwordless auth example"

	bodyHTML := `<h1>Create a passkey</h1>
<p>Create a passkey for your account on your device, security key, or password manager.</p>
<button id="create-passkey-button" class="block-button">Create</button>
<button id="cancel-button" class="link-button">Cancel</button>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("passkey_registration_session_token", passkeyRegistrationSessionToken)
	pageDataJSONBuilder.AddString("user_id", user.id)
	pageDataJSONBuilder.AddString("user_email_address", user.emailAddress)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, registerPasskeyCreatePasskeyPageScript, registerPasskeyCreatePasskeyPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/register_passkey_set_passkey_name.js
var registerPasskeySetPasskeyNamePageScript string

func (server *serverStruct) registerPasskeySetPasskeyNamePageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeyCreatePasskeyPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyRegistrationSession, passkeyRegistrationSessionToken, err := server.validateRequestPasskeyRegistrationSessionToken(r)
	if errors.Is(err, errInvalidPasskeyRegistrationSessionToken) {
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey registration session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeyCreatePasskeyPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyRegistrationSession.authSessionId != authSession.id {
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistrationSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	if !passkeyRegistrationSession.passkeyWebauthnCredentialIdDefined {
		w.Header().Set("Location", "/register-passkey/create-passkey")
		w.WriteHeader(303)
		return
	}
	if !passkeyRegistrationSession.passkeyCOSEPublicKeyDefined {
		errorMessage := "passkey registration session passkey cose public key not defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeyCreatePasskeyPage, errorMessage)

		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}
	if !passkeyRegistrationSession.passkeyWebauthnAuthenticatorIdDefined {
		errorMessage := "passkey registration session passkey webauthn authenticator id not defined"
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeyCreatePasskeyPage, errorMessage)

		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyNameSuggestion := ""
	if authenticatorName, ok := server.getWebauthnAuthenticatorName(passkeyRegistrationSession.passkeyWebauthnAuthenticatorId); ok {
		passkeyNameSuggestion = authenticatorName
	}

	pageTitle := "Name your passkey | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Name your passkey</h1>
<p>Give your passkey a name so you can easily recognize and manage it later. The name must contain only standard characters (excluding double quotes) and must be 50 characters or fewer.</p>
<form id="set-passkey-name-form">
	<label for="set-passkey-name-form-name-input">Passkey name</label>
	<input id="set-passkey-name-form-name-input" name="passkey_name" required value="%s" />
	<button id="set-passkey-name-form-submit-button">Complete</button>
</form>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(passkeyNameSuggestion))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("passkey_registration_session_token", passkeyRegistrationSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, registerPasskeySetPasskeyNamePageScript, "", pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/delete_passkey_confirm.js
var deletePasskeyConfirmPageScript string

//go:embed frontend_assets/delete_passkey_confirm.css
var deletePasskeyConfirmPageStylesheet string

func (server *serverStruct) deletePasskeyConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeySetPasskeyNamePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	passkeyDeletionSession, passkeyDeletionSessionToken, err := server.validateRequestPasskeyDeletionSessionToken(r)
	if errors.Is(err, errInvalidPasskeyDeletionSessionToken) {
		server.setBlankPasskeyDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request passkey deletion session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeySetPasskeyNamePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if passkeyDeletionSession.authSessionId != authSession.id {
		server.setBlankPasskeyDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !passkeyDeletionSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	passkey, err := server.getPasskey(passkeyDeletionSession.passkeyId)
	if errors.Is(err, errItemNotFound) {
		server.setBlankPasskeyRegistrationSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to get passkey: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeRegisterPasskeySetPasskeyNamePage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	pageTitle := "Delete a passkey | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Delete a passkey</h1>
<p>Are you sure you want to delete passkey "%s"? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button" class="block-button">Delete passkey</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(passkey.name))

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("passkey_deletion_session_token", passkeyDeletionSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, deletePasskeyConfirmPageScript, deletePasskeyConfirmPageStylesheet, pageDataJSON)

	writePageHTMLResponse(w, 200, pageHTML)
}

//go:embed frontend_assets/delete_account_confirm.js
var deleteAccountConfirmPageScript string

//go:embed frontend_assets/delete_account_confirm.css
var deleteAccountConfirmPageStylesheet string

func (server *serverStruct) deleteAccountConfirmPageRoute(w http.ResponseWriter, r *http.Request, requestId string, clientIPAddress string) {
	authSession, authSessionToken, err := server.validateRequestAuthSessionToken(r)
	if errors.Is(err, errInvalidAuthSessionToken) {
		server.setBlankAuthSessionTokenCookie(w)
		w.Header().Set("Location", "/sign-in")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request auth session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeletePasskeyConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	accountDeletionSession, accountDeletionSessionToken, err := server.validateRequestAccountDeletionSessionToken(r)
	if errors.Is(err, errInvalidAccountDeletionSessionToken) {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if err != nil {
		errorMessage := fmt.Sprintf("failed to validate request account deletion session token: %s", err.Error())
		server.logRouteInternalError(requestId, clientIPAddress, routeDeletePasskeyConfirmPage, errorMessage)
		pageHTML := createUnexpectedErrorErrorPageHTML(requestId)
		writePageHTMLResponse(w, 500, pageHTML)
		return
	}

	if accountDeletionSession.authSessionId != authSession.id {
		server.setBlankAccountDeletionSessionTokenCookie(w)
		w.Header().Set("Location", "/account")
		w.WriteHeader(303)
		return
	}
	if !accountDeletionSession.identityVerified {
		w.Header().Set("Location", "/verify-identity")
		w.WriteHeader(303)
		return
	}

	pageTitle := "Delete your account | Passwordless auth example"

	bodyHTML := `<h1>Delete your account</h1>
<p>Are you sure you want to delete your account? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button" class="block-button">Delete account</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	pageDataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	pageDataJSONBuilder.AddString("auth_session_token", authSessionToken)
	pageDataJSONBuilder.AddString("account_deletion_session_token", accountDeletionSessionToken)
	pageDataJSON := pageDataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, pageTitle, bodyHTML, deleteAccountConfirmPageScript, deleteAccountConfirmPageStylesheet, pageDataJSON)

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
