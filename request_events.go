package main

const (
	requestEventSignupStarted                             = "signup_started"
	requestEventSignupEmailAddressVerified                = "signup_email_address_verified"
	requestEventSignupEmailAddressVerificationFailed      = "signup_email_address_verification_failed"
	requestEventSignupCompletedWithoutPasskeyRegistration = "signup_completed_without_passkey_registration"
	requestEventSignupCompletedWithPasskeyRegistration    = "signup_completed_with_passkey_registration"

	requestEventEmailCodeSigninStarted                     = "email_code_signin_started"
	requestEventEmailCodeSigninCompleted                   = "email_code_signin_completed"
	requestEventEmailCodeSigninEmailCodeVerificationFailed = "email_code_signin_email_code_verification_failed"

	requestEventPasskeySigninStarted                     = "passkey_signin_started"
	requestEventPasskeySigninCompleted                   = "passkey_signin_completed"
	requestEventPasskeySigninSignatureVerificationFailed = "passkey_signin_signature_verification_failed"

	requestEventIdentityVerificationPasskeyVerificationCompleted               = "identity_verification_passkey_verification_completed"
	requestEventIdentityVerificationPasskeyWebauthnSignatureVerificationFailed = "identity_verification_passkey_verification_webauthn_signature_verification_failed"
	requestEventIdentityVerificationEmailCodeIssued                            = "identity_verification_email_code_issued"
	requestEventIdentityVerificationEmailCodeVerificationCompleted             = "identity_verification_email_code_verification_completed"
	requestEventIdentityVerificationEmailCodeVerificationFailed                = "identity_verification_email_code_verification_failed"

	requestEventEmailAddressUpdateStarted                           = "email_address_update_started"
	requestEventEmailAddressUpdateCompleted                         = "email_address_update_completed"
	requestEventEmailAddressUpdateNewEmailAddressVerificationFailed = "email_address_update_new_email_address_verification_failed"

	requestEventPasskeyRegistrationStarted   = "passkey_registration_started"
	requestEventPasskeyRegistrationCompleted = "passkey_registration_completed"

	requestEventPasskeyDeletionStarted   = "passkey_deletion_started"
	requestEventPasskeyDeletionCompleted = "passkey_deletion_completed"

	requestEventAccountDeletionStarted   = "account_deletion_started"
	requestEventAccountDeletionCompleted = "account_deletion_completed"
)

func (server *serverStruct) logSignupStartedRequestEvent(requestId string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupStarted, requestId, tags)
}

func (server *serverStruct) logSignupEmailAddressVerifiedRequestEvent(requestId string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerified, requestId, tags)
}

func (server *serverStruct) logSignupEmailAddressVerificationFailedRequestEvent(requestId string, signupId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerificationFailed, requestId, tags)
}

func (server *serverStruct) logSignupCompletedWithoutPasskeyRegistrationRequestEvent(requestId string, signupId string, emailAddress string, userId string, sessionId string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
		userId:       userId,
		sessionId:    sessionId,
	}

	server.logRequestEvent(requestEventSignupCompletedWithoutPasskeyRegistration, requestId, tags)
}

func (server *serverStruct) logSignupCompletedWithPasskeyRegistrationRequestEvent(requestId string, signupId string, emailAddress string, userId string, passkeyId string, sessionId string) {
	tags := requestEventTagsStruct{
		signupId:     signupId,
		emailAddress: emailAddress,
		userId:       userId,
		passkeyId:    passkeyId,
		sessionId:    sessionId,
	}

	server.logRequestEvent(requestEventSignupCompletedWithPasskeyRegistration, requestId, tags)
}

func (server *serverStruct) logEmailCodeSigninStartedRequestEvent(requestId string, emailCodeSigninId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		emailCodeSigninId: emailCodeSigninId,
		userId:            userId,
		emailAddress:      emailAddress,
	}

	server.logRequestEvent(requestEventEmailCodeSigninStarted, requestId, tags)
}

func (server *serverStruct) logEmailCodeSigninEmailCodeVerificationFailedRequestEvent(requestId string, emailCodeSigninId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		emailCodeSigninId: emailCodeSigninId,
		userId:            userId,
		emailAddress:      emailAddress,
	}

	server.logRequestEvent(requestEventEmailCodeSigninEmailCodeVerificationFailed, requestId, tags)
}

func (server *serverStruct) logEmailCodeSigninCompletedRequestEvent(requestId string, emailCodeSigninId string, userId string, emailAddress string, sessionId string) {
	tags := requestEventTagsStruct{
		emailCodeSigninId: emailCodeSigninId,
		userId:            userId,
		emailAddress:      emailAddress,
		sessionId:         sessionId,
	}

	server.logRequestEvent(requestEventEmailCodeSigninCompleted, requestId, tags)
}

func (server *serverStruct) logPasskeySigninStartedRequestEvent(requestId string, passkeySigninId string) {
	tags := requestEventTagsStruct{
		passkeySigninId: passkeySigninId,
	}

	server.logRequestEvent(requestEventPasskeySigninStarted, requestId, tags)
}

func (server *serverStruct) logPasskeySigninSignatureVerificationFailedRequestEvent(requestId string, passkeySigninId string, passkeyId string, userId string) {
	tags := requestEventTagsStruct{
		passkeySigninId: passkeySigninId,
		passkeyId:       passkeyId,
		userId:          userId,
	}

	server.logRequestEvent(requestEventPasskeySigninSignatureVerificationFailed, requestId, tags)
}

func (server *serverStruct) logPasskeySigninCompletedRequestEvent(requestId string, passkeySigninId string, passkeyId string, userId string, sessionId string) {
	tags := requestEventTagsStruct{
		passkeySigninId: passkeySigninId,
		passkeyId:       passkeyId,
		userId:          userId,
		sessionId:       sessionId,
	}

	server.logRequestEvent(requestEventPasskeySigninCompleted, requestId, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeIssuedRequestEvent(
	requestId string,
	sessionId string,
	userId string,
	identityVerificationId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		emailAddress:           emailAddress,
	}
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		tags.accountDeletionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeIssued, requestId, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeVerificationCompletedRequestEvent(
	requestId string,
	sessionId string,
	userId string,
	identityVerificationId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		emailAddress:           emailAddress,
	}
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		tags.accountDeletionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeVerificationCompleted, requestId, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeVerificationFailedRequestEvent(
	requestId string,
	sessionId string,
	userId string,
	identityVerificationId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		emailAddress:           emailAddress,
	}
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		tags.accountDeletionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeVerificationFailed, requestId, tags)
}

func (server *serverStruct) logIdentityVerificationPasskeyVerificationCompletedRequestEvent(
	requestId string,
	sessionId string,
	userId string,
	identityVerificationId string,
	verifyingAction string,
	verifyingActionId string,
	passkeyId string,
) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		passkeyId:              passkeyId,
	}
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		tags.accountDeletionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationPasskeyVerificationCompleted, requestId, tags)
}

func (server *serverStruct) logIdentityVerificationPasskeyWebauthnSignatureVerificationFailedRequestEvent(
	requestId string,
	sessionId string,
	userId string,
	identityVerificationId string,
	verifyingAction string,
	verifyingActionId string,
	passkeyId string,
) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		passkeyId:              passkeyId,
	}
	if verifyingAction == identityVerificationVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionId = verifyingActionId
	} else if verifyingAction == identityVerificationVerifyingActionAccountDeletion {
		tags.accountDeletionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationPasskeyWebauthnSignatureVerificationFailed, requestId, tags)
}

func (server *serverStruct) logEmailAddressUpdateStartedRequestEvent(requestId string, sessionId string, userId string, emailAddressUpdateId string, identityVerificationId string) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		identityVerificationId: identityVerificationId,
		emailAddressUpdateId:   emailAddressUpdateId,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateStarted, requestId, tags)
}

func (server *serverStruct) logEmailAddressUpdateCompletedRequestEvent(requestId string, sessionId string, userId string, emailAddressUpdateId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
		emailAddress:         newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateCompleted, requestId, tags)
}

func (server *serverStruct) logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId string, sessionId string, userId string, emailAddressUpdateId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		sessionId:            sessionId,
		userId:               userId,
		emailAddressUpdateId: emailAddressUpdateId,
		emailAddress:         newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateNewEmailAddressVerificationFailed, requestId, tags)
}

func (server *serverStruct) logPasskeyRegistrationStartedRequestEvent(requestId string, sessionId string, userId string, passkeyRegistrationId string, identityVerificationId string) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		passkeyRegistrationId:  passkeyRegistrationId,
		identityVerificationId: identityVerificationId,
	}

	server.logRequestEvent(requestEventPasskeyRegistrationStarted, requestId, tags)
}

func (server *serverStruct) logPasskeyRegistrationCompletedRequestEvent(requestId string, sessionId string, userId string, passkeyRegistrationId string, passkeyId string) {
	tags := requestEventTagsStruct{
		sessionId:             sessionId,
		userId:                userId,
		passkeyRegistrationId: passkeyRegistrationId,
		passkeyId:             passkeyId,
	}

	server.logRequestEvent(requestEventPasskeyRegistrationCompleted, requestId, tags)
}

func (server *serverStruct) logPasskeyDeletionStartedRequestEvent(requestId string, sessionId string, userId string, passkeyDeletionId string, passkeyId string, identityVerificationId string) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		passkeyDeletionId:      passkeyDeletionId,
		passkeyId:              passkeyId,
		identityVerificationId: identityVerificationId,
	}

	server.logRequestEvent(requestEventPasskeyDeletionStarted, requestId, tags)
}

func (server *serverStruct) logPasskeyDeletionCompletedRequestEvent(requestId string, sessionId string, userId string, passkeyDeletionId string, passkeyId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		passkeyDeletionId: passkeyDeletionId,
		passkeyId:         passkeyId,
	}

	server.logRequestEvent(requestEventPasskeyDeletionCompleted, requestId, tags)
}

func (server *serverStruct) logAccountDeletionStartedRequestEvent(requestId string, sessionId string, userId string, accountDeletionId string, identityVerificationId string) {
	tags := requestEventTagsStruct{
		sessionId:              sessionId,
		userId:                 userId,
		accountDeletionId:      accountDeletionId,
		identityVerificationId: identityVerificationId,
	}

	server.logRequestEvent(requestEventAccountDeletionStarted, requestId, tags)
}

func (server *serverStruct) logAccountDeletionCompletedRequestEvent(requestId string, sessionId string, userId string, accountDeletionId string) {
	tags := requestEventTagsStruct{
		sessionId:         sessionId,
		userId:            userId,
		accountDeletionId: accountDeletionId,
	}

	server.logRequestEvent(requestEventAccountDeletionCompleted, requestId, tags)
}
