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

func (server *serverStruct) logSignupStartedRequestEvent(requestId string, clientIPAddress string, signupSessionId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupSessionId: signupSessionId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventSignupStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupEmailAddressVerifiedRequestEvent(requestId string, clientIPAddress string, signupSessionId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupSessionId: signupSessionId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerified, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupEmailAddressVerificationFailedRequestEvent(requestId string, clientIPAddress string, signupSessionId string, emailAddress string) {
	tags := requestEventTagsStruct{
		signupSessionId: signupSessionId,
		emailAddress:    emailAddress,
	}

	server.logRequestEvent(requestEventSignupEmailAddressVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupCompletedWithoutPasskeyRegistrationRequestEvent(requestId string, clientIPAddress string, signupSessionId string, emailAddress string, userId string, authSessionId string) {
	tags := requestEventTagsStruct{
		signupSessionId: signupSessionId,
		emailAddress:    emailAddress,
		userId:          userId,
		authSessionId:   authSessionId,
	}

	server.logRequestEvent(requestEventSignupCompletedWithoutPasskeyRegistration, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logSignupCompletedWithPasskeyRegistrationRequestEvent(requestId string, clientIPAddress string, signupSessionId string, emailAddress string, userId string, passkeyId string, authSessionId string) {
	tags := requestEventTagsStruct{
		signupSessionId: signupSessionId,
		emailAddress:    emailAddress,
		userId:          userId,
		passkeyId:       passkeyId,
		authSessionId:   authSessionId,
	}

	server.logRequestEvent(requestEventSignupCompletedWithPasskeyRegistration, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailCodeSigninStartedRequestEvent(requestId string, clientIPAddress string, emailCodeSigninSessionId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		emailCodeSigninSessionId: emailCodeSigninSessionId,
		userId:                   userId,
		emailAddress:             emailAddress,
	}

	server.logRequestEvent(requestEventEmailCodeSigninStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailCodeSigninEmailCodeVerificationFailedRequestEvent(requestId string, clientIPAddress string, emailCodeSigninSessionId string, userId string, emailAddress string) {
	tags := requestEventTagsStruct{
		emailCodeSigninSessionId: emailCodeSigninSessionId,
		userId:                   userId,
		emailAddress:             emailAddress,
	}

	server.logRequestEvent(requestEventEmailCodeSigninEmailCodeVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailCodeSigninCompletedRequestEvent(requestId string, clientIPAddress string, emailCodeSigninSessionId string, userId string, emailAddress string, authSessionId string) {
	tags := requestEventTagsStruct{
		emailCodeSigninSessionId: emailCodeSigninSessionId,
		userId:                   userId,
		emailAddress:             emailAddress,
		authSessionId:            authSessionId,
	}

	server.logRequestEvent(requestEventEmailCodeSigninCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeySigninStartedRequestEvent(requestId string, clientIPAddress string, passkeySigninAttemptId string) {
	tags := requestEventTagsStruct{
		passkeySigninAttemptId: passkeySigninAttemptId,
	}

	server.logRequestEvent(requestEventPasskeySigninStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeySigninSignatureVerificationFailedRequestEvent(requestId string, clientIPAddress string, passkeySigninAttemptId string, passkeyId string, userId string) {
	tags := requestEventTagsStruct{
		passkeySigninAttemptId: passkeySigninAttemptId,
		passkeyId:              passkeyId,
		userId:                 userId,
	}

	server.logRequestEvent(requestEventPasskeySigninSignatureVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeySigninCompletedRequestEvent(requestId string, clientIPAddress string, passkeySigninAttemptId string, passkeyId string, userId string, authSessionId string) {
	tags := requestEventTagsStruct{
		passkeySigninAttemptId: passkeySigninAttemptId,
		passkeyId:              passkeyId,
		userId:                 userId,
		authSessionId:          authSessionId,
	}

	server.logRequestEvent(requestEventPasskeySigninCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeIssuedRequestEvent(
	requestId string,
	clientIPAddress string,
	authSessionId string,
	userId string,
	identityVerificationSessionId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		emailAddress:                  emailAddress,
	}
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateSessionId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		tags.accountDeletionSessionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeIssued, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeVerificationCompletedRequestEvent(
	requestId string,
	clientIPAddress string,
	authSessionId string,
	userId string,
	identityVerificationSessionId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		emailAddress:                  emailAddress,
	}
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateSessionId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		tags.accountDeletionSessionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeVerificationCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logIdentityVerificationEmailCodeVerificationFailedRequestEvent(
	requestId string,
	clientIPAddress string,
	authSessionId string,
	userId string,
	identityVerificationSessionId string,
	verifyingAction string,
	verifyingActionId string,
	emailAddress string,
) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		emailAddress:                  emailAddress,
	}
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateSessionId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		tags.accountDeletionSessionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationEmailCodeVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logIdentityVerificationPasskeyVerificationCompletedRequestEvent(
	requestId string,
	clientIPAddress string,
	authSessionId string,
	userId string,
	identityVerificationSessionId string,
	verifyingAction string,
	verifyingActionId string,
	passkeyId string,
) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		passkeyId:                     passkeyId,
	}
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateSessionId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		tags.accountDeletionSessionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationPasskeyVerificationCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logIdentityVerificationPasskeyWebauthnSignatureVerificationFailedRequestEvent(
	requestId string,
	clientIPAddress string,
	authSessionId string,
	userId string,
	identityVerificationSessionId string,
	verifyingAction string,
	verifyingActionId string,
	passkeyId string,
) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		passkeyId:                     passkeyId,
	}
	if verifyingAction == identityVerificationSessionVerifyingActionEmailAddressUpdate {
		tags.emailAddressUpdateSessionId = verifyingActionId
	} else if verifyingAction == emailTypePasskeyRegisteredNotification {
		tags.passkeyRegistrationSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionPasskeyDeletion {
		tags.passkeyDeletionSessionId = verifyingActionId
	} else if verifyingAction == identityVerificationSessionVerifyingActionAccountDeletion {
		tags.accountDeletionSessionId = verifyingActionId
	}

	server.logRequestEvent(requestEventIdentityVerificationPasskeyWebauthnSignatureVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateStartedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, emailAddressUpdateSessionId string, identityVerificationSessionId string) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		identityVerificationSessionId: identityVerificationSessionId,
		emailAddressUpdateSessionId:   emailAddressUpdateSessionId,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateCompletedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, emailAddressUpdateSessionId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		authSessionId:               authSessionId,
		userId:                      userId,
		emailAddressUpdateSessionId: emailAddressUpdateSessionId,
		emailAddress:                newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logEmailAddressUpdateNewEmailAddressVerificationFailedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, emailAddressUpdateSessionId string, newEmailAddress string) {
	tags := requestEventTagsStruct{
		authSessionId:               authSessionId,
		userId:                      userId,
		emailAddressUpdateSessionId: emailAddressUpdateSessionId,
		emailAddress:                newEmailAddress,
	}

	server.logRequestEvent(requestEventEmailAddressUpdateNewEmailAddressVerificationFailed, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeyRegistrationStartedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, passkeyRegistrationSessionId string, identityVerificationSessionId string) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		passkeyRegistrationSessionId:  passkeyRegistrationSessionId,
		identityVerificationSessionId: identityVerificationSessionId,
	}

	server.logRequestEvent(requestEventPasskeyRegistrationStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeyRegistrationCompletedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, passkeyRegistrationSessionId string, passkeyId string) {
	tags := requestEventTagsStruct{
		authSessionId:                authSessionId,
		userId:                       userId,
		passkeyRegistrationSessionId: passkeyRegistrationSessionId,
		passkeyId:                    passkeyId,
	}

	server.logRequestEvent(requestEventPasskeyRegistrationCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeyDeletionStartedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, passkeyDeletionSessionId string, passkeyId string, identityVerificationSessionId string) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		passkeyDeletionSessionId:      passkeyDeletionSessionId,
		passkeyId:                     passkeyId,
		identityVerificationSessionId: identityVerificationSessionId,
	}

	server.logRequestEvent(requestEventPasskeyDeletionStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logPasskeyDeletionCompletedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, passkeyDeletionSessionId string, passkeyId string) {
	tags := requestEventTagsStruct{
		authSessionId:            authSessionId,
		userId:                   userId,
		passkeyDeletionSessionId: passkeyDeletionSessionId,
		passkeyId:                passkeyId,
	}

	server.logRequestEvent(requestEventPasskeyDeletionCompleted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionStartedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, accountDeletionSessionId string, identityVerificationSessionId string) {
	tags := requestEventTagsStruct{
		authSessionId:                 authSessionId,
		userId:                        userId,
		accountDeletionSessionId:      accountDeletionSessionId,
		identityVerificationSessionId: identityVerificationSessionId,
	}

	server.logRequestEvent(requestEventAccountDeletionStarted, requestId, clientIPAddress, tags)
}

func (server *serverStruct) logAccountDeletionCompletedRequestEvent(requestId string, clientIPAddress string, authSessionId string, userId string, accountDeletionSessionId string) {
	tags := requestEventTagsStruct{
		authSessionId:            authSessionId,
		userId:                   userId,
		accountDeletionSessionId: accountDeletionSessionId,
	}

	server.logRequestEvent(requestEventAccountDeletionCompleted, requestId, clientIPAddress, tags)
}
