package main

import (
	"fmt"
	"time"

	"github.com/pilcrowonpaper/go-json"
)

func (server *serverStruct) logActionSuccessResult(requestId string, actionName string) {
	if !server.logging.actionResult {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_success_result")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddString("action", actionName)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logActionErrorResult(requestId string, actionName string, errorCode string) {
	if !server.logging.actionResult {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_error_result")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddString("action", actionName)
	logJSONBuilder.AddString("error_code", errorCode)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logActionError(requestId string, errorMessage string) {
	if !server.logging.actionError {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_error")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddString("message", errorMessage)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logRequestEvent(eventName string, requestId string, tags requestEventTagsStruct) {
	if !server.logging.requestEvent {
		return
	}

	now := time.Now()

	tagsJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	if tags.userId != "" {
		tagsJSONBuilder.AddString("user_id", tags.userId)
	}
	if tags.passkeyId != "" {
		tagsJSONBuilder.AddString("passkey_id", tags.passkeyId)
	}
	if tags.sessionId != "" {
		tagsJSONBuilder.AddString("session_id", tags.sessionId)
	}
	if tags.signupId != "" {
		tagsJSONBuilder.AddString("signup_id", tags.signupId)
	}
	if tags.signupPasskeyRegistrationId != "" {
		tagsJSONBuilder.AddString("signup_passkey_registration_id", tags.signupPasskeyRegistrationId)
	}
	if tags.emailCodeSigninId != "" {
		tagsJSONBuilder.AddString("email_code_signin_id", tags.emailCodeSigninId)
	}
	if tags.passkeySigninId != "" {
		tagsJSONBuilder.AddString("passkey_signin_id", tags.passkeySigninId)
	}
	if tags.identityVerificationId != "" {
		tagsJSONBuilder.AddString("identity_verification_id", tags.identityVerificationId)
	}
	if tags.emailAddressUpdateId != "" {
		tagsJSONBuilder.AddString("email_address_update_id", tags.emailAddressUpdateId)
	}
	if tags.passkeyRegistrationId != "" {
		tagsJSONBuilder.AddString("passkey_registration_id", tags.passkeyRegistrationId)
	}
	if tags.passkeyDeletionId != "" {
		tagsJSONBuilder.AddString("passkey_deletion_id", tags.passkeyDeletionId)
	}
	if tags.accountDeletionId != "" {
		tagsJSONBuilder.AddString("account_deletion_id", tags.accountDeletionId)
	}
	if tags.emailAddress != "" {
		tagsJSONBuilder.AddString("email_address", tags.emailAddress)
	}
	tagsJSON := tagsJSONBuilder.Done()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_event")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddString("event", eventName)
	logJSONBuilder.AddJSON("tags", tagsJSON)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

type requestEventTagsStruct struct {
	userId                      string
	passkeyId                   string
	sessionId                   string
	signupId                    string
	signupPasskeyRegistrationId string
	emailCodeSigninId           string
	passkeySigninId             string
	identityVerificationId      string
	emailAddressUpdateId        string
	passkeyRegistrationId       string
	passkeyDeletionId           string
	accountDeletionId           string
	emailAddress                string
}

func (server *serverStruct) logBackgroundJobRun(runId string, backgroundJobName string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_run")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddString("background_job", backgroundJobName)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logBackgroundJobError(runId string, errorMessage string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_error")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("message", errorMessage)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logBackgroundJobRunCompletion(runId string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_run_completion")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

var loggingJSONStringCharacterEscapingBehavior json.StringCharacterEscapingBehaviorInterface = loggingJSONStringCharacterEscapingBehaviorStruct{}

type loggingJSONStringCharacterEscapingBehaviorStruct struct{}

func (loggingJSONStringCharacterEscapingBehaviorStruct) UseCharacter(r rune) bool {
	return r != '\n'
}

func (loggingJSONStringCharacterEscapingBehaviorStruct) UseShorthandEscapeSequence(_ rune) bool {
	return true
}

const (
	emailTypeSignupEmailAddressVerificationCode                = "signup_email_address_verification_code"
	emailTypeSigninEmailCode                                   = "signin_email_code"
	emailTypeSignedInNotification                              = "signed_in_notification"
	emailTypeEmailAddressUpdatedNotification                   = "email_address_updated_notification"
	emailTypeEmailAddressUpdateNewEmailAddressVerificationCode = "email_address_update_new_email_address_verification_code"
	emailTypeIdentityVerificationEmailCode                     = "identity_verification_email_code"
	emailTypePasskeyRegisteredNotification                     = "passkey_registered_notification"
	emailTypePasskeyDeletedNotification                        = "passkey_deleted_notification"
)

func (server *serverStruct) logRequestEmail(requestId string, emailAddress string, emailType string) {
	if !server.logging.requestEmail {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "request_email")
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("email_address", emailAddress)
	logJSONBuilder.AddString("email_type", emailType)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}
