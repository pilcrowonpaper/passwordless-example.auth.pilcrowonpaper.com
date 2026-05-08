"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const identityVerificationSessionToken = pageDataJSONObject.identity_verification_session_token;

const verifyEmailCodeFormElement = document.getElementById("verify-email-code-form");
verifyEmailCodeFormElement.addEventListener("submit", handleVerifyEmailCodeFormSubmitEvent);

const resendEmailCodeButtonElement = document.getElementById("resend-email-code-button");
resendEmailCodeButtonElement.addEventListener("click", handleResendEmailCodeButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleVerifyEmailCodeFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailCodeInputValue = formData.get("email_code");
	const emailCode = emailCodeInputValue.replaceAll(" ", "").replaceAll("-", "").toUpperCase();

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
		email_code: emailCode,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_identity_verification_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "email_code_not_issued") {
			alert("Your session has expired.");
			window.location.href = "/verify-identity";
			return;
		}
		if (actionResult.errorCode === "incorrect_email_code") {
			alert("Incorrect email code.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			submitButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	const verifiedAction = actionResult.valuesJSONObject.verified_action;

	deleteIdentityVerificationSessionTokenCookie();

	if (verifiedAction === "email_address_update") {
		window.location.href = "/update-email-address/set-new-email-address";
	} else if (verifiedAction === "passkey_registration") {
		window.location.href = "/register-passkey/create-passkey";
	} else if (verifiedAction === "passkey_deletion") {
		window.location.href = "/delete-passkey/confirm";
	} else if (verifiedAction === "account_deletion") {
		window.location.href = "/delete-account/confirm";
	} else {
		console.error(new Error(`Unknown verified action '${verifiedAction}'`));
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}
}

async function handleResendEmailCodeButtonClickEvent() {
	resendEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"send_identity_verification_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendEmailCodeButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			resendEmailCodeButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "email_code_not_issued") {
			alert("Your session has expired.");
			window.location.href = "/verify-identity";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendEmailCodeButtonElement.disabled = false;
		return;
	}

	alert("We've sent another email to your inbox.");
	resendEmailCodeButtonElement.disabled = false;
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"revoke_identity_verification_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "email_code_not_issued") {
			alert("Your session has expired.");
			window.location.href = "/verify-identity";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	window.location.href = "/verify-identity";
}
