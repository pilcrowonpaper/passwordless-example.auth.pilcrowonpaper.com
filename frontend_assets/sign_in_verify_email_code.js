"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const emailCodeSigninSessionToken = pageDataJSONObject.email_code_signin_session_token;

const verifyEmailCodeFormElement = document.getElementById("verify-email-code-form");
verifyEmailCodeFormElement.addEventListener("submit", handleVerifyEmailCodeFormSubmitEvent);

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
		email_code_signin_session_token: emailCodeSigninSessionToken,
		email_code: emailCode,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_email_code_signin_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_email_code_signin_session_token") {
			deleteEmailCodeSigninSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
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

	deleteEmailCodeSigninSessionTokenCookie();
	setSessionTokenCookie(actionResult.valuesJSONObject.auth_session_token);

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		email_code_signin_session_token: emailCodeSigninSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_email_code_signin", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_email_code_signin_session_token") {
			deleteEmailCodeSigninSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deleteEmailCodeSigninSessionTokenCookie();

	window.location.href = "/sign-in";
}
