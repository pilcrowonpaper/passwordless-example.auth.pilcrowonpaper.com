"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const emailAddressUpdateToken = pageDataJSONObject.email_address_update_token;

const verifyVerificationCodeFormElement = document.getElementById("verify-verification-code-form");
verifyVerificationCodeFormElement.addEventListener(
	"submit",
	handleVerifyVerificationCodeFormSubmitEvent,
);

const resendVerificationCodeButtonElement = document.getElementById(
	"resend-verification-code-button",
);
resendVerificationCodeButtonElement.addEventListener(
	"click",
	handleResendVerificationButtonClickEvent,
);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleVerifyVerificationCodeFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById(
		"verify-verification-code-form-submit-button",
	);
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const verificationCodeInputValue = formData.get("verification_code");
	const verificationCode = verificationCodeInputValue
		.replaceAll(" ", "")
		.replaceAll("-", "")
		.toUpperCase();

	const actionValuesJSONObject = {
		session_token: sessionToken,
		email_address_update_token: emailAddressUpdateToken,
		verification_code: verificationCode,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_email_address_update_new_email_address_verification_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_email_address_update_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "email_address_already_used") {
			alert("This email address is already linked to an existing account.");
			return;
		}
		if (actionResult.errorCode === "incorrect_verification_code") {
			alert("Incorrect verification code.");
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

	deleteEmailAddressUpdateTokenCookie();
	window.location.href = "/account";
}

async function handleResendVerificationButtonClickEvent() {
	resendVerificationCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		email_address_update_token: emailAddressUpdateToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"send_email_address_update_new_email_address_verification_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendVerificationCodeButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_email_address_update_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			resendVerificationCodeButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendVerificationCodeButtonElement.disabled = false;
		return;
	}

	alert("We've sent another email to your inbox.");
	resendVerificationCodeButtonElement.disabled = false;
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		email_address_update_token: emailAddressUpdateToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_email_address_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (
			actionResult.errorCode === "invalid_session_token" ||
			actionResult.errorCode === "invalid_email_address_update_token"
		) {
			deleteSessionTokenCookie();
			deleteEmailAddressUpdateTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deleteEmailAddressUpdateTokenCookie();

	window.location.href = "/account";
}
