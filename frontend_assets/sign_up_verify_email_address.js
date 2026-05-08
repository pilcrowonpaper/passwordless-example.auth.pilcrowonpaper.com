"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;

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
	handleResendVerificationCodeButtonClickEvent,
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
		signup_token: signupToken,
		verification_code: verificationCode,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_signup_email_address_verification_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_token") {
			deleteSignupTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
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

	window.location.href = "/sign-up/register-passkey";
}

async function handleResendVerificationCodeButtonClickEvent() {
	resendVerificationCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"send_signup_email_address_verification_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendVerificationCodeButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_token") {
			deleteSignupTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
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
		signup_token: signupToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_signup", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_token") {
			deleteSignupTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	deleteSignupTokenCookie();

	window.location.href = "/sign-up";
}
