"use strict";

const signUpFormElement = document.getElementById("sign-up-form");
signUpFormElement.addEventListener("submit", handleSignUpFormSubmitElement);

async function handleSignUpFormSubmitElement(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("sign-up-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_signup", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_email_address") {
			alert("Please enter a valid email address.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "email_address_already_used") {
			alert("This email address is already linked to an existing account.");
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

	setSignupSessionTokenCookie(actionResult.valuesJSONObject.signup_session_token);

	window.location.href = "/sign-up/verify-email-address";
}
