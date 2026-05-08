"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;

const setPasskeyNameFormElement = document.getElementById("set-passkey-name-form");
setPasskeyNameFormElement.addEventListener("submit", handleSetPasskeyNameFormSubmitEvent);

async function handleSetPasskeyNameFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-passkey-name-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const passkeyName = formData.get("passkey_name").trim();

	const actionValuesJSONObject = {
		signup_token: signupToken,
		passkey_name: passkeyName,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("set_signup_passkey_name", actionValuesJSONObject);
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
		if (actionResult.errorCode === "invalid_passkey_name") {
			alert("Please enter a valid passkey name.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "email_address_already_used") {
			deleteSignupTokenCookie();

			alert("This email address is already linked to an existing account.");
			window.location.href = "/sign-up";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	deleteSignupTokenCookie();
	setSessionTokenCookie(actionResult.valuesJSONObject.session_token);

	window.location.href = "/account";
}
