"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const passkeyRegistrationSessionToken = pageDataJSONObject.passkey_registration_session_token;

const setPasskeyNameFormElement = document.getElementById("set-passkey-name-form");
setPasskeyNameFormElement.addEventListener("submit", handleSetPasskeyNameFormSubmitEvent);

async function handleSetPasskeyNameFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-passkey-name-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const passkeyName = formData.get("passkey_name").trim();

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		passkey_registration_session_token: passkeyRegistrationSessionToken,
		passkey_name: passkeyName,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"set_passkey_registration_passkey_name",
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
			deleteSessionTokenCookie();
			deletePasskeyRegistrationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_registration_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyRegistrationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "invalid_passkey_name") {
			alert("Please enter a valid passkey name.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "passkey_limit_reached") {
			deletePasskeyRegistrationSessionTokenCookie();

			alert("Passkey limit reached.");
			window.location.href = "/account";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	deletePasskeyRegistrationSessionTokenCookie();

	window.location.href = "/account";
}
