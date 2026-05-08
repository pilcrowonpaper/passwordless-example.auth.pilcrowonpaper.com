"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const passkeyDeletionSessionToken = pageDataJSONObject.passkey_deletion_session_token;

const confirmButtonElement = document.getElementById("confirm-button");
confirmButtonElement.addEventListener("click", handleConfirmButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleConfirmButtonClickEvent() {
	confirmButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		passkey_deletion_session_token: passkeyDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("confirm_passkey_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		confirmButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyDeletionSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_deletion_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyDeletionSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		confirmButtonElement.disabled = false;
		return;
	}

	deletePasskeyDeletionSessionTokenCookie();

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		passkey_deletion_session_token: passkeyDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_passkey_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyDeletionSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_deletion_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyDeletionSessionTokenCookie();

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

	deletePasskeyDeletionSessionTokenCookie();

	window.location.href = "/account";
}
