"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const passkeyDeletionToken = pageDataJSONObject.passkey_deletion_token;

const confirmButtonElement = document.getElementById("confirm-button");
confirmButtonElement.addEventListener("click", handleConfirmButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleConfirmButtonClickEvent() {
	confirmButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_deletion_token: passkeyDeletionToken,
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
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_deletion_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyDeletionTokenCookie();

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

	deletePasskeyDeletionTokenCookie();

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_deletion_token: passkeyDeletionToken,
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
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyDeletionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_deletion_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyDeletionTokenCookie();

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

	deletePasskeyDeletionTokenCookie();

	window.location.href = "/account";
}
