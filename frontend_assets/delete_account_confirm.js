"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const accountDeletionSessionToken = pageDataJSONObject.account_deletion_session_token;

const confirmButtonElement = document.getElementById("confirm-button");
confirmButtonElement.addEventListener("click", handleConfirmButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleConfirmButtonClickEvent() {
	confirmButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		account_deletion_session_token: accountDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("confirm_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		confirmButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();
			deleteAccountDeletionSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_account_deletion_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteAccountDeletionSessionTokenCookie();

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

	deleteAccountDeletionSessionTokenCookie();
	deleteSessionTokenCookie();

	window.location.href = "/account";
}

async function handleCancelButtonClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		account_deletion_session_token: accountDeletionSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();
			deleteAccountDeletionSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_account_deletion_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteAccountDeletionSessionTokenCookie();

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

	deleteAccountDeletionSessionTokenCookie();

	window.location.href = "/account";
}
