"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;

const updateEmailAddressButtonElement = document.getElementById("update-email-address-button");
updateEmailAddressButtonElement.addEventListener("click", handleUpdateEmailAddressButtonClickEvent);

const deletePasskeyButtonElements = document.getElementsByClassName("delete-passkey-button");
for (const deletePasskeyButtonElement of deletePasskeyButtonElements) {
	deletePasskeyButtonElement.addEventListener("click", handleDeletePasskeyButtonClickEvent);
}

const registerPasskeyButtonElement = document.getElementById("register-passkey-button");
if (registerPasskeyButtonElement !== null) {
	registerPasskeyButtonElement.addEventListener("click", handleRegisterPasskeyButtonClickEvent);
}

const signOutButtonElement = document.getElementById("sign-out-button");
signOutButtonElement.addEventListener("click", handleSignOutButtonClickEvent);

const signOutAllDevicesButtonElement = document.getElementById("sign-out-all-devices-button");

signOutAllDevicesButtonElement.addEventListener("click", handleSignOutAllDevicesButtonClickEvent);

const deleteAccountButtonElement = document.getElementById("delete-account-button");
deleteAccountButtonElement.addEventListener("click", handleDeleteAccountButtonClickEvent);

async function handleUpdateEmailAddressButtonClickEvent() {
	updateEmailAddressButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_email_address_update", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			updateEmailAddressButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	setEmailAddressUpdateSessionTokenCookie(
		actionResult.valuesJSONObject.email_address_update_session_token,
	);
	setIdentityVerificationSessionTokenCookie(
		actionResult.valuesJSONObject.identity_verification_session_token,
	);

	window.location.href = "/verify-identity";
}

async function handleDeletePasskeyButtonClickEvent(event) {
	const passkeyId = event.target.getAttribute("data-passkey-id");

	event.target.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		passkey_id: passkeyId,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_passkey_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		event.target.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			event.target.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		event.target.disabled = false;
		return;
	}

	setPasskeyDeletionSessionTokenCookie(
		actionResult.valuesJSONObject.passkey_deletion_session_token,
	);
	setIdentityVerificationSessionTokenCookie(
		actionResult.valuesJSONObject.identity_verification_session_token,
	);

	window.location.href = "/verify-identity";
}

async function handleRegisterPasskeyButtonClickEvent() {
	registerPasskeyButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_passkey_registration", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		registerPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "passkey_limit_reached") {
			alert("Passkey limit reached.");
			registerPasskeyButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			registerPasskeyButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		registerPasskeyButtonElement.disabled = false;
		return;
	}

	setPasskeyRegistrationSessionTokenCookie(
		actionResult.valuesJSONObject.passkey_registration_session_token,
	);
	setIdentityVerificationSessionTokenCookie(
		actionResult.valuesJSONObject.identity_verification_session_token,
	);

	window.location.href = "/verify-identity";
}

async function handleSignOutButtonClickEvent() {
	signOutButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("sign_out", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			signOutButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	deleteSessionTokenCookie();

	window.location.href = "/sign-in";
}

async function handleSignOutAllDevicesButtonClickEvent() {
	const confirmed = confirm("Do you want to sign out of all devices?");
	if (!confirmed) {
		return;
	}

	signOutAllDevicesButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("sign_out_all_devices", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}

		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			signOutAllDevicesButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);

		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	deleteSessionTokenCookie();

	window.location.href = "/sign-in";
}

async function handleDeleteAccountButtonClickEvent() {
	deleteAccountButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_account_deletion", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			deleteAccountButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButtonElement.disabled = false;
		return;
	}

	setAccountDeletionSessionTokenCookie(
		actionResult.valuesJSONObject.account_deletion_session_token,
	);
	setIdentityVerificationSessionTokenCookie(
		actionResult.valuesJSONObject.identity_verification_session_token,
	);

	window.location.href = "/verify-identity";
}
