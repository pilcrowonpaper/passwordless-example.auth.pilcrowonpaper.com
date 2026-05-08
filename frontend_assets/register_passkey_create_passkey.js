"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const passkeyRegistrationToken = pageDataJSONObject.passkey_registration_token;
const userId = pageDataJSONObject.user_id;
const userEmailAddress = pageDataJSONObject.user_email_address;

const createPasskeyButtonElement = document.getElementById("create-passkey-button");
createPasskeyButtonElement.addEventListener("click", handleCreatePasskeyButtonClickEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleCreatePasskeyButtonClickEvent(event) {
	createPasskeyButtonElement.disabled = true;

	let actionValuesJSONObject = {
		session_token: sessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("get_webauthn_credential_ids", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyRegistrationTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	const webauthnCredentialIds = [];
	for (const encodedWebauthnCredentialId of actionResult.valuesJSONObject.webauthn_credential_ids) {
		webauthnCredentialIds.push(Uint8Array.fromBase64(encodedWebauthnCredentialId));
	}

	const publicKeyOptions = {
		// Ignore challenge because we don't verify the attestation statement.
		challenge: new Uint8Array(0),
		rp: {
			name: "Passwordless auth example",
			id: new URL(window.location.href).hostname,
		},
		user: {
			id: new TextEncoder().encode(userId),
			name: userEmailAddress,
			displayName: userEmailAddress,
		},
		pubKeyCredParams: [
			{ type: "public-key", alg: -8 },
			{ type: "public-key", alg: -7 },
			{ type: "public-key", alg: -257 },
		],
		excludeCredentials: [],
		authenticatorSelection: {
			residentKey: "required",
			requireResidentKey: true,
			userVerification: "required",
		},
		attestation: "none",
		extensions: {
			credentialProtectionPolicy: "userVerificationRequired",
			enforceCredentialProtectionPolicy: false,
		},
	};
	for (const credentialId of webauthnCredentialIds) {
		publicKeyOptions.excludeCredentials.push({
			id: credentialId,
			type: "public-key",
		});
	}

	let credential;
	try {
		credential = await navigator.credentials.create({
			publicKey: publicKeyOptions,
		});
	} catch (error) {
		if (error.name === "NotAllowedError") {
			alert("Request cancelled. Please try again.");
			createPasskeyButtonElement.disabled = false;
			return;
		}
		if (error.name === "NotSupportedError") {
			alert("Your device, password manager, or security key is not supported.");
			createPasskeyButtonElement.disabled = false;
			return;
		}
		if (error.name === "InvalidStateError") {
			alert("A passkey is already saved using your device, password manager, or security key.");
			createPasskeyButtonElement.disabled = false;
			return;
		}
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	const authenticatorDataBytes = new Uint8Array(credential.response.getAuthenticatorData());

	actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_registration_token: passkeyRegistrationToken,
		webauthn_authenticator_data: authenticatorDataBytes.toBase64(),
	};

	try {
		actionResult = await sendActionRequest(
			"set_passkey_registration_passkey_webauthn_credential",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyRegistrationTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_registration_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyRegistrationTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "invalid_or_unsupported_public_key") {
			alert("This device is not supported.");
			createPasskeyButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			createPasskeyButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	window.location.href = "/register-passkey/set-passkey-name";
}

async function handleCancelButtonClickEvent(event) {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_registration_token: passkeyRegistrationToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_passkey_registration", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_session_token") {
			deleteSessionTokenCookie();
			deletePasskeyRegistrationTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_passkey_registration_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deletePasskeyRegistrationTokenCookie();

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

	deletePasskeyRegistrationTokenCookie();

	window.location.href = "/account";
}
