"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;
const signupTargetUserId = pageDataJSONObject.signup_target_user_id;
const signupEmailAddress = pageDataJSONObject.signup_email_address;

const createPasskeyButtonElement = document.getElementById("create-passkey-button");
createPasskeyButtonElement.addEventListener("click", handleCreatePasskeyButtonClickEvent);

const skipButtonElement = document.getElementById("skip-button");
skipButtonElement.addEventListener("click", handleSkipButtonClickEvent);

async function handleCreatePasskeyButtonClickEvent() {
	createPasskeyButtonElement.disabled = true;

	const publicKeyOptions = {
		// Ignore challenge because we don't verify the attestation statement.
		challenge: new Uint8Array(0),
		rp: {
			name: "Passwordless auth example",
			id: new URL(window.location.href).hostname,
		},
		user: {
			id: new TextEncoder().encode(signupTargetUserId),
			name: signupEmailAddress,
			displayName: signupEmailAddress,
		},
		pubKeyCredParams: [
			{ type: "public-key", alg: -8 },
			{ type: "public-key", alg: -7 },
			{ type: "public-key", alg: -257 },
		],
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
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	const authenticatorDataBytes = new Uint8Array(credential.response.getAuthenticatorData());

	const actionValuesJSONObject = {
		signup_token: signupToken,
		webauthn_authenticator_data: authenticatorDataBytes.toBase64(),
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"set_signup_passkey_webauthn_credential",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_token") {
			deleteSignupTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
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

	window.location.href = "/sign-up/register-passkey/set-passkey-name";
}

async function handleSkipButtonClickEvent() {
	skipButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"complete_signup_without_passkey_registration",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		skipButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_signup_token") {
			deleteSignupTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-up";
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
		skipButtonElement.disabled = false;
		return;
	}

	deleteSignupTokenCookie();
	setSessionTokenCookie(actionResult.valuesJSONObject.session_token);

	window.location.href = "/account";
}
