"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const identityVerificationSessionToken = pageDataJSONObject.identity_verification_session_token;
const identityVerificationSessionPasskeyVerificationChallenge = Uint8Array.fromBase64(
	pageDataJSONObject.identity_verification_passkey_verification_challenge,
);

const verifyWithPasskeyButtonElement = document.getElementById("verify-with-passkey-button");
if (verifyWithPasskeyButtonElement !== null) {
	verifyWithPasskeyButtonElement.addEventListener("click", handleVerifyWithPasskeyButtonClickEvent);
}

const verifyWithEmailCodeButtonElement = document.getElementById("verify-with-email-code-button");
verifyWithEmailCodeButtonElement.addEventListener(
	"click",
	handleVerifyWithEmailCodeButtonClickEvent,
);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonElementClickEvent);

async function handleVerifyWithPasskeyButtonClickEvent() {
	verifyWithPasskeyButtonElement.disabled = true;

	let actionValuesJSONObject = {
		auth_session_token: authSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("get_webauthn_credential_ids", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}

	const encodedWebauthnCredentialIds = actionResult.valuesJSONObject.webauthn_credential_ids;
	const webauthnCredentialIds = [];
	for (const encodedWebauthnCredentialId of encodedWebauthnCredentialIds) {
		webauthnCredentialIds.push(Uint8Array.fromBase64(encodedWebauthnCredentialId));
	}

	const publicKeyOptions = {
		challenge: identityVerificationSessionPasskeyVerificationChallenge,
		allowCredentials: [],
		userVerification: "required",
		timeout: 5 * 60 * 1000,
	};
	for (const credentialId of webauthnCredentialIds) {
		publicKeyOptions.allowCredentials.push({
			id: credentialId,
			type: "public-key",
		});
	}

	let credential;
	try {
		credential = await navigator.credentials.get({
			publicKey: publicKeyOptions,
		});
	} catch (error) {
		console.error(error);
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}

	const credentialId = new Uint8Array(credential.rawId);
	const authenticatorData = new Uint8Array(credential.response.authenticatorData);
	const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
	const signature = new Uint8Array(credential.response.signature);

	actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
		webauthn_credential_id: credentialId.toBase64(),
		webauthn_authenticator_data: authenticatorData.toBase64(),
		webauthn_client_data_json: clientDataJSON.toBase64(),
		webauthn_signature: signature.toBase64(),
	};

	try {
		actionResult = await sendActionRequest(
			"verify_identity_verification_passkey_webauthn_signature",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "passkey_not_found") {
			alert("This passkey has been deleted.");
			verifyWithPasskeyButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "invalid_webauthn_signature") {
			alert("Please try again.");
			verifyWithPasskeyButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}

	const verifiedAction = actionResult.valuesJSONObject.verified_action;

	deleteIdentityVerificationSessionTokenCookie();

	if (verifiedAction === "email_address_update") {
		window.location.href = "/update-email-address/set-new-email-address";
	} else if (verifiedAction === "passkey_registration") {
		window.location.href = "/register-passkey/create-passkey";
	} else if (verifiedAction === "passkey_deletion") {
		window.location.href = "/delete-passkey/confirm";
	} else if (verifiedAction === "account_deletion") {
		window.location.href = "/delete-account/confirm";
	} else {
		console.error(new Error(`Unknown verified action '${verifiedAction}'`));
		alert("An unexpected error occurred. Please try again.");
		verifyWithPasskeyButtonElement.disabled = false;
		return;
	}
}

async function handleVerifyWithEmailCodeButtonClickEvent() {
	verifyWithEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"issue_identity_verification_email_code",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithEmailCodeButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			verifyWithEmailCodeButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithEmailCodeButtonElement.disabled = false;
		return;
	}

	window.location.href = "/verify-identity/verify-email-code";
}

async function handleCancelButtonElementClickEvent() {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		identity_verification_session_token: identityVerificationSessionToken,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("cancel_identity_verification", actionValuesJSONObject);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteIdentityVerificationSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_identity_verification_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteIdentityVerificationSessionTokenCookie();

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

	const cancelledAction = actionResult.valuesJSONObject.cancelled_action;
	deleteIdentityVerificationSessionTokenCookie();

	if (cancelledAction === "email_address_update") {
		deleteEmailAddressUpdateSessionTokenCookie();
	} else if (cancelledAction === "passkey_registration") {
		deletePasskeyRegistrationSessionTokenCookie();
	} else if (cancelledAction === "passkey_deletion") {
		deletePasskeyDeletionSessionTokenCookie();
	} else if (cancelledAction === "account_deletion") {
		deleteAccountDeletionSessionTokenCookie();
	}

	window.location.href = "/account";
}
