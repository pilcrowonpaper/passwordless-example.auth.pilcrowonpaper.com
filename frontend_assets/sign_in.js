"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);

let passkeySigninAttemptId = pageDataJSONObject.passkey_signin_attempt_id;
let passkeySigninWebauthnChallenge = Uint8Array.fromBase64(
	pageDataJSONObject.passkey_signin_webauthn_challenge,
);
let passkeySigninAttemptRefreshAt = new Date(Date.now() + 50 * 60 * 1000);

const conditionalWebauthnRequestAbortController = new AbortController();
setTimeout(() => conditionalWebauthnRequestAbortController.abort(), 60 * 60 * 1000);

const signInWithEmailCodeFormElement = document.getElementById("sign-in-with-email-code-form");
signInWithEmailCodeFormElement.addEventListener("submit", handleSignInWithEmailCodeFormSubmitEvent);

const signInWithPasskeyButtonElement = document.getElementById("sign-in-with-passkey-button");
signInWithPasskeyButtonElement.addEventListener("click", handleSignInWithPasskeyButtonClickEvent);

startConditionalMediationCredentialRequest();

async function handleSignInWithEmailCodeFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("sign-in-with-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest("start_email_code_signin", actionValuesJSONObject);
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
		if (actionResult.errorCode === "user_not_found") {
			alert("No account found with this email address.");
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

	setEmailCodeSigninSessionTokenCookie(
		actionResult.valuesJSONObject.email_code_signin_session_token,
	);
	window.location.href = "/sign-in/verify-email-code";
}

async function handleSignInWithPasskeyButtonClickEvent() {
	signInWithPasskeyButtonElement.disabled = true;

	if (Date.now() >= passkeySigninAttemptRefreshAt.getTime()) {
		const actionValuesJSONObject = {
			email_address: emailAddress,
		};

		let actionResult;
		try {
			actionResult = await sendActionRequest("start_passkey_signin", actionValuesJSONObject);
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			signInWithPasskeyButtonElement.disabled = false;
			return;
		}

		if (!actionResult.ok) {
			if (actionResult.errorCode === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				signInWithPasskeyButtonElement.disabled = false;
				return;
			}

			const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			signInWithPasskeyButtonElement.disabled = false;
			return;
		}

		passkeySigninAttemptId = actionResult.valuesJSONObject.passkey_signin_attempt_id;
		passkeySigninWebauthnChallenge = Uint8Array.fromBase64(
			actionResult.valuesJSONObject.webauthn_challenge,
		);
		passkeySigninAttemptRefreshAt = new Date(Date.now() + 50 * 60 * 1000);
	}

	conditionalWebauthnRequestAbortController.abort();
	let credential;
	try {
		credential = await navigator.credentials.get({
			publicKey: {
				challenge: passkeySigninWebauthnChallenge,
				userVerification: "required",
				timeout: 5 * 60 * 1000,
			},
		});
	} catch (error) {
		console.error(error);
		signInWithPasskeyButtonElement.disabled = false;
		return;
	}

	await completePasskeySignin(credential);
}

async function startConditionalMediationCredentialRequest() {
	const conditionalGetAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
	if (!conditionalGetAvailable) {
		return;
	}

	let credential;
	try {
		credential = await navigator.credentials.get({
			publicKey: {
				challenge: passkeySigninWebauthnChallenge,
				userVerification: "required",
			},
			mediation: "conditional",
			signal: conditionalWebauthnRequestAbortController.signal,
		});
	} catch (error) {
		console.error(error);
		return;
	}

	signInWithPasskeyButtonElement.disabled = true;

	await completePasskeySignin(credential);
}

async function completePasskeySignin(credential) {
	const credentialId = new Uint8Array(credential.rawId);
	const authenticatorData = new Uint8Array(credential.response.authenticatorData);
	const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
	const signature = new Uint8Array(credential.response.signature);

	const actionValuesJSONObject = {
		passkey_signin_attempt_id: passkeySigninAttemptId,
		webauthn_credential_id: credentialId.toBase64(),
		webauthn_authenticator_data: authenticatorData.toBase64(),
		webauthn_client_data_json: clientDataJSON.toBase64(),
		webauthn_signature: signature.toBase64(),
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"verify_passkey_signin_webauthn_signature",
			actionValuesJSONObject,
		);
	} catch (error) {
		throw new Error("Failed to send action", {
			cause: error,
		});
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "passkey_signin_attempt_not_found") {
			alert("Please try again.");
			signInWithPasskeyButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "passkey_not_found") {
			alert("This passkey is not registered.");
			signInWithPasskeyButtonElement.disabled = false;
			return;
		}

		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signInWithPasskeyButtonElement.disabled = false;
		return;
	}

	setSessionTokenCookie(actionResult.valuesJSONObject.auth_session_token);

	window.location.href = "/account";
}
