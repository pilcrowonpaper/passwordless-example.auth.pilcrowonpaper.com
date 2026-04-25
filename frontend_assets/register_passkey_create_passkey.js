const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const passkeyRegistrationToken = pageDataJSONObject.passkey_registration_token;
const userId = pageDataJSONObject.user_id;
const userEmailAddress = pageDataJSONObject.user_email_address;
const passkeyWebauthnCredentialIds = [];
for (const encodedCredentialId of pageDataJSONObject.passkey_webauthn_credential_ids) {
	passkeyWebauthnCredentialIds.push(Uint8Array.fromBase64(encodedCredentialId));
}

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "passkey_registration_updated") {
		window.location.reload();
	}
});

const createPasskeyButtonElement = document.getElementById("create-passkey-button");
createPasskeyButtonElement.addEventListener("click", async () => {
	createPasskeyButtonElement.disabled = true;

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
	};
	for (const credentialId of passkeyWebauthnCredentialIds) {
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
			alert(
				"A passkey managed by your device, password manager, or security key is already registered.",
			);
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
		session_token: sessionToken,
		passkey_registration_token: passkeyRegistrationToken,
		webauthn_authenticator_data: authenticatorDataBytes.toBase64(),
	};
	const requestBodyJSONObject = {
		action: "set_passkey_registration_passkey_webauthn_credential",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_session_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_passkey_registration_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				clientStateEventChannel.postMessage("passkey_registration_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "invalid_or_unsupported_public_key") {
				alert("This device is not supported.");
				createPasskeyButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				createPasskeyButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		createPasskeyButtonElement.disabled = false;
		return;
	}

	clientStateEventChannel.postMessage("passkey_registration_updated");

	window.location.href = "/register-passkey/set-passkey-name";
});

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_registration_token: passkeyRegistrationToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_passkey_registration",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_session_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_passkey_registration_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				clientStateEventChannel.postMessage("passkey_registration_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("passkey_registration_updated");

	window.location.href = "/account";
});
