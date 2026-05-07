const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;
const signupTargetUserId = pageDataJSONObject.signup_target_user_id;
const signupEmailAddress = pageDataJSONObject.signup_email_address;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "signup_updated" || event.data === "signup_passkey_registration_updated") {
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
	const requestBodyJSONObject = {
		action: "set_signup_passkey_webauthn_credential",
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
			if (resultJSONObject.error_code === "invalid_signup_token") {
				clientStateEventChannel.postMessage("signup_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/sign-up";
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

	clientStateEventChannel.postMessage("signup_updated");

	window.location.href = "/sign-up/register-passkey/set-passkey-name";
});

const skipButtonElement = document.getElementById("skip-button");
skipButtonElement.addEventListener("click", async () => {
	skipButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};
	const requestBodyJSONObject = {
		action: "complete_signup_without_passkey_registration",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let sessionToken;
	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_signup_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("signup_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-up";
				return;
			}
			if (resultJSONObject.error_code === "email_address_already_used") {
				if (window.location.protocol === "https:") {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("signup_updated");

				alert("This email address is already linked to an existing account.");
				window.location.href = "/sign-up";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		sessionToken = resultJSONObject.values.session_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		skipButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/`;
		document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("signup_updated");
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/account";
});
