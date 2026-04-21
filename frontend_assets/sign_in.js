const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);

let passkeySigninId = pageDataJSONObject.passkey_signin_id;
let passkeySigninChallenge = Uint8Array.fromBase64(pageDataJSONObject.passkey_signin_challenge);
let passkeySigninRefreshAt = new Date(Date.now() + 50 * 60 * 1000);

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated") {
		window.location.reload();
	}
});

document.getElementById("sign-in-with-email-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("sign-in-with-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress
	};
	const requestBodyJSONObject = {
		action: "start_email_code_signin",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let emailCodeSigninToken;
	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_email_address") {
				alert("Please enter a valid email address.");
				submitButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "user_not_found") {
				alert("No account found with this email address.");
				submitButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				submitButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		emailCodeSigninToken = resultJSONObject.values.email_code_signin_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `email_code_signin_token=${emailCodeSigninToken}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `email_code_signin_token=${emailCodeSigninToken}; Max-Age=3600; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("email_code_signin_updated");

	window.location.href = "/sign-in/verify-email-code";
});

const conditionalWebauthnRequestAbortController = new AbortController();
setTimeout(conditionalWebauthnRequestAbortController.abort, 50 * 60 * 1000);

const signInWithPasskeyButtonElement = document.getElementById("sign-in-with-passkey-button")
signInWithPasskeyButtonElement.addEventListener("click", async () => {
	signInWithPasskeyButtonElement.disabled = true;

	if (Date.now() >= passkeySigninRefreshAt.getTime()) {
		const startPasskeySigninActionValuesJSONObject = {
			email_address: emailAddress,
		};
		const startPasskeySigninActionRequestBodyJSONObject = {
			action: "start_passkey_signin",
			values: startPasskeySigninActionValuesJSONObject,
		};
		const startPasskeySigninActionRequestBody = JSON.stringify(startPasskeySigninActionRequestBodyJSONObject);

		const startPasskeySigninActionRequest = new Request("/action", {
			method: "POST",
			body: startPasskeySigninActionRequestBody,
		});
		startPasskeySigninActionRequest.headers.set("Content-Type", "application/json");

		try {
			const response = await fetch(startPasskeySigninActionRequest);
			if (!response.ok) {
				await response.body.cancel();
				throw new Error(`Unexpected response status code ${response.status}`);
			}
			const resultJSONObject = await response.json();
			if (!resultJSONObject.ok) {
				if (resultJSONObject.error_code === "rate_limited") {
					alert("Too many attempts. Please try again later.");
					signInWithPasskeyButtonElement.disabled = false;
					return;
				}
				throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
			}
			passkeySigninId = resultJSONObject.values.passkey_signin_id;
			passkeySigninChallenge = Uint8Array.fromBase64(resultJSONObject.values.passkey_signin_challenge);
			passkeySigninRefreshAt = new Date(Date.now() + 50 * 60 * 1000);
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			signInWithPasskeyButtonElement.disabled = false;
			return;
		}
	}

	conditionalWebauthnRequestAbortController.abort();
	let credential;
	try {
		credential = await navigator.credentials.get({
        	publicKey: {
            	challenge: passkeySigninChallenge,
            	userVerification: "required",
				timeout: 5 * 60 * 1000,
        	},
    	});
	} catch (error) {
		console.error(error);
		signInWithPasskeyButtonElement.disabled = false;
		return;
	}

	const credentialId = new Uint8Array(credential.rawId);
	const authenticatorData = new Uint8Array(credential.response.authenticatorData);
	const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
	const signature = new Uint8Array(credential.response.signature);

	let sessionToken;
	try {
		const result = await verifyPasskeySigninWebauthnSignatureAction(credentialId, authenticatorData, clientDataJSON, signature);
		if (!result.ok) {
			if (result.errorCode === "passkey_signin_not_found") {
				alert("Please try again.");
				signInWithPasskeyButtonElement.disabled = false;
				return;
			}
			if (result.errorCode === "passkey_not_found") {
				alert("This passkey is not registered.");
				signInWithPasskeyButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		sessionToken = result.sessionToken;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signInWithPasskeyButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/account";
});

startConditionalMediationCredentialRequest();

async function startConditionalMediationCredentialRequest() {
	const conditionalGetAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
	if (!conditionalGetAvailable) {
		return;
	}

	let credential;
	try {
		credential = await navigator.credentials.get({
        	publicKey: {
        	    challenge: passkeySigninChallenge,
        	    userVerification: "required",
        	},
			mediation: "conditional",
			signal: conditionalWebauthnRequestAbortController.signal,
    	});
	} catch (error) {
		console.error(error);
		return
	}

	signInWithPasskeyButtonElement.disabled = true;

	const credentialId = new Uint8Array(credential.rawId);
	const authenticatorData = new Uint8Array(credential.response.authenticatorData);
	const clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
	const signature = new Uint8Array(credential.response.signature);

	let sessionToken;
	try {
		const result = await verifyPasskeySigninWebauthnSignatureAction(credentialId, authenticatorData, clientDataJSON, signature);
		if (!result.ok) {
			if (result.errorCode === "passkey_signin_not_found") {
				alert("Please try again.");
				signInWithPasskeyButtonElement.disabled = false;
				return;
			}
			if (result.errorCode === "passkey_not_found") {
				alert("This passkey is not registered.");
				signInWithPasskeyButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		sessionToken = result.sessionToken;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signInWithPasskeyButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/account";
}

async function verifyPasskeySigninWebauthnSignatureAction(credentialId, authenticatorData, clientDataJSON, signature) {
	const actionValuesJSONObject = {
		passkey_signin_id: passkeySigninId,
		webauthn_credential_id: credentialId.toBase64(),
		webauthn_authenticator_data: authenticatorData.toBase64(),
		webauthn_client_data_json: clientDataJSON.toBase64(),
		webauthn_signature: signature.toBase64(),
	};
	const requestBodyJSONObject = {
		action: "verify_passkey_signin_webauthn_signature",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let response;
	try {
		response = await fetch(request);
	} catch (error) {
		throw new Error("Failed to send request", {
			cause: error,
		});
	}
	if (!response.ok) {
		await response.body.cancel();
		throw new Error(`Unexpected response status code ${response.status}`);
	}

	const resultJSONObject = await response.json();
	if (!resultJSONObject.ok) {
		const result = {
			ok: false,
			errorCode: resultJSONObject.error_code,
		};
		return result
	}

	const result = {
		ok: true,
		sessionToken: resultJSONObject.values.session_token,
	};

	return result;
}