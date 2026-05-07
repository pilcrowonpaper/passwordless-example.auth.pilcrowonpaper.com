const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const identityVerificationToken = pageDataJSONObject.identity_verification_token;
const identityVerificationPasskeyVerificationChallenge = Uint8Array.fromBase64(
	pageDataJSONObject.identity_verification_passkey_verification_challenge,
);

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "identity_verification_updated") {
		window.location.reload();
	}
});

const verifyWithPasskeyButtonElement = document.getElementById("verify-with-passkey-button");
if (verifyWithPasskeyButtonElement !== null) {
	verifyWithPasskeyButtonElement.addEventListener("click", async () => {
		verifyWithPasskeyButtonElement.disabled = true;

		const getWebauthnCredentialIdsActionValuesJSONObject = {
			session_token: sessionToken,
		};
		const getWebauthnCredentialIdsActionRequestBodyJSONObject = {
			action: "get_webauthn_credential_ids",
			values: getWebauthnCredentialIdsActionValuesJSONObject,
		};

		const getWebauthnCredentialIdsActionRequest = new Request("/action", {
			method: "POST",
			body: JSON.stringify(getWebauthnCredentialIdsActionRequestBodyJSONObject),
		});
		getWebauthnCredentialIdsActionRequest.headers.set("Content-Type", "application/json");

		const webauthnCredentialIds = [];
		try {
			const response = await fetch(getWebauthnCredentialIdsActionRequest);
			if (!response.ok) {
				await response.body.cancel();
				throw new Error(`Unexpected response status code ${response.status}`);
			}
			const resultJSONObject = await response.json();
			if (!resultJSONObject.ok) {
				if (resultJSONObject.error_code === "invalid_session_token") {
					clientStateEventChannel.postMessage("session_updated");
					if (window.location.protocol === "https:") {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					} else {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}
					alert("Your session has expired.");
					window.location.href = "/sign-in";
					return;
				}
				throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
			}

			for (const encodedWebauthnCredentialId of resultJSONObject.values.webauthn_credential_ids) {
				webauthnCredentialIds.push(Uint8Array.fromBase64(encodedWebauthnCredentialId));
			}
		} catch (e) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			verifyWithPasskeyButtonElement.disabled = false;
			return;
		}

		const publicKeyOptions = {
			challenge: identityVerificationPasskeyVerificationChallenge,
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

		const verifyIdentityVerificationPasskeyWebauthnSignatureActionValuesJSONObject = {
			session_token: sessionToken,
			identity_verification_token: identityVerificationToken,
			webauthn_credential_id: credentialId.toBase64(),
			webauthn_authenticator_data: authenticatorData.toBase64(),
			webauthn_client_data_json: clientDataJSON.toBase64(),
			webauthn_signature: signature.toBase64(),
		};
		const verifyIdentityVerificationPasskeyWebauthnSignatureActionRequestBodyJSONObject = {
			action: "verify_identity_verification_passkey_webauthn_signature",
			values: verifyIdentityVerificationPasskeyWebauthnSignatureActionValuesJSONObject,
		};

		const verifyIdentityVerificationPasskeyWebauthnSignatureActionRequest = new Request("/action", {
			method: "POST",
			body: JSON.stringify(
				verifyIdentityVerificationPasskeyWebauthnSignatureActionRequestBodyJSONObject,
			),
		});
		verifyIdentityVerificationPasskeyWebauthnSignatureActionRequest.headers.set(
			"Content-Type",
			"application/json",
		);

		let verifiedAction;
		try {
			const response = await fetch(verifyIdentityVerificationPasskeyWebauthnSignatureActionRequest);
			if (!response.ok) {
				await response.body.cancel();
				throw new Error(`Unexpected response status code ${response.status}`);
			}
			const resultJSONObject = await response.json();
			if (!resultJSONObject.ok) {
				if (resultJSONObject.error_code === "invalid_session_token") {
					clientStateEventChannel.postMessage("session_updated");
					if (window.location.protocol === "https:") {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					} else {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}
					alert("Your session has expired.");
					window.location.href = "/sign-in";
					return;
				}
				if (
					resultJSONObject.error_code === "invalid_identity_verification_token" ||
					resultJSONObject.error_code === "session_mismatch"
				) {
					clientStateEventChannel.postMessage("identity_verification_updated");
					if (window.location.protocol === "https:") {
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					} else {
						document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}
					alert("Your session has expired.");
					window.location.href = "/account";
					return;
				}
				if (resultJSONObject.error_code === "passkey_not_found") {
					alert("This passkey has been deleted.");
					verifyWithPasskeyButtonElement.disabled = false;
					return;
				}
				if (resultJSONObject.error_code === "invalid_webauthn_signature") {
					alert("Please try again.");
					verifyWithPasskeyButtonElement.disabled = false;
					return;
				}
				throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
			}

			verifiedAction = resultJSONObject.values.verified_action;
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			verifyWithPasskeyButtonElement.disabled = false;
			return;
		}

		clientStateEventChannel.postMessage("identity_verification_updated");

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
	});
}

const verifyWithEmailCodeButtonElement = document.getElementById("verify-with-email-code-button");
verifyWithEmailCodeButtonElement.addEventListener("click", async () => {
	verifyWithEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		identity_verification_token: identityVerificationToken,
	};
	const requestBodyJSONObject = {
		action: "issue_identity_verification_email_code",
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
				clientStateEventChannel.postMessage("session_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_identity_verification_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				clientStateEventChannel.postMessage("identity_verification_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				verifyWithEmailCodeButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		verifyWithEmailCodeButtonElement.disabled = false;
		return;
	}

	clientStateEventChannel.postMessage("identity_verification_updated");

	window.location.href = "/verify-identity/verify-email-code";
});

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		identity_verification_token: identityVerificationToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_identity_verification",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let cancelledAction;
	try {
		const response = await fetch(request);
		if (!response.ok) {
			await response.body.cancel();
			throw new Error(`Unexpected response status code ${response.status}`);
		}
		const resultJSONObject = await response.json();
		if (!resultJSONObject.ok) {
			if (resultJSONObject.error_code === "invalid_session_token") {
				clientStateEventChannel.postMessage("session_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_identity_verification_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				clientStateEventChannel.postMessage("identity_verification_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		cancelledAction = resultJSONObject.values.cancelled_action;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("identity_verification_updated");

	if (cancelledAction === "email_address_update") {
		if (window.location.protocol === "https:") {
			document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("email_address_update_updated");
	} else if (cancelledAction === "passkey_registration") {
		if (window.location.protocol === "https:") {
			document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("passkey_registration_updated");
	} else if (cancelledAction === "passkey_deletion") {
		if (window.location.protocol === "https:") {
			document.cookie = `passkey_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `passkey_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("passkey_deletion_updated");
	} else if (cancelledAction === "account_deletion") {
		if (window.location.protocol === "https:") {
			document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("account_deletion_updated");
	}

	window.location.href = "/account";
});
