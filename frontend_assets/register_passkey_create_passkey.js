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
            { type: "public-key", alg: -257 }
        ],
        excludeCredentials: [],
        authenticatorSelection: {
            residentKey: "required",
            requireResidentKey: true,
            userVerification: "required"
        },
        attestation: "none"
    };
    for (const credentialId of passkeyWebauthnCredentialIds) {
        publicKeyOptions.excludeCredentials.push({
            id: credentialId,
            type: "public-key"
        })
    }

    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyOptions,
        })
    } catch (error) {
        if (error.name === "NotAllowedError") {
            alert("Request cancelled. Please try again.");
            createPasskeyButtonElement.disabled = false;
            return
        }
        if (error.name === "NotSupportedError") {
            alert("Your device, password manager, or security key is not supported.");
            createPasskeyButtonElement.disabled = false;
            return
        }
        if (error.name === "InvalidStateError") {
            alert("Your device, password manager, or security key already holds a registered passkey.");
            createPasskeyButtonElement.disabled = false;
            return
        }
        console.error(error);
        alert("An unexpected error occurred. Please try again.");
        createPasskeyButtonElement.disabled = false;
        return
    }

    const authenticatorDataBytes = new Uint8Array(credential.response.getAuthenticatorData());
    const parseAuthenticatorDataResult = parseAuthenticatorDataBytes(authenticatorDataBytes);
    
	const actionValuesJSONObject = {
		session_token: sessionToken,
        passkey_registration_token: passkeyRegistrationToken,
        webauthn_credential_id: parseAuthenticatorDataResult.credentialId.toBase64(),
        signature_algorithm: parseAuthenticatorDataResult.signatureAlgorithm,
        public_key: parseAuthenticatorDataResult.publicKey.toBase64(),
        webauthn_authenticator_id: parseAuthenticatorDataResult.aaguid.toBase64(),
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
			if (resultJSONObject.error_code === "invalid_passkey_registration_token" || resultJSONObject.error_code === "session_mismatch") {
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
			if (resultJSONObject.error_code === "invalid_passkey_registration_token" || resultJSONObject.error_code === "session_mismatch") {
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

function parseAuthenticatorDataBytes(bytes) {
    const aaguid = bytes.slice(37, 53);
    const credentialIdSize = bytes[53] << 8 | bytes[54];
    const credentialId = bytes.slice(55, 55 + credentialIdSize);
    const parseCOSEPublicKeyResult = parseCOSEPublicKey(bytes.slice(55 + credentialIdSize));

    const result = {
        aaguid,
        credentialId,
        signatureAlgorithm: parseCOSEPublicKeyResult.signatureAlgorithm,
        publicKey: parseCOSEPublicKeyResult.publicKey
    };
    return result;
};

function parseCOSEPublicKey(bytes) {
    if ((bytes[0] >>> 5) !== 5) {
        throw new Error("expected map major type");
    }
    if ((bytes[0] & 0x1f) >= 24) {
        throw new Error("expected small pair count");
    }
    if (bytes[1] !== 0x01) {
       throw new Error("expected cbor unsigned integer with value of 1 (kty)");
    }
    if (bytes[2] === 0x01) {
        // Ed25519
        if (bytes.length !== 42) {
           throw new Error("unexpected byte length");
        }
        if (bytes[3] !== 0x03) {
            throw new Error("expected cbor unsigned integer with value of 3 (alg)");
        }
        if (bytes[4] !== 0x27) {
            throw new Error("expected cbor negative integer with value of -8 (Ed25519)");
        }
        if (bytes[5] !== 0x20) {
            throw new Error("expected cbor negative integer with value of -1 (crv)");
        }
        if (bytes[6] !== 0x06) {
            throw new Error("expected cbor unsigned integer with value of 6 (Ed25519)");
        }
        if (bytes[7] !== 0x21) {
            throw new Error("expected cbor negative integer with value of -2 (x)");
        }
        if (bytes[8] !== 0x58 || bytes[9] !== 32) {
            throw new Error("expected cbor binary string with size of 32 bytes");
        }
        const x = bytes.slice(10, 42);
        const result = {
            signatureAlgorithm: "ed25519",
            publicKey: x,
        };
        return result;
    }
    if (bytes[2] === 0x02) {
        // ES256
        if (bytes.length !== 77) {
            throw new Error("unexpected byte length");
        }
        if (bytes[3] !== 0x03) {
            throw new Error("expected cbor unsigned integer with value of 3 (alg)");
        }
        if (bytes[4] !== 0x26) {
            throw new Error("expected cbor negative integer with value of -7 (ES256)");
        }
        if (bytes[5] !== 0x20) {
            throw new Error("expected cbor negative integer with value of -1 (crv)");
        }
        if (bytes[6] !== 0x01) {
            throw new Error("expected cbor unsigned integer with value of 1 (P-256)");
        }
        if (bytes[7] !== 0x21) {
            throw new Error("expected cbor negative integer with value of -2 (x)");
        }
        if (bytes[8] !== 0x58 || bytes[9] !== 32) {
            throw new Error("expected cbor binary string with size of 32 bytes");
        }
        const x = bytes.slice(10, 42);
        if (bytes[42] !== 0x22) {
            throw new Error("expected cbor negative integer with value of -3 (y)");
        }
        if (bytes[43] !== 0x58 || bytes[44] !== 32) {
            throw new Error("expected cbor binary string with size of 32 bytes");
        }
        const y = bytes.slice(45, 77);
        const publicKey = new Uint8Array(65);
        publicKey[0] = 0x04;
        publicKey.set(x, 1);
        publicKey.set(y, 33);
        const result = {
            signatureAlgorithm: "ecdsa.p256.sha256",
            publicKey,
        };
        return result;
    }
    if (bytes[2] === 0x03) {
        // RS256
        if (bytes.length !== 272) {
            throw new Error("unexpected byte length");
        }
        if (bytes[3] !== 0x03) {
            throw new Error("expected cbor unsigned integer with value of 3 (alg)");
        }
        if (bytes[4] !== 0x39 || bytes[5] !== 0x01 || bytes[6] !== 0x00) {
            throw new Error("expected cbor negative integer with value of -257 (RS256)");
        }
        if (bytes[7] !== 0x20) {
            throw new Error("expected cbor negative integer with value of -1 (n)");
        }
        if (bytes[8] === 0x39 || bytes[9] !== 0x01 || bytes[10] !== 0x00) {
            throw new Error("expected cbor binary string with size of 256 bytes");
        }
        const n = bytes.slice(11, 267);
        if (bytes[267] !== 0x21) {
            throw new Error("expected cbor negative integer with value of -2 (3)");
        }
        if (bytes[268] !== 0x43 || bytes[269] !== 0x01 || bytes[270] !== 0x00 || bytes[271] !== 0x01) {
            throw new Error("expected cbor unsigned integer with value of 65537");
        }
        const publicKey = new Uint8Array(270);
        publicKey[0] = 0x30;
        publicKey[1] = 0x82;
        publicKey[2] = 0x01;
        publicKey[3] = 0x0a;
        publicKey[4] = 0x02;
        publicKey[5] = 0x82;
        publicKey[6] = 0x01;
        publicKey[7] = 0x01;
        publicKey[8] = 0x00;
        publicKey.set(n, 9);
        publicKey[265] = 0x02;
        publicKey[266] = 0x03;
        publicKey[267] = 0x01;
        publicKey[268] = 0x00;
        publicKey[269] = 0x01;

        const result = {
            signatureAlgorithm: "rsassa_pkcs1_v1_5.sha256",
            publicKey,
        };
        return result;
    }
    throw new Error("unknown key type");
};