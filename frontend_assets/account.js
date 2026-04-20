const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated") {
		window.location.reload();
	}
});

const updateEmailAddressButtonElement = document.getElementById("update-email-address-button");
updateEmailAddressButtonElement.addEventListener("click", async () => {
	updateEmailAddressButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "start_email_address_update",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let emailAddressUpdateToken;
	let identityVerificationToken;
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
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				updateEmailAddressButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		emailAddressUpdateToken = resultJSONObject.values.email_address_update_token;
		identityVerificationToken = resultJSONObject.values.identity_verification_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		updateEmailAddressButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `email_address_update_token=${emailAddressUpdateToken}; Max-Age=4800; SameSite=Lax; Path=/; Secure`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `email_address_update_token=${emailAddressUpdateToken}; Max-Age=4800; SameSite=Lax; Path=/;`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/;`;
	}
	clientStateEventChannel.postMessage("email_address_update_updated");
	clientStateEventChannel.postMessage("identity_verification_updated");

	window.location.href = "/verify-identity";
});

const deletePasskeyButtonElements = document.getElementsByClassName("delete-passkey-button");
for (const deletePasskeyButtonElement of deletePasskeyButtonElements) {
	deletePasskeyButtonElement.addEventListener("click", async () => {
		const passkeyId = deletePasskeyButtonElement.getAttribute("data-passkey-id");

		deletePasskeyButtonElement.disabled = true;

		const actionValuesJSONObject = {
			session_token: sessionToken,
			passkey_id: passkeyId,
		};
		const requestBodyJSONObject = {
			action: "start_passkey_deletion",
			values: actionValuesJSONObject,
		};
		const requestBody = JSON.stringify(requestBodyJSONObject);

		const request = new Request("/action", {
			method: "POST",
			body: requestBody,
		});
		request.headers.set("Content-Type", "application/json");

		let passkeyDeletionToken;
		let identityVerificationToken;
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
					} else {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}
					clientStateEventChannel.postMessage("session_updated");

					alert("Your session has expired.");
					window.location.href = "/sign-in";
					return;
				}
				if (resultJSONObject.error_code === "rate_limited") {
					alert("Too many attempts. Please try again later.");
					deletePasskeyButtonElement.disabled = false;
					return;
				}
				throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
			}

			passkeyDeletionToken = resultJSONObject.values.passkey_deletion_token;
			identityVerificationToken = resultJSONObject.values.identity_verification_token;
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			deletePasskeyButtonElement.disabled = false;
			return;
		}

		if (window.location.protocol === "https:") {
			document.cookie = `passkey_deletion_token=${passkeyDeletionToken}; Max-Age=4800; SameSite=Lax; Path=/; Secure`;
			document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `passkey_deletion_token=${passkeyDeletionToken}; Max-Age=4800; SameSite=Lax; Path=/;`;
			document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/;`;
		}
		clientStateEventChannel.postMessage("passkey_deletion_updated");
		clientStateEventChannel.postMessage("identity_verification_updated");

		window.location.href = "/verify-identity";
	})
}

const registerPasskeyButtonElement = document.getElementById("register-passkey-button");
registerPasskeyButtonElement.addEventListener("click", async () => {
	registerPasskeyButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "start_passkey_registration",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let passkeyRegistrationToken;
	let identityVerificationToken;
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
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				registerPasskeyButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		passkeyRegistrationToken = resultJSONObject.values.passkey_registration_token;
		identityVerificationToken = resultJSONObject.values.identity_verification_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		registerPasskeyButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `passkey_registration_token=${passkeyRegistrationToken}; Max-Age=4800; SameSite=Lax; Path=/; Secure`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `passkey_registration_token=${passkeyRegistrationToken}; Max-Age=4800; SameSite=Lax; Path=/;`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/;`;
	}
	clientStateEventChannel.postMessage("passkey_registration_updated");
	clientStateEventChannel.postMessage("identity_verification_updated");

	window.location.href = "/verify-identity";
});

const signOutButtonElement = document.getElementById("sign-out-button");
signOutButtonElement.addEventListener("click", async () => {
	signOutButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "sign_out",
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
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				signOutButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/sign-in";
});

const signOutAllDevicesButtonElement = document.getElementById("sign-out-all-devices-button");

signOutAllDevicesButtonElement.addEventListener("click", async () => {
	const confirmed = confirm("Do you want to sign out of all devices?");
	if (!confirmed) {
		return;
	}

	signOutAllDevicesButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "sign_out_all_devices",
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
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				signOutAllDevicesButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		signOutAllDevicesButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("session_updated");

	window.location.href = "/sign-in";
});

const deleteAccountButtonElement = document.getElementById("delete-account-button");
deleteAccountButtonElement.addEventListener("click", async () => {
	deleteAccountButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
	};
	const requestBodyJSONObject = {
		action: "start_account_deletion",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let accountDeletionToken;
	let identityVerificationToken;
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
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				deleteAccountButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		accountDeletionToken = resultJSONObject.values.account_deletion_token;
		identityVerificationToken = resultJSONObject.values.identity_verification_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		deleteAccountButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `account_deletion_token=${accountDeletionToken}; Max-Age=4800; SameSite=Lax; Path=/; Secure`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `account_deletion_token=${accountDeletionToken}; Max-Age=4800; SameSite=Lax; Path=/;`;
		document.cookie = `identity_verification_token=${identityVerificationToken}; Max-Age=3600; SameSite=Lax; Path=/;`;
	}
	clientStateEventChannel.postMessage("account_deletion_updated");
	clientStateEventChannel.postMessage("identity_verification_updated");

	window.location.href = "/verify-identity";
});
