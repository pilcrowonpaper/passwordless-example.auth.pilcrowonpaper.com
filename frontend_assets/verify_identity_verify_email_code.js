const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const identityVerificationToken = pageDataJSONObject.identity_verification_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (
		event.data === "session_updated" ||
		event.data === "identity_verification_updated" ||
		event.data === "identity_verification_email_code_verification_updated"
	) {
		window.location.reload();
	}
});

document.getElementById("verify-email-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailCodeInputValue = formData.get("email_code");
	const emailCode = emailCodeInputValue.replaceAll(" ", "").replaceAll("-", "");

	const actionValuesJSONObject = {
		session_token: sessionToken,
		identity_verification_token: identityVerificationToken,
		email_code: emailCode,
	};
	const requestBodyJSONObject = {
		action: "verify_identity_verification_email_code",
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let verifiedAction;
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
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_identity_verification_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				if (window.location.protocol === "https:") {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("identity_verification_updated");

				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "email_code_not_issued") {
				alert("Your session has expired.");
				window.location.href = "/verify-identity";
				return;
			}
			if (resultJSONObject.error_code === "incorrect_email_code") {
				alert("Incorrect email code.");
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

		verifiedAction = resultJSONObject.values.verified_action;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
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
		submitButtonElement.disabled = false;
		return;
	}
});

const resendEmailCodeButtonElement = document.getElementById("resend-email-code-button");

resendEmailCodeButtonElement.addEventListener("click", async () => {
	resendEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		identity_verification_token: identityVerificationToken,
	};
	const requestBodyJSONObject = {
		action: "send_identity_verification_email_code",
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
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_identity_verification_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				if (window.location.protocol === "https:") {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("identity_verification_updated");

				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				resendEmailCodeButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "email_code_not_issued") {
				alert("Your session has expired.");
				window.location.href = "/verify-identity";
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendEmailCodeButtonElement.disabled = false;
		return;
	}

	alert("We've sent another email to your inbox.");
	resendEmailCodeButtonElement.disabled = false;
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		identity_verification_token: identityVerificationToken,
	};
	const requestBodyJSONObject = {
		action: "revoke_identity_verification_email_code",
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
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_identity_verification_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				if (window.location.protocol === "https:") {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `identity_verification_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("identity_verification_updated");

				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "email_code_not_issued") {
				alert("Your session has expired.");
				window.location.href = "/verify-identity";
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

	clientStateEventChannel.postMessage("identity_verification_updated");

	window.location.href = "/verify-identity";
});
