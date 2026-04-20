const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const signupToken = pageDataJSONObject.signup_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "signup_updated") {
		window.location.reload();
	}
});

document.getElementById("verify-verification-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-verification-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const verificationCodeInputValue = formData.get("verification_code");
	const verificationCode = verificationCodeInputValue.replaceAll(" ", "").replaceAll("-", "");

	const actionValuesJSONObject = {
		signup_token: signupToken,
		verification_code: verificationCode,
	};
	const requestBodyJSONObject = {
		action: "verify_signup_email_address_verification_code",
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
			if (resultJSONObject.error_code === "incorrect_verification_code") {
				alert("Incorrect verification code.");
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

		clientStateEventChannel.postMessage("signup_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/sign-up/register-passkey";
});

const resendVerificationCodeButtonElement = document.getElementById("resend-verification-code-button");
resendVerificationCodeButtonElement.addEventListener("click", async () => {
	resendVerificationCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};
	const requestBodyJSONObject = {
		action: "send_signup_email_address_verification_code",
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
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				resendVerificationCodeButtonElement.disabled = false;
				return;
			}
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		resendVerificationCodeButtonElement.disabled = false;
		return;
	}

	alert("We've sent another email to your inbox.");
	resendVerificationCodeButtonElement.disabled = false;
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		signup_token: signupToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_signup",
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
			throw new Error(`Unexpected error code ${resultJSONObject.error_code}`);
		}

		clientStateEventChannel.postMessage("signup_updated");
		if (window.location.protocol === "https:") {
			document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `signup_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		cancelButtonElement.disabled = false;
		return;
	}

	window.location.href = "/sign-up";
});
