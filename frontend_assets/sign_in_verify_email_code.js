const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const emailCodeSigninToken = pageDataJSONObject.email_code_signin_token;

document.getElementById("verify-email-code-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("verify-email-code-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailCodeInputValue = formData.get("email_code");
	const emailCode = emailCodeInputValue.replaceAll(" ", "").replaceAll("-", "");

	const actionValuesJSONObject = {
		email_code_signin_token: emailCodeSigninToken,
		email_code: emailCode,
	};
	const requestBodyJSONObject = {
		action: "verify_email_code_signin_email_code",
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
			if (resultJSONObject.error_code === "invalid_email_code_signin_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}

				alert("Your session has expired.");
				window.location.href = "/account";
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

		sessionToken = resultJSONObject.values.session_token;
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/`;
		document.cookie = `session_token=${sessionToken}; Max-Age=86400; SameSite=Lax; Path=/`;
	}

	window.location.href = "/account";
});

const cancelButtonElement = document.getElementById("cancel-button");

cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		email_code_signin_token: emailCodeSigninToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_email_code_signin",
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
			if (resultJSONObject.error_code === "invalid_email_code_signin_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/`;
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

	window.location.href = "/sign-in";
});

const resendEmailCodeButtonElement = document.getElementById("resend-email-code-button");

resendEmailCodeButtonElement.addEventListener("click", async () => {
	resendEmailCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		email_code_signin_token: emailCodeSigninToken,
	};
	const requestBodyJSONObject = {
		action: "send_email_code_signin_email_code",
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
			if (resultJSONObject.error_code === "invalid_email_code_signin_token") {
				if (window.location.protocol === "https:") {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `email_code_signin_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}

				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			if (resultJSONObject.error_code === "rate_limited") {
				alert("Too many attempts. Please try again later.");
				resendEmailCodeButtonElement.disabled = false;
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
