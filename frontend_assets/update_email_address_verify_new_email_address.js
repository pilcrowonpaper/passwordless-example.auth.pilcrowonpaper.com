const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const emailAddressUpdateToken = pageDataJSONObject.email_address_update_token;

document
	.getElementById("verify-verification-code-form")
	.addEventListener("submit", async (event) => {
		event.preventDefault();

		const submitButtonElement = document.getElementById(
			"verify-verification-code-form-submit-button",
		);
		submitButtonElement.disabled = true;

		const formData = new FormData(event.target);
		const verificationCodeInputValue = formData.get("verification_code");
		const verificationCode = verificationCodeInputValue
			.replaceAll(" ", "")
			.replaceAll("-", "")
			.toUpperCase();

		const actionValuesJSONObject = {
			session_token: sessionToken,
			email_address_update_token: emailAddressUpdateToken,
			verification_code: verificationCode,
		};
		const requestBodyJSONObject = {
			action: "verify_email_address_update_new_email_address_verification_code",
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
						document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					} else {
						document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
						document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}

					alert("Your session has expired.");
					window.location.href = "/sign-in";
					return;
				}
				if (
					resultJSONObject.error_code === "invalid_email_address_update_token" ||
					resultJSONObject.error_code === "session_mismatch"
				) {
					if (window.location.protocol === "https:") {
						document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					} else {
						document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
					}

					alert("Your session has expired.");
					window.location.href = "/account";
					return;
				}
				if (resultJSONObject.error_code === "email_address_already_used") {
					alert("This email address is already linked to an existing account.");
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
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			submitButtonElement.disabled = false;
			return;
		}

		if (window.location.protocol === "https:") {
			document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
		}

		window.location.href = "/account";
	});

const resendVerificationCodeButtonElement = document.getElementById(
	"resend-verification-code-button",
);

resendVerificationCodeButtonElement.addEventListener("click", async () => {
	resendVerificationCodeButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		email_address_update_token: emailAddressUpdateToken,
	};
	const requestBodyJSONObject = {
		action: "send_email_address_update_new_email_address_verification_code",
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
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				resultJSONObject.error_code === "invalid_email_address_update_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
				if (window.location.protocol === "https:") {
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}

				alert("Your session has expired.");
				window.location.href = "/account";
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
		session_token: sessionToken,
		email_address_update_token: emailAddressUpdateToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_email_address_update",
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
			if (
				resultJSONObject.error_code === "invalid_session_token" ||
				resultJSONObject.error_code === "invalid_email_address_update_token"
			) {
				if (window.location.protocol === "https:") {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}

				alert("Your session has expired.");
				window.location.href = "/sign-in";
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
		document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `email_address_update_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}

	window.location.href = "/account";
});
