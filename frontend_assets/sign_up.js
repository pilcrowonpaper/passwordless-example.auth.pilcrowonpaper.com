const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated") {
		window.location.reload();
	}
});

document.getElementById("sign-up-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("sign-up-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const emailAddress = formData.get("email_address");

	const actionValuesJSONObject = {
		email_address: emailAddress,
	};
	const requestBodyJSONObject = {
		action: "start_signup",
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
			if (resultJSONObject.error_code === "invalid_email_address") {
				alert("Please enter a valid email address.");
				submitButtonElement.disabled = false;
				return;
			}
			if (resultJSONObject.error_code === "email_address_already_used") {
				alert("This email address is already linked to an existing account.");
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

		if (window.location.protocol === "https:") {
			document.cookie = `signup_token=${resultJSONObject.values.signup_token}; Max-Age=3600; SameSite=Lax; Path=/; Secure`;
		} else {
			document.cookie = `signup_token=${resultJSONObject.values.signup_token}; Max-Age=3600; SameSite=Lax; Path=/`;
		}
		clientStateEventChannel.postMessage("signup_updated");
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/sign-up/verify-email-address";
});
