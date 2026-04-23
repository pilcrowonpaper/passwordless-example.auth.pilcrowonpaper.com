const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const passkeyRegistrationToken = pageDataJSONObject.passkey_registration_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "passkey_registration_updated") {
		window.location.reload();
	}
});

document.getElementById("set-passkey-name-form").addEventListener("submit", async (event) => {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-passkey-name-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const passkeyName = formData.get("passkey_name").trim();

	const actionValuesJSONObject = {
		session_token: sessionToken,
		passkey_registration_token: passkeyRegistrationToken,
		passkey_name: passkeyName,
	};
	const requestBodyJSONObject = {
		action: "set_passkey_registration_passkey_name",
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
			if (
				resultJSONObject.error_code === "invalid_passkey_registration_token" ||
				resultJSONObject.error_code === "session_mismatch"
			) {
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
			if (resultJSONObject.error_code === "invalid_passkey_name") {
				alert("Please enter a valid passkey name.");
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
		document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `passkey_registration_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("passkey_registration_updated");

	window.location.href = "/account";
});
