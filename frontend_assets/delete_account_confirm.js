const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const sessionToken = pageDataJSONObject.session_token;
const accountDeletionToken = pageDataJSONObject.account_deletion_token;

const clientStateEventChannel = new BroadcastChannel("client_state_event");
clientStateEventChannel.addEventListener("message", (event) => {
	if (event.data === "session_updated" || event.data === "account_deletion_updated") {
		window.location.reload();
	}
});

const confirmButtonElement = document.getElementById("confirm-button");
confirmButtonElement.addEventListener("click", async () => {
	confirmButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		account_deletion_token: accountDeletionToken,
	};
	const requestBodyJSONObject = {
		action: "confirm_account_deletion",
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
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "invalid_account_deletion_token" || resultJSONObject.error_code === "session_mismatch") {
				clientStateEventChannel.postMessage("account_deletion_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
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
		confirmButtonElement.disabled = false;
		return;
	}

	if (window.location.protocol === "https:") {
		document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("account_deletion_updated");

	window.location.href = "/account";
});

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", async () => {
	cancelButtonElement.disabled = true;

	const actionValuesJSONObject = {
		session_token: sessionToken,
		account_deletion_token: accountDeletionToken,
	};
	const requestBodyJSONObject = {
		action: "cancel_account_deletion",
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
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `session_token=; Max-Age=0; SameSite=Lax; Path=/`;
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
				}
				clientStateEventChannel.postMessage("session_updated");

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (resultJSONObject.error_code === "invalid_account_deletion_token" || resultJSONObject.error_code === "session_mismatch") {
				clientStateEventChannel.postMessage("account_deletion_updated");
				if (window.location.protocol === "https:") {
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
				} else {
					document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
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
		document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `account_deletion_token=; Max-Age=0; SameSite=Lax; Path=/`;
	}
	clientStateEventChannel.postMessage("account_deletion_updated");

	window.location.href = "/account";
});
