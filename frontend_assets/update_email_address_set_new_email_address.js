"use strict";

const pageDataJSONObject = JSON.parse(document.getElementById("data").innerText);
const authSessionToken = pageDataJSONObject.auth_session_token;
const emailAddressUpdateSessionToken = pageDataJSONObject.email_address_update_session_token;

const setNewEmailAddressFormElement = document.getElementById("set-new-email-address-form");
setNewEmailAddressFormElement.addEventListener("submit", handleSetNewEmailAddressFormSubmitEvent);

const cancelButtonElement = document.getElementById("cancel-button");
cancelButtonElement.addEventListener("click", handleCancelButtonClickEvent);

async function handleSetNewEmailAddressFormSubmitEvent(event) {
	event.preventDefault();

	const submitButtonElement = document.getElementById("set-new-email-address-form-submit-button");
	submitButtonElement.disabled = true;

	const formData = new FormData(event.target);
	const newEmailAddress = formData.get("new_email_address");

	const actionValuesJSONObject = {
		auth_session_token: authSessionToken,
		email_address_update_session_token: emailAddressUpdateSessionToken,
		new_email_address: newEmailAddress,
	};

	let actionResult;
	try {
		actionResult = await sendActionRequest(
			"set_email_address_update_new_email_address",
			actionValuesJSONObject,
		);
	} catch (error) {
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	if (!actionResult.ok) {
		if (actionResult.errorCode === "invalid_auth_session_token") {
			deleteSessionToken();
			deleteEmailAddressUpdateSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/sign-in";
			return;
		}
		if (
			actionResult.errorCode === "invalid_email_address_update_session_token" ||
			actionResult.errorCode === "session_mismatch"
		) {
			deleteEmailAddressUpdateSessionTokenCookie();

			alert("Your session has expired.");
			window.location.href = "/account";
			return;
		}
		if (actionResult.errorCode === "email_address_already_used") {
			alert("This email address already linked to an existing account.");
			submitButtonElement.disabled = false;
			return;
		}
		if (actionResult.errorCode === "rate_limited") {
			alert("Too many attempts. Please try again later.");
			submitButtonElement.disabled = false;
			return;
		}
		const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
		console.error(error);
		alert("An unexpected error occurred. Please try again.");
		submitButtonElement.disabled = false;
		return;
	}

	window.location.href = "/update-email-address/verify-new-email-address";
}

async function handleCancelButtonClickEvent() {
	{
		cancelButtonElement.disabled = true;

		const actionValuesJSONObject = {
			auth_session_token: authSessionToken,
			email_address_update_session_token: emailAddressUpdateSessionToken,
		};

		let actionResult;
		try {
			actionResult = await sendActionRequest("cancel_email_address_update", actionValuesJSONObject);
		} catch (error) {
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			cancelButtonElement.disabled = false;
			return;
		}

		if (!actionResult.ok) {
			if (actionResult.errorCode === "invalid_auth_session_token") {
				deleteSessionToken();
				deleteEmailAddressUpdateSessionTokenCookie();

				alert("Your session has expired.");
				window.location.href = "/sign-in";
				return;
			}
			if (
				actionResult.errorCode === "invalid_email_address_update_session_token" ||
				actionResult.errorCode === "session_mismatch"
			) {
				deleteEmailAddressUpdateSessionTokenCookie();

				alert("Your session has expired.");
				window.location.href = "/account";
				return;
			}
			const error = new Error(`Unexpected error code ${actionResult.errorCode}`);
			console.error(error);
			alert("An unexpected error occurred. Please try again.");
			cancelButtonElement.disabled = false;
			return;
		}

		deleteEmailAddressUpdateSessionTokenCookie();

		window.location.href = "/account";
	}
}
