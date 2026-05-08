"use strict";

window.addEventListener("pageshow", () => {
	const buttonElements = document.getElementsByTagName("button");
	for (const buttonElement of buttonElements) {
		buttonElement.disabled = false;
	}
});

function setSessionTokenCookie(authSessionToken) {
	setCookieWithExpiration("auth_session_token", authSessionToken, 86400);
}

function deleteSessionTokenCookie() {
	setCookieWithExpiration("auth_session_token", "", 0);
}

function setSignupSessionTokenCookie(signupSessionToken) {
	setCookieWithExpiration("signup_session_token", signupSessionToken, 86400);
}

function deleteSignupSessionTokenCookie() {
	setCookieWithExpiration("signup_session_token", "", 0);
}

function setEmailAddressUpdateSessionTokenCookie(emailAddressUpdateSessionToken) {
	setCookieWithExpiration(
		"email_address_update_session_token",
		emailAddressUpdateSessionToken,
		86400,
	);
}

function deleteEmailAddressUpdateSessionTokenCookie() {
	setCookieWithExpiration("email_address_update_session_token", "", 0);
}

function setPasskeyRegistrationSessionTokenCookie(passkeyRegistrationSessionToken) {
	setCookieWithExpiration(
		"passkey_registration_session_token",
		passkeyRegistrationSessionToken,
		86400,
	);
}

function deletePasskeyRegistrationSessionTokenCookie() {
	setCookieWithExpiration("passkey_registration_session_token", "", 0);
}

function setPasskeyDeletionSessionTokenCookie(passkeyDeletionSessionToken) {
	setCookieWithExpiration("passkey_deletion_session_token", passkeyDeletionSessionToken, 86400);
}

function deletePasskeyDeletionSessionTokenCookie() {
	setCookieWithExpiration("passkey_deletion_session_token", "", 0);
}

function setAccountDeletionSessionTokenCookie(accountDeletionSessionToken) {
	setCookieWithExpiration("account_deletion_session_token", accountDeletionSessionToken, 86400);
}

function deleteAccountDeletionSessionTokenCookie() {
	setCookieWithExpiration("account_deletion_session_token", "", 0);
}

function setIdentityVerificationSessionTokenCookie(identityVerificationSessionToken) {
	setCookieWithExpiration(
		"identity_verification_session_token",
		identityVerificationSessionToken,
		86400,
	);
}

function deleteIdentityVerificationSessionTokenCookie() {
	setCookieWithExpiration("identity_verification_session_token", "", 0);
}

function setEmailCodeSigninSessionTokenCookie(emailCodeSigninSessionToken) {
	setCookieWithExpiration("email_code_signin_session_token", emailCodeSigninSessionToken, 86400);
}

function deleteEmailCodeSigninSessionTokenCookie() {
	setCookieWithExpiration("email_code_signin_session_token", "", 0);
}

function setCookieWithExpiration(name, value, maxAge) {
	if (window.location.protocol === "https:") {
		document.cookie = `${name}=${value}; Max-Age=${maxAge}; SameSite=Lax; Path=/; Secure`;
	} else {
		document.cookie = `${name}=${value}; Max-Age=${maxAge}; SameSite=Lax; Path=/`;
	}
}

async function sendActionRequest(action, actionValuesJSONObject) {
	const requestBodyJSONObject = {
		action: action,
		values: actionValuesJSONObject,
	};
	const requestBody = JSON.stringify(requestBodyJSONObject);

	const request = new Request("/action", {
		method: "POST",
		body: requestBody,
	});
	request.headers.set("Content-Type", "application/json");

	let response;
	try {
		response = await fetch(request);
	} catch (error) {
		throw new Error("Failed to fetch request", {
			cause: error,
		});
	}

	if (!response.ok) {
		await response.body.cancel();
		throw new Error(`Unexpected response status code ${response.status}`);
	}

	const resultJSONObject = await response.json();
	if (!resultJSONObject.ok) {
		const result = {
			ok: false,
			errorCode: resultJSONObject.error_code,
		};
		return result;
	}

	const result = {
		ok: true,
		valuesJSONObject: resultJSONObject.values,
	};

	return result;
}
