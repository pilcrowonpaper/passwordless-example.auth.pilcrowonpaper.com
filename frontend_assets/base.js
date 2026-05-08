"use strict";

window.addEventListener("pageshow", () => {
	const buttonElements = document.getElementsByTagName("button");
	for (const buttonElement of buttonElements) {
		buttonElement.disabled = false;
	}
});

function setSessionTokenCookie(sessionToken) {
	setCookieWithExpiration("session_token", sessionToken, 86400);
}

function deleteSessionTokenCookie() {
	setCookieWithExpiration("session_token", "", 0);
}

function setSignupTokenCookie(signupToken) {
	setCookieWithExpiration("signup_token", signupToken, 86400);
}

function deleteSignupTokenCookie() {
	setCookieWithExpiration("signup_token", "", 0);
}

function setEmailAddressUpdateTokenCookie(emailAddressUpdateToken) {
	setCookieWithExpiration("email_address_update_token", emailAddressUpdateToken, 86400);
}

function deleteEmailAddressUpdateTokenCookie() {
	setCookieWithExpiration("email_address_update_token", "", 0);
}

function setPasskeyRegistrationTokenCookie(passkeyRegistrationToken) {
	setCookieWithExpiration("passkey_registration_token", passkeyRegistrationToken, 86400);
}

function deletePasskeyRegistrationTokenCookie() {
	setCookieWithExpiration("passkey_registration_token", "", 0);
}

function setPasskeyDeletionTokenCookie(passkeyDeletionToken) {
	setCookieWithExpiration("passkey_deletion_token", passkeyDeletionToken, 86400);
}

function deletePasskeyDeletionTokenCookie() {
	setCookieWithExpiration("passkey_deletion_token", "", 0);
}

function setAccountDeletionTokenCookie(accountDeletionToken) {
	setCookieWithExpiration("account_deletion_token", accountDeletionToken, 86400);
}

function deleteAccountDeletionTokenCookie() {
	setCookieWithExpiration("account_deletion_token", "", 0);
}

function setIdentityVerificationTokenCookie(identityVerificationToken) {
	setCookieWithExpiration("identity_verification_token", identityVerificationToken, 86400);
}

function deleteIdentityVerificationTokenCookie() {
	setCookieWithExpiration("identity_verification_token", "", 0);
}

function setEmailCodeSigninTokenCookie(emailCodeSigninToken) {
	setCookieWithExpiration("email_code_signin_token", emailCodeSigninToken, 86400);
}

function deleteEmailCodeSigninTokenCookie() {
	setCookieWithExpiration("email_code_signin_token", "", 0);
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
