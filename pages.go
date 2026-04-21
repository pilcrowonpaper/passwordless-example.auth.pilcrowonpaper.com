package main

import (
	"encoding/base64"
	"fmt"
	"html"
	"strings"

	"github.com/pilcrowonpaper/go-json"

	_ "embed"
)

//go:embed frontend_assets/home.css
var homePageStylesheet string

func createHomePageHTML(requestId string) string {
	title := "Passwordless auth example"
	bodyHTML := `<h1>Passwordless auth example</h1>
<p>This an example website that implements email code sign-in and passkeys following best practices. All accounts older than 24 hours are automatically deleted at midnight (UTC).</p>
<div id="auth">
	<a href="/sign-in" class="block-button">Sign in</a>
	<a href="/sign-up" class="block-button">Create an account</a>
</div>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, "", homePageStylesheet, "")

	return pageHTML
}

//go:embed frontend_assets/account.js
var accountPageScript string

//go:embed frontend_assets/account.css
var accountPageStylesheet string

func createAccountPageHTML(requestId string, sessionToken string, user userStruct, passkeys []passkeyStruct) string {
	passkeyListHTML := ""
	if len(passkeys) > 0 {
		passkeyListHTMLBuilder := strings.Builder{}
		passkeyListHTMLBuilder.WriteString(`<ul id="passkeys-list">`)
		for _, passkey := range passkeys {
			listItemHTML := fmt.Sprintf(`<li><p>%s</p><button class="delete-passkey-button link-button" data-passkey-id="%s">Delete</button></li>`, html.EscapeString(passkey.name), html.EscapeString(passkey.id))
			passkeyListHTMLBuilder.WriteString(listItemHTML)
		}
		passkeyListHTMLBuilder.WriteString("</ul>")

		passkeyListHTML = passkeyListHTMLBuilder.String()
	}

	title := "My account | Passwordless auth example"
	bodyHTMLTemplate := `<h1>My account</h1>
<section>
	<h2>Account information</h2>
	<p id="account-info-user-id">User ID: %s</p>
	<p id="account-info-email-address">Email address: %s</p>
	<button id="update-email-address-button" class="block-button">Update email address</button>
</section>
<section>
	<h2>Passkeys</h2>
	<p id="passkeys-description">Passkeys are secure login credentials stored on your device, password manager, or security key that allow you to sign in using your device PIN or biometrics.</p>
	%s
	<button id="register-passkey-button" class="block-button">Register passkey</button>
</section>
<section>
	<h2>Sign out</h2>
	<div id="sign-out-controls">
		<button id="sign-out-button" class="block-button">Sign out</button>
		<button id="sign-out-all-devices-button" class="link-button">Sign out of all devices</button>
	</div>
</section>
<section>
	<h2>Delete your account</h2>
	<p id="delete-account-description">Deleting your account will permanently remove all your data. Some logs (including your IP address and email address) may be retained for up to 90 days.</p>
	<button id="delete-account-button" class="block-button">Delete account</button>
</section>`

	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(user.id), html.EscapeString(user.emailAddress), passkeyListHTML)

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, accountPageScript, accountPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/sign_up.js
var signUpPageScript string

//go:embed frontend_assets/sign_up.css
var signUpPageStylesheet string

func createSignUpPageHTML(requestId string) string {
	title := "Create an account | Passwordless auth example"
	bodyHTML := `<h1>Create an account</h1>
<p>All accounts older than 24 hours are permanently deleted at midnight UTC each day. For security purposes, logs (which may include your IP address and email address) are retained for up to 90 days. These logs are processed and stored by <a href="https://cloudflare.com">Cloudflare</a> and <a href="https://railway.com">Railway</a>. We do not share or sell this data to any third parties.</p>
<form id="sign-up-form">
	<label for="sign-up-form-email-address-input">Email address (lowercase)</label>
	<input id="sign-up-form-email-address-input" name="email_address" type="email" required />
	<button id="sign-up-form-submit-button">Continue</button>
</form>
<a id="sign-in-link" href="/sign-in" class="link-button">Sign in with an existing account</a>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpPageScript, signUpPageStylesheet, "")

	return pageHTML
}

//go:embed frontend_assets/sign_up_verify_email_address.js
var signUpVerifyEmailAddressPageScript string

//go:embed frontend_assets/sign_up_verify_email_address.css
var signUpVerifyEmailAddressPageStylesheet string

func createSignUpVerifyEmailAddressPageHTML(requestId string, signupToken string, signup signupStruct) string {
	title := "Verify your email address | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Verify your email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" autocomplete="one-time-code" required />
	<button id="verify-verification-code-form-submit-button">Verify email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(signup.emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("signup_token", signupToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpVerifyEmailAddressPageScript, signUpVerifyEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/sign_up_register_passkey.js
var signUpRegisterPasskeyScript string

//go:embed frontend_assets/sign_up_register_passkey.css
var signUpRegisterPasskeyStylesheet string

func createSignUpRegisterPasskeyPage(requestId string, signupToken string, signup signupStruct) string {
	title := "Register a passkey | Passwordless auth example"

	bodyHTML := `<h1>Register a passkey</h1>
<p>Passkeys are secure login credentials stored on your device, password manager, or security key that allow you to sign in using your device PIN or biometrics.</p>
<div id="controls">
	<button id="create-passkey-button" class="block-button">Create a passkey</button>
	<button id="skip-button" class="link-button">Skip</button>
</div>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("signup_token", signupToken)
	dataJSONBuilder.AddString("signup_target_user_id", signup.targetUserId)
	dataJSONBuilder.AddString("signup_email_address", signup.emailAddress)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpRegisterPasskeyScript, signUpRegisterPasskeyStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/sign_up_register_passkey_set_passkey_name.js
var signUpRegisterPasskeySetPasskeyNameScript string

//go:embed frontend_assets/sign_up_register_passkey_set_passkey_name.css
var signUpRegisterPasskeySetPasskeyNameStylesheet string

func createSignUpRegisterPasskeySetPasskeyNamePage(requestId string, signupToken string, passkeyNameSuggestion string) string {
	title := "Name your passkey | Passwordless auth example"

	template := `<h1>Name your passkey</h1>
<p>Give your passkey a name so you can easily recognize and manage it later.</p>
<form id="set-passkey-name-form">
	<label for="set-passkey-name-form-name-input">Passkey name (Standard characters except double quotes)</label>
	<input id="set-passkey-name-form-name-input" name="passkey_name" required value="%s" />
	<button id="set-passkey-name-form-submit-button">Complete</button>
</form>`
	bodyHTML := fmt.Sprintf(template, html.EscapeString(passkeyNameSuggestion))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("signup_token", signupToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signUpRegisterPasskeySetPasskeyNameScript, signUpRegisterPasskeySetPasskeyNameStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/sign_in.js
var signInPageScript string

//go:embed frontend_assets/sign_in.css
var signInPageStylesheet string

func createSignInPage(requestId string, passkeySignin passkeySigninStruct) string {
	title := "Sign in | Passwordless auth example"

	bodyHTML := `<h1>Sign in</h1>
<form id="sign-in-with-email-code-form">
	<label for="sign-in-with-email-code-form-email-address-input">Email address (lowercase)</label>
	<input id="sign-in-with-email-code-form-email-address-input" name="email_address" type="email" autocomplete="webauthn" required/>
	<button id="sign-in-with-email-code-form-submit-button">Continue</button>
</form>
<button id="sign-in-with-passkey-button" class="link-button">Sign in with passkeys</button>
<div id="links">
	<a id="create-account-link" href="/sign-up" class="link-button">Create a new account</a>
</div>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("passkey_signin_id", passkeySignin.id)
	dataJSONBuilder.AddString("passkey_signin_challenge", base64.StdEncoding.EncodeToString(passkeySignin.challenge))
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signInPageScript, signInPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/sign_in_verify_email_code.js
var signInVerifyEmailCodePageScript string

//go:embed frontend_assets/sign_in_verify_email_code.css
var signInVerifyEmailCodePageStylesheet string

func createSignInVerifyEmailCodePage(requestId string, emailCodeSigninToken string, emailAddress string) string {
	title := "Sign in with email code | Passwordless auth example"

	template := `<h1>Sign in with email code</h1>
<p>We sent a one-time code to %s.</p> 
<form id="verify-email-code-form">
	<label for="verify-email-code-form-email-code-input">Code</label>
	<input id="verify-email-code-form-email-code-input" name="email_code" autocomplete="one-time-code" required/>
	<button id="verify-email-code-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	bodyHTML := fmt.Sprintf(template, html.EscapeString(emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("email_code_signin_token", emailCodeSigninToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, signInVerifyEmailCodePageScript, signInVerifyEmailCodePageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/verify_identity.js
var verifyIdentityPageScript string

//go:embed frontend_assets/verify_identity.css
var verifyIdentityPageStylesheet string

func createVerifyIdentityPageHTML(requestId string, sessionToken string, identityVerificationToken string, identityVerification identityVerificationStruct, passkeys []passkeyStruct) string {
	title := "Verify your identity | Passwordless auth example"

	if len(passkeys) > 0 {
		bodyHTML := `<h1>Verify your identity</h1>
<p>Verify your identity to continue.</p>
<div id="controls">
	<button id="verify-with-passkey-button" class="block-button">Verify with passkeys</button>
	<button id="verify-with-email-code-button" class="link-button">Verify with email code</button>
</div>
<button id="cancel-button" class="link-button">Cancel</button>`

		passkeyWebauthnCredentialIdsJSONArray := json.NewArrayBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
		for _, passkey := range passkeys {
			passkeyWebauthnCredentialIdsJSONArray.AddString(base64.StdEncoding.EncodeToString(passkey.webauthnCredentialId))
		}
		passkeyWebauthnCredentialIdsJSON := passkeyWebauthnCredentialIdsJSONArray.Done()

		dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
		dataJSONBuilder.AddString("session_token", sessionToken)
		dataJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
		dataJSONBuilder.AddString("identity_verification_passkey_verification_challenge", base64.StdEncoding.EncodeToString(identityVerification.passkeyVerificationChallenge))
		dataJSONBuilder.AddJSON("passkey_webauthn_credential_ids", passkeyWebauthnCredentialIdsJSON)
		dataJSON := dataJSONBuilder.Done()

		pageHTML := createPageHTML(requestId, title, bodyHTML, verifyIdentityPageScript, verifyIdentityPageStylesheet, dataJSON)

		return pageHTML
	}

	bodyHTML := `<h1>Verify your identity</h1>
<p>Verify your identity to continue.</p>
<div id="controls">
	<button id="verify-with-email-code-button" class="block-button">Verify with email code</button>
</div>
<button id="cancel-button" class="link-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
	dataJSONBuilder.AddString("identity_verification_passkey_verification_challenge", base64.StdEncoding.EncodeToString(identityVerification.passkeyVerificationChallenge))
	dataJSONBuilder.AddJSON("passkey_webauthn_credential_ids", "[]")
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, verifyIdentityPageScript, verifyIdentityPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/verify_identity_verify_email_code.js
var verifyIdentityVerifyEmailCodePageScript string

//go:embed frontend_assets/verify_identity_verify_email_code.css
var verifyIdentityVerifyEmailCodePageStylesheet string

func createVerifyIdentityVerifyEmailCodePageHTML(requestId string, sessionToken string, identityVerificationToken string, emailAddress string) string {
	title := "Verify identity with email code | Passwordless auth example"

	template := `<h1>Verify identity with email code</h1>
<p>We sent a one-time code to %s.</p> 
<form id="verify-email-code-form">
	<label for="verify-email-code-form-email-code-input">Code</label>
	<input id="verify-email-code-form-email-code-input" name="email_code" autocomplete="one-time-code" required/>
	<button id="verify-email-code-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	bodyHTML := fmt.Sprintf(template, html.EscapeString(emailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("identity_verification_token", identityVerificationToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, verifyIdentityVerifyEmailCodePageScript, verifyIdentityVerifyEmailCodePageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/update_email_address_set_new_email_address.js
var updateEmailAddressSetNewEmailAddressPageScript string

//go:embed frontend_assets/update_email_address_set_new_email_address.css
var updateEmailAddressSetNewEmailAddressPageStylesheet string

func createUpdateEmailAddressSetNewEmailAddressPageHTML(requestId string, sessionToken string, emailAddressUpdateToken string) string {
	title := "Set your new email address | Passwordless auth example"

	bodyHTML := `<h1>Set your new email address</h1>
<form id="set-new-email-address-form">
	<label for="set-new-email-address-form-new-email-address-input">New email address</label>
	<input id="set-new-email-address-form-new-email-address-input" name="new_email_address" type="email" required />
	<button id="set-new-email-address-form-submit-button">Continue</button>
</form>
<button id="cancel-button" class="link-button">Cancel</button>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updateEmailAddressSetNewEmailAddressPageScript, updateEmailAddressSetNewEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/update_email_address_verify_new_email_address.js
var updateEmailAddressVerifyNewEmailAddressPageScript string

//go:embed frontend_assets/update_email_address_verify_new_email_address.css
var updateEmailAddressVerifyNewEmailAddressPageStylesheet string

func createUpdateEmailAddressVerifyNewEmailAddressPageHTML(requestId string, sessionToken string, emailAddressUpdateToken string, newEmailAddress string) string {
	title := "Verify your new email address | Passwordless auth example"

	bodyHTMLTemplate := `<h1>Verify your new email address</h1>
<p>We sent an 8-digit verification code to %s. It may take up to 30 seconds to arrive. Check your spam or junk folder if you don't see it.</p>
<form id="verify-verification-code-form">
	<label for="verify-verification-code-form-verification-code-input">Verification code (hyphens and spaces are optional)</label>
	<input id="verify-verification-code-form-verification-code-input" name="verification_code" autocomplete="one-time-code" required />
	<button id="verify-verification-code-form-submit-button">Update email address</button>
</form>
<div id="controls">
	<button id="resend-verification-code-button" class="link-button">Resend verification code</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`
	bodyHTML := fmt.Sprintf(bodyHTMLTemplate, html.EscapeString(newEmailAddress))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("email_address_update_token", emailAddressUpdateToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, updateEmailAddressVerifyNewEmailAddressPageScript, updateEmailAddressVerifyNewEmailAddressPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/register_passkey_create_passkey.js
var registerPasskeyCreatePasskeyPageScript string

//go:embed frontend_assets/register_passkey_create_passkey.css
var registerPasskeyCreatePasskeyPageStylesheet string

func createRegisterPasskeyCreatePasskeyPageHTML(requestId string, sessionToken string, passkeyRegistrationToken string, user userStruct, passkeys []passkeyStruct) string {
	title := "Create a passkey | Passwordless auth example"

	bodyHTML := `<h1>Create a passkey</h1>
<p>Create a passkey for your account on your device, security key, or password manager.</p>
<button id="create-passkey-button" class="block-button">Create</button>
<button id="cancel-button" class="link-button">Cancel</button>`

	passkeyWebauthnCredentialIdsJSONArray := json.NewArrayBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	for _, passkey := range passkeys {
		passkeyWebauthnCredentialIdsJSONArray.AddString(base64.StdEncoding.EncodeToString(passkey.webauthnCredentialId))
	}
	passkeyWebauthnCredentialIdsJSON := passkeyWebauthnCredentialIdsJSONArray.Done()

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("passkey_registration_token", passkeyRegistrationToken)
	dataJSONBuilder.AddString("user_id", user.id)
	dataJSONBuilder.AddString("user_email_address", user.emailAddress)
	dataJSONBuilder.AddJSON("passkey_webauthn_credential_ids", passkeyWebauthnCredentialIdsJSON)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, registerPasskeyCreatePasskeyPageScript, registerPasskeyCreatePasskeyPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/register_passkey_set_passkey_name.js
var registerPasskeySetPasskeyNamePageScript string

//go:embed frontend_assets/register_passkey_set_passkey_name.css
var registerPasskeySetPasskeyNamePageStylesheet string

func createRegisterPasskeySetPasskeyNamePageHTML(requestId string, sessionToken string, passkeyRegistrationToken string, passkeyNameSuggestion string) string {
	title := "Name your passkey | Passwordless auth example"

	template := `<h1>Name your passkey</h1>
<p>Give your passkey a name so you can easily recognize and manage it later.</p>
<form id="set-passkey-name-form">
	<label for="set-passkey-name-form-name-input">Passkey name (Standard characters except double quotes)</label>
	<input id="set-passkey-name-form-name-input" name="passkey_name" required value="%s" />
	<button id="set-passkey-name-form-submit-button">Complete</button>
</form>`
	bodyHTML := fmt.Sprintf(template, html.EscapeString(passkeyNameSuggestion))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("passkey_registration_token", passkeyRegistrationToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, registerPasskeySetPasskeyNamePageScript, registerPasskeySetPasskeyNamePageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/delete_passkey_confirm.js
var deletePasskeyConfirmPageScript string

//go:embed frontend_assets/delete_passkey_confirm.css
var deletePasskeyConfirmPageStylesheet string

func createDeletePasskeyConfirmPageHTML(requestId string, sessionToken string, passkeyDeletionToken string, passkeyName string) string {
	title := "Delete a passkey | Passwordless auth example"

	template := `<h1>Delete a passkey</h1>
<p>Are you sure you want to delete passkey "%s"? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button" class="block-button">Delete passkey</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	bodyHTML := fmt.Sprintf(template, html.EscapeString(passkeyName))

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("passkey_deletion_token", passkeyDeletionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, deletePasskeyConfirmPageScript, deletePasskeyConfirmPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/delete_account_confirm.js
var deleteAccountConfirmPageScript string

//go:embed frontend_assets/delete_account_confirm.css
var deleteAccountConfirmPageStylesheet string

func createDeleteAccountConfirmPageHTML(requestId string, sessionToken string, accountDeletionToken string) string {
	title := "Delete your account | Passwordless auth example"

	bodyHTML := `<h1>Delete your account</h1>
<p>Are you sure you want to delete your account? This action is permanent and cannot be undone.<p>
<div id="controls">
	<button id="confirm-button" class="block-button">Delete account</button>
	<button id="cancel-button" class="link-button">Cancel</button>
</div>`

	dataJSONBuilder := json.NewObjectBuilder(htmlSafeJSONStringCharacterEscapingBehavior)
	dataJSONBuilder.AddString("session_token", sessionToken)
	dataJSONBuilder.AddString("account_deletion_token", accountDeletionToken)
	dataJSON := dataJSONBuilder.Done()

	pageHTML := createPageHTML(requestId, title, bodyHTML, deleteAccountConfirmPageScript, deleteAccountConfirmPageStylesheet, dataJSON)

	return pageHTML
}

//go:embed frontend_assets/base.css
var baseStylesheet string

//go:embed frontend_assets/base.js
var baseScript string

func createPageHTML(requestId string, title string, bodyHTML string, script string, stylesheet string, dataJSON string) string {
	htmlTemplate := `<html lang="en">
<head>
	<title>%s</title>
	<meta name="description" content="An example website that implements email code sign-in and passkeys following best practices." />

	<meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" />

	<meta property="og:title" content="%s" />
	<meta property="og:type" content="website" />
	<meta property="og:locale" content="en_US" />
	<meta property="og:site_name" content="Passwordless auth example" />
	<meta property="og:description" content="An example website that implements email code sign-in and passkeys following best practices." />
	<meta property="og:url" content="https://passwordless-example.auth.pilcrowonpaper.com" />
	<meta property="og:image" content="https://pilcrowonpaper.com/profile.jpg" />

	<meta name="twitter:card" content="summary">
    <meta name="twitter:site" content="@pilcrowonpaper">

	<style>%s</style>
	<style>%s</style>
</head>

<body>
	<header>
		<a id="home-link" href="/">Passwordless auth example</a>
	</header>
	<main>%s</main>
	<footer>
		<p>Created by <a href="https://pilcrowonpaper.com">pilcrow</a></p>
		<p>Questions and support: <a href="mailto:examples@auth.pilcrowonpaper.com">examples@auth.pilcrowonpaper.com</a></p>
		<p>Request ID: %s</p>
	</footer>
</body>
<script type="module">%s</script>
<script id="data" type="application/json">%s</script>
<script type="module">%s</script>
</html>`

	pageHTML := fmt.Sprintf(
		htmlTemplate,
		html.EscapeString(title),
		html.EscapeString(title),
		baseStylesheet,
		stylesheet,
		bodyHTML,
		html.EscapeString(requestId),
		script,
		dataJSON,
		baseScript,
	)

	return pageHTML
}

var htmlSafeJSONStringCharacterEscapingBehavior json.StringCharacterEscapingBehaviorInterface = htmlSafeJSONStringCharacterEscapingBehaviorStruct{}

type htmlSafeJSONStringCharacterEscapingBehaviorStruct struct{}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseCharacter(r rune) bool {
	return r != '<' && r != '>'
}

func (htmlSafeJSONStringCharacterEscapingBehaviorStruct) UseShorthandEscapeSequence(_ rune) bool {
	return true
}

func createUnexpectedErrorErrorPageHTML(requestId string) string {
	title := "An unexpected error occurred | Passwordless auth example"

	bodyHTML := `<h1>An unexpected error occurred</h1>
<p>Something went wrong. Please refresh the page or try again later.</p>`

	pageHTML := createPageHTML(requestId, title, bodyHTML, "", "", "")

	return pageHTML
}
