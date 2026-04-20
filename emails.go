package main

import (
	"fmt"
)

func (server *serverStruct) sendSignupEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	formattedEmailAddressVerificationCode := formatEmailAddressVerificationCode(emailAddressVerificationCode)

	subject := "Verify your account email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedEmailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	formattedEmailAddressVerificationCode := formatEmailAddressVerificationCode(emailAddressVerificationCode)

	subject := "Verify your new account email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedEmailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendSigninEmailCode(emailAddress string, emailCode string) error {
	formattedCode := formatEmailCode(emailCode)

	subject := "Sign in to your account"
	bodyTemplate := `Your sign-in code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendSignedInNotificationEmail(emailAddress string) error {
	subject := "New sign-in to your account"
	body := `We detected a recent login to your account. If this wasn't you, please secure your account by resetting your password immediately.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendIdentityVerificationEmailCode(emailAddress string, emailCode string) error {
	formattedCode := formatEmailCode(emailCode)

	subject := "Sign in to your account"
	bodyTemplate := `Your sign-in code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendEmailAddressUpdatedNotificationEmail(emailAddress string) error {
	subject := "Your account email address was recently updated"
	body := `This email address is no longer tied to your account.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasskeyRegisteredNotificationEmail(emailAddress string, passkeyName string) error {
	subject := "A new passkey was registered to your account"
	bodyTemplate := `A new passkey "%s" was registered to your account. If you did not make this change, please secure your account by signing in to your password immediately.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, passkeyName)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasskeyDeletedNotificationEmail(emailAddress string, passkeyName string) error {
	subject := "A passkey was deleted from your account"
	bodyTemplate := `Your passkey "%s" was deleted from your account. If you did not make this change, please secure your account by signing in to your password immediately.

Passwordless auth example: https://passwordless-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, passkeyName)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}
