package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	aws_config "github.com/aws/aws-sdk-go-v2/config"
	aws_credentials "github.com/aws/aws-sdk-go-v2/credentials"
	aws_ses "github.com/aws/aws-sdk-go-v2/service/sesv2"
)

func main() {
	portString := os.Getenv("PORT")
	if portString == "" {
		portString = "3000"
	}
	port, err := parseNonNegativeIntegerString(portString)
	if err != nil {
		log.Fatalf("invalid PORT environment variable value: %s", err.Error())
	}

	originEnvValue := os.Getenv("ORIGIN")
	if originEnvValue == "" {
		originEnvValue = fmt.Sprintf("http://localhost:%d", port)
	}
	webauthnRelyingPartyId := ""
	if originEnvValue != "" {
		originURL, err := url.Parse(originEnvValue)
		if err == nil {
			webauthnRelyingPartyId = originURL.Hostname()
		}
	}

	awsSESEnvValue := os.Getenv("AWS_SES")
	if awsSESEnvValue == "" {
		awsSESEnvValue = "0"
	}
	var emailClient emailClientInterface
	if awsSESEnvValue == "1" {
		awsAccessKeyEnvValue := os.Getenv("AWS_ACCESS_KEY_ID")

		awsSecretAccessKeyEnvValue := os.Getenv("AWS_SECRET_ACCESS_KEY")

		awsRegionEnvValue := os.Getenv("AWS_REGION")
		if awsRegionEnvValue == "" {
			awsRegionEnvValue = "us-east-1"
		}

		awsSESEmailAddressEnvValue := os.Getenv("AWS_SES_EMAIL_ADDRESS")

		awsCredentialsProvider := aws_credentials.NewStaticCredentialsProvider(awsAccessKeyEnvValue, awsSecretAccessKeyEnvValue, "")

		awsConfig, err := aws_config.LoadDefaultConfig(context.Background(),
			aws_config.WithRegion(awsRegionEnvValue),
			aws_config.WithCredentialsProvider(awsCredentialsProvider),
		)
		if err != nil {
			log.Fatalf("failed to aws load config, %v", err)
		}

		awsSESClient := aws_ses.NewFromConfig(awsConfig)

		emailClient = newAWSSESEmailClient(awsSESClient, awsSESEmailAddressEnvValue)
	} else if awsSESEnvValue == "0" {
		emailClient = stdoutEmailClient
	} else {
		log.Fatal("invalid AWS_SES environment variable value")
	}

	logsEnvValue := os.Getenv("LOGS")
	if logsEnvValue == "" {
		logsEnvValue = "internal_error,background_job"
	}
	serverLogging := serverLoggingStruct{}
	logsEnvValueItems := strings.SplitSeq(logsEnvValue, ",")
	for logsEnvValueItem := range logsEnvValueItems {
		if logsEnvValueItem == "internal_error" {
			serverLogging.internalError = true
		} else if logsEnvValueItem == "background_job" {
			serverLogging.backgroundJob = true
		} else if logsEnvValueItem == "action_result" {
			serverLogging.actionResult = true
		} else if logsEnvValueItem == "request_email" {
			serverLogging.requestEmail = true
		} else if logsEnvValueItem == "request_event" {
			serverLogging.requestEvent = true
		} else {
			log.Fatalf("unknown LOGS environment variable value item: %s", logsEnvValueItem)
		}
	}

	err = setUpDatabase()
	if err != nil {
		log.Fatalf("failed to set up database: %s\n", err.Error())
	}

	server, err := createServer(emailClient, originEnvValue, webauthnRelyingPartyId, serverLogging)
	if err != nil {
		log.Fatalf("failed to create server: %s\n", err.Error())
	}

	fmt.Printf("Starting server on port %d...\n", port)
	err = server.start(port)
	if err != nil {
		log.Fatalf("failed to start server: %s\n", err.Error())
	}
}

func parseNonNegativeIntegerString(s string) (int, error) {
	if len(s) == 0 {
		return 0, errors.New("empty string")
	}
	if s == "0" {
		return 0, nil
	}
	result := 0
	chars := []rune(s)
	if chars[0] == '0' {
		return 0, errors.New("leading zero")
	}
	for _, char := range chars {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			return 0, errors.New("invalid character")
		}
	}
	return result, nil
}
