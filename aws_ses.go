package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type awsSESEmailClientStruct struct {
	sesClient    *sesv2.Client
	emailAddress string
}

func newAWSSESEmailClient(sesClient *sesv2.Client, emailAddress string) *awsSESEmailClientStruct {
	awsSESEmailClient := &awsSESEmailClientStruct{
		sesClient:    sesClient,
		emailAddress: emailAddress,
	}
	return awsSESEmailClient
}

func (awsSESEmailClient *awsSESEmailClientStruct) sendEmail(toEmailAddress string, subject string, body string) error {
	input := &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(awsSESEmailClient.emailAddress),
		Destination: &types.Destination{
			ToAddresses: []string{toEmailAddress},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data: aws.String(subject),
				},
				Body: &types.Body{
					Text: &types.Content{
						Data: aws.String(body),
					},
				},
			},
		},
	}

	_, err := awsSESEmailClient.sesClient.SendEmail(context.Background(), input)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}

	return nil
}
