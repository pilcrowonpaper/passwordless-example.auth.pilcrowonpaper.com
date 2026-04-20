package main

import (
	"fmt"
)

type emailClientInterface interface {
	sendEmail(toEmailAddress string, subject string, body string) error
}

var stdoutEmailClient emailClientInterface = &stdoutEmailClientStruct{}

type stdoutEmailClientStruct struct{}

func (stdoutEmailClient *stdoutEmailClientStruct) sendEmail(toEmailAddress string, subject string, body string) error {
	template := `[Email] To: %s
Subject: %s

%s
`
	fmt.Printf(template, toEmailAddress, subject, body)

	return nil
}
