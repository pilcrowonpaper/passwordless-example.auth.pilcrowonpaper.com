package main

import (
	"fmt"
	"time"
)

const (
	backgroundJobClearData = "clear_data"
)

func (server *serverStruct) clearDataBackgroundJob() {
	for {
		now := time.Now().UTC()
		nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)

		time.Sleep(time.Until(nextMidnight))

		runId := generateLongItemId()
		server.logBackgroundJobRun(runId, backgroundJobClearData)

		err := server.cleanDatabase()
		if err != nil {
			errorMessage := fmt.Sprintf("failed to clean database: %s", err.Error())
			server.logBackgroundJobError(runId, backgroundJobClearData, errorMessage)
		}

		server.userEmailCodeVerificationAuthenticationRateLimit.Clear()
		server.emailAddressVerificationRateLimit.Clear()
		server.userEmailCodeVerificationAuthenticationRateLimit.Clear()
		server.unverifiedEmailAddressEmailRateLimit.Clear()

		server.logBackgroundJobRunCompletion(runId, backgroundJobClearData)
	}
}
