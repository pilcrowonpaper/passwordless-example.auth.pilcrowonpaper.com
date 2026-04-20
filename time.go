package main

import "time"

func getCurrentTimeSecondPrecision() time.Time {
	return time.Now().Truncate(time.Second)
}
