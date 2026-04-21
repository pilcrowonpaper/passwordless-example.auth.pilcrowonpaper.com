package main

import "errors"

var errItemNotFound = errors.New("item not found")
var errItemConflict = errors.New("item conflict")
