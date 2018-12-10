package main

import (
	"errors"
)

var (
	NoErr       = errors.New("Everything OK")
	FormErr     = errors.New("Incorrect format")
	ServerFail  = errors.New("Server could't handle it")
	NXDomainErr = errors.New("Domain not exist")
	NotImpErr   = errors.New("Query not supported")
	RefuseErr   = errors.New("Query refused by server")
)

func main() {

}
