package dnsoverhttps_test

import (
	"net/http"
	"testing"

	"../dnsoverhttps"
)

func TestQueryWithGet(t *testing.T) {
	domain := "baidu.com"
	//statuscode := 200

	clnt := &dnsoverhttps.DoHclient{
		Client: &http.Client{},
	}
	err := clnt.QueryWithGet(domain)
	if err != nil {
		t.Error("QueryWithGet failed,", err)
	}
}
