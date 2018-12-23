package dnsoverhttps_test

import (
	"net/http"
	"testing"

	"github.com/Katsusan/go-dns/dnsoverhttps"
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

func TestQueryWithPost(t *testing.T) {
	domain := "google.com"
	clnt := &dnsoverhttps.DoHclient{
		Client: &http.Client{},
	}

	err := clnt.QueryWithPost(domain)
	if err != nil {
		t.Error("QueryWithPost failed.", err)
	}
}
