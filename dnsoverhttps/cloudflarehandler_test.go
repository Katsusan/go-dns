package dnsoverhttps_test

import (
	"fmt"
	"log"
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
	ans, err := clnt.QueryWithGet(domain)
	if err != nil {
		t.Error("QueryWithGet failed,", err)
	}
	log.Printf("%+v\n", ans)
}

func TestQueryWithPost(t *testing.T) {
	domain := "baidu.com"
	clnt := &dnsoverhttps.DoHclient{
		Client: &http.Client{},
	}

	ans, err := clnt.QueryWithPost(domain)
	if err != nil {
		t.Error("QueryWithPost failed.", err)
	}
	log.Printf("%+v\n", ans)
}

func TestQueryWithJSON(t *testing.T) {
	domain := "qq.com"
	clnt := &dnsoverhttps.DoHclient{
		Client: &http.Client{},
	}

	ans, err := clnt.QueryWithJSON(domain, 1)
	if err != nil {
		t.Errorf("TestQueryWithJSON failed.%s", err)
	}
	fmt.Printf("ans:%+v\n", ans)
}
