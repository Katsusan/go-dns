package dnsclient_test

import (
	"fmt"
	"testing"

	"github.com/Katsusan/go-dns/dnsclient"
)

func TestDnsQuery(t *testing.T) {
	clnt := &dnsclient.Dnsclient{}
	dresp, err := clnt.DnsQuery("cloudflare-dns.com", []string{"114.114.114.114:53", "1.1.1.1:53"})
	if err != nil {
		t.Error("query failed.", err)
		return
	}
	fmt.Printf("dnsresp:%+v\n", dresp)
}
