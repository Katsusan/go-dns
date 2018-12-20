package dnsoverhttps

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/Katsusan/go-dns/dnsclient"
)

const (
	CLOUDFLARE_QUERY_URL = "https://cloudflare-dns.com/dns-query"
	HEADER_ACCEPT        = "application/dns-message"
)

type DoHclient struct {
	Client *http.Client
}

func (dohclnt *DoHclient) QueryWithGet(domain string) error {
	var err error
	req, err := http.NewRequest("GET", CLOUDFLARE_QUERY_URL, nil)
	if err != nil {
		return err
	}

	req.Header.Add("accept", HEADER_ACCEPT)

	//make dns query message, including transaction id, flags, ..., see dnsmessage.go:DNSHeader
	transid, _ := dnsclient.GenTransactionID()
	log.Printf("transction id:%X\n", transid)
	header := dnsclient.MakeQueryHeader(transid)
	dnsmsg, _ := dnsclient.MakeQueryMsg(domain)
	msgall := append(header, dnsmsg...)
	msgencoded := base64.RawURLEncoding.EncodeToString(msgall)

	q := req.URL.Query()
	q.Add("dns", msgencoded)
	req.URL.RawQuery = q.Encode()

	resp, err := dohclnt.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Printf("res:%s\n", res)
	log.Printf("resX:%X\n", res)
	return err

}
