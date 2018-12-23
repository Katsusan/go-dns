package dnsoverhttps

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/Katsusan/go-dns/dnsclient"
)

const (
	CLOUDFLARE_QUERY_URL = "https://cloudflare-dns.com/dns-query"
	HEADER_ACCEPT        = "application/dns-message"
	CONTENT_TYPE         = "application/dns-message"
)

var (
	errMap = map[int]error{
		400: errors.New("DNS query not specified or too small"),
		413: errors.New("DNS query is larger than maximum allowed DNS message size"),
		415: errors.New("Unsupported content type"),
		504: errors.New("Resolver timeout while waiting for the query response"),
	}
)

type DoHclient struct {
	Client *http.Client
}

//QueryWithPost: make DnsOverHttps query with HTTP Method 'POST'
func (dohclnt *DoHclient) QueryWithPost(domain string) ([]dnsclient.DNSAnswer, error) {
	var err error
	ans := make([]dnsclient.DNSAnswer, 0)

	//make dns query message, including transaction id, flags, ..., see dnsmessage.go:DNSHeader
	transid, _ := dnsclient.GenTransactionID()
	log.Printf("transction id:%X\n", transid)
	header := dnsclient.MakeQueryHeader(transid)
	dnsmsg, _ := dnsclient.MakeQueryMsg(domain)
	msgall := append(header, dnsmsg...)

	req, err := http.NewRequest("POST", CLOUDFLARE_QUERY_URL, bytes.NewReader(msgall))
	if err != nil {
		return ans, err
	}

	req.Header.Add("accept", HEADER_ACCEPT)
	req.Header.Add("content-type", CONTENT_TYPE)

	resp, err := dohclnt.Client.Do(req)
	if err != nil {
		return ans, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if err, found := errMap[resp.StatusCode]; found == true {
			return ans, err
		} else {
			return ans, errors.New("Can't get correct response, status=" + resp.Status + "(Unknown code)")
		}
	}

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ans, err
	}

	//verify the transaction id
	if bytes.Compare([]byte{byte(transid >> 8), byte(transid)}, res[:2]) != 0 {
		err = errors.New("Transaction id not consistent")
		return ans, err
	}

	err = dnsclient.ParseResp(res[2:], &ans)
	if err != nil {
		return ans, err
	}
	//log.Printf("answer:%+v\n", ans)

	return ans, err
}

//QueryWithGet: make DnsOverHttps query with HTTP Method 'GET'
func (dohclnt *DoHclient) QueryWithGet(domain string) ([]dnsclient.DNSAnswer, error) {
	var err error
	ans := make([]dnsclient.DNSAnswer, 0)

	req, err := http.NewRequest("GET", CLOUDFLARE_QUERY_URL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("accept", HEADER_ACCEPT)

	//make dns query message, including transaction id, flags, ..., see dnsmessage.go:DNSHeader
	transid, _ := dnsclient.GenTransactionID()
	//log.Printf("transction id:%X\n", transid)
	header := dnsclient.MakeQueryHeader(transid)
	dnsmsg, _ := dnsclient.MakeQueryMsg(domain)
	msgall := append(header, dnsmsg...)
	msgencoded := base64.RawURLEncoding.EncodeToString(msgall)
	//log.Printf("msgall:%X\n", msgall)

	q := req.URL.Query()
	q.Add("dns", msgencoded)
	req.URL.RawQuery = q.Encode()

	resp, err := dohclnt.Client.Do(req)
	if err != nil {
		return ans, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if err, found := errMap[resp.StatusCode]; found == true {
			return ans, err
		} else {
			return ans, errors.New("Can't get correct response, status=" + resp.Status + "(Unknown code)")
		}
	}

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ans, err
	}

	//log.Printf("resX:%X\n", res)

	//verify the transaction id
	if bytes.Compare([]byte{byte(transid >> 8), byte(transid)}, res[:2]) != 0 {
		err = errors.New("Transaction id not consistent")
		return ans, err
	}

	err = dnsclient.ParseResp(res[2:], &ans)
	if err != nil {
		return ans, err
	}
	//log.Printf("answer:%+v\n", ans)
	return ans, err

}
