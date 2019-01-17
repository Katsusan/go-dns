package dnsserver

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/Katsusan/go-dns/dnsoverhttps"
	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

const usage = `
	Usage: gDNS	[options]

	Server Options:
		-c,	--Config	<Config file>	configuration file path
	Command Options:
		-h,	--help	show help message
		-v,	--version	show version and exit
`
const (
	ARCCacheSize = 1024
	TwoQueueSize = 1024

	TTLDay = 86400
)

var (
	userhosts Hosts
	cache     *ServerCache
)

func NewServer(cfg *Config) (*DNSServer, error) {

	dnssrv := new(DNSServer)
	//if cfg.ipv4InterfaceName is null string or non-exist name,
	//then ipv4Interface will be nil and ListenMulticastUDP will use default interface.
	ipv4Interface, _ := net.InterfaceByName(cfg.ipv4InterfaceName)
	ipv6Interface, _ := net.InterfaceByName(cfg.ipv6InterfaceName)

	ipv4Addr, _ := net.ResolveUDPAddr("udp4", cfg.ipv4Addr+":"+cfg.port)
	ipv4Listen, ipv4err := net.ListenMulticastUDP("udp4", ipv4Interface, ipv4Addr)

	ipv6Addr, _ := net.ResolveUDPAddr("udp6", cfg.ipv6Addr+":"+cfg.port)
	ipv6Listen, ipv6err := net.ListenMulticastUDP("udp6", ipv6Interface, ipv6Addr)

	if ipv4err != nil && ipv6err != nil {
		return dnssrv, fmt.Errorf("No listeners could be established.")
	}

	if ipv4Listen != nil {
		atomic.StoreInt32(&dnssrv.listeningv4, 1)
		dnssrv.ipv4conn = ipv4Listen
	}

	if ipv6Listen != nil {
		atomic.StoreInt32(&dnssrv.listeningv6, 1)
		dnssrv.ipv6conn = ipv6Listen
	}

	//initializec dns cache, use "ARC" or "TwoQueue"
	if cfg.cache == "ARC" {
		var err error
		cache.Arccache, err = lru.NewARC(ARCCacheSize)
		cache.cachename = "ARC"
		if err != nil {
			return dnssrv, fmt.Errorf("Can't create dns arccache,%v", err)
		}
	} else if cfg.cache == "TwoQueue" {
		var err error
		cache.TwoQueuecache, err = lru.New2Q(TwoQueueSize)
		cache.cachename = "TwoQueue"
		if err != nil {
			return dnssrv, fmt.Errorf("Can not create dns twoqueue cache, %v", err)
		}
	}

	dnssrv.cfg = cfg

	return dnssrv, nil
}

func (s *DNSServer) Run() {
	if s.ipv4conn != nil || s.ipv6conn != nil {
		atomic.StoreInt32(&s.running, 1)
		s.start()
	}
}

func (s *DNSServer) start() {
	if atomic.CompareAndSwapInt32(&s.listeningv4, 0, 1) {
		go s.recvmsg(s.ipv4conn)
	}

	if atomic.CompareAndSwapInt32(&s.listeningv6, 0, 1) {
		go s.recvmsg(s.ipv6conn)
	}
}

func (s *DNSServer) recvmsg(con *net.UDPConn) {

	for atomic.LoadInt32(&s.running) == 1 {
		buf := make([]byte, 65535) //max length of UDP packet
		n, fromAddr, err := con.ReadFrom(buf)
		if err != nil {
			continue
		}

		if err := s.handleQuery(buf[:n], fromAddr); err != nil {
			log.Printf("handling packets failed.error=%s\n", err)
		}
	}
}

func (s *DNSServer) handleQuery(qry []byte, addr net.Addr) error {

	//use Unpack() method to parse packet
	querymsg := new(dns.Msg)
	if err := querymsg.Unpack(qry); err != nil {
		return fmt.Errorf("unpack() failed: %s", err)
	}

	//judge the QR flag of DNS packet(0->query, 1->response)
	if querymsg.MsgHdr.Response || querymsg.MsgHdr.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("not dns query packet,QR=%t, OpCode=%d", querymsg.MsgHdr.Response, querymsg.MsgHdr.Opcode)
	}

	//if there is mutlti queries coming, suggest split up.
	if querymsg.Truncated {
		return fmt.Errorf("Not supported wireformat(flag Truncated=%t), split query into smaller ones", querymsg.Truncated)
	}

	//usualy only one Question
	var answers []dns.RR
	for _, ques := range querymsg.Question {
		if rrtmp, err := s.Resolve(ques); err != nil {
			answers = append(answers, rrtmp...)
		}
	}

	//length=0 means hosts/cache(or DoH) lookup failed and need to forward the dns query
	if len(answers) == 0 {
		if resp, err := s.forwardQuery(qry); err != nil {
			return s.sendResp(resp, addr)
		}
	}

	return nil
}

//Resolve preference:
//	user-defined hosts > dns cache > instant query
func (s *DNSServer) Resolve(question dns.Question) ([]dns.RR, error) {
	resRR := make([]dns.RR, 0)

	//only handles query with CLASS-IN
	//TODO: CLASS-ANY...
	if question.Qclass != dns.ClassINET {
		return nil, fmt.Errorf("Unexpected query class, should be IN(0x0001), Got %d", question.Qclass)
	}

	//handles query type of A(ipv4), AAAA(ipv6), NS, CNAME, MX, TXT, ANY
	switch question.Qtype {
	case dns.TypeA:
		//lookup in user-defined hosts
		if hostsip, err := userhosts.Get(question.Name); err == nil && len(hostsip) != 0 {
			for _, ip := range hostsip {
				resRR = append(resRR, &dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    TTLDay,
					},
					A: ip,
				})
			}
			return resRR, nil
		}

		//lookup in server cache
		//TODO: filter the expired dnsRR(by TTL)
		if res, found := cache.Get(question.Name); found {
			if dnsrr, ok := res.([]dns.RR); ok {
				return dnsrr, nil
			}
		}

		//neither hosts nor cache has the corespond dnsRR, then issue the instant query

		//use dnsoverhttps or not
		if s.cfg.DoH {
			clnt := &dnsoverhttps.DoHclient{
				Client: &http.Client{},
			}
			if ansarr, err := clnt.QueryWithJSON(question.Name, "A"); err == nil && len(ansarr) != 0 {
				for _, ans := range ansarr {
					resRR = append(resRR, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    ans.TTL,
						},
						A: net.ParseIP(ans.Ip),
					})
				}
				return resRR, nil
			}
		}

		//return 0-len dnsRR so that handleQuery can sense that and
		//forward the whole query bytes to dns server.
		return resRR, nil

	case dns.TypeAAAA:

	}
	return resRR, nil
}

//forward query to config.serverlist and return the response
func (s *DNSServer) forwardQuery(src []byte) ([]byte, error) {
	var resp []byte

	return resp, nil
}

//
func (s *DNSServer) sendResp(resp []byte, dst net.Addr) error {

	return nil
}
func (s *DNSServer) shutDown() {
	if atomic.CompareAndSwapInt32(&s.running, 1, 0) {
	}
}
