package dnsserver

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

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
	//ipv4Interface, _ := net.InterfaceByName(cfg.ipv4InterfaceName)
	//ipv6Interface, _ := net.InterfaceByName(cfg.ipv6InterfaceName)

	//ipv4Addr, _ := net.ResolveUDPAddr("udp4", cfg.ipv4Addr+":"+cfg.port)
	ipv4Addr := &net.UDPAddr{
		IP:   net.ParseIP(cfg.ipv4Addr),
		Port: cfg.port,
	}
	ipv4Listen, ipv4err := net.ListenUDP("udp4", ipv4Addr)

	//ipv6Addr, _ := net.ResolveUDPAddr("udp6", cfg.ipv6Addr+":"+cfg.port)
	ipv6Addr := &net.UDPAddr{
		IP:   net.ParseIP(cfg.ipv6Addr),
		Port: cfg.port,
	}
	ipv6Listen, ipv6err := net.ListenUDP("udp6", ipv6Addr)

	if ipv4err != nil && ipv6err != nil {
		log.Println("ipv4err:", ipv4err)
		log.Println("ipv6err:", ipv6err)
		return dnssrv, fmt.Errorf("No listeners could be established")
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
	cache = new(ServerCache)
	if cfg.cache == "ARC" {
		/*var err error
		cache.Arccache, err = lru.NewARC(ARCCacheSize)
		cache.cachename = "ARC"
		if err != nil {
			return dnssrv, fmt.Errorf("Can't create dns arccache,%v", err)
		}*/
		var err error
		dnssrv.cache, err = lru.NewARC(ARCCacheSize)
		if err != nil {
			return dnssrv, fmt.Errorf("can not create ARCCache -%s", err)
		}
	} else if cfg.cache == "TwoQueue" {
		var err error
		/*cache.TwoQueuecache, err = lru.New2Q(TwoQueueSize)
		cache.cachename = "TwoQueue"*/
		dnssrv.cache, err = lru.New2Q(TwoQueueSize)
		if err != nil {
			return dnssrv, fmt.Errorf("can not create dns twoqueue cache, %v", err)
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
	if atomic.LoadInt32(&s.listeningv4) == 1 {
		go s.recvmsg(s.ipv4conn)
	}

	if atomic.LoadInt32(&s.listeningv6) == 1 {
		go s.recvmsg(s.ipv6conn)
	}
}

func (s *DNSServer) recvmsg(con *net.UDPConn) {

	buf := make([]byte, 65535) //max length of UDP packet
	for atomic.LoadInt32(&s.running) == 1 {

		n, fromAddr, err := con.ReadFrom(buf)
		if err != nil {
			continue
		}
		log.Println("recv ", n, "bytes udp packet:\n", buf[:n])

		go s.handleQuery(buf[:n], fromAddr)
		/*
			if err := s.handleQuery(buf[:n], fromAddr); err != nil {
				log.Printf("handling packets failed.error=%s\n", err)
			}*/
	}
	return
}

func (s *DNSServer) handleQuery(qry []byte, addr net.Addr) error {

	//use Unpack() method to parse packet
	querymsg := new(dns.Msg)
	if err := querymsg.Unpack(qry); err != nil {
		return fmt.Errorf("unpack() failed: %s", err)
	}

	//judge the QR flag of DNS packet(0->query, 1->response)
	if querymsg.MsgHdr.Response || querymsg.MsgHdr.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("Not dns query packet,QR=%t, OpCode=%d", querymsg.MsgHdr.Response, querymsg.MsgHdr.Opcode)
	}

	//if there is mutlti queries coming, suggest split up.
	if querymsg.Truncated {
		return fmt.Errorf("Not supported wireformat(flag Truncated=%t), split query into smaller ones", querymsg.Truncated)
	}

	//usualy only one Question, although there is "usually 1" in RFC1035 4.1.2,
	//how to define RCode with multiple questions is up in the air.
	var answers []dns.RR

	if len(answers) > 1 {
		return fmt.Errorf("over one question in query")
	}
	for _, ques := range querymsg.Question {
		if rrtmp, err := s.Resolve(ques); err == nil {
			answers = append(answers, rrtmp...)
		}
	}
	log.Println("after resolve, answers is", answers)

	//length=0 means hosts/cache(or DoH) lookup failed and need to forward the dns query
	if len(answers) == 0 {
		fwdresp, err := s.forwardQuery(qry)
		if err != nil {
			log.Println("Failed to forward the query")
			return err
		}

		//convert forward response into dns.Msg and add dns.Msg.Answer(dns.RR) into cache
		fwdmsg := new(dns.Msg)
		if err := fwdmsg.Unpack(fwdresp); err != nil {
			return fmt.Errorf("failed to unpack the forward response,%v", err)
		}

		/*
			if len(fwdmsg.Answer) > 0 && len(fwdmsg.Question) > 0 {
				s.cache.Add(fwdmsg.Question[0].Name, fwdmsg.Answer[0])
			}*/

		return s.sendResp(fwdresp, addr)
	}

	//otherwise means hosts/cache/DoH succeed
	respmsg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			//transcation ID needs to be consistent
			Id: querymsg.Id,

			//set Query/Response flag to Response(1).
			//	false(0) measn query.
			Response: true,

			//set OpCode to be 0 (Normal Query)
			//	4 means DNS NOTIFY(RFC1996)
			//	5 measn DNS UPDATE(RFC2136)
			Opcode: dns.OpcodeQuery,

			//Authoritative Answer. always 1.
			Authoritative: true,

			//the following flag in response usually set to 0.
			//TC, RD, RA, Z, AD, CD

			//Response Code.
			//	0	->	NoError
			//	1	->	FormErr
			//	2	->	ServFail
			//	3	->	NXDomain
			//	4	->	Notlmp
			//	5	->	Refused
			Rcode: dns.RcodeSuccess,
		},
		Compress: true,
		Answer:   answers,
	}

	if msgb, err := respmsg.Pack(); err != nil {
		return err
	} else {
		return s.sendResp(msgb, addr)
	}
}

//Resolve preference:
//	user-defined hosts > dns cache > DoH
func (s *DNSServer) Resolve(question dns.Question) ([]dns.RR, error) {
	resRR := make([]dns.RR, 0)

	//only handles query with CLASS-IN
	//TODO: CLASS-ANY...
	if question.Qclass != dns.ClassINET {
		return nil, fmt.Errorf("unexpected query class, should be IN(0x0001), Got %d", question.Qclass)
	}

	//lookup in user-defined hosts
	if hostsRR, err := userhosts.Get(question.Name); err == nil && len(hostsRR) != 0 {
		return hostsRR, nil
	}

	//handles query type of A(ipv4), AAAA(ipv6), NS, CNAME, MX, TXT, ANY
	switch question.Qtype {
	case dns.TypeA:
		//lookup in server cache
		//TODO: filter the expired dnsRR(by TTL)
		if res, found := s.cache.Get(strings.Trim(question.Name, ".")); found {
			log.Println("all keys in cache", s.cache.Keys())
			log.Println("now query", question.Name, "in cache")
			log.Printf("type of res is %T\n", res)

			if dnsrr, ok := res.([]dns.RR); ok {
				log.Println("found in dns cache:", dnsrr)
				return dnsrr, nil
			}
		}

		//neither hosts nor cache has the corespond dns.RR, then according to the DoH option
		//to decide using dnsoverhttps or not
		if s.cfg.DoH {
			log.Println("will query by DoH")
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
				//Add to cache for later query
				s.cache.Add(strings.Trim(question.Name, "."), resRR)
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
	resp := make([]byte, 65535)
	var resplen int

	resch := make(chan []byte, len(s.cfg.serverlist))
	defer close(resch)

	for _, srv := range s.cfg.serverlist {
		go func(s string) {
			udpaddr, _ := net.ResolveUDPAddr("udp", s)
			udpconn, err := net.DialUDP("udp", nil, udpaddr)
			if err != nil {
				log.Printf("Server:%s DialUDP failed,error=%v\n", s, err)
				return
			}
			defer udpconn.Close()

			udpconn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = udpconn.Write(src)
			if err != nil {
				log.Printf("Failed to write to server:%s, error=%v\n", s, err)
				return
			}

			buf := make([]byte, 65535)
			n, err := udpconn.Read(buf)
			if err != nil {
				log.Printf("Failed to read from udp connection, error=%v\n", err)
				return
			}
			log.Println("receive", n, "bytes data from DNS", buf[:n])
			resch <- buf[:n]
		}(srv)
	}

	select {
	case v := <-resch:
		resplen = copy(resp, v)
		log.Println("copy", resplen, "bytes")
	case <-time.After(5 * time.Second):
		log.Printf("Timeout for waiting for server's response")
	}

	log.Println("overall DNS response:", resp[:resplen])
	//convert response to dns.RR and add it to cache
	dnsmsg := new(dns.Msg)
	if err := dnsmsg.Unpack(resp[:resplen]); err != nil {
		log.Println("unpack failed, invalid format or messages")
	}
	//usually only one question
	for _, quesname := range dnsmsg.Question {
		s.cache.Add(strings.Trim(quesname.Name, "."), dnsmsg.Answer)
		log.Println("add", strings.Trim(quesname.Name, "."), "to cache")
	}

	return resp[:resplen], nil
}

//sendResp will
func (s *DNSServer) sendResp(resp []byte, dst net.Addr) error {

	log.Println("will send to client:", resp)

	clientAddr := dst.(*net.UDPAddr)

	if clientAddr.IP.To4() != nil {
		_, err := s.ipv4conn.WriteToUDP(resp, clientAddr)
		if err != nil {
			return err
		}
	} else {
		_, err := s.ipv6conn.WriteToUDP(resp, clientAddr)
		if err != nil {
			return err
		}
	}

	return nil
}
func (s *DNSServer) ShutDown() error {
	if atomic.CompareAndSwapInt32(&s.running, 1, 0) {
		//close all listeners, including ipv4/ipv6/http
		if s.ipv4conn != nil {
			if err := s.ipv4conn.Close(); err != nil {
				log.Printf("failed to close ipv4 listener, error=%v\n", err)
			}
		}

		if s.ipv6conn != nil {
			if err := s.ipv6conn.Close(); err != nil {
				log.Printf("failed to close ipv6 listener, error=%v\n", err)
			}
		}

		if s.extendsrv != nil {
			if err := s.extendsrv.Close(); err != nil {
				log.Printf("failed to close http server, error=%v\n", err)
			}
		}
	}

	return nil
}
