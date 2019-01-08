package dnsserver

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

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
const ARCCacheSize = 4096

type Config struct {
	ipv4Addr          string //format: host
	ipv6Addr          string //format: host%zone
	ipv4InterfaceName string //Interface name, eg: eth0
	ipv6InterfaceName string
	port              string
	cache             string //optional cache algorithm, "ARC"/"2Q"
}

type DNSServer struct {
	config        *Config
	args          []string
	ipv4conn      *net.UDPConn
	ipv6conn      *net.UDPConn
	cache         *ServerCache
	extendsrv     *http.Server
	shutdownLock  sync.Mutex
	listeningv4   int32 //1->listenning, 0->closed
	listeningv6   int32 //1->listenning, 0->closed
	listeninghttp int32 //1->listenning, 0->closed
	running       int32
}

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

	if cfg.cache == "ARC" {
		var err error
		dnssrv.cache.Arccache, err = lru.NewARC(ARCCacheSize)
		if err != nil {

		}
	}

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

	for _, ques := range querymsg.Question {

	}

	return nil
}

func Resolve(name string) {

}

func (s *DNSServer) shutDown() {
	if atomic.CompareAndSwapInt32(&s.running, 1, 0) {
	}
}
