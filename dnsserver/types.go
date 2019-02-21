package dnsserver

import (
	"net"
	"net/http"
	"sync"

	"github.com/miekg/dns"
)

type Config struct {
	ipv4Addr          string //ipv4 listening address, format: host
	ipv6Addr          string //ipv6 listening address, format: host%zone
	ipv4InterfaceName string //Interface name, eg: eth0
	ipv6InterfaceName string //same to above
	port              int
	cache             string //optional cache algorithm, "ARC"/"TwoQueue"
	DoH               bool   //use DNSoverHTTPS
	serverlist        []string
}

type DNSServer struct {
	cfg           *Config
	args          []string
	ipv4conn      *net.UDPConn
	ipv6conn      *net.UDPConn
	extendsrv     *http.Server
	shutdownLock  sync.Mutex
	listeningv4   int32 //1->listenning, 0->closed
	listeningv6   int32 //1->listenning, 0->closed
	listeninghttp int32 //1->listenning, 0->closed
	running       int32
	cache         DNSCache
}

type Hosts struct {
	ip    map[string][]dns.RR
	state uint32 //unready=0/on service=1
}

type test struct {
	rr   []dns.RR
	ques dns.Question
}
