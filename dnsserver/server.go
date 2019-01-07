package dnsserver

import (
	"fmt"
	"net"
	"net/http"
	"sync"
)

const usage = `
	Usage: gDNS	[options]

	Server Options:
		-c,	--Config	<Config file>	configuration file path
	Command Options:
		-h,	--help	show help message
		-v,	--version	show version and exit
`

type Config struct {
	ipv4Addr          string //format: host
	ipv6Addr          string //format: host%zone
	ipv4InterfaceName string //Interface name, eg: eth0
	ipv6InterfaceName string
	port              string
}

type DNSServer struct {
	config       *Config
	args         []string
	ipv4conn     *net.UDPConn
	ipv6conn     *net.UDPConn
	cache        *ServerCache
	extendsrv    *http.Server
	shutdownLock sync.Mutex
	err          error
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

	dnssrv.ipv4conn = ipv4Listen
	dnssrv.ipv6conn = ipv6Listen

	return dnssrv, nil
}

func (s *DNSServer) Run() {
	if s.ipv4conn != nil {
		go s.recvmsg()
	}

}

func (s *DNSServer) recvmsg() {

}

func (s *DNSServer) ShutDown() {

}
