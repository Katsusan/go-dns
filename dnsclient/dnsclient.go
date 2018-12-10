package dnsclient

import (
	"net"
	"os"
	"time"
)

const (
	UNIX_CONFIG_FILE   = "/etc/resolv.conf"
	DEFAULT_DNS1       = "8.8.8.8:53"
	DEFAULT_DNS2       = "1.1.1.1:53"
	DEFAULT_TIMEOUT    = 3 * time.Second
	DEFAULT_RETRYTIMES = 3
)

type DNSHeader struct {
	TransctionID uint16
	Flagss       uint16
	QDOrZOCount  uint16
	ANOrPRCount  uint16
	NSOrUPCount  uint16
	AROrADCount  uint16
}

type dnsclient struct {
	conn *net.UDPConn
}

type dnsConfig struct {
	nameservers []string
	timeout     time.Duration
	retrytimes  int8
	err         error
}

//GenTransactionID will return 16bit transaction ID(for matching different queries)
func GenTransactionID() uint16 {
	var transID uint16

	unixnano := time.Now().UnixNano()

	return transID
}

func (client *dnsclient) Dnsquery(domain string, dnsserver string) error {
	var err error
	if dnsserver == "" {
		//use system default DNS server

	}
	return err
}

//read system dns config from /etc/resolv.conf
func readsystemcfg() *dnsConfig {
	var err error
	defaultcfg := &dnsConfig{
		nameservers: []string{DEFAULT_DNS1, DEFAULT_DNS2},
		timeout:     DEFAULT_TIMEOUT,
		retrytimes:  DEFAULT_RETRYTIMES,
		err:         nil,
	}

	file, err := os.Open(UNIX_CONFIG_FILE)
	if err != nil {
		return defaultcfg
	}
	defer file.Close()

	var fcontent []byte
	if _, err := file.Read(fcontent); err != nil {
		return defaultcfg
	}

	return defaultcfg
}

//use '\n' as delimiter to split []byte into []string
func byteintolines(src []byte, dst []string) error {
	//if nothing in src, then nothing will be appended into dst.
	srcstr := string(src)
	if len(src) == 0 {
		dst = []string{}
		return nil
	}

	start := 0
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			dst = append(dst)
		}
	}
}
