package dnsclient

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	UNIX_CONFIG_FILE   = "/etc/resolv.conf"
	DEFAULT_DNS1       = "8.8.8.8"
	DEFAULT_DNS2       = "1.1.1.1"
	DEFAULT_PORT       = "53"
	DEFAULT_TIMEOUT    = 5 * time.Second
	DEFAULT_RETRYTIMES = 3
	DEFAULT_PROTOCOLv4 = "udp4"

	QR = 1 << 15 //query=0 (from client), response=1 (from server)
	AA = 1 << 10 //authority response (from server)
	TC = 1 << 9  //truncated response (from server)
	RD = 1 << 8  //recursion desired (from client)
	RA = 1 << 7  //recursion available (from server)
	AD = 1 << 5  //true data (from both server and client <-> RFC4035)
	CD = 1 << 4  //verify forbidden (from both server and client <-> RFC4035)
)

var (
	//errors in DNS response
	NoErr       = errors.New("Everything OK")
	FormErr     = errors.New("Incorrect format")
	ServerFail  = errors.New("Server could't handle it")
	NXDomainErr = errors.New("Domain not exist")
	NotImpErr   = errors.New("Query not supported")
	RefuseErr   = errors.New("Query refused by server")

	DomainLenErr     = errors.New("Domain name over max length(255)")
	DomainInvalidErr = errors.New("Invalid characters in domain name")
)

type DNSHeader struct {
	TransctionID uint16
	Flags        uint16
	QDOrZOCount  uint16
	ANOrPRCount  uint16
	NSOrUPCount  uint16
	AROrADCount  uint16
}

type dnsclient struct {
	conn *net.Conn
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

	//unixnano := time.Now().UnixNano()

	return transID
}

func (client *dnsclient) Dnsquery(domain string, dnsserver []string) (map[string]string, error) {
	var fnerr error
	result := make(map[string]string)
	dnslist := dnsserver
	if len(dnsserver) == 0 {
		//use system default DNS server
		syscfg := readsystemcfg()
		dnslist = syscfg.nameservers
	}

	for _, server := range dnslist {
		go func(srvaddr string) {
			if !strings.Contains(srvaddr, ":") {
				if net.ParseIP(srvaddr) == nil {
					fnerr = errors.New("Invalid IP format")
					return
				}
				srvaddr = net.JoinHostPort(srvaddr, DEFAULT_PORT)
			} else if _, _, err := net.SplitHostPort(srvaddr); err != nil {
				fnerr = errors.New("Invalid IP:Host format")
				return
			}

			hd := makeQueryHeader()
			bHeader := []byte{byte(hd.Flags >> 8), byte(hd.Flags),
				byte(hd.QDOrZOCount >> 8), byte(hd.QDOrZOCount),
				byte(hd.ANOrPRCount >> 8), byte(hd.ANOrPRCount),
				byte(hd.NSOrUPCount >> 8), byte(hd.NSOrUPCount),
				byte(hd.AROrADCount >> 8), byte(hd.AROrADCount)}

			bquerymsg, err := makeQueryMsg(domain)
			if err != nil {
				fnerr = err
				return
			}

			udpaddr, err := net.ResolveUDPAddr(DEFAULT_PROTOCOLv4, srvaddr)
			if err != nil {
				fnerr = err
				return
			}

			udpcon, err := net.DialUDP(DEFAULT_PROTOCOLv4, nil, udpaddr)
			if err != nil {
				fnerr = err
				return
			}
			udpcon.SetDeadline()

		}(server)
	}
}

//return dns header of standard query
func makeQueryHeader() *DNSHeader {
	header := new(DNSHeader)
	header.Flags = 0 | RD | AD //or header.Flags=0x0120
	header.QDOrZOCount = 1     //query count=1
	header.ANOrPRCount = 0
	header.NSOrUPCount = 0
	header.AROrADCount = 1 //additional infomation count=1
	return header
}

//
func makeQueryMsg(domainname string) ([]byte, error) {
	var result []byte
	//length of FQDN <= 255 bytes
	if len(domainname) > 255 {
		return result, DomainLenErr
	}

	fields, err := getFields(domainname)
	if err != nil {
		return result, err
	}

	for _, tag := range fields {
		if len(tag) == 0 {
			continue
		}
		lentag := append([]byte{}, byte(len(tag)))
		tmptag := append(lentag, []byte(tag)...)
		result = append(result, tmptag...)
	}

	return result, nil
}

func getFields(src string) ([]string, error) {
	//use ascii only, as Punycode not so universal
	for ch := range src {
		if (ch < '0') || (ch > '9' && ch < 'A') || (ch > 'Z' && ch < 'a') || (ch > 'z') {
			return []string{}, DomainInvalidErr
		}
	}

	return strings.SplitN(src, ".", 4), nil

}

//read system dns config from /etc/resolv.conf
func readsystemcfg() *dnsConfig {
	var err error
	var conf *dnsConfig
	defaultcfg := &dnsConfig{
		nameservers: []string{DEFAULT_DNS1, DEFAULT_DNS2},
		timeout:     DEFAULT_TIMEOUT,
		retrytimes:  DEFAULT_RETRYTIMES,
		err:         nil,
	}

	file, err := os.Open(UNIX_CONFIG_FILE)
	if err != nil {
		defaultcfg.err = err
		return defaultcfg
	}
	defer file.Close()

	var fcontent []byte
	if _, err := file.Read(fcontent); err != nil {
		defaultcfg.err = err
		return defaultcfg
	}

	lines := bytes.Split(fcontent, []byte{'\n'})
	for i := 0; i < len(lines); i++ {
		//start with "nameserver"
		if index := bytes.LastIndexAny(lines[i], "nameserver"); index == 9 {
			servers := bytes.TrimSpace(lines[i][index+1:]) //remove the space, " a.b.c.d x.y.z.t "->"a.b.c.d x.y.z.t"
			serversarr := bytes.Split(servers, []byte{' '})
			for n := 0; n < len(serversarr); n++ {
				conf.nameservers = append(conf.nameservers, string(serversarr[n]))
			}
			continue
		}

		if index := bytes.LastIndexAny(lines[i], "options"); index == 6 {
			options := bytes.TrimSpace(lines[i][index+1:])
			optionsarr := bytes.Fields(options) //split by space, so there should be no space between option and value
			for n := 0; n < len(optionsarr); n++ {
				if bytes.Equal(optionsarr[n], []byte("timeout:")) {
					if tmout, err := strconv.Atoi(string(optionsarr[n][8:])); err == nil && tmout > 0 {
						conf.timeout = time.Duration(tmout) * time.Second
					}
				}

				if bytes.Equal(optionsarr[n], []byte("attempts:")) {
					if retry, err := strconv.Atoi(string(optionsarr[n][9:])); err == nil && retry > 0 {
						conf.retrytimes = int8(retry)
					}
				}
			}
		}
	}

	if len(conf.nameservers) == 0 {
		conf.nameservers = []string{DEFAULT_DNS1, DEFAULT_DNS2}
	}

	if conf.timeout == time.Duration(0) {
		conf.timeout = DEFAULT_TIMEOUT
	}

	if conf.retrytimes == 0 {
		conf.retrytimes = DEFAULT_RETRYTIMES
	}
	return conf
}
