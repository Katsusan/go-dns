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
	DEFAULT_TIMEOUT    = 3 * time.Second
	DEFAULT_RETRYTIMES = 3
)

var (
	NoErr       = errors.New("Everything OK")
	FormErr     = errors.New("Incorrect format")
	ServerFail  = errors.New("Server could't handle it")
	NXDomainErr = errors.New("Domain not exist")
	NotImpErr   = errors.New("Query not supported")
	RefuseErr   = errors.New("Query refused by server")
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

		}(server)
	}
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
