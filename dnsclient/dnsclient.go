package dnsclient

import (
	"bytes"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

	QUERY_TYPE_A   = []byte{0x0, 0x1} //query ipv4
	QUERY_CLASS_IN = []byte{0x0, 0x1}

	syscfg *dnsConfig
)

type DNSHeader struct {
	TransctionID uint16
	Flags        uint16
	QDOrZOCount  uint16
	ANOrPRCount  uint16
	NSOrUPCount  uint16
	AROrADCount  uint16
}

type Dnsclient struct {
	conn *net.Conn
}

type dnsConfig struct {
	nameservers []string
	timeout     time.Duration
	retrytimes  int8
	err         error
}

//GenTransactionID will help generate 16bit transaction ID(for matching concurrent queries )
//formula: BasicTransID + n * Step
func GenTransactionID() (uint16, uint16) {
	var BasicTransID uint16
	var Step uint16

	unixnano := time.Now().UnixNano()
	r := rand.New(rand.NewSource(unixnano))
	BasicTransID = uint16(r.Int31n(65536))
	Step = uint16(r.Int31n(255))

	return BasicTransID, Step
}

func (client *Dnsclient) DnsQuery(domain string, dnsserver []string) (map[string]string, error) {
	var fnerr error
	result := make(map[string]string)
	dnslist := dnsserver
	if len(dnsserver) == 0 {
		//use system default DNS server
		syscfg := readsystemcfg()
		dnslist = syscfg.nameservers
	}

	var wg sync.WaitGroup
	wg.Add(len(dnslist))
	bTransID, step := GenTransactionID()

	for k, server := range dnslist {
		go func(srvaddr string) {
			defer wg.Done()
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

			TransID := bTransID + uint16(k)*step
			bTransID := []byte{byte(TransID >> 8), byte(TransID)}

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

			//issue UDP connect
			udpcon, err := net.DialUDP(DEFAULT_PROTOCOLv4, nil, udpaddr)
			if err != nil {
				fnerr = err
				return
			}
			defer udpcon.Close()

			//get local udp address as DNS server will respond to the same ip:port
			localudpaddr, err := net.ResolveUDPAddr(DEFAULT_PROTOCOLv4, udpcon.LocalAddr().String())
			if err != nil {
				fnerr = err
				return
			}

			//listen for dns response, as ttl may smaller than listen->send's execute time, so listen better before send
			log.Println("will listen at", localudpaddr)
			recvcon, err := net.ListenUDP(DEFAULT_PROTOCOLv4, localudpaddr)
			if err != nil {
				fnerr = err
				return
			}
			defer recvcon.Close()

			//set wait timeout
			recvcon.SetDeadline(time.Now().Add(syscfg.timeout))

			//send dns query msg
			msgall := append(append(bTransID, bHeader...), bquerymsg...)
			wn, err := udpcon.Write(msgall)
			if err != nil {
				fnerr = err
				return
			}
			log.Printf("write bytes:%d\n", wn)

			//read response
			rc := make([]byte, 512)
			var rn int
			for {
				rn, _, err := recvcon.ReadFrom(rc)
				if err != nil {
					fnerr = err
					return
				}
				if rn > 0 {
					log.Printf("recv: %X\n", rc)
					break
				}
			}

			log.Printf("length: %d,\nresponse: %s\n", rn, rc)

		}(server)
	}

	wg.Wait()
	return result, nil
}

//return dns header of standard query
func makeQueryHeader() *DNSHeader {
	header := new(DNSHeader)
	header.Flags = 0 | RD | AD //or header.Flags=0x0120
	header.QDOrZOCount = 1     //query count=1
	header.ANOrPRCount = 0
	header.NSOrUPCount = 0
	header.AROrADCount = 0 //usually additional records count not set
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

	//buidl domainname to dns query format, eg: "baidu.com" -> "5baidu3com0"
	for _, tag := range fields {
		if len(tag) == 0 {
			continue
		}
		lentag := append([]byte{}, byte(len(tag)))
		tmptag := append(lentag, []byte(tag)...)
		result = append(result, tmptag...)
	}
	result = append(result, byte(0x0))

	//add query type, if query ipv4 address then type is A (0x01)
	result = append(result, QUERY_TYPE_A...)

	//add query class, usually class is IN (0x01)
	result = append(result, QUERY_CLASS_IN...)

	return result, nil
}

func getFields(src string) ([]string, error) {
	//use ascii only, as Punycode not so universal
	for _, ch := range src {
		if (ch < '0' && ch != '.') || (ch > '9' && ch < 'A') || (ch > 'Z' && ch < 'a') || (ch > 'z') {
			return []string{}, DomainInvalidErr
		}
	}

	return strings.SplitN(src, ".", 4), nil

}

//*nix: read system dns config from /etc/resolv.conf
//windows: use defaultcfg
func readsystemcfg() *dnsConfig {
	var err error
	var conf *dnsConfig
	defaultcfg := &dnsConfig{
		nameservers: []string{DEFAULT_DNS1, DEFAULT_DNS2},
		timeout:     DEFAULT_TIMEOUT,
		retrytimes:  DEFAULT_RETRYTIMES,
		err:         nil,
	}

	if runtime.GOOS == "windows" {
		return defaultcfg
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
