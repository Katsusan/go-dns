package dnsclient

import (
	"bytes"
	"errors"
	"fmt"
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

	DNS_HEADER_LENGTH = 12

	//DNS中的RR类型
	RR_TYPE_A     = 1 //IPv4地址
	RR_TYPE_NS    = 2 //Name Server，名称服务器
	RR_TYPE_CNAME = 5
	RR_TYPE_SOA   = 6
	RR_TYPE_PTR   = 12
	RR_TYPE_MX    = 15 //邮件交换器，为域提供电子邮件处理主机的名称
	RR_TYPE_TXT   = 16
	RR_TYPE_AAAA  = 28 //IPv6地址
	RR_TYPE_SRV   = 33
	RR_TYPE_NAPTR = 35
	RR_TYPE_OPT   = 41
	RR_TYPE_IXFR  = 251 //增量区域传输
	RR_TYPE_AXFR  = 252
	RR_TYPE_ANY   = 255
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

	mapRRType = map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		35:  "NAPTR",
		41:  "OPT",
		251: "IXFR",
		255: "ANY",
	}

	mapRRClass = map[uint16]string{
		1: "IN",
	}

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

type DNSResponse struct {
	FromServer string
	Answer     []DNSAnswer
}

type DNSAnswer struct {
	Name    string
	RRType  string
	Class   string
	TTL     uint32
	DataLen uint16
	Ip      string
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

func (client *Dnsclient) DnsQuery(domain string, dnsserver []string) ([]DNSResponse, error) {
	var fnerr error
	result := make([]DNSResponse, 0)
	dnslist := dnsserver
	syscfg = readsystemcfg()
	if len(dnsserver) == 0 {
		//use system default DNS server
		dnslist = syscfg.nameservers
	}

	var wg sync.WaitGroup
	wg.Add(len(dnslist))
	queue := make(chan *DNSResponse, 1) // for receviving different responses from goroutines
	baseTransID, step := GenTransactionID()

	for k, server := range dnslist {
		go func(srvaddr string, srvi int) {
			//defer wg.Done()

			dnsresp := new(DNSResponse)
			log.Printf("start->server:%s, serveri:%d\n", srvaddr, srvi)
			var retry int8
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

			TransID := baseTransID + uint16(srvi)*step
			bTransID := []byte{byte(TransID >> 8), byte(TransID)} //16bit's unique tansaction id

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

			//set timer for timeout (after syscfg.timeout of time, will send true to timout channel)
			/*tmr := time.AfterFunc(syscfg.timeout, func() {
				log.Printf("goroutine[%d] timeout\n", k)
				tmout[k] <- true
			})*/

		STARTQUERY:
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
			_, err = udpcon.Write(msgall)
			if err != nil {
				fnerr = err
				return
			}
			//log.Printf("write bytes:%d\n", wn)

			//read response
			dnsresp.FromServer = srvaddr
			rc := make([]byte, 512) //usually DNS response length < 512 byte
			var rn int
			for {
				rn, _, err = recvcon.ReadFrom(rc)
				if err != nil {
					//try to make dns query again
					if retry < syscfg.retrytimes {
						log.Printf("retry to dns query again,[%d]\n ", retry)
						retry++
						goto STARTQUERY
					} else {
						//over the max retry times
						log.Printf("retry over the max retry times.")
						goto RTERR
					}
				}

				//transaction ID is consistent
				if rn > DNS_HEADER_LENGTH && bytes.Equal(bTransID, rc[0:2]) {
					//log.Printf("recv: %X\n", rc)
					if err = ParseResp(rc[2:], dnsresp); err != nil {
						continue
					}
					break
				}
			}
			//log.Printf("dnsresponse: %+v\n", dnsresp)
			queue <- dnsresp
			return

		RTERR:
			fnerr = err
			wg.Done()
			return
		}(server, k)
	}

	//collect the response
	go func() {
		for resp := range queue {
			//log.Printf("resp:%+v\n", resp)
			result = append(result, *resp)
			wg.Done()
		}
	}()

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
		if (ch < '0' && ch != '.' && ch != '-') || (ch > '9' && ch < 'A') ||
			(ch > 'Z' && ch < 'a') || (ch > 'z') {
			return []string{}, DomainInvalidErr
		}
	}

	return strings.SplitN(src, ".", 4), nil

}

//Linux: read system dns config from /etc/resolv.conf
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

	//if OS is windows then don't read from resolv.conf(use the default)
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

func ParseResp(src []byte, dnsresp *DNSResponse) error {
	var err error

	//verify QR(1->response) and OpCode(0000->normal query)
	//that is , whether src[0] is euqal to 10000xxx
	if (src[0] >> 3) != 0x10 {
		err = errors.New("QR or OpCode not correct.(should be 10000)")
		return err
	}

	//verify Reply Code(0000->no error)
	//that is , whether src[1] is equal to xxxx0000
	if (src[1] << 4) != 0x0 {
		err = errors.New("reply code not correct.(should be 0000)")
		return err
	}

	//number of RR
	RRnum := uint16(src[4])*256 + uint16(src[5])
	if RRnum < 1 {
		err = errors.New("RR number is 0")
		return err
	}

	//get query name in response
	nameb := make([]byte, 0)
	for nameindex := 10; nameindex < len(src) && src[nameindex] != 0x0; {
		unitlen := src[nameindex]
		nameb = append(nameb, src[nameindex+1:nameindex+int(unitlen)+1]...)
		nameb = append(nameb, '.')
		nameindex = nameindex + int(unitlen) + 1
	}
	domainname := string(bytes.TrimRight(nameb, "."))

	//look for 0xc00c(which indicates the first index of the domain name if it is repeated)
	//meaning of 0xc00c: 0xc00c = 11000000 00001100
	// first 2 bit "11" means it's a pointer, and the rest "1100" specifies the index of first appearance of domain name.
	// so if you count 12 bytes from tanscation id, you will see the domain name.
	firsti := bytes.Index(src, []byte{0xc0, 0x0c})
	if firsti == -1 {
		err = errors.New("domain name not found in response")
		return err
	}

	for l := 0; l < int(RRnum); l++ {
		anstype := mapRRType[uint16(src[firsti+2])*256+uint16(src[firsti+3])]
		ansclass := mapRRClass[uint16(src[firsti+4])*256+uint16(src[firsti+5])]
		ansttl := uint32(src[firsti+6])<<24 + uint32(src[firsti+7])<<16 +
			uint32(src[firsti+8])<<8 + uint32(src[firsti+9])
		ansdatalen := uint16(src[firsti+10])>>8 + uint16(src[firsti+11])
		ansip := fmt.Sprint(net.IPv4(src[firsti+12], src[firsti+13], src[firsti+14], src[firsti+15]))
		dnsresp.Answer = append(dnsresp.Answer, DNSAnswer{
			Name:    domainname,
			RRType:  anstype,
			Class:   ansclass,
			TTL:     ansttl,
			DataLen: ansdatalen,
			Ip:      ansip,
		})
		firsti = firsti + 16
	}

	return err
}
