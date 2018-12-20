package dnsclient

import (
	"errors"
	"math/rand"
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

//Use a 16bit transaction id and add the rest of DNS query
//return header of a standard DNS query msg
func MakeQueryHeader(transid uint16) []byte {

	header := new(DNSHeader)
	header.TransctionID = transid
	header.Flags = 0 | RD | AD //or header.Flags=0x0120
	header.QDOrZOCount = 1     //query count=1
	header.ANOrPRCount = 0
	header.NSOrUPCount = 0
	header.AROrADCount = 0 //usually additional records count not set

	bHeader := []byte{byte(transid >> 8), byte(transid),
		byte(header.Flags >> 8), byte(header.Flags),
		byte(header.QDOrZOCount >> 8), byte(header.QDOrZOCount),
		byte(header.ANOrPRCount >> 8), byte(header.ANOrPRCount),
		byte(header.NSOrUPCount >> 8), byte(header.NSOrUPCount),
		byte(header.AROrADCount >> 8), byte(header.AROrADCount)}

	return bHeader
}

//encode the domain name to the DNS query format
func MakeQueryMsg(domainname string) ([]byte, error) {
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
