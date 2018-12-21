package dnsclient

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Dnsclient struct {
	conn *net.Conn
}

type dnsConfig struct {
	nameservers []string
	timeout     time.Duration
	retrytimes  int8
	err         error
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
			bHeader := MakeQueryHeader(TransID)
			bquerymsg, err := MakeQueryMsg(domain)
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
			msgall := append(bHeader, bquerymsg...)
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
				if rn > DNS_HEADER_LENGTH && byte(TransID>>8) == rc[0] && byte(TransID) == rc[1] {
					//log.Printf("recv: %X\n", rc)
					if err = ParseResp(rc[2:], dnsresp.Answer); err != nil {
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

//parse the dns response into dns answer including RR type,RR class, TTL, IP etc..
func ParseResp(src []byte, answer []DNSAnswer) error {
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
		answer = append(answer, DNSAnswer{
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
