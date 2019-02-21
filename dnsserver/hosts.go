package dnsserver

import (
	"errors"
	"sync/atomic"

	"github.com/miekg/dns"
)

func (h *Hosts) Get(name string) ([]dns.RR, error) {
	if atomic.LoadUint32(&h.state) != 1 {
		return []dns.RR{}, errors.New("state of Hosts is unready(not init or reloading)")
	}

	return h.ip[name], nil
}
