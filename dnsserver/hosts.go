package dnsserver

import (
	"errors"
	"net"
	"sync/atomic"
)

func (h *Hosts) Get(name string) ([]net.IP, error) {
	if atomic.LoadUint32(&h.state) != 1 {
		return []net.IP{}, errors.New("state of Hosts is unready(uninit or reloading)")
	}

	return h.ip[name], nil
}
