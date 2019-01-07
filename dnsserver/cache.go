package dnsserver

import "sync"

type ServerCache struct {
	mu sync.RWMutex
}
