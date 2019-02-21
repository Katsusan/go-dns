package dnsserver

import (
	lru "github.com/hashicorp/golang-lru"
)

//DNSCache is implement for  ARCCache/TwoQueueCache
//usually k is the domain name(string),
//while v is the []dns.RR
type DNSCache interface {
	Add(k, v interface{})
	Contains(k interface{}) bool
	Get(k interface{}) (v interface{}, ok bool)
	Keys() []interface{}
	Len() int
	Peek(k interface{}) (v interface{}, ok bool)
	Purge()
	Remove(k interface{})
}

type ServerCache struct {
	Arccache      *lru.ARCCache
	TwoQueuecache *lru.TwoQueueCache
	cachename     string
}
