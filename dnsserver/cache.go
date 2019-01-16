package dnsserver

import (
	lru "github.com/hashicorp/golang-lru"
)

//for  ARCCache/TwoQueueCache
/*type CacheImpl interface {
	Add(k, v interface{})
	Contains(k interface{}) bool
	Get(k interface{}) (v interface{}, ok bool)
	Keys() []interface{}
	Len() int
	Peek(k interface{}) (v interface{}, ok bool)
	Purge()
	Remove(k interface{})
}*/

type ServerCache struct {
	Arccache      *lru.ARCCache
	TwoQueuecache *lru.TwoQueueCache
	cachename     string
}

func (c *ServerCache) Get(k interface{}) (v interface{}, ok bool) {
	if c.cachename == "ARC" {
		return c.Arccache.Get(v)
	} else if c.cachename == "TwoQueue" {
		return c.TwoQueuecache.Get(k)
	}

	return nil, false
}
