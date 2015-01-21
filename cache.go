package main

import (
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"

	"repo.anb.im/goutil/log"
)

type Cache struct {
	lru *lru.Cache
	sync.Mutex
}

type CacheEntry struct {
	an, ns, ex []dns.RR
	aa         bool
	ts         time.Time
}

func NewCache(size int) *Cache {
	switch size {
	case 0:
		return &Cache{}
	case -1:
		return &Cache{
			lru: lru.New(0),
		}
	default:
		return &Cache{
			lru: lru.New(size),
		}
	}
}

func (c *Cache) Put(key string, e *CacheEntry) {
	if c.lru == nil {
		return
	}

	// already in cache
	c.Lock()
	defer c.Unlock()

	e.ts = time.Now()

	c.lru.Add(key, e)
}

func (c *Cache) Get(key string) (*CacheEntry, bool) {
	if c.lru == nil {
		return nil, false
	}

	c.Lock()
	defer c.Unlock()
	value, ok := c.lru.Get(key)
	if !ok {
		log.Debug("cache miss for key: %s", key)
		return nil, false
	}

	entry := value.(*CacheEntry)
	elapse := uint32(time.Since(entry.ts).Seconds())
	newentry := &CacheEntry{}

	if newentry.an, ok = checkTTL(entry.an, elapse); !ok {
		return nil, false
	}
	if newentry.ns, ok = checkTTL(entry.ns, elapse); !ok {
		return nil, false
	}
	if newentry.ex, ok = checkTTL(entry.ex, elapse); !ok {
		return nil, false
	}
	newentry.aa = entry.aa
	return newentry, true
}

func checkTTL(sec []dns.RR, elapse uint32) ([]dns.RR, bool) {
	var newsec []dns.RR
	for _, rr := range sec {
		if rr.Header().Ttl <= elapse {
			log.Debug("ttl expire: %s, elapse: %d", rr, elapse)
			return nil, false
		}
		newrr := dns.Copy(rr)
		newrr.Header().Ttl -= elapse
		newsec = append(newsec, newrr)
	}
	return newsec, true
}
