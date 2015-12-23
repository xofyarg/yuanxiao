package main

import (
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"

	"go.papla.net/goutil/log"

	"go.papla.net/yuanxiao/source"
)

type Cache struct {
	lru     *lru.Cache
	timeout time.Duration
	sync.Mutex
}

type cacheEntry struct {
	ans *source.Answer
	ts  time.Time
}

func NewCache(size int, to time.Duration) *Cache {
	switch size {
	case 0:
		return &Cache{}
	case -1:
		return &Cache{
			lru:     lru.New(0),
			timeout: to,
		}
	default:
		return &Cache{
			lru:     lru.New(size),
			timeout: to,
		}
	}
}

func (c *Cache) Put(key string, a *source.Answer) {
	if c.lru == nil {
		return
	}

	c.Lock()
	defer c.Unlock()

	e := &cacheEntry{}
	e.ts = time.Now()
	e.ans = a

	c.lru.Add(key, e)
}

func (c *Cache) Get(key string) (*source.Answer, bool) {
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

	entry := value.(*cacheEntry)
	elapse := time.Since(entry.ts)
	if elapse > c.timeout {
		return nil, false
	}

	delta := uint32(elapse.Seconds())
	newans := &source.Answer{}

	if newans.An, ok = checkTTL(entry.ans.An, delta); !ok {
		return nil, false
	}
	if newans.Ns, ok = checkTTL(entry.ans.Ns, delta); !ok {
		return nil, false
	}
	if newans.Ex, ok = checkTTL(entry.ans.Ex, delta); !ok {
		return nil, false
	}
	newans.Auth = entry.ans.Auth
	newans.Rcode = entry.ans.Rcode
	return newans, true
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
