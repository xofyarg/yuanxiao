package source

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	client "github.com/coreos/go-etcd/etcd"
	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
)

func init() {
	registerSource("etcd", &etcd{})
}

type etcd struct {
	machines  []string
	client    *client.Client
	cachesize int
	cachettl  time.Duration
	init      bool

	cl    sync.Mutex
	cache *lru.Cache

	sync.RWMutex
}

type entry struct {
	r      *client.Response
	expire time.Time
}

func (e *etcd) String() string {
	return fmt.Sprintf("[source.etcd]")
}

func (e *etcd) Reload(o map[string]string) error {
	var (
		key       string
		err       error
		machines  []string
		cli       *client.Client
		cachesize int
		cachettl  time.Duration
	)

	key = "machines"
	v := o[key]
	if v == "" {
		return makeErr("%s option value error: %s", e, key)
	}

	machines = commaSplit(v)
	cli = client.NewClient(machines)
	if cli == nil {
		return makeErr("%s cannot make client: %s", e, key)
	}

	key = "cache.size"
	v = o[key]
	cachesize, err = strconv.Atoi(v)
	if err != nil {
		return makeErr("%s option value error: %s", e, key)
	}

	key = "cache.ttl"
	v = o[key]
	cachettl, err = time.ParseDuration(v)
	if err != nil {
		return makeErr("%s option value error: %s", e, key)
	}

	// all done
	e.Lock()
	defer e.Unlock()
	e.machines = machines
	e.client = cli
	e.cachesize = cachesize
	e.cachettl = cachettl
	e.cache = lru.New(e.cachesize)
	e.init = true
	return nil
}

func (e *etcd) Query(qname string, qtype uint16, ip net.IP) *Answer {
	if !e.init {
		panic(ErrSourceNotInit.Error())
	}

	e.RLock()
	defer e.RUnlock()

	a := &authBase{e}
	ans := a.query(qname, qtype, ip)
	ans.Auth = true
	return ans
}

func (e *etcd) IsAuth() bool {
	return true
}

func (e *etcd) Get(key string) *client.Response {
	e.cl.Lock()
	v, ok := e.cache.Get(key)
	e.cl.Unlock()
	var item *entry
	if ok {
		item = v.(*entry)
		if item.expire.Before(time.Now()) {
			return item.r
		}
	}

	item = &entry{}
	r, err := e.client.Get(key, false, false)
	if err != nil {
		item.r = nil
	} else {
		item.r = r
	}
	item.expire = time.Now().Add(e.cachettl)
	e.cl.Lock()
	e.cache.Add(key, item)
	e.cl.Unlock()
	return item.r
}

func (e *etcd) findNode(qname string) int {
	qname = strings.ToLower(qname)
	labels := dns.SplitDomainName(qname)
	reverseSlice(labels)

	for i := len(labels); i >= 0; i-- {
		key := strings.Join(labels[:i], "/")
		r := e.Get(key)
		if r == nil {
			continue
		}

		return len(labels) - i
	}

	return len(labels)
}

func (e *etcd) getRR(qname string, qtype uint16, ip net.IP) []dns.RR {
	qname = strings.ToLower(qname)
	labels := dns.SplitDomainName(qname)
	reverseSlice(labels)
	key := strings.Join(labels, "/")

	r := e.Get(key)
	if r == nil {
		return nil
	}

	if r.Node.Nodes == nil {
		return nil
	}

	var result []dns.RR
	for _, n := range r.Node.Nodes {
		rr, err := dns.NewRR(n.Value)
		if err != nil || rr == nil {
			continue
		}

		if rr.Header().Rrtype != qtype && qtype != dns.TypeANY {
			continue
		}

		result = append(result, rr)
	}

	return result
}
