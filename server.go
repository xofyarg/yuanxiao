package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"repo.anb.im/goutil/log"

	"repo.anb.im/yuanxiao/source"

	"repo.anb.im/goutil/option"
)

type context struct {
	sources []source.Source
	cache   *Cache
	server  *dns.Server
}

var GlobalContext *context

func serverInit() error {
	var (
		err     error
		sources []source.Source
		cache   *Cache
		server  *dns.Server
	)

	enabled := option.GetString("source.enable")
	ss := strings.Split(enabled, ",")
	for _, s := range ss {
		s = strings.TrimSpace(s)
		obj := source.Sources[s]
		if obj == nil {
			return makeErr("invalid source: %s", s)
		}

		opt := getoption(s)
		if err = obj.Reload(opt); err != nil {
			log.Debug("failed to config source: %s", s)
			return err
		}

		sources = append(sources, obj)
		log.Info("source %s loaded", s)
	}

	cache = NewCache(option.GetInt("server.cachesize"))

	server = &dns.Server{}
	server.Addr = option.GetString("server.addr")
	server.Net = "udp"
	server.Handler = dns.HandlerFunc(rootHandler)
	server.NotifyStartedFunc = func() {
		log.Info("server started")
	}

	if GlobalContext == nil {
		GlobalContext = &context{}
	}

	GlobalContext.sources = sources
	GlobalContext.cache = cache
	GlobalContext.server = server

	return nil
}

func serverReload() error {
	// check config
	if err := option.LoadConfig(option.GetString("config.path")); err != nil {
		return err
	}

	// parse cli args again to overwrite config value
	if err := option.Parse(); err != nil {
		return err
	}

	oldserver := GlobalContext.server
	if err := serverInit(); err != nil {
		return err
	}

	return oldserver.Shutdown()
}

func serverStart() error {
	for {
		s := GlobalContext.server
		err := s.ListenAndServe()
		if err != nil {
			return err
		}
	}
}

func getoption(name string) map[string]string {
	all := option.All()
	o := make(map[string]string)
	prefix := fmt.Sprintf("source.%s.", name)

	for k, v := range all {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		key := k[len(prefix):]
		o[key] = v
	}

	return o
}

func rootHandler(w dns.ResponseWriter, m *dns.Msg) {
	// TODO: add some checks
	if len(m.Question) != 1 {
		// err
	}

	sources := GlobalContext.sources
	cache := GlobalContext.cache

	q := m.Question[0]

	a := &dns.Msg{}
	a.SetReply(m)

	client := net.ParseIP(strings.Split(w.RemoteAddr().String(), ":")[0])
	//   or from eDNS
	if o := m.IsEdns0(); o != nil {
		for _, v := range o.Option {
			if e, ok := v.(*dns.EDNS0_SUBNET); ok {
				client = e.Address
				break
			}
		}
	}
	log.Debug("query from client: %s", client)

	key := fmt.Sprintf("%s %s %s", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
	if entry, ok := cache.Get(key); !ok {
		for _, obj := range sources {
			log.Debug("try to get answer from: %s", obj)
			a.Answer, a.Ns, a.Extra = obj.Query(q.Name, q.Qtype, client)
			a.Authoritative = obj.IsAuth()
			if a.Answer != nil || a.Ns != nil || a.Extra != nil {
				break
			}
		}

		if len(a.Answer) != 0 ||
			len(a.Ns) != 0 ||
			len(a.Extra) != 0 {

			e := &CacheEntry{
				an: a.Answer,
				ns: a.Ns,
				ex: a.Extra,
				aa: a.Authoritative,
			}
			cache.Put(key, e)
			log.Debug("add to cache: %s", key)
		} else {
			log.Debug("ignore empty answer: %s", key)
		}
	} else {
		log.Debug("get from cache: %s", key)
		a.Answer = entry.an
		a.Ns = entry.ns
		a.Extra = entry.ex
		a.Authoritative = entry.aa
	}

	a.RecursionAvailable = false
	w.WriteMsg(a)
}

func makeErr(v ...interface{}) error {
	var msg string
	if len(v) == 1 {
		msg = fmt.Sprintf("%s", v[0])
	} else {
		msg = fmt.Sprintf(v[0].(string), v[1:]...)
	}
	return errors.New(msg)
}
