// implement a relay server as a source
package source

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"repo.anb.im/goutil/log"
)

func init() {
	registerSource("relay", &relay{})
}

type result struct {
	upstream *resolver
	filtered bool
	response *dns.Msg
}

type resolver struct {
	addr       string
	unpolluted bool
}

type relay struct {
	upstreams []*resolver
	timeout   time.Duration
	delay     time.Duration
	init      bool
	sync.RWMutex
}

func (r *relay) String() string {
	return "[source.relay]"
}

func (r *relay) Reload(o map[string]string) error {
	var (
		err       error
		key       string
		upstreams []*resolver
		timeout   time.Duration
		delay     time.Duration
	)

	key = "upstream"
	v, exist := o[key]
	if !exist || v == "" {
		return makeErr("option not found: %s", key)
	}

	upstream := strings.Split(v, ",")
	for _, u := range upstream {
		s := strings.TrimSpace(u)

		resolv := &resolver{}
		if strings.HasSuffix(s, "U") {
			s = s[:len(s)-1]
			resolv.unpolluted = true
		}

		if _, _, err := net.SplitHostPort(s); err == nil {
			resolv.addr = s
		} else {
			resolv.addr = net.JoinHostPort(s, "53")
		}

		upstreams = append(upstreams, resolv)
	}

	if len(upstreams) == 0 {
		return makeErr("option value error: %s", key)
	}

	key = "timeout"
	v, exist = o[key]
	if !exist || v == "" {
		return makeErr("option not found: %s", key)
	}

	timeout, err = time.ParseDuration(v)
	if err != nil {
		return makeErr("option value error: [%s]%s", key, err)
	}

	// optional option
	key = "delay"
	v, exist = o[key]
	if exist && v != "" {
		delay, err = time.ParseDuration(v)
		if err != nil {
			return makeErr("option value error: [%s]%s", key, err)
		}
		delay = delay
	}

	haveU := false
	for _, u := range upstreams {
		if u.unpolluted {
			haveU = true
		}
	}
	if delay != 0 && !haveU {
		log.Info("using polluted source with non-zero delay")
	}

	r.Lock()
	defer r.Unlock()
	r.upstreams = upstreams
	r.timeout = timeout
	r.delay = delay
	r.init = true

	return nil
}

func (r *relay) Query(qname string, qtype uint16, client net.IPNet) *Answer {
	if !r.init {
		panic(ErrSourceNotInit.Error())
	}

	r.RLock()
	delay := r.delay
	upCount := len(r.upstreams)
	out := make(chan *result, upCount)
	for _, u := range r.upstreams {
		go relayResolve(u, r.timeout, delay, qname, qtype, out)
	}
	to := time.After(r.timeout)
	r.RUnlock()

	var results []*result
	done := false
	for !done {
		select {
		case res := <-out:
			results = append(results, res)
			// don't wait if no delay, or every upstream has returned
			if delay == 0 || len(results) == upCount {
				done = true
			}
		case <-to:
			done = true
		}
	}

	ans := &Answer{
		Rcode: dns.RcodeSuccess,
		Auth:  false,
		RA:    true,
	}
	a := relayChoose(results)
	if a != nil {
		ans.An = a.Answer
		ans.Ns = a.Ns
		ans.Ex = a.Extra
		ans.Rcode = a.Rcode
	}

	return ans
}

func relayResolve(upstream *resolver,
	timeout time.Duration, delay time.Duration,
	qname string, qtype uint16, out chan *result) {
	res := &result{
		upstream: upstream,
	}

	m := &dns.Msg{}
	m.RecursionDesired = true
	m.SetQuestion(qname, qtype)

	conn, err := dns.DialTimeout("udp", upstream.addr, timeout)
	if err != nil {
		return
	}

	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if err = conn.WriteMsg(m); err != nil {
		log.Warn("cannot write to upstream %s", upstream.addr)
		return
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	a, err := conn.ReadMsg()
	if err != nil {
		return
	}

	if delay == 0 {
		res.response = a
		select {
		case out <- res:
		default:
		}
		return
	}

	// anti-GFW tricks, delay for real answer
	var answers []*dns.Msg
	answers = append(answers, a)
	ch := make(chan *dns.Msg, 5)
	go func() {
		for {
			conn.SetReadDeadline(time.Now().Add(timeout))
			a, err := conn.ReadMsg()
			if err != nil {
				return
			}
			select {
			case ch <- a:
			default:
				return
			}
		}
	}()

	to := time.After(delay)
	done := false
	for !done {
		select {
		case a := <-ch:
			answers = append(answers, a)
		case <-to:
			done = true
		}
	}

	if len(answers) == 1 {
		res.response = answers[0]
	} else {
		log.Debug("find real answer from %d responses for query: %s", len(answers), qname)
		res.response = relayClean(answers)
		res.filtered = true
	}

	select {
	case out <- res:
	default:
	}
}

// return filtered answer if polluted, else the local one
func relayChoose(rs []*result) *dns.Msg {
	if len(rs) == 0 {
		return nil
	}

	var filtered, local *result
	for _, r := range rs {
		if r.filtered {
			filtered = r
		}

		if !r.upstream.unpolluted {
			local = r
		}
	}

	if filtered != nil {
		log.Debug("using filtered answer from %s", filtered.upstream.addr)
		return filtered.response
	}

	if local != nil {
		log.Debug("using local answer from %s", local.upstream.addr)
		return local.response
	}

	log.Debug("no local answer, use %s", rs[0].upstream.addr)
	return rs[0].response
}

func relayClean(answers []*dns.Msg) *dns.Msg {
	var lowerTTL *dns.Msg
	minTtl := uint32(86400)
	for _, a := range answers {
		// gfw's reply only contains 1 A record with very large ttl
		if len(a.Answer) != 1 {
			return a
		}

		ttl := a.Answer[0].Header().Ttl
		if minTtl >= ttl {
			minTtl = ttl
			lowerTTL = a
		}
	}

	// reduce the affection in case that we've selected a wrong
	// answer.
	if lowerTTL != nil && lowerTTL.Answer[0].Header().Ttl > 1800 {
		lowerTTL.Answer[0].Header().Ttl = 300
	}
	return lowerTTL
}
