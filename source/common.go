package source

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"repo.anb.im/goutil/log"
)

var (
	ErrSourceNotInit = errors.New("source not initialized")
)

type Source interface {
	Reload(o map[string]string) error
	Query(qname string, qtype uint16, ip net.IP) ([]dns.RR, []dns.RR, []dns.RR)
	IsAuth() bool
}

var Sources = map[string]Source{}

func registerSource(name string, obj Source) {
	Sources[name] = obj
	log.Info("register a source: %s", name)
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

func commaSplit(s string) []string {
	tok := strings.Split(s, ",")
	var r []string
	for _, v := range tok {
		r = append(r, strings.TrimSpace(v))
	}
	return r
}

func reverseSlice(s []string) {
	if s == nil {
		return
	}

	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

type authBase struct {
	authExt
}

type authExt interface {
	findNode(string) int
	getRR(string, uint16, net.IP) []dns.RR
}

func (a *authBase) query(qname string, qtype uint16, ip net.IP) (an []dns.RR, ns []dns.RR, ex []dns.RR) {
	// change rr's name to qname
	defer func() {
		an = a.applyName(an, qname)
		ns = a.applyName(ns, qname)
		ex = a.applyName(ex, qname)
	}()

	labels := dns.SplitDomainName(qname)
	remains := a.findNode(qname)

	switch remains {
	// normal case
	case 0:
		rr := a.getRR(qname, qtype, ip)
		if rr == nil {
			if qtype == dns.TypeCNAME {
				return
			}

			// TODO: start a sub query internally
			rr := a.getRR(qname, dns.TypeCNAME, ip)
			an = rr
			return
		}

		an = rr
		return

	// need to check wildcard and domain delegation
	case 1:
		// check if already a wildcard query
		if labels[0] == "*" {
			return
		}

		// try wildcard first
		name := fmt.Sprintf("*.%s.", strings.Join(labels[remains:], "."))
		an, ns, ex = a.query(name, qtype, ip)
		if an != nil || ns != nil || ex != nil {
			return
		}

		name = fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS, ip)
		if rr != nil {
			an = nil
			ns = rr
			ex = nil
			return
		}

	// check domain delegation only
	default:
		name := fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS, ip)
		if rr != nil {
			an = nil
			ns = rr
			ex = nil
			return
		}
	}

	return
}

func (a *authBase) applyName(list []dns.RR, qname string) []dns.RR {
	if list == nil {
		return nil
	}

	result := make([]dns.RR, len(list))
	for i := 0; i < len(list); i++ {
		rr := list[i]
		if rr.Header().Name != qname {
			result[i] = dns.Copy(rr)
			result[i].Header().Name = qname
		} else {
			result[i] = list[i]
		}
	}
	return result
}

// subnet record support
type srecord struct {
	r []dns.RR
	n *net.IPNet
}
type Srecords struct {
	d []*srecord
}

func NewSrecords() *Srecords {
	return &Srecords{}
}

func (s *Srecords) Add(r dns.RR, n *net.IPNet) {
	header := r.Header()
	match := false
	for _, v := range s.d {
		if n.String() == v.n.String() {
			// check if records has a cname. (p15 of rfc1034)
			if header.Rrtype == dns.TypeCNAME {
				log.Info("overwrite all the previous records by a CNAME record: %s", header.Name)
				v.r = []dns.RR{r}
			} else {
				v.r = append(v.r, r)
			}
			match = true
			break
		}
	}

	if !match {
		s.d = append(s.d, &srecord{r: []dns.RR{r}, n: n})
	}
}

func (s *Srecords) Get(qtype uint16, ip net.IP) []dns.RR {
	var min *srecord
	for _, v := range s.d {
		if !v.n.Contains(ip) {
			continue
		}

		if min == nil {
			min = v
			continue
		}

		o1, _ := v.n.Mask.Size()
		o2, _ := min.n.Mask.Size()
		if o1 > o2 {
			min = v
			continue
		}
	}

	if min == nil {
		return nil
	}

	var result []dns.RR
	for _, rr := range min.r {
		if rr.Header().Rrtype != qtype && qtype != dns.TypeANY {
			continue
		}

		result = append(result, rr)
	}
	return result
}
