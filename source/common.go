package source

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"repo.anb.im/goutil/log"
)

var (
	ErrSourceNotInit = errors.New("source not initialized")
)

type Source interface {
	Reload(o map[string]string) error
	Query(qname string, qtype uint16) ([]dns.RR, []dns.RR, []dns.RR)
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
	getRR(string, uint16) []dns.RR
}

func (a *authBase) query(qname string, qtype uint16) (an []dns.RR, ns []dns.RR, ex []dns.RR) {
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
		rr := a.getRR(qname, qtype)
		if rr == nil {
			if qtype == dns.TypeCNAME {
				return
			}

			// TODO: start a sub query internally
			rr := a.getRR(qname, dns.TypeCNAME)
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
		an, ns, ex = a.query(name, qtype)
		if an != nil || ns != nil || ex != nil {
			return
		}

		name = fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS)
		if rr != nil {
			an = nil
			ns = rr
			ex = nil
			return
		}

	// check domain delegation only
	default:
		name := fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS)
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
