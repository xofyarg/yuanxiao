package source

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"go.papla.net/goutil/log"
)

var (
	ErrSourceNotInit = errors.New("source not initialized")
)

type Source interface {
	Reload(o map[string]string) error
	Query(qname string, qtype uint16, client net.IPNet) *Answer
}

var Sources = map[string]Source{}

func registerSource(name string, obj Source) {
	Sources[name] = obj
	log.Info("register a source: %s", name)
}

type Answer struct {
	An, Ns, Ex []dns.RR
	Rcode      int
	Auth       bool
	RA         bool
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
	getRR(string, uint16, net.IPNet) []dns.RR
}

func (a *authBase) query(qname string, qtype uint16, client net.IPNet) *Answer {
	ans := &Answer{}

	// change rr's name to qname
	defer func() {
		if ans == nil {
			return
		}

		ans.An = a.applyName(ans.An, qname)
		ans.Ns = a.applyName(ans.Ns, qname)
		ans.Ex = a.applyName(ans.Ex, qname)
	}()

	labels := dns.SplitDomainName(qname)
	remains := a.findNode(qname)

	switch remains {
	// normal case
	case 0:
		rr := a.getRR(qname, qtype, client)
		if rr == nil {
			if qtype == dns.TypeCNAME {
				ans.Rcode = dns.RcodeSuccess
				return ans
			}

			// TODO: start a sub query internally
			rr := a.getRR(qname, dns.TypeCNAME, client)
			ans.An = rr
			ans.Rcode = dns.RcodeSuccess
			return ans
		}

		ans.An = rr
		ans.Rcode = dns.RcodeSuccess
		return ans

	// need to check wildcard and domain delegation
	case 1:
		// check if already a wildcard query
		if labels[0] == "*" {
			ans.Rcode = dns.RcodeNameError
			return ans
		}

		// try wildcard first
		name := fmt.Sprintf("*.%s.", strings.Join(labels[remains:], "."))
		ans = a.query(name, qtype, client)
		if ans.Rcode != dns.RcodeNameError {
			return ans
		}

		name = fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS, client)
		if rr != nil {
			ans.An = nil
			ans.Ns = rr
			ans.Ex = nil
			ans.Rcode = dns.RcodeSuccess
			return ans
		}

		ans.Rcode = dns.RcodeNameError
		return ans

	// check domain delegation only
	default:
		name := fmt.Sprintf("%s.", strings.Join(labels[remains:], "."))
		rr := a.getRR(name, dns.TypeNS, client)
		if rr != nil {
			ans.An = nil
			ans.Ns = rr
			ans.Ex = nil
			ans.Rcode = dns.RcodeSuccess
			return ans
		}

		ans.Rcode = dns.RcodeNameError
		return ans
	}

	panic("should not reach here")
	//return ans
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

func (s *Srecords) Get(qtype uint16, sn net.IPNet) []dns.RR {
	var min *srecord
	// find a subnet contains sn
	for _, v := range s.d {
		o1, _ := v.n.Mask.Size()
		o2, _ := sn.Mask.Size()
		if o1 > o2 {
			continue
		}
		if !v.n.Contains(sn.IP) {
			continue
		}

		if min == nil {
			min = v
			continue
		}

		o3, _ := min.n.Mask.Size()
		if o1 > o3 {
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
