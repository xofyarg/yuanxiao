package source

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type ae struct {
	remains []int
	rr      []string

	// internal counter
	remIndex int
	rrIndex  int

	// query
	qname string
	qtype string

	// expect
	an, ns, ex string
}

func (a *ae) findNode(qname string) int {
	i := a.remIndex
	if i >= len(a.remains) {
		i = len(a.remains) - 1
	}
	a.remIndex++
	return a.remains[i]
}

func (a *ae) getRR(qname string, qtype uint16, ip net.IP) []dns.RR {
	i := a.rrIndex
	if i >= len(a.rr) {
		i = len(a.rr) - 1
	}

	rr, _ := dns.NewRR(a.rr[i])
	if rr.Header().Rrtype != qtype {
		return nil
	}

	a.rrIndex++
	return []dns.RR{rr}
}

func normalize(s string) string {
	rr, _ := dns.NewRR(s)
	if rr == nil {
		return ""
	} else {
		return rr.String()
	}
}

func equalFirst(rr []dns.RR, s string) bool {
	if rr == nil || len(rr) == 0 {
		if s == "" {
			return true
		} else {
			return false
		}
	}

	return rr[0].String() == s

}

func checkBaseQuery(t *testing.T, a *ae) {
	ab := &authBase{a}

	a.an = normalize(a.an)
	a.ns = normalize(a.ns)
	a.ex = normalize(a.ex)

	ans := ab.query(a.qname, dns.StringToType[a.qtype], nil)
	if !equalFirst(ans.An, a.an) {
		t.Errorf("answer not equal: %s != %s", ans.An, a.an)
	}

	if !equalFirst(ans.Ns, a.ns) {
		t.Errorf("authority not equal: %s != %s", ans.Ns, a.ns)
	}

	if !equalFirst(ans.Ex, a.ex) {
		t.Errorf("additional not equal: %s != %s", ans.Ex, a.ex)
	}
}

func TestAuthBasic(t *testing.T) {
	a := &ae{
		remains: []int{0},
		rr: []string{
			" A 1.1.1.1",
		},
		qname: "foo.com.",
		qtype: "A",
		an:    "foo.com. A 1.1.1.1",
		ns:    "",
		ex:    "",
	}

	checkBaseQuery(t, a)
}

func TestAuthCname(t *testing.T) {
	a := &ae{
		remains: []int{0},
		rr: []string{
			" CNAME bar.com.",
		},
		qname: "foo.com.",
		qtype: "A",
		an:    "foo.com. CNAME bar.com.",
		ns:    "",
		ex:    "",
	}

	checkBaseQuery(t, a)
}

func TestAuthNs(t *testing.T) {
	a := &ae{
		remains: []int{1},
		rr: []string{
			" NS com.",
		},
		qname: "foo.com.",
		qtype: "A",
		an:    "",
		ns:    "foo.com. NS com.",
		ex:    "",
	}

	checkBaseQuery(t, a)
}

func TestAuthWildcard(t *testing.T) {
	a := &ae{
		remains: []int{1, 0},
		rr: []string{
			" A 1.1.1.1",
		},
		qname: "bar.foo.com.",
		qtype: "A",
		an:    "bar.foo.com. A 1.1.1.1",
		ns:    "",
		ex:    "",
	}

	checkBaseQuery(t, a)
}
