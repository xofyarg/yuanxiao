// implement a plain text file source
package source

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"repo.anb.im/goutil/log"
)

func init() {
	registerSource("plain", &plain{})
}

type plain struct {
	path string
	root *node
	init bool
	sync.RWMutex
}

func (p *plain) String() string {
	return fmt.Sprintf("[source.plain]")
}

type node struct {
	records []dns.RR
	sub     map[string]*node
}

func (n *node) String() string {
	var f func(*node) string
	f = func(n *node) string {
		c := ""
		for _, rr := range n.records {
			c += rr.String() + "\n"
		}

		for _, sn := range n.sub {
			c += f(sn)
		}
		return c
	}

	return f(n)
}

func (p *plain) Reload(o map[string]string) error {
	var key string
	key = "path"
	v := o[key]
	if v == "" {
		return makeErr("%s option value error: %s", p, key)
	}

	root, err := plainLoad(v)
	if err != nil {
		return err
	}

	p.Lock()
	defer p.Unlock()

	p.path = v
	p.root = root
	p.init = true
	return nil
}

// implement algorithm described in p24 of rfc1034.
func (p *plain) Query(qname string, qtype uint16) ([]dns.RR, []dns.RR, []dns.RR) {
	if !p.init {
		panic(ErrSourceNotInit.Error())
	}

	p.RLock()
	defer p.RUnlock()

	a := &authBase{p}
	return a.query(qname, qtype)
}

func (p *plain) IsAuth() bool {
	return true
}

func (p *plain) findNode(qname string) int {
	qname = strings.ToLower(qname)
	labels := dns.SplitDomainName(qname)
	reverseSlice(labels)

	ptr := p.root
	for i := range labels {
		sn := ptr.sub[labels[i]]
		if sn == nil {
			return len(labels) - i
		}
		ptr = sn
	}
	return 0
}

func (p *plain) getRR(qname string, qtype uint16) []dns.RR {
	qname = strings.ToLower(qname)
	labels := dns.SplitDomainName(qname)
	reverseSlice(labels)

	ptr := p.root
	for i := range labels {
		ptr = ptr.sub[labels[i]]
	}

	var result []dns.RR
	for _, rr := range ptr.records {
		if rr.Header().Rrtype != qtype && qtype != dns.TypeANY {
			continue
		}

		result = append(result, rr)
	}

	return result
}

func plainLoad(path string) (*node, error) {
	root := plainNewNode()
	f := func(path string, info os.FileInfo, err error) error {
		result := "success"
		defer func() {
			log.Debug("loading file: %s(%s)", path, result)
		}()

		if err != nil {
			result = "error"
			return err
		}

		if info.IsDir() {
			result = "ignore"
			return nil
		}

		// ignore hidden files
		if strings.HasPrefix(filepath.Base(path), ".") {
			result = "ignore"
			return nil
		}

		return plainLoadFile(path, root)
	}

	if err := filepath.Walk(path, f); err != nil {
		return nil, err
	}

	return root, nil
}

func plainLoadFile(path string, root *node) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := dns.ParseZone(f, ".", "")
	for t := range r {
		if t.Error != nil {
			return t.Error
		}

		plainAddToNode(root, t.RR)
	}
	return nil
}

func plainAddToNode(n *node, rr dns.RR) {

	header := rr.Header()
	labels := dns.SplitDomainName(header.Name)

	ptr := n
	if labels != nil {
		for i := len(labels) - 1; i >= 0; i-- {
			l := strings.ToLower(labels[i])
			v := ptr.sub[l]
			if v != nil {
				ptr = v
			} else {
				nn := plainNewNode()
				ptr.sub[l] = nn
				ptr = nn
			}
		}
	}

	// check if records has a cname. (p15 of rfc1034)
	if header.Rrtype == dns.TypeCNAME {
		if len(ptr.records) != 0 {
			log.Debug("overwrite all the previous records by a CNAME record: %s", header.Name)
		}
		ptr.records = []dns.RR{rr}
	} else {
		ptr.records = append(ptr.records, rr)
	}
	//log.Debug("added to node: [%s]", rr)
}

func plainNewNode() *node {
	return &node{
		sub: make(map[string]*node),
	}
}
