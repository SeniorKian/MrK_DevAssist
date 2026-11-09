package filter

import "bytes"

// Names is a small immutable set of "name and subdomains" entries tagged
// with an id (the blocked-services catalogue of a client group).
type Names struct {
	m map[string]string // wire suffix → id
}

// NewNames builds a set from id → names.
func NewNames(byID map[string][]string) *Names {
	n := &Names{m: map[string]string{}}
	for id, names := range byID {
		for _, s := range names {
			n.m[string(AppendWire(nil, s))] = id
		}
	}
	return n
}

// Len is the number of names.
func (n *Names) Len() int {
	if n == nil {
		return 0
	}
	return len(n.m)
}

// Match returns the id of the entry covering wire.
func (n *Names) Match(wire []byte) (string, bool) {
	if n == nil || len(n.m) == 0 {
		return "", false
	}
	off := 0
	for off < len(wire) && wire[off] != 0 {
		if id, ok := n.m[string(wire[off:])]; ok {
			return id, true
		}
		next := off + 1 + int(wire[off])
		if next > len(wire) {
			break
		}
		off = next
	}
	return "", false
}

// Safe-search targets (the engines' documented DNS enforcement names).
const (
	SafeGoogle  = "forcesafesearch.google.com."
	SafeYouTube = "restrict.youtube.com."
	SafeBing    = "strict.bing.com."
	SafeDDG     = "safe.duckduckgo.com."
	SafeYandex  = "familysearch.yandex.ru."
)

var safeExact = func() map[string]string {
	m := map[string]string{}
	add := func(target string, names ...string) {
		for _, n := range names {
			m[string(AppendWire(nil, n))] = target
		}
	}
	add(SafeYouTube, "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com",
		"www.youtube-nocookie.com")
	add(SafeBing, "www.bing.com", "bing.com")
	add(SafeDDG, "duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com", "html.duckduckgo.com")
	add(SafeYandex, "yandex.ru", "www.yandex.ru", "yandex.com", "www.yandex.com", "ya.ru", "www.ya.ru")
	return m
}()

// SafeSearch returns the enforcement CNAME target for a search engine name:
// google.<tld>, www.google.<tld> (one- or two-label TLDs like co.uk) and
// the fixed YouTube/Bing/DuckDuckGo/Yandex names.
func SafeSearch(wire []byte) (string, bool) {
	if t, ok := safeExact[string(wire)]; ok {
		return t, true
	}
	b := wire
	if bytes.HasPrefix(b, []byte("\x03www")) {
		b = b[4:]
	}
	if !bytes.HasPrefix(b, []byte("\x06google")) {
		return "", false
	}
	b = b[7:]
	labels := 0
	for len(b) > 0 && b[0] != 0 {
		n := int(b[0])
		if n+1 > len(b) || n > 3 {
			return "", false // TLD labels are short (com, co, uk, de, ...)
		}
		b = b[n+1:]
		labels++
	}
	if labels < 1 || labels > 2 {
		return "", false
	}
	return SafeGoogle, true
}
