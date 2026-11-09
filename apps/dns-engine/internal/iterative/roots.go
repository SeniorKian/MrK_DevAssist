package iterative

import "net/netip"

// Server is a name server with one address.
type Server struct {
	Name string
	Addr netip.Addr
}

// builtinRoots is named.root (IANA root hints): the 13 root servers a..m.
var builtinRoots = []struct{ name, v4, v6 string }{
	{"a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"},
	{"c.root-servers.net.", "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net.", "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net.", "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net.", "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"},
	{"m.root-servers.net.", "202.12.27.33", "2001:dc3::35"},
}

// BuiltinRoots returns the built-in root hints (both address families).
func BuiltinRoots() []Server {
	out := make([]Server, 0, 2*len(builtinRoots))
	for _, r := range builtinRoots {
		out = append(out, Server{Name: r.name, Addr: netip.MustParseAddr(r.v4)})
		out = append(out, Server{Name: r.name, Addr: netip.MustParseAddr(r.v6)})
	}
	return out
}
