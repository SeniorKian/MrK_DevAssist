package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"mrk/dns-engine/internal/fielderr"
)

// Filter list formats (docs/41 §3.1).
const (
	FormatHosts   = "hosts"
	FormatDomains = "domains"
	FormatAdblock = "adblock"
	FormatRPZ     = "rpz"
)

// Block actions.
const (
	BlockNXDomain = "nxdomain"
	BlockNullIP   = "null_ip"
	BlockRefuse   = "refuse"
)

// Client group filtering modes (docs/41 §3.2).
const (
	GroupInherit = "inherit"
	GroupOn      = "on"
	GroupOff     = "off"
)

// Bounds of the policy sections.
const (
	MaxFilterLists      = 31 // one bit each in the matcher masks (bit 31 = the custom lists)
	MaxCustomNames      = 10_000
	MaxClientGroups     = 64
	MaxGroupNetworks    = 256
	DefaultUpdateHours  = 24
	MaxUpdateHours      = 168
	MaxFilterListURLLen = 2048
)

// FilterList is one downloadable block list.
type FilterList struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Format      string `json:"format"`
	Enabled     bool   `json:"enabled"`
	UpdateHours int    `json:"update_hours"`
}

// Filtering is the settings section `filtering` (docs/41 §3.1).
type Filtering struct {
	Enabled    bool         `json:"enabled"`
	Lists      []FilterList `json:"lists"`
	Allow      []string     `json:"allow"`
	Block      []string     `json:"block"`
	Action     string       `json:"action"`
	SafeSearch bool         `json:"safe_search"`
}

// ClientGroup is one entry of `client_groups` (docs/41 §3.2). Lists and
// Upstreams empty mean "all enabled lists" and "the default upstreams".
type ClientGroup struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Networks        []string `json:"networks"`
	Filtering       string   `json:"filtering"`
	Lists           []string `json:"lists"`
	Upstreams       []string `json:"upstreams"`
	BlockedServices []string `json:"blocked_services"`
}

// DefaultFiltering is the factory section: off, no lists.
func DefaultFiltering() Filtering {
	return Filtering{Lists: []FilterList{}, Allow: []string{}, Block: []string{}, Action: BlockNXDomain}
}

func (f Filtering) clone() Filtering {
	c := f
	c.Lists = append([]FilterList{}, f.Lists...)
	c.Allow = append([]string{}, f.Allow...)
	c.Block = append([]string{}, f.Block...)
	return c
}

func cloneGroups(gs []ClientGroup) []ClientGroup {
	out := make([]ClientGroup, len(gs))
	for i, g := range gs {
		g.Networks = append([]string{}, g.Networks...)
		g.Lists = append([]string{}, g.Lists...)
		g.Upstreams = append([]string{}, g.Upstreams...)
		g.BlockedServices = append([]string{}, g.BlockedServices...)
		out[i] = g
	}
	return out
}

// PolicyID is the syntax of list, group and view identifiers.
var PolicyID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NormalizeFilterName validates a custom allow/block entry and returns its
// canonical form (lower case, no trailing dot, a leading "*." dropped: an
// entry always covers the name and its subdomains). Names must be ASCII
// (IDNs in punycode, the panel converts).
func NormalizeFilterName(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return s, true
}

func validateFiltering(s *Settings, l *fielderr.List) {
	f := &s.Filtering
	if f.Lists == nil {
		f.Lists = []FilterList{}
	}
	if f.Allow == nil {
		f.Allow = []string{}
	}
	if f.Block == nil {
		f.Block = []string{}
	}
	if f.Action == "" {
		f.Action = BlockNXDomain
	}
	switch f.Action {
	case BlockNXDomain, BlockNullIP, BlockRefuse:
	default:
		l.Add("filtering.action", "invalid_choice", "choices", []string{BlockNXDomain, BlockNullIP, BlockRefuse})
	}
	if len(f.Lists) > MaxFilterLists {
		l.Add("filtering.lists", "too_many", "max", MaxFilterLists)
	}
	ids := map[string]bool{}
	for i := range f.Lists {
		fl := &f.Lists[i]
		p := fmt.Sprintf("filtering.lists[%d]", i)
		fl.ID = strings.TrimSpace(fl.ID)
		if !PolicyID.MatchString(fl.ID) {
			l.Add(p+".id", "invalid_id")
		} else if ids[fl.ID] {
			l.Add(p+".id", "duplicate")
		}
		ids[fl.ID] = true
		fl.Name = strings.TrimSpace(fl.Name)
		if len(fl.Name) > 100 {
			l.Add(p+".name", "too_long", "max", 100)
		}
		switch u, err := url.Parse(strings.TrimSpace(fl.URL)); {
		case err != nil || u.Host == "" || u.User != nil || len(fl.URL) > MaxFilterListURLLen:
			l.Add(p+".url", "invalid_url")
		case u.Scheme != "https":
			l.Add(p+".url", "https_required")
		default:
			fl.URL = u.String()
		}
		switch fl.Format {
		case FormatHosts, FormatDomains, FormatAdblock, FormatRPZ:
		default:
			l.Add(p+".format", "invalid_choice", "choices", []string{FormatHosts, FormatDomains, FormatAdblock, FormatRPZ})
		}
		if fl.UpdateHours == 0 {
			fl.UpdateHours = DefaultUpdateHours
		}
		rng(l, p+".update_hours", fl.UpdateHours, 1, MaxUpdateHours)
	}
	names := func(field string, items []string) {
		if len(items) > MaxCustomNames {
			l.Add(field, "too_many", "max", MaxCustomNames)
			return
		}
		seen := map[string]bool{}
		out := items[:0]
		for i, it := range items {
			n, ok := NormalizeFilterName(it)
			if !ok {
				l.Add(fmt.Sprintf("%s[%d]", field, i), "invalid_name")
				out = append(out, it)
				continue
			}
			if seen[n] {
				continue // duplicates are dropped silently
			}
			seen[n] = true
			out = append(out, n)
		}
		if field == "filtering.allow" {
			f.Allow = out
		} else {
			f.Block = out
		}
	}
	names("filtering.allow", f.Allow)
	names("filtering.block", f.Block)

	if s.ClientGroups == nil {
		s.ClientGroups = []ClientGroup{}
	}
	if len(s.ClientGroups) > MaxClientGroups {
		l.Add("client_groups", "too_many", "max", MaxClientGroups)
	}
	ups := map[string]bool{}
	for _, u := range s.Upstreams {
		ups[u.ID] = true
	}
	gids := map[string]bool{}
	for i := range s.ClientGroups {
		g := &s.ClientGroups[i]
		p := fmt.Sprintf("client_groups[%d]", i)
		g.ID = strings.TrimSpace(g.ID)
		if !PolicyID.MatchString(g.ID) {
			l.Add(p+".id", "invalid_id")
		} else if gids[g.ID] {
			l.Add(p+".id", "duplicate")
		}
		gids[g.ID] = true
		g.Name = strings.TrimSpace(g.Name)
		if len(g.Name) > 100 {
			l.Add(p+".name", "too_long", "max", 100)
		}
		if g.Filtering == "" {
			g.Filtering = GroupInherit
		}
		switch g.Filtering {
		case GroupInherit, GroupOn, GroupOff:
		default:
			l.Add(p+".filtering", "invalid_choice", "choices", []string{GroupInherit, GroupOn, GroupOff})
		}
		if len(g.Networks) == 0 {
			l.Add(p+".networks", "required")
		}
		if len(g.Networks) > MaxGroupNetworks {
			l.Add(p+".networks", "too_many", "max", MaxGroupNetworks)
		}
		for j, n := range g.Networks {
			pf, ok := ParsePrefix(n)
			if !ok {
				l.Add(fmt.Sprintf("%s.networks[%d]", p, j), "invalid_network")
				continue
			}
			g.Networks[j] = pf.String()
		}
		if g.Lists == nil {
			g.Lists = []string{}
		}
		for j, id := range g.Lists {
			if !ids[id] {
				l.Add(fmt.Sprintf("%s.lists[%d]", p, j), "unknown_list")
			}
		}
		if g.Upstreams == nil {
			g.Upstreams = []string{}
		}
		for j, id := range g.Upstreams {
			if !ups[id] {
				l.Add(fmt.Sprintf("%s.upstreams[%d]", p, j), "unknown_upstream")
			}
		}
		if g.BlockedServices == nil {
			g.BlockedServices = []string{}
		}
		for j, sv := range g.BlockedServices {
			if _, ok := BlockedServices[sv]; !ok {
				l.Add(fmt.Sprintf("%s.blocked_services[%d]", p, j), "invalid_choice", "choices", ServiceIDs())
			}
		}
	}
}

// ParsePrefix accepts an IP (as a host prefix) or a CIDR and returns the
// masked prefix.
func ParsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		a, b := p.Addr(), p.Bits()
		if a.Is4In6() {
			if b < 96 {
				return netip.Prefix{}, false
			}
			a, b = a.Unmap(), b-96
		}
		return netip.PrefixFrom(a, b).Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// BlockedServices is the built-in catalogue of `blocked_services`: each
// service blocks its domains and their subdomains.
var BlockedServices = map[string][]string{
	"youtube":   {"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be"},
	"facebook":  {"facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fb.me", "messenger.com", "fbsbx.com"},
	"instagram": {"instagram.com", "cdninstagram.com", "ig.me", "instagr.am"},
	"whatsapp":  {"whatsapp.com", "whatsapp.net", "wa.me"},
	"tiktok":    {"tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com", "musical.ly"},
	"twitter":   {"twitter.com", "x.com", "twimg.com", "t.co"},
	"snapchat":  {"snapchat.com", "snap.com", "sc-cdn.net", "snapkit.co", "snapads.com"},
	"telegram":  {"telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe"},
	"discord":   {"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"},
	"reddit":    {"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"},
	"twitch":    {"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net"},
	"netflix":   {"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"},
	"spotify":   {"spotify.com", "scdn.co", "spotifycdn.com", "spotify.design"},
	"steam":     {"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net"},
	"roblox":    {"roblox.com", "rbxcdn.com", "roblox.cn"},
	"pinterest": {"pinterest.com", "pinimg.com", "pin.it"},
	"linkedin":  {"linkedin.com", "licdn.com", "lnkd.in"},
	"tinder":    {"tinder.com", "gotinder.com", "tindersparks.com"},
}

// ServiceIDs returns the catalogue keys, sorted.
func ServiceIDs() []string {
	out := make([]string, 0, len(BlockedServices))
	for k := range BlockedServices {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ { // tiny insertion sort (no sort import churn)
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
