package filter

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"

	"mrk/dns-engine/internal/config"
)

// Rule is one parsed list entry: Name (presentation, lower case, no trailing
// dot), Sub = the name and all its subdomains, Allow = an exception.
type Rule struct {
	Name  string
	Sub   bool
	Allow bool
}

// Parse errors.
var (
	ErrTooMany = errors.New("too many entries")
	ErrEmpty   = errors.New("no usable entries")
)

// Parsed is a list compiled to sorted unique keys.
type Parsed struct {
	Block []uint64
	Allow []uint64
	Lines int
}

// Entries is the number of unique rules.
func (p *Parsed) Entries() int { return len(p.Block) + len(p.Allow) }

// maxLine bounds one line; longer lines are skipped.
const maxLine = 4096

// Parse reads a list of the given format. maxEntries bounds the rules (raw,
// before de-duplication); 0 = unbounded.
func Parse(r io.Reader, format string, maxEntries int) (*Parsed, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	p := &parser{format: format}
	out := &Parsed{}
	var wbuf [256]byte
	n := 0
	var tooMany bool
	emit := func(ru Rule) {
		if tooMany {
			return
		}
		n++
		if maxEntries > 0 && n > maxEntries {
			tooMany = true
			return
		}
		k := key(AppendWire(wbuf[:0], ru.Name), ru.Sub)
		if ru.Allow {
			out.Allow = append(out.Allow, k)
		} else {
			out.Block = append(out.Block, k)
		}
	}
	skipping := false
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			skipping = true // overlong line: drop it up to its end
			continue
		}
		if len(line) > 0 && !skipping {
			out.Lines++
			if len(line) <= maxLine {
				p.parse(line, emit)
			}
		}
		if len(line) > 0 && line[len(line)-1] == '\n' {
			skipping = false
		}
		if tooMany {
			return nil, ErrTooMany
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	out.Block = sortUnique(out.Block)
	out.Allow = sortUnique(out.Allow)
	if len(out.Block) == 0 && len(out.Allow) == 0 {
		return nil, ErrEmpty
	}
	return out, nil
}

// ParseRules parses text and returns the rules (tests, check tools, fuzzing).
func ParseRules(format string, text []byte) []Rule {
	p := &parser{format: format}
	var out []Rule
	for _, line := range bytes.Split(text, []byte{'\n'}) {
		if len(line) <= maxLine {
			p.parse(line, func(r Rule) { out = append(out, r) })
		}
	}
	return out
}

type parser struct {
	format string
	origin string // RPZ $ORIGIN, no trailing dot
}

func trimSpace(b []byte) []byte { return bytes.TrimSpace(b) }

// cut returns b before the first c.
func cutAt(b []byte, c byte) []byte {
	if i := bytes.IndexByte(b, c); i >= 0 {
		return b[:i]
	}
	return b
}

func (p *parser) parse(line []byte, emit func(Rule)) {
	switch p.format {
	case config.FormatHosts:
		p.hosts(line, emit)
	case config.FormatDomains:
		p.domains(line, emit)
	case config.FormatAdblock:
		p.adblock(line, emit)
	case config.FormatRPZ:
		p.rpz(line, emit)
	}
}

// skipNames are hosts-file housekeeping entries, never blocked.
var skipNames = map[string]bool{"localhost.localdomain": true, "local.localdomain": true, "ip6-localhost.localdomain": true}

// listName validates a list entry: ASCII LDH (plus "_"), at least two labels,
// not an IP address.
func listName(b []byte) (string, bool) {
	if len(b) > 0 && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}
	if len(b) == 0 || len(b) > 253 {
		return "", false
	}
	var buf [253]byte
	out := buf[:0]
	labels, ll := 1, 0
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		case c == '.':
			if ll == 0 {
				return "", false
			}
			labels++
			ll = 0
			out = append(out, c)
			continue
		default:
			return "", false
		}
		ll++
		if ll > 63 {
			return "", false
		}
		out = append(out, c)
	}
	if ll == 0 || labels < 2 {
		return "", false
	}
	s := string(out)
	if _, err := netip.ParseAddr(s); err == nil || skipNames[s] {
		return "", false
	}
	return s, true
}

func (p *parser) hosts(line []byte, emit func(Rule)) {
	f := bytes.Fields(cutAt(line, '#'))
	if len(f) < 2 {
		return
	}
	if _, err := netip.ParseAddr(string(f[0])); err != nil {
		return
	}
	for _, n := range f[1:] {
		if s, ok := listName(n); ok {
			emit(Rule{Name: s})
		}
	}
}

func (p *parser) domains(line []byte, emit func(Rule)) {
	b := trimSpace(line)
	if len(b) == 0 || b[0] == '#' || b[0] == '!' || b[0] == ';' {
		return
	}
	b = trimSpace(cutAt(b, '#'))
	if f := bytes.Fields(b); len(f) == 2 {
		if _, err := netip.ParseAddr(string(f[0])); err == nil {
			p.hosts(b, emit) // hosts-style lines are common in "domains" lists
			return
		}
	}
	sub := false
	if bytes.HasPrefix(b, []byte("*.")) {
		b, sub = b[2:], true
	}
	if s, ok := listName(b); ok {
		emit(Rule{Name: s, Sub: sub})
	}
}

// adblock supports the DNS subset of the adblock syntax: ||name^, |name^,
// @@ exceptions, the $important modifier, bare names and hosts lines. Rules
// with other modifiers, wildcards, paths or regular expressions are skipped
// (they cannot be applied to DNS names faithfully).
func (p *parser) adblock(line []byte, emit func(Rule)) {
	b := trimSpace(line)
	if len(b) == 0 || b[0] == '!' || b[0] == '[' || b[0] == '#' {
		return
	}
	if bytes.Contains(b, []byte("##")) || bytes.Contains(b, []byte("#@#")) || bytes.Contains(b, []byte("#?#")) ||
		bytes.Contains(b, []byte("#$#")) {
		return // cosmetic rules
	}
	allow := false
	if bytes.HasPrefix(b, []byte("@@")) {
		b, allow = b[2:], true
	}
	if i := bytes.IndexByte(b, '$'); i >= 0 {
		for _, m := range bytes.Split(b[i+1:], []byte{','}) {
			if s := string(trimSpace(m)); s != "important" && s != "all" {
				return
			}
		}
		b = b[:i]
	}
	sub := false
	switch {
	case bytes.HasPrefix(b, []byte("||")):
		b, sub = b[2:], true
	case bytes.HasPrefix(b, []byte("|")):
		b = b[1:]
	default:
		if f := bytes.Fields(b); len(f) >= 2 {
			if !allow {
				p.hosts(b, emit)
			}
			return
		}
	}
	b = bytes.TrimSuffix(b, []byte("|"))
	b = bytes.TrimSuffix(b, []byte("^"))
	if s, ok := listName(b); ok {
		emit(Rule{Name: s, Sub: sub, Allow: allow})
	}
}

// rpz parses Response Policy Zone records (one per line): QNAME triggers
// with CNAME . (NXDOMAIN), CNAME *. (NODATA), CNAME rpz-drop., local data
// (A/AAAA/CNAME to another name) → blocked with the configured action;
// CNAME rpz-passthru. → allowed. "*.name" triggers cover the subdomains.
// Other trigger types (rpz-ip, rpz-nsdname, …) are skipped.
func (p *parser) rpz(line []byte, emit func(Rule)) {
	if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
		return // continuation of the previous owner (SOA/NS bodies)
	}
	b := trimSpace(cutAt(line, ';'))
	if len(b) == 0 {
		return
	}
	f := bytes.Fields(b)
	if bytes.EqualFold(f[0], []byte("$ORIGIN")) {
		if len(f) >= 2 {
			o := bytes.ToLower(bytes.TrimSuffix(f[1], []byte(".")))
			p.origin = string(o)
		}
		return
	}
	if f[0][0] == '$' || bytes.Equal(f[0], []byte("@")) || len(f) < 3 {
		return
	}
	i := 1
	for i < len(f) && (isNumber(f[i]) || bytes.EqualFold(f[i], []byte("IN"))) {
		i++
	}
	if i+1 >= len(f) {
		return
	}
	typ := bytes.ToUpper(f[i])
	rdata := bytes.ToLower(f[i+1])
	allow := false
	switch string(typ) {
	case "CNAME":
		if bytes.Equal(rdata, []byte("rpz-passthru.")) {
			allow = true
		}
	case "A", "AAAA", "TXT":
	default:
		return
	}
	owner := bytes.ToLower(f[0])
	if bytes.HasSuffix(owner, []byte(".")) {
		owner = owner[:len(owner)-1]
		if p.origin != "" {
			if bytes.HasSuffix(owner, []byte("."+p.origin)) {
				owner = owner[:len(owner)-len(p.origin)-1]
			} else {
				return // outside the policy zone
			}
		}
	}
	if bytes.Contains(owner, []byte(".rpz-")) || bytes.HasPrefix(owner, []byte("rpz-")) {
		return // IP / NSDNAME / client-IP triggers
	}
	sub := false
	if bytes.HasPrefix(owner, []byte("*.")) {
		owner, sub = owner[2:], true
	}
	if s, ok := listName(owner); ok {
		emit(Rule{Name: s, Sub: sub, Allow: allow})
	}
}

func isNumber(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
