package filter

// Matcher is an immutable compiled view of all loaded lists plus the custom
// allow/block names. Safe for concurrent use.
type Matcher struct {
	block *set
	allow *set
}

// Hit describes a match.
type Hit struct {
	Mask uint32 // matching (active) list bits
	Off  int    // offset in the wire name of the matched suffix
	Sub  bool   // a "name and subdomains" rule matched
}

// Verdict of Match.
type Verdict int

// Match outcomes.
const (
	NotListed Verdict = iota
	Blocked
	Allowed // an allow rule (custom or list exception) matched
)

// find looks wire (lower-case wire-form name) up: exact and subtree rules
// for the full name, then subtree rules for each parent.
func (s *set) find(wire []byte, active uint32) (Hit, bool) {
	if s.len() == 0 {
		return Hit{}, false
	}
	off := 0
	for off < len(wire) && wire[off] != 0 {
		suffix := wire[off:]
		if off == 0 {
			if m := s.get(key(suffix, false)) & active; m != 0 {
				return Hit{Mask: m}, true
			}
		}
		if m := s.get(key(suffix, true)) & active; m != 0 {
			return Hit{Mask: m, Off: off, Sub: true}, true
		}
		next := off + 1 + int(wire[off])
		if next > len(wire) {
			break
		}
		off = next
	}
	return Hit{}, false
}

// Match checks a wire-form name against the lists in active (CustomBit
// selects the custom allow/block names). Allow rules win over block rules.
func (m *Matcher) Match(wire []byte, active uint32) (Verdict, Hit) {
	if m == nil {
		return NotListed, Hit{}
	}
	if h, ok := m.allow.find(wire, active); ok {
		return Allowed, h
	}
	if h, ok := m.block.find(wire, active); ok {
		return Blocked, h
	}
	return NotListed, Hit{}
}

// AllowedBy reports whether an allow rule of the lists in active covers wire.
func (m *Matcher) AllowedBy(wire []byte, active uint32) (Hit, bool) {
	if m == nil {
		return Hit{}, false
	}
	return m.allow.find(wire, active)
}

// Len is the number of unique block rules.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return m.block.len()
}

// Bytes is the memory held by the matcher.
func (m *Matcher) Bytes() int64 {
	if m == nil {
		return 0
	}
	return m.block.bytes() + m.allow.bytes()
}

// Counts returns per-bit rule counts (block + allow).
func (m *Matcher) Counts() [32]int {
	if m == nil {
		return [32]int{}
	}
	a, b := m.block.counts(), m.allow.counts()
	for i := range a {
		a[i] += b[i]
	}
	return a
}

// CustomKeys builds the custom-list sources from validated names (each covers
// the name and its subdomains).
func CustomKeys(names []string) []uint64 {
	out := make([]uint64, 0, len(names))
	for _, n := range names {
		out = append(out, nameKey(n, true))
	}
	return sortUnique(out)
}

// Update is one change applied by Rebuild: the list bit's entries are
// replaced by Parsed (nil Parsed removes the bit).
type Update struct {
	Bit    uint32
	Parsed *Parsed
}

// Rebuild derives a matcher from old keeping the bits in keep, replacing the
// bits of updates. Cost O(entries); the old matcher stays valid.
func Rebuild(old *Matcher, keep uint32, updates []Update) *Matcher {
	var ob, oa *set
	if old != nil {
		ob, oa = old.block, old.allow
	}
	var bs, as []source
	for _, u := range updates {
		if u.Parsed == nil {
			keep &^= u.Bit
			continue
		}
		bs = append(bs, source{keys: u.Parsed.Block, bit: u.Bit})
		as = append(as, source{keys: u.Parsed.Allow, bit: u.Bit})
	}
	return &Matcher{block: merge(ob, keep, bs), allow: merge(oa, keep, as)}
}
