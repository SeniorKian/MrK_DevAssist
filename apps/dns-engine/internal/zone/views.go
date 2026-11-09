package zone

import (
	"regexp"
	"sort"
)

// View declares a split-horizon view of a zone (docs/41 §3.3): records whose
// `view` is GroupID are served to that client group. With RecordsOverride
// (the default) a view RRset replaces the general RRset of the same name and
// type; without it the view records are added to the general ones.
type View struct {
	GroupID         string `json:"group_id"`
	RecordsOverride *bool  `json:"records_override,omitempty"`
}

// Override reports the effective records_override flag.
func (v View) Override() bool { return v.RecordsOverride == nil || *v.RecordsOverride }

// viewID is the syntax of a view (client group) identifier.
var viewID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidViewID reports whether s is a valid view identifier.
func ValidViewID(s string) bool { return viewID.MatchString(s) }

// ViewIDs returns the distinct views used by enabled records, sorted.
func ViewIDs(z *Zone) []string {
	seen := map[string]bool{}
	var out []string
	for i := range z.Records {
		if v := z.Records[i].View; v != "" && !z.Records[i].Disabled && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// ViewOverride returns the records_override flag of a view of z.
func (z *Zone) ViewOverride(view string) bool {
	for _, v := range z.Views {
		if v.GroupID == view {
			return v.Override()
		}
	}
	return true
}

// CompileView compiles the zone as seen by view: the general records plus
// the view's records (replacing general RRsets of the same name/type when
// the view overrides). A view CNAME replaces every general record of its
// name and a view record of another type replaces a general CNAME, so the
// result stays a valid zone.
func CompileView(z *Zone, view string) (*Compiled, error) {
	override := z.ViewOverride(view)
	type nt struct{ name, typ string }
	vTypes := map[nt]bool{}
	vNames := map[string]bool{}
	vCNAME := map[string]bool{}
	for i := range z.Records {
		r := &z.Records[i]
		if r.View == view && !r.Disabled {
			vTypes[nt{r.Name, r.Type}] = true
			vNames[r.Name] = true
			if r.Type == "CNAME" {
				vCNAME[r.Name] = true
			}
		}
	}
	vz := *z
	vz.Records = make([]Record, 0, len(z.Records))
	for i := range z.Records {
		r := z.Records[i]
		switch {
		case r.View == view:
			r.View = ""
		case r.View != "":
			continue // another view
		case vCNAME[r.Name]:
			continue
		case vNames[r.Name] && r.Type == "CNAME":
			continue
		case override && vTypes[nt{r.Name, r.Type}]:
			continue
		}
		vz.Records = append(vz.Records, r)
	}
	return Compile(&vz)
}
