package metrics

import (
	"strings"
	"testing"
)

func TestMetrics(t *testing.T) {
	m := New()
	for i := 0; i < 120; i++ {
		m.QueriesUDP.Add(1)
	}
	m.Tick()
	if q1, _ := m.QPS(); q1 != 120 {
		t.Fatalf("qps1s %v", q1)
	}
	m.QueriesTCP.Add(30)
	m.Tick()
	q1, q60 := m.QPS()
	if q1 != 30 || q60 <= 0 {
		t.Fatalf("qps %v %v", q1, q60)
	}
	m.Source(SrcCache)
	m.Rcode(3)
	m.Drop(DropRRL)
	m.Upstream("cloudflare").Queries.Add(2)
	var b strings.Builder
	m.WritePrometheus(&b, []Gauge{{Name: "mrk_dns_x", Help: "x", Labels: `a="b"`, Value: 1.5}})
	out := b.String()
	for _, want := range []string{`mrk_dns_queries_total{proto="udp"} 120`, `mrk_dns_answers_total{source="cache"} 1`,
		`mrk_dns_responses_total{rcode="3"} 1`, `mrk_dns_dropped_total{reason="rrl"} 1`,
		`mrk_dns_upstream_queries_total{upstream="cloudflare"} 2`, `mrk_dns_x{a="b"} 1.5`, "# TYPE mrk_dns_qps gauge"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}
