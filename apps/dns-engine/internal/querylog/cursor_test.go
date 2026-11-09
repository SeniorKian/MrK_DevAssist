package querylog

import (
	"fmt"
	"testing"
	"time"
)

// TestCursorStableAfterDelete pages through the log while rows are deleted
// between pages (segments rewritten in place): every remaining row is
// returned exactly once, in order (docs/41 §4).
func TestCursorStableAfterDelete(t *testing.T) {
	l, ck, _, _ := newLogger(t, nil)
	l.st.SegmentRows = 300
	base := ck.now()
	var recs []Record
	for i := 0; i < 1000; i++ {
		recs = append(recs, rec(base.Add(time.Duration(i)*time.Second), fmt.Sprintf("10.0.0.%d", i%4), fmt.Sprintf("n%d.example", i), 1, 0, SrcCache))
	}
	l.Process(recs, nil, nil)
	l.Process(nil, nil, nil)

	// first page: the newest 100 rows (n999 … n900)
	r := search(t, l, "limit=100")
	if len(r.Rows) != 100 || r.Next == nil || r.Next.Gen == 0 {
		t.Fatalf("page 1: %d rows, next %+v", len(r.Rows), r.Next)
	}
	seen := map[string]bool{}
	for _, row := range r.Rows {
		seen[row.Name] = true
	}
	next := r.Next.String()
	// delete one client's rows everywhere: every segment is rewritten and the
	// row indices behind the cursor shift
	if res, err := l.Delete("10.0.0.1", 0); err != nil || res.DeletedRows != 250 {
		t.Fatal(err, res)
	}
	var got []Row
	for page := 0; next != "" && page < 50; page++ {
		r = search(t, l, "limit=100&cursor="+next)
		got = append(got, r.Rows...)
		next = ""
		if r.Next != nil {
			next = r.Next.String()
		}
	}
	// expected: rows older than n900 whose client is not 10.0.0.1
	want := 0
	for i := 899; i >= 0; i-- {
		if i%4 != 1 {
			want++
		}
	}
	if len(got) != want {
		t.Fatalf("got %d rows after the delete, want %d", len(got), want)
	}
	last := int64(1 << 62)
	for _, row := range got {
		if seen[row.Name] {
			t.Fatalf("row %s returned twice", row.Name)
		}
		seen[row.Name] = true
		if row.Client == "10.0.0.1" {
			t.Fatal("deleted row returned")
		}
		if row.TS > last {
			t.Fatal("order broken")
		}
		last = row.TS
	}

	// a cursor from before "delete everything" does not resurface new rows
	r = search(t, l, "limit=10")
	next = r.Next.String()
	if _, err := l.Delete("", 0); err != nil {
		t.Fatal(err)
	}
	var fresh []Record
	for i := 0; i < 50; i++ {
		fresh = append(fresh, rec(base.Add(time.Duration(2000+i)*time.Second), "10.0.0.9", fmt.Sprintf("new%d.example", i), 1, 0, SrcCache))
	}
	l.Process(fresh, nil, nil)
	l.Process(nil, nil, nil)
	if r = search(t, l, "limit=100&cursor="+next); len(r.Rows) != 0 {
		t.Fatalf("stale cursor returned %d newer rows", len(r.Rows))
	}
	// v1 cursors (before this change) still parse
	if c, ok := ParseCursor(Cursor{Seq: 3, Row: 7}.String()); !ok || c.Gen != 0 || c.Row != 7 {
		t.Fatal("v1 cursor", c, ok)
	}
	if c, ok := ParseCursor(Cursor{Seq: 3, Row: 7, Gen: 9, TS: 12}.String()); !ok || c.Gen != 9 || c.TS != 12 {
		t.Fatal("v2 cursor", c, ok)
	}
}
