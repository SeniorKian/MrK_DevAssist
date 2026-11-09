package tokens

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mrk/dns-engine/internal/fielderr"
	"mrk/dns-engine/internal/store"
)

func code(err error) string {
	var fe *fielderr.Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	return ""
}

func TestTokens(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	s, err := Open(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Create("  phone ", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Token) != 43 || c.QPS != DefaultQPS || c.Name != "phone" {
		t.Fatalf("created %+v", c)
	}
	b, _ := os.ReadFile(filepath.Join(dir, file))
	if strings.Contains(string(b), c.Token) {
		t.Fatal("secret stored in clear")
	}
	if fi, _ := os.Stat(filepath.Join(dir, file)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if tk := s.Lookup(c.Token); tk == nil || tk.ID != c.ID {
		t.Fatal("lookup failed")
	}
	if s.Lookup(c.Token[:42]) != nil || s.Lookup("") != nil {
		t.Fatal("wrong secret accepted")
	}
	for _, bad := range []int{0, MaxQPS + 1} {
		q := bad
		if _, err := s.Create("x", &q); code(err) != CodeInvalid {
			t.Fatalf("qps %d: %v", bad, err)
		}
	}
	if _, err := s.Create("", nil); code(err) != CodeInvalid {
		t.Fatal("empty name accepted")
	}
	if _, err := s.Create(strings.Repeat("n", 65), nil); code(err) != CodeInvalid {
		t.Fatal("long name accepted")
	}
	q := 5
	n := "tablet"
	v, err := s.Patch(c.ID, &n, &q)
	if err != nil || v.Name != "tablet" || v.QPS != 5 {
		t.Fatalf("patch %+v %v", v, err)
	}
	if _, err := s.Patch("nope", &n, nil); code(err) != CodeNotFound {
		t.Fatal("patch missing")
	}
	tk := s.Lookup(c.Token)
	now := time.Now().UnixNano()
	allowed := 0
	for i := 0; i < 20; i++ {
		if tk.Allow(now) {
			allowed++
		}
	}
	if allowed != 10 { // burst = 2 s of qps
		t.Fatalf("allowed %d", allowed)
	}
	if !tk.Allow(now + int64(time.Second)) {
		t.Fatal("bucket did not refill")
	}
	tk.Used(time.Now())
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, _ := Open(st, nil)
	if l := s2.List(); len(l) != 1 || l[0].Queries != 1 || l[0].LastUsedAt == nil || l[0].Name != "tablet" {
		t.Fatalf("reloaded %+v", l)
	}
	if s2.Lookup(c.Token) == nil {
		t.Fatal("lookup after reload")
	}
	if err := s2.Delete(c.ID); err != nil {
		t.Fatal(err)
	}
	if err := s2.Delete(c.ID); code(err) != CodeNotFound {
		t.Fatal("double delete")
	}
	for i := 0; i < MaxTokens; i++ {
		if _, err := s2.Create("t", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s2.Create("t", nil); code(err) != CodeLimitReached {
		t.Fatalf("limit: %v", err)
	}
}
