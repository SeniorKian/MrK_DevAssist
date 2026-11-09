package certs

import "path/filepath"

// Reload replaces the certificate with the stored files (backup restore); a
// missing certificate clears it.
func (s *Store) Reload() error {
	n, err := Open(filepath.Dir(s.dir), s.now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cur.Store(n.cur.Load())
	s.mu.Unlock()
	return nil
}
