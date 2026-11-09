package mitigate

// Reload replaces the in-memory set with the file's content (backup restore,
// docs/41 §4). The query path keeps reading the previous index until the
// new one is published.
func (s *Store) Reload() error {
	n, err := Open(s.path, s.now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.m = n.m
	s.rebuildLocked()
	s.mu.Unlock()
	return nil
}
