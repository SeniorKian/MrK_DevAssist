package tokens

// Reload replaces the token set with the stored file (backup restore).
func (s *Store) Reload() error {
	n, err := Open(s.st, s.now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.list.Store(n.list.Load())
	s.saved = n.saved
	s.mu.Unlock()
	return nil
}
