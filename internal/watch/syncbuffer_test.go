package watch_test

import (
	"bytes"
	"sync"
)

// syncBuffer is a thread-safe bytes.Buffer for use in tests where a goroutine
// writes to the buffer (via Watch) while the test goroutine polls buf.String().
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
