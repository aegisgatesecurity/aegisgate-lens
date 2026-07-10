// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens - devtools_test.go
//
// Regression test for the B6fix4 fix: the close() method must be
// idempotent (calling it twice or having it called by both close()
// AND readLoop() must not panic with "close of closed channel").
//
// The previous version had a double-close bug:
//   close()    does close(c.closeEv)
//   readLoop() does close(c.closeEv) on conn error
// Calling close() after the goroutine had already errored would
// cause the panic, which was visible in the CI log as
// "panic: close of closed channel, goroutine 124 [running]".
//
// The fix uses sync.Once to ensure closeEv is closed at most once.

package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestCDPClientCloseIsIdempotent(t *testing.T) {
	// Build a CDPClient directly (no real WebSocket) so we can
	// test the close() logic in isolation.
	c := &CDPClient{
		events:    make(chan json.RawMessage, 1),
		closeEv:   make(chan struct{}),
		closeOnce: sync.Once{},
		timeout:   1 * time.Second,
	}

	// Call close() multiple times - none should panic
	c.close()
	c.close()
	c.close()

	// closeEv should be closed exactly once
	select {
	case <-c.closeEv:
		// good
	default:
		t.Fatal("closeEv was not closed")
	}

	// Calling close() a 4th time should still be a no-op
	c.close()
}

func TestCDPClientCloseThenReadLoopExit(t *testing.T) {
	// Simulate the real scenario: close() is called, then readLoop
	// (would) also try to close() on a conn error. With sync.Once
	// this should NOT panic.
	c := &CDPClient{
		events:    make(chan json.RawMessage, 1),
		closeEv:   make(chan struct{}),
		closeOnce: sync.Once{},
		timeout:   1 * time.Second,
	}

	// First close (e.g., from main()'s defer)
	c.close()

	// Simulate readLoop seeing a conn error and (in the OLD code)
	// trying to close(c.closeEv) again. With sync.Once, close()
	// is now a no-op so this is safe.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("close() panicked on second call: %v", r)
		}
	}()
	c.close() // would be the readLoop path in old code

	// Should still be closed
	select {
	case <-c.closeEv:
		// good
	default:
		t.Fatal("closeEv was not closed after 2nd close")
	}
}

func TestCDPClientCloseConcurrently(t *testing.T) {
	// Concurrent close() calls from multiple goroutines - all should
	// be safe with sync.Once (no panic, no double-close).
	c := &CDPClient{
		events:    make(chan json.RawMessage, 1),
		closeEv:   make(chan struct{}),
		closeOnce: sync.Once{},
		timeout:   1 * time.Second,
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("concurrent close() panicked: %v", r)
				}
			}()
			c.close()
		}()
	}
	wg.Wait()
}
