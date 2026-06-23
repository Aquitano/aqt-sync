package server

import (
	"testing"
	"time"
)

func TestKeyedMutexSerializesSameKey(t *testing.T) {
	k := newKeyedMutex()
	unlock := k.lock("r1")

	acquired := make(chan struct{})
	go func() {
		release := k.lock("r1")
		close(acquired)
		release()
	}()

	select {
	case <-acquired:
		t.Fatal("a second lock on the same key acquired while the first was held")
	case <-time.After(50 * time.Millisecond):
		// expected: the goroutine is blocked
	}

	unlock()
	select {
	case <-acquired:
		// expected: it proceeds once released
	case <-time.After(time.Second):
		t.Fatal("the second lock did not proceed after release")
	}
}

func TestKeyedMutexIndependentKeys(t *testing.T) {
	k := newKeyedMutex()
	held := k.lock("a")
	defer held()

	done := make(chan struct{})
	go func() {
		release := k.lock("b") // a different key must not block
		release()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("locks on different keys must not block each other")
	}
}
