package guard

import (
	"testing"
	"time"
)

func TestPendingRequestsAreBoundedInBytesAndAge(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newPendingRequests(10, time.Minute)
	r.now = func() time.Time { return now }
	put := func(key string, n int) bool { return r.put(&pending{key: key, body: make([]byte, n)}) }

	if !put("a", 4) || !put("b", 4) {
		t.Fatal("room for both")
	}
	if !put("c", 4) {
		t.Fatal("room is made")
	}
	if _, ok := r.take("a"); ok {
		t.Fatal("the oldest makes room")
	}
	if put("huge", 11) {
		t.Fatal("one request over the bound is not held")
	}
	if p, ok := r.take("b"); !ok || len(p.body) != 4 {
		t.Fatal("b is held")
	}
	if _, ok := r.take("b"); ok {
		t.Fatal("taken once")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := r.take("c"); ok || r.used != 0 || r.order.Len() != 0 {
		t.Fatalf("an old request expires: used %d", r.used)
	}
	put("d", 3)
	put("d", 5)
	if r.used != 5 || r.order.Len() != 1 {
		t.Fatalf("a repeated key replaces: used %d", r.used)
	}
}

func TestADroppedRequestIsRememberedOnce(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newPendingRequests(8, time.Minute)
	r.now = func() time.Time { return now }
	r.put(&pending{key: "a", body: make([]byte, 6)})
	r.put(&pending{key: "b", body: make([]byte, 6)}) // evicts a
	if !r.wasLost("a") || r.wasLost("a") {
		t.Fatal("an evicted request is reported lost, once")
	}
	if r.wasLost("never") {
		t.Fatal("a request never held is not lost")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := r.take("b"); ok || !r.wasLost("b") {
		t.Fatal("an expired request is lost too")
	}
}
