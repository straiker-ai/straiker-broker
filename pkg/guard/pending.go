package guard

import (
	"container/list"
	"sync"
	"time"

	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
	"github.com/straiker-ai/straiker-broker/pkg/guard/provider"
)

// pending is a model request whose answer is still to come: the answer's check needs the request it answers.
type pending struct {
	key  string
	call provider.Call
	body []byte
	id   detect.Identity
	at   time.Time
}

// pendingRequests holds requests from their check until their answer's preflight, bounded in bytes and age: an
// answer that never comes (a failed upstream, a response stage not attached) costs nothing for long.
type pendingRequests struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	used  int
	byKey map[string]*list.Element
	order *list.List // oldest first
	now   func() time.Time
	// lost are requests dropped before their answer came (evicted for room, or expired): their answers must not pass
	// as unseen. Bounded in count and age.
	lost      map[string]time.Time
	lostOrder *list.List
}

const (
	maxLost = 4096
	lostTTL = 10 * time.Minute
)

func newPendingRequests(max int, ttl time.Duration) *pendingRequests {
	return &pendingRequests{max: max, ttl: ttl, byKey: map[string]*list.Element{}, order: list.New(), now: time.Now,
		lost: map[string]time.Time{}, lostOrder: list.New()}
}

// put holds p, evicting the oldest to make room; false when p alone exceeds the bound.
func (r *pendingRequests) put(p *pending) bool {
	if len(p.body) > r.max {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p.at = r.now()
	if el, ok := r.byKey[p.key]; ok {
		r.remove(el)
	}
	r.expire()
	for r.used+len(p.body) > r.max && r.order.Len() > 0 {
		r.drop(r.order.Front())
	}
	r.byKey[p.key] = r.order.PushBack(p)
	r.used += len(p.body)
	return true
}

// take removes and returns the request for key.
func (r *pendingRequests) take(key string) (*pending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expire()
	el, ok := r.byKey[key]
	if !ok {
		return nil, false
	}
	r.remove(el)
	return el.Value.(*pending), true
}

func (r *pendingRequests) expire() {
	cutoff := r.now().Add(-r.ttl)
	for el := r.order.Front(); el != nil && el.Value.(*pending).at.Before(cutoff); el = r.order.Front() {
		r.drop(el)
	}
}

// drop removes a request whose answer hasn't come, and remembers it as lost.
func (r *pendingRequests) drop(el *list.Element) {
	key := el.Value.(*pending).key
	r.remove(el)
	r.lost[key] = r.now()
	r.lostOrder.PushBack(key)
	for r.lostOrder.Len() > maxLost {
		delete(r.lost, r.lostOrder.Remove(r.lostOrder.Front()).(string))
	}
}

// wasLost reports, once, whether key's request was dropped before its answer came (and not long ago).
func (r *pendingRequests) wasLost(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.lost[key]
	if !ok {
		return false
	}
	delete(r.lost, key)
	return r.now().Sub(at) < lostTTL
}

func (r *pendingRequests) remove(el *list.Element) {
	p := el.Value.(*pending)
	r.order.Remove(el)
	delete(r.byKey, p.key)
	r.used -= len(p.body)
}
