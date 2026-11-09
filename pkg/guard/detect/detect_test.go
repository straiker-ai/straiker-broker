package detect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "sk_agt_k1.secret.crc"

// straiker is a fake detect endpoint: reply answers each call, and the last request is kept.
type straiker struct {
	srv    *httptest.Server
	header http.Header
	body   []byte
	path   string
}

func newStraiker(t *testing.T, answer func(w http.ResponseWriter)) *straiker {
	t.Helper()
	s := &straiker{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.header, s.path = r.Header.Clone(), r.URL.Path
		s.body, _ = io.ReadAll(r.Body)
		answer(w)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *straiker) client(t *testing.T, timeout time.Duration) *Client {
	t.Helper()
	c, err := New(s.srv.URL, testKey, "gw-openshell", timeout, s.srv.Client().Transport, "straiker-broker-guard/test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func respond(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

var who = Identity{Agent: "3f1c2a9e-5b7d-4e8f-9a0b-1c2d3e4f5a6b", Session: "sess-1"}

func TestTheInputCallCarriesTheRequestAndTheAgent(t *testing.T) {
	s := newStraiker(t, respond(200, `{"turn_id":"t1","action":"allow","controls":[],"blocked_by":[],"config_hash":"h"}`))
	request := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}`
	v, err := s.client(t, time.Second).Input(context.Background(), who, []byte(request))
	if err != nil || v.Action != Allow || v.TurnID != "t1" {
		t.Fatalf("%+v %v", v, err)
	}
	if s.path != "/api/v3/detect" || string(s.body) != request {
		t.Fatalf("posted %s %s", s.path, s.body)
	}
	for h, want := range map[string]string{"Authorization": "Bearer " + testKey, "X-S6r-Ingress": "gw-openshell",
		"X-S6r-Agent-Id": who.Agent, "X-S6r-Session": "sess-1", "Content-Type": "application/json"} {
		if got := s.header.Get(h); got != want {
			t.Errorf("%s: %q, want %q", h, got, want)
		}
	}
}

func TestAnIDDefendWouldDropIsSentAsAnAgentName(t *testing.T) {
	s := newStraiker(t, respond(200, `{"action":"allow"}`))
	if _, err := s.client(t, time.Second).Input(context.Background(), Identity{Agent: "gw/sb 1"}, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if s.header.Get("X-S6r-Agent-Id") != "" || s.header.Get("X-S6r-Agent") != "gw/sb 1" || s.header.Get("X-S6r-Session") != "" {
		t.Fatalf("%v", s.header)
	}
}

func TestTheOutputCallSendsTheHeldAnswerInTheRelayEnvelope(t *testing.T) {
	s := newStraiker(t, respond(200, `{"action":"allow"}`))
	request := `{"model":"claude-sonnet-4-5","stream":true,"messages":[]}`
	answer := "data: {\"type\":\"message_stop\"}\n\n"
	if _, err := s.client(t, time.Second).Output(context.Background(), who, "claude-sonnet-4-5", []byte(request), answer); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Phase   string          `json:"straiker_phase"`
		SSE     string          `json:"sse"`
		Model   string          `json:"model"`
		Request json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(s.body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Phase != "response-sync" || env.SSE != answer || env.Model != "claude-sonnet-4-5" || string(env.Request) != request {
		t.Fatalf("%+v", env)
	}
	if _, err := OutputEnvelope("m", []byte("not json"), "x"); err == nil {
		t.Fatal("a request that is not JSON cannot be enveloped")
	}
}

func TestVerdictsInEitherShape(t *testing.T) {
	cases := map[string]struct {
		body string
		want Verdict
	}{
		"neutral allow":  {`{"action":"allow","controls":[]}`, Verdict{Action: Allow, Controls: []string{}}},
		"neutral detect": {`{"action":"detect","controls":["pii"]}`, Verdict{Action: Detect, Controls: []string{"pii"}}},
		"neutral block": {`{"turn_id":"t","action":"block","controls":["api_key"],"blocked_by":["api_key"],"block_message":"No secrets."}`,
			Verdict{Action: Block, Controls: []string{"api_key"}, BlockedBy: []string{"api_key"}, Message: "No secrets.", TurnID: "t"}},
		"kong deny": {`{"hookSpecificOutput":{"hookEventName":"GatewayRequest","permissionDecision":"deny","permissionDecisionReason":"agent text"},
			"continue":false,"stopReason":"Not allowed.","straiker":{"action":"block","controls":["api_key"],"blocked_by":["api_key"],"turn_id":"t","killswitch":false}}`,
			Verdict{Action: Block, Controls: []string{"api_key"}, BlockedBy: []string{"api_key"}, Message: "Not allowed.", TurnID: "t"}},
		"kong allow of a detect": {`{"hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"allow"},"straiker":{"action":"detect","controls":["pii"]}}`,
			Verdict{Action: Detect, Controls: []string{"pii"}}},
		"kong killswitch": {`{"hookSpecificOutput":{"permissionDecision":"deny"},"stopReason":"Killswitch is enabled.","straiker":{"action":"block","blocked_by":[],"killswitch":true}}`,
			Verdict{Action: Block, BlockedBy: []string{}, Message: "Killswitch is enabled.", Killswitch: true}},
		"kong deny, no straiker block": {`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"why"}}`,
			Verdict{Action: Block, Message: "why"}},
	}
	for name, c := range cases {
		v, err := ParseVerdict([]byte(c.body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, _ := json.Marshal(v)
		want, _ := json.Marshal(c.want)
		if string(got) != string(want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
	for _, bad := range []string{`{}`, `{"action":"maybe"}`, `{"hookSpecificOutput":{"permissionDecision":"ask"}}`, `[]`, `nope`} {
		if v, err := ParseVerdict([]byte(bad)); err == nil {
			t.Errorf("%s: read as %+v; a reply that is neither allow nor block is an error", bad, v)
		}
	}
}

func TestFailuresAreErrorsNeverVerdicts(t *testing.T) {
	slow := newStraiker(t, func(w http.ResponseWriter) { time.Sleep(300 * time.Millisecond); respond(200, `{"action":"block"}`)(w) })
	if _, err := slow.client(t, 50*time.Millisecond).Input(context.Background(), who, []byte(`{}`)); !errors.Is(err, ErrTimeout) {
		t.Errorf("slow: %v", err)
	}
	for _, code := range []int{401, 500, 501, 503} {
		s := newStraiker(t, respond(code, `{"detail":"x"}`))
		_, err := s.client(t, time.Second).Input(context.Background(), who, []byte(`{}`))
		var se *StatusError
		if !errors.As(err, &se) || se.Code != code {
			t.Errorf("HTTP %d: %v", code, err)
		}
	}
	redirect := newStraiker(t, func(w http.ResponseWriter) {
		w.Header().Set("Location", "https://elsewhere.example/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	var se *StatusError
	if _, err := redirect.client(t, time.Second).Input(context.Background(), who, []byte(`{}`)); !errors.As(err, &se) {
		t.Errorf("a redirect is not followed (the key would go with it): %v", err)
	}
	down := newStraiker(t, respond(200, `{}`))
	c := down.client(t, time.Second)
	down.srv.Close()
	_, err := c.Input(context.Background(), who, []byte(`{}`))
	if !errors.Is(err, ErrUnreachable) || strings.Contains(err.Error(), testKey) {
		t.Errorf("down: %v", err)
	}
}

func TestTheClientNeedsHTTPSAKeyAndAGatewayArrival(t *testing.T) {
	for _, c := range []struct{ base, key, ingress string }{
		{"http://api.dev.straiker.ai", testKey, "gw-openshell"}, {"https://api.dev.straiker.ai", " ", "gw-openshell"},
		{"api", testKey, "gw-openshell"}, {"https://api.dev.straiker.ai", testKey, ""},
		{"https://api.dev.straiker.ai", testKey, "openshell"}, {"https://api.dev.straiker.ai", testKey, "gw-Open Shell"},
	} {
		if _, err := New(c.base, c.key, c.ingress, time.Second, nil, "ua"); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}
