package openshell

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell/extauth"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/extensionv1"
	pb "github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/middlewarev1"
)

const sandbox = "3f1c2a9e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"

// fakeChecker answers with input and output, and keeps what it was asked.
type fakeChecker struct {
	mu        sync.Mutex
	input     func(body []byte) (*detect.Verdict, error)
	output    func(answer string) (*detect.Verdict, error)
	inputs    []string
	outputs   []string
	ids       []detect.Identity
	deadlines []time.Time
}

func (f *fakeChecker) Input(ctx context.Context, id detect.Identity, body []byte) (*detect.Verdict, error) {
	f.mu.Lock()
	f.inputs, f.ids = append(f.inputs, string(body)), append(f.ids, id)
	d, _ := ctx.Deadline()
	f.deadlines = append(f.deadlines, d)
	f.mu.Unlock()
	if f.input == nil {
		return &detect.Verdict{Action: detect.Allow}, nil
	}
	return f.input(body)
}

func (f *fakeChecker) Output(_ context.Context, id detect.Identity, _ string, _ []byte, answer string) (*detect.Verdict, error) {
	f.mu.Lock()
	f.outputs, f.ids = append(f.outputs, answer), append(f.ids, id)
	f.mu.Unlock()
	if f.output == nil {
		return &detect.Verdict{Action: detect.Allow}, nil
	}
	return f.output(answer)
}

type memLog struct {
	mu     sync.Mutex
	events []map[string]any
}

func (l *memLog) Log(event string, kv ...any) {
	m := map[string]any{"event": event}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	l.mu.Lock()
	l.events = append(l.events, m)
	l.mu.Unlock()
}

func (l *memLog) find(event string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, e := range l.events {
		if e["event"] == event {
			out = append(out, e)
		}
	}
	return out
}

func supervisor(id string) context.Context {
	return extauth.WithClaims(context.Background(), &extauth.Claims{CallerKind: extauth.CallerSupervisor, SandboxID: id})
}

func block(msg string, controls ...string) func([]byte) (*detect.Verdict, error) {
	return func([]byte) (*detect.Verdict, error) {
		return &detect.Verdict{Action: detect.Block, Controls: controls, BlockedBy: controls, Message: msg, TurnID: "t1"}, nil
	}
}

const (
	prompt           = "PROMPT-CONTENT-7f3a"
	anthropicRequest = `{"model":"claude-sonnet-4-5","stream":true,"messages":[{"role":"user","content":"` + prompt + `"}]}`
)

func evaluation(requestID, path, body string, cfg *structpb.Struct) *pb.HttpRequestEvaluation {
	return &pb.HttpRequestEvaluation{
		Phase:   pb.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
		Context: &pb.RequestContext{RequestId: requestID, SandboxId: sandbox, Sandbox: "claude-dev", Workspace: "team-a"},
		Config:  cfg,
		Target:  &pb.HttpRequestTarget{Scheme: "https", Host: "api.anthropic.com", Port: 443, Method: "POST", Path: path},
		Headers: []*pb.HttpHeader{{Name: "content-type", Value: "application/json"},
			{Name: "x-claude-code-session-id", Value: "sess-9"}},
		Body: []byte(body),
	}
}

// harness is an engine and the two services OpenShell calls, wired as Register wires them.
type harness struct {
	*guard.Engine
	mw   *middlewareServer
	resp *responseServer
}

func newHarness(o guard.Options) *harness {
	e := guard.NewEngine(o)
	return &harness{Engine: e, mw: &middlewareServer{e: e, audience: DefaultAudience, version: "test"},
		resp: &responseServer{e: e}}
}

func (h *harness) preflight(sandboxID string, pf *pb.HttpResponsePreflight) (*inspection, *pb.HttpResponsePreflightResult, error) {
	return h.resp.preflight(sandboxID, pf)
}

func newGuard(c *fakeChecker, onError guard.Policy) (*harness, *memLog) {
	l := &memLog{}
	return newHarness(guard.Options{Checker: c, OnError: onError, Log: l}), l
}

func TestDescribeAdvertisesBothBindingsAndTheAudience(t *testing.T) {
	g, _ := newGuard(&fakeChecker{}, guard.FailOpen)
	s := g.mw
	gw := &extensionv1.PeerMetadata{ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1, Minor: 0},
		ImplementationName: "openshell/gateway", SupportedCapabilities: []string{contract}, RequiredCapabilities: []string{contract}}
	m, err := s.Describe(context.Background(), &pb.MiddlewareDescribeRequest{Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	if m.GetExpectedAudience() != DefaultAudience || len(m.GetBindings()) != 2 || m.GetExtension().GetProtocolVersion().GetMajor() != 1 ||
		m.GetExtension().GetSupportedCapabilities()[0] != contract {
		t.Fatalf("%v", m)
	}
	for _, b := range m.GetBindings() {
		if b.GetMaxPayloadBytes() != MaxPayload {
			t.Errorf("binding %v", b)
		}
	}
	for name, bad := range map[string]*extensionv1.PeerMetadata{
		"no metadata":            nil,
		"protocol 2":             {ProtocolVersion: &extensionv1.ProtocolVersion{Major: 2}},
		"an unknown requirement": {ProtocolVersion: &extensionv1.ProtocolVersion{Major: 1}, RequiredCapabilities: []string{"openshell.supervisor-middleware.future"}},
	} {
		if _, err := s.Describe(context.Background(), &pb.MiddlewareDescribeRequest{Gateway: bad}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	s := &middlewareServer{}
	cases := map[string]struct {
		cfg   map[string]any
		valid bool
	}{
		"empty":            {nil, true},
		"request only":     {map[string]any{"request": true, "response": false}, true},
		"both off":         {map[string]any{"request": false, "response": false}, false},
		"an unknown key":   {map[string]any{"mode": "block"}, false},
		"not a bool":       {map[string]any{"request": "yes"}, false},
		"response, number": {map[string]any{"response": 1}, false},
	}
	for name, c := range cases {
		var st *structpb.Struct
		if c.cfg != nil {
			var err error
			if st, err = structpb.NewStruct(c.cfg); err != nil {
				t.Fatal(err)
			}
		}
		r, err := s.ValidateConfig(context.Background(), &pb.ValidateConfigRequest{Config: st, MiddlewareName: RegistrationName})
		if err != nil || r.GetValid() != c.valid || (r.GetValid() == (r.GetReason() != "")) {
			t.Errorf("%s: %v %v", name, r, err)
		}
	}
}

func TestABlockedModelRequestIsDenied(t *testing.T) {
	c := &fakeChecker{input: block("Secrets are not allowed.", "api_key")}
	g, l := newGuard(c, guard.FailOpen)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetDecision() != pb.Decision_DECISION_DENY || r.GetReasonCode() != guard.CodeBlocked || len(r.GetHeaderMutations()) != 0 {
		t.Fatalf("%v", r)
	}
	if f := r.GetFindings(); len(f) != 2 || f[0].GetLabel() != "Secrets are not allowed." || f[1].GetLabel() != "api_key" {
		t.Fatalf("findings %v", f)
	}
	if c.inputs[0] != anthropicRequest || c.ids[0] != (detect.Identity{Agent: sandbox, Session: "sess-9"}) {
		t.Fatalf("asked %v as %+v", c.inputs, c.ids)
	}
	if _, held := g.TakeHeld(guard.HoldKey(sandbox, "r1")); held {
		t.Fatal("a denied request has no answer to wait for")
	}
	d := l.find("decision")
	if len(d) != 1 || d[0]["decision"] != "deny" || d[0]["action"] != "block" || d[0]["workspace"] != "team-a" || d[0]["api"] != "anthropic_messages" {
		t.Fatalf("logged %v", d)
	}
	if strings.Contains(fmt.Sprint(d[0]), prompt) {
		t.Fatalf("the log carries content: %v", d[0])
	}
}

func TestAnAllowedModelRequestIsHeldForItsAnswer(t *testing.T) {
	c := &fakeChecker{input: func([]byte) (*detect.Verdict, error) {
		return &detect.Verdict{Action: detect.Detect, Controls: []string{"pii"}}, nil
	}}
	g, _ := newGuard(c, guard.FailOpen)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetDecision() != pb.Decision_DECISION_ALLOW || len(r.GetFindings()) != 1 || r.GetFindings()[0].GetType() != "straiker.detect" {
		t.Fatalf("%v", r)
	}
	if w := r.GetHeaderMutations()[0].GetWrite(); w.GetName() != "accept-encoding" || w.GetValue() != "identity" {
		t.Fatalf("an inspected answer must come uncompressed: %v", r.GetHeaderMutations())
	}
	if p, held := g.TakeHeld(guard.HoldKey(sandbox, "r1")); !held || string(p.Body()) != anthropicRequest {
		t.Fatal("the request waits for its answer's check")
	}
}

func TestOtherTrafficPassesUnchecked(t *testing.T) {
	c := &fakeChecker{input: block("no")}
	g, _ := newGuard(c, guard.FailClosed)
	for _, e := range []*pb.HttpRequestEvaluation{
		evaluation("r1", "/v1/files", `{"purpose":"x"}`, nil),
		evaluation("r2", "/v1/messages/count_tokens", anthropicRequest, nil),
	} {
		r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), e)
		if err != nil || r.GetDecision() != pb.Decision_DECISION_ALLOW || len(r.GetHeaderMutations()) != 0 {
			t.Fatalf("%v %v", r, err)
		}
	}
	if len(c.inputs) != 0 {
		t.Fatal("Straiker sees only model calls")
	}
}

func TestStraikerFailuresFollowThePolicy(t *testing.T) {
	down := func([]byte) (*detect.Verdict, error) { return nil, detect.ErrTimeout }
	for _, p := range []guard.Policy{guard.FailOpen, guard.FailClosed} {
		g, l := newGuard(&fakeChecker{input: down}, p)
		r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, nil))
		if err != nil {
			t.Fatal(err)
		}
		deny := r.GetDecision() == pb.Decision_DECISION_DENY
		if deny != (p == guard.FailClosed) || r.GetMetadata()["straiker_error"] != "timeout" {
			t.Errorf("%s: %v", p, r)
		}
		if deny && r.GetReasonCode() != guard.CodeUnavailable {
			t.Errorf("%s: reason code %q", p, r.GetReasonCode())
		}
		if d := l.find("decision"); d[0]["action"] != "error" || d[0]["on_straiker_error"] != string(p) {
			t.Errorf("%s: logged %v", p, d)
		}
	}
}

func TestTheKillswitchIsABlock(t *testing.T) {
	ks := func([]byte) (*detect.Verdict, error) {
		return &detect.Verdict{Action: detect.Block, Killswitch: true, Message: "Killswitch is enabled."}, nil
	}
	g, _ := newGuard(&fakeChecker{input: ks}, guard.FailOpen)
	r, _ := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, nil))
	if r.GetDecision() != pb.Decision_DECISION_DENY || r.GetReasonCode() != guard.CodeKillswitch {
		t.Fatalf("%v", r)
	}
}

func TestOnlyTheTokensSandboxIsEvaluated(t *testing.T) {
	g, _ := newGuard(&fakeChecker{}, guard.FailOpen)
	s := g.mw
	e := evaluation("r1", "/v1/messages", anthropicRequest, nil)
	gateway := extauth.WithClaims(context.Background(), &extauth.Claims{CallerKind: extauth.CallerGateway})
	for name, ctx := range map[string]context.Context{
		"no token":        context.Background(),
		"the gateway":     gateway,
		"another sandbox": supervisor("other-sandbox"),
	} {
		if _, err := s.EvaluateHttpRequest(ctx, e); status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.Phase = pb.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN
	if _, err := s.EvaluateHttpRequest(supervisor(sandbox), e); status.Code(err) != codes.InvalidArgument {
		t.Errorf("another phase: %v", err)
	}
}

func TestRequestOnlyAttachmentsHoldNothing(t *testing.T) {
	cfg, _ := structpb.NewStruct(map[string]any{"response": false})
	g, _ := newGuard(&fakeChecker{}, guard.FailOpen)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, cfg))
	if err != nil || len(r.GetHeaderMutations()) != 0 {
		t.Fatalf("%v %v", r, err)
	}
	if _, held := g.TakeHeld(guard.HoldKey(sandbox, "r1")); held {
		t.Fatal("held")
	}
	cfg, _ = structpb.NewStruct(map[string]any{"request": false})
	c := &fakeChecker{}
	g, _ = newGuard(c, guard.FailOpen)
	if _, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, cfg)); err != nil {
		t.Fatal(err)
	}
	if _, held := g.TakeHeld(guard.HoldKey(sandbox, "r1")); !held || len(c.inputs) != 0 {
		t.Fatal("a response-only attachment holds the request without checking it")
	}
}

func TestAClientWithoutASessionHeaderGetsOneFromItsConversation(t *testing.T) {
	c := &fakeChecker{}
	g, l := newGuard(c, guard.FailOpen)
	ask := func(body string) {
		ev := evaluation("r", "/v1/messages", body, nil)
		ev.Headers = ev.Headers[:1] // no session header, as OpenClaw sends
		if _, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), ev); err != nil {
			t.Fatal(err)
		}
	}
	ask(anthropicRequest)
	ask(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"` + prompt + `"},` +
		`{"role":"assistant","content":"ok"},{"role":"user","content":"next"}]}`)
	if c.ids[0].Session == "" || c.ids[0].Session != c.ids[1].Session {
		t.Fatalf("one conversation, sessions %+v", c.ids)
	}
	if d := l.find("decision"); len(d) != 2 || d[0]["session"] != c.ids[0].Session {
		t.Fatalf("logged %v", d)
	}
}

func TestWithNoVerdictTheGuardsOwnCheckStillBlocksACredential(t *testing.T) {
	timeout := func([]byte) (*detect.Verdict, error) { return nil, detect.ErrTimeout }
	key := `{"model":"m","messages":[{"role":"user","content":"hello"},` +
		`{"role":"user","content":"My key is OPENAI_API_KEY=sk-proj-Ab3dEf5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH2iJ4"}]}`
	g, l := newGuard(&fakeChecker{input: timeout}, guard.FailOpen)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", key, nil))
	if err != nil || r.GetDecision() != pb.Decision_DECISION_DENY || r.GetReasonCode() != guard.CodeLocalBlock {
		t.Fatalf("%v %v", r, err)
	}
	if d := l.find("decision"); len(d) != 1 || d[0]["local_check"] != "openai_scoped" || strings.Contains(fmt.Sprint(d[0]), "sk-proj") {
		t.Fatalf("logged %v", d)
	}
	// A clean call still follows the policy (fail open allows it).
	r, _ = g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r2", "/v1/messages", anthropicRequest, nil))
	if r.GetDecision() == pb.Decision_DECISION_DENY {
		t.Fatalf("a clean call was denied: %v", r)
	}
}

func TestWhenStraikerAnswersItsVerdictStandsOverTheGuardsOwnCheck(t *testing.T) {
	key := `{"model":"m","messages":[{"role":"user","content":"AKIAABCDEFGHIJKLMNOP"}]}`
	g, _ := newGuard(&fakeChecker{}, guard.FailOpen) // Straiker allows (the tenant monitors keys only)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", key, nil))
	if err != nil || r.GetDecision() == pb.Decision_DECISION_DENY {
		t.Fatalf("%v %v", r, err)
	}
}

const leakedKey = "sk-proj-Ab3dEf5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH2iJ4"

var keyRequest = `{"model":"m","stream":true,"messages":[{"role":"user","content":"My key is OPENAI_API_KEY=` + leakedKey + `"}]}`

func newReplacingGuard(c *fakeChecker, onError guard.Policy) *harness {
	return newHarness(guard.Options{Checker: c, OnError: onError, OnBlock: guard.BlockReplace, Log: &memLog{}})
}

func TestReplaceRedactsACredentialBlockAndLetsTheCallGoAhead(t *testing.T) {
	c := &fakeChecker{input: func(body []byte) (*detect.Verdict, error) {
		if strings.Contains(string(body), leakedKey) {
			return &detect.Verdict{Action: detect.Block, BlockedBy: []string{"api_key"}, Controls: []string{"api_key"}}, nil
		}
		return &detect.Verdict{Action: detect.Allow}, nil
	}}
	g := newReplacingGuard(c, guard.FailOpen)
	r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", keyRequest, nil))
	if err != nil || r.GetDecision() != pb.Decision_DECISION_ALLOW || !r.GetHasBody() || r.GetReasonCode() != "" {
		t.Fatalf("%v %v", r, err)
	}
	if strings.Contains(string(r.GetBody()), leakedKey) || !strings.Contains(string(r.GetBody()), "REDACTED by Straiker") ||
		r.GetMetadata()["straiker_replaced"] != "masked" || len(r.GetFindings()) == 0 {
		t.Fatalf("%s %v", r.GetBody(), r.GetMetadata())
	}
	if len(c.inputs) != 2 || strings.Contains(c.inputs[1], leakedKey) {
		t.Fatalf("Straiker re-checks the redacted request: %d checks", len(c.inputs))
	}
	if h, ok := g.TakeHeld(guard.HoldKey(sandbox, "r1")); !ok || strings.Contains(string(h.Body()), leakedKey) {
		t.Fatal("the redacted request is held for its answer's check")
	}
}

func TestReplaceStubsOtherBlocksAndNeverTheKillSwitch(t *testing.T) {
	g := newReplacingGuard(&fakeChecker{input: block("no", "prompt_injection")}, guard.FailOpen)
	r, _ := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", anthropicRequest, nil))
	if r.GetDecision() != pb.Decision_DECISION_ALLOW || r.GetMetadata()["straiker_replaced"] != "stub" ||
		strings.Contains(string(r.GetBody()), prompt) || !strings.Contains(string(r.GetBody()), "Straiker Defend blocked") {
		t.Fatalf("%v %s", r, r.GetBody())
	}
	if _, held := g.TakeHeld(guard.HoldKey(sandbox, "r1")); held {
		t.Fatal("a stub's answer is not followed")
	}
	kill := func([]byte) (*detect.Verdict, error) {
		return &detect.Verdict{Action: detect.Block, Killswitch: true, BlockedBy: []string{"killswitch"}}, nil
	}
	g = newReplacingGuard(&fakeChecker{input: kill}, guard.FailOpen)
	r, _ = g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r2", "/v1/messages", anthropicRequest, nil))
	if r.GetDecision() != pb.Decision_DECISION_DENY || r.GetReasonCode() != guard.CodeKillswitch || r.GetHasBody() {
		t.Fatalf("the kill switch must deny: %v", r)
	}
}

func TestReplaceWithNoVerdictFollowsThePolicy(t *testing.T) {
	timeout := func([]byte) (*detect.Verdict, error) { return nil, detect.ErrTimeout }
	for p, want := range map[guard.Policy]string{guard.FailOpen: "masked", guard.FailClosed: "stub"} {
		g := newReplacingGuard(&fakeChecker{input: timeout}, p)
		r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", keyRequest, nil))
		if err != nil || r.GetDecision() != pb.Decision_DECISION_ALLOW || r.GetMetadata()["straiker_replaced"] != want ||
			strings.Contains(string(r.GetBody()), leakedKey) {
			t.Errorf("%s: %v %s", p, r, r.GetBody())
		}
	}
	// A clean call with no verdict under fail closed is stubbed too, not denied.
	g := newReplacingGuard(&fakeChecker{input: timeout}, guard.FailClosed)
	r, _ := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r2", "/v1/messages", anthropicRequest, nil))
	if r.GetMetadata()["straiker_replaced"] != "stub" || !strings.Contains(string(r.GetBody()), "could not check") {
		t.Fatalf("%v %s", r, r.GetBody())
	}
}

func TestAModelRequestTheGuardCannotReadFollowsThePolicy(t *testing.T) {
	gz := "\x1f\x8b\x08\x00\x00\x00\x00\x00"
	for _, p := range []guard.Policy{guard.FailOpen, guard.FailClosed} {
		c := &fakeChecker{}
		g, l := newGuard(c, p)
		r, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", gz, nil))
		if err != nil {
			t.Fatal(err)
		}
		if denied := r.GetDecision() == pb.Decision_DECISION_DENY; denied != (p == guard.FailClosed) {
			t.Errorf("%s: %v", p, r)
		}
		if len(c.inputs) != 0 || !l.has("uninspected") {
			t.Errorf("%s: never sent to Straiker, and logged: %d %v", p, len(c.inputs), l.events)
		}
	}
}

func TestReplacingShareOneDeadlineInsideTheGatewaysTimeout(t *testing.T) {
	c := &fakeChecker{input: func(body []byte) (*detect.Verdict, error) {
		if strings.Contains(string(body), leakedKey) {
			return &detect.Verdict{Action: detect.Block, BlockedBy: []string{"api_key"}}, nil
		}
		return &detect.Verdict{Action: detect.Allow}, nil
	}}
	g := newReplacingGuard(c, guard.FailClosed)
	start := time.Now()
	if _, err := g.mw.EvaluateHttpRequest(supervisor(sandbox), evaluation("r1", "/v1/messages", keyRequest, nil)); err != nil {
		t.Fatal(err)
	}
	if len(c.deadlines) != 2 || !c.deadlines[0].Equal(c.deadlines[1]) || c.deadlines[0].IsZero() ||
		c.deadlines[0].After(start.Add(guard.GatewayTimeout)) {
		t.Fatalf("the check and its re-check share one deadline under %s: %v", guard.GatewayTimeout, c.deadlines)
	}
}

// has reports whether an event was logged.
func (l *memLog) has(event string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.events {
		if e["event"] == event {
			return true
		}
	}
	return false
}
