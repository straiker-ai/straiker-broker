// Package guard is the Straiker Broker guard's gateway-neutral core: it checks the model calls an agent makes with
// Straiker Defend, inline, for a gateway that asks it before a request leaves and before an answer reaches the agent.
// A gateway adapter (pkg/guard/openshell) speaks the gateway's protocol, verifies its caller and names the agent;
// the core recognises a model call, asks Straiker, holds an allowed request for its answer's check, follows the
// answer as it arrives, and decides what the guard says when Straiker cannot.
package guard

import (
	"context"
	"errors"
	"time"

	"github.com/straiker-ai/straiker-broker/pkg/guard/answer"
	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
	"github.com/straiker-ai/straiker-broker/pkg/guard/provider"
	"github.com/straiker-ai/straiker-broker/pkg/guard/secrets"
)

const (
	defaultMaxAnswer  = 4 << 20
	defaultMaxPending = 64 << 20
	defaultStreams    = 64
	pendingTTL        = 2 * time.Minute
	// requestBudget bounds every check of one request: under the gateway's timeout (GatewayTimeout), with room to answer.
	requestBudget = GatewayTimeout - 500*time.Millisecond
)

// Checker asks Straiker for a verdict (detect.Client).
type Checker interface {
	Input(ctx context.Context, id detect.Identity, request []byte) (*detect.Verdict, error)
	Output(ctx context.Context, id detect.Identity, model string, request []byte, answer string) (*detect.Verdict, error)
}

// Logger writes one structured event (agent.Audit).
type Logger interface {
	Log(event string, kv ...any)
}

// Options configure an Engine.
type Options struct {
	Checker Checker
	OnError Policy
	OnBlock BlockMode // default deny
	Log     Logger

	MaxAnswer  int // bytes of one answer kept for its check; default 4 MiB
	MaxPending int // bytes of requests held for their answers' checks; default 64 MiB
	Streams    int // answers followed at once; default 64
}

// Engine decides on model calls for every connection of one guard.
type Engine struct {
	check     Checker
	onError   Policy
	onBlock   BlockMode
	log       Logger
	maxAnswer int
	pending   *pendingRequests
	streams   chan struct{}
	now       func() time.Time
}

// NewEngine makes an engine.
func NewEngine(o Options) *Engine {
	if o.MaxAnswer <= 0 {
		o.MaxAnswer = defaultMaxAnswer
	}
	if o.MaxPending <= 0 {
		o.MaxPending = defaultMaxPending
	}
	if o.Streams <= 0 {
		o.Streams = defaultStreams
	}
	if o.OnError == "" {
		o.OnError = FailOpen
	}
	if o.OnBlock == "" {
		o.OnBlock = BlockDeny
	}
	return &Engine{check: o.Checker, onError: o.OnError, onBlock: o.OnBlock, log: o.Log, maxAnswer: o.MaxAnswer,
		pending: newPendingRequests(o.MaxPending, pendingTTL), streams: make(chan struct{}, o.Streams), now: time.Now}
}

// OnError is what the guard decides when Straiker gives no verdict, or the guard has no room to look.
func (e *Engine) OnError() Policy { return e.onError }

// MaxAnswer is the most of one answer the guard keeps for its check.
func (e *Engine) MaxAnswer() int { return e.maxAnswer }

// Request is one HTTP request a gateway asks about.
type Request struct {
	Agent   string // the gateway's verified id for the agent
	Session string // the agent's conversation, when its client names one
	Method  string
	Path    string
	Body    []byte
	Check   bool   // check the request with Straiker
	HoldAs  string // when set, hold an allowed model request under this key for its answer's check (HoldKey)
	Log     []any  // the gateway's names for the call, for the decision log: names and ids, never content
}

// RequestDecision is the engine's answer for one request.
type RequestDecision struct {
	Outcome
	Held bool // held for its answer's check: the gateway should ask the model for an unencoded answer
}

// HoldKey is the key a request is held under: the agent and the gateway's id for the request.
func HoldKey(agent, requestID string) string { return agent + "\x00" + requestID }

// EvaluateRequest checks a model request with Straiker before it leaves. Anything that is not a model call is
// allowed unchecked.
func (e *Engine) EvaluateRequest(ctx context.Context, r Request) RequestDecision {
	call := provider.Classify(r.Method, r.Path, r.Body)
	if call.Kind == provider.None {
		if call.Unreadable && r.Check {
			// A model call whose body the guard can't read (compressed, or not JSON) goes unchecked: fail closed refuses it.
			e.LogSkip("uninspectable", r.Log, "on_straiker_error", string(e.onError))
			if e.onError == FailClosed {
				return RequestDecision{Outcome: Outcome{Deny: true, ReasonCode: CodeBusy,
					Reason: "the guard can't read this model request to check it"}}
			}
		}
		return RequestDecision{}
	}
	// Every check of this request (a replacement's re-check too) shares one deadline inside the gateway's timeout:
	// past it the gateway gives up, and its own on_error decides instead of the guard.
	ctx, cancel := context.WithTimeout(ctx, requestBudget)
	defer cancel()
	id := detect.Identity{Agent: r.Agent, Session: r.Session}
	if id.Session == "" {
		id.Session = provider.Session(call.Kind, r.Body)
	}
	var d RequestDecision
	if r.Check {
		start := e.now()
		v, err := e.check.Input(ctx, id, r.Body)
		d.Outcome = e.outcome(v, err)
		log := r.Log
		if err != nil {
			d.Outcome, log = e.fallback(d.Outcome, provider.Newest(call.Kind, r.Body), log)
		}
		if d.Deny && e.onBlock == BlockReplace && d.ReasonCode != CodeKillswitch {
			d.Outcome, log = e.replace(ctx, id, call, r.Body, v, d.Outcome, log)
		}
		e.logDecision("request", log, id.Session, call, v, err, d.Outcome, e.now().Sub(start))
	}
	body := r.Body
	if d.Replace != nil {
		body = d.Replace
	}
	// A stub's answer is the guard's own notice: there is nothing in it to check.
	if r.HoldAs != "" && !d.Deny && d.Metadata["straiker_replaced"] != replacedStub {
		d.Held = e.pending.put(&pending{key: r.HoldAs, call: call, body: body, id: id})
		if !d.Held && e.onError == FailClosed {
			// No room to hold it means its answer would go unchecked: fail closed refuses the request instead.
			d.Outcome = Outcome{Deny: true, ReasonCode: CodeBusy, Reason: "the guard has no room to check this answer"}
			e.LogSkip("busy", r.Log, "on_straiker_error", string(e.onError))
			if e.onBlock == BlockReplace {
				d.Outcome = e.stub(d.Outcome, call, r.Body, noticeUnchecked)
			}
		}
	}
	return d
}

// fallback is the guard's own check when Straiker gave no verdict: a credential whose format proves it is denied
// whatever on_straiker_error says, so a slow verdict never lets a key through. Otherwise the policy's outcome stands.
func (e *Engine) fallback(o Outcome, text string, log []any) (Outcome, []any) {
	family := secrets.Find(text)
	if family == "" {
		return o, log
	}
	o.Deny, o.ReasonCode = true, CodeLocalBlock
	o.Reason = clip("Straiker Defend gave no verdict; the guard's own check found a credential: "+family, maxReasonBytes)
	o.Findings = append(o.Findings, Finding{Type: findingLocalBlock, Label: family, Count: 1, Severity: "high"})
	return o, append(append([]any{}, log...), "local_check", family)
}

const (
	replacedMasked  = "masked"
	replacedStub    = "stub"
	noticeBlocked   = "Straiker Defend blocked this message, so it was not sent to the model."
	noticeUnchecked = "Straiker Defend could not check this message in time, so it was not sent to the model."
)

// replace turns a denial into a replacement (on_block: replace). A request blocked only for a credential goes ahead
// with its credentials redacted, once nothing else stops it: Straiker clears the redacted request, or, when Straiker
// gave no verdict, the policy is fail open. Anything else is replaced by a stub that asks the model for a notice.
func (e *Engine) replace(ctx context.Context, id detect.Identity, call provider.Call, body []byte, v *detect.Verdict,
	o Outcome, log []any) (Outcome, []any) {
	credential := o.ReasonCode == CodeLocalBlock || (o.ReasonCode == CodeBlocked && v != nil && onlyCredentials(v.BlockedBy))
	if credential {
		// Only a body with every credential gone may go ahead masked; otherwise it's a stub.
		if masked, families, clean := secrets.MaskJSON(body); len(families) > 0 && clean {
			clear := o.ReasonCode == CodeLocalBlock && e.onError == FailOpen
			if o.ReasonCode == CodeBlocked {
				again, err := e.check.Input(ctx, id, masked)
				clear = (err == nil && again.Action != detect.Block) || (err != nil && e.onError == FailOpen)
			}
			if clear {
				return replaced(o, masked, replacedMasked), append(append([]any{}, log...), "replaced", replacedMasked)
			}
		}
	}
	notice := noticeBlocked
	if o.ReasonCode == CodeUnavailable || o.ReasonCode == CodeBusy {
		notice = noticeUnchecked
	}
	out := e.stub(o, call, body, notice)
	if out.Replace == nil {
		return o, log
	}
	return out, append(append([]any{}, log...), "replaced", replacedStub)
}

// stub is o with the request replaced by a stub asking the model for notice; o unchanged when no stub can be made.
func (e *Engine) stub(o Outcome, call provider.Call, body []byte, notice string) Outcome {
	s := provider.Stub(call, body, notice)
	if s == nil {
		return o
	}
	return replaced(o, s, replacedStub)
}

// replaced allows the request with body in place of the original, keeping o's findings for the gateway's log.
func replaced(o Outcome, body []byte, how string) Outcome {
	o.Deny, o.ReasonCode, o.Replace = false, "", body
	meta := make(map[string]string, len(o.Metadata)+1)
	for k, v := range o.Metadata {
		meta[k] = v
	}
	meta["straiker_replaced"] = how
	o.Metadata = meta
	return o
}

// onlyCredentials is a block for credentials alone: redacting them leaves nothing blocked.
func onlyCredentials(controls []string) bool {
	if len(controls) == 0 {
		return false
	}
	for _, c := range controls {
		if c != "api_key" {
			return false
		}
	}
	return true
}

// Held is a request taken back for its answer's check.
type Held struct{ p *pending }

// TakeHeld returns the request held under key, if any: only the answer to a model request the guard saw is
// followed. Taking it frees its room whether or not the answer is then followed.
func (e *Engine) TakeHeld(key string) (Held, bool) {
	p, ok := e.pending.take(key)
	return Held{p}, ok
}

// WasHeld reports whether key's request was held but dropped (for room, or age) before its answer came: that answer
// can't be checked, which under fail closed means it isn't delivered.
func (e *Engine) WasHeld(key string) bool { return e.pending.wasLost(key) }

// ErrBusy is an answer the guard has no room to follow: the gateway decides it by OnError.
var ErrBusy = errors.New("the guard is following as many answers as it may")

// ErrTooLarge is an answer past MaxAnswer: the guard stops following it and the rest is released unchecked.
var ErrTooLarge = errors.New("the answer is larger than the guard keeps")

// Answer is one model answer being followed as it arrives.
type Answer struct {
	e       *Engine
	req     *pending
	tracker *answer.Tracker
	log     []any
	held    bool
}

// Follow starts following the answer to h, an event stream when sse. log names the call, as for Request.Log.
func (e *Engine) Follow(h Held, sse bool, log []any) (*Answer, error) {
	select {
	case e.streams <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	return &Answer{e: e, req: h.p, tracker: answer.New(h.p.call.Kind, sse, e.maxAnswer), log: log, held: true}, nil
}

// Feed takes the answer's next piece and says what to do with it. It checks the answer with Straiker when the piece
// completes a tool call the agent would run, or ends the answer: a block then withholds this piece, so the agent
// never receives a runnable call, and nothing more is followed. Otherwise the piece is released.
func (a *Answer) Feed(ctx context.Context, data []byte, end bool) (Outcome, error) {
	if err := a.tracker.Feed(data); err != nil {
		a.Close()
		return Outcome{}, ErrTooLarge
	}
	var out Outcome
	if a.tracker.Due(end) {
		start := a.e.now()
		answer := a.tracker.Text()
		v, err := a.e.check.Output(ctx, a.req.id, a.req.call.Model, a.req.body, answer)
		a.tracker.Checked()
		out = a.e.outcome(v, err)
		log := a.log
		if err != nil {
			out, log = a.e.fallback(out, a.tracker.Content(), log)
		}
		a.e.logDecision("response", log, a.req.id.Session, a.req.call, v, err, out, a.e.now().Sub(start))
	}
	if out.Deny || end {
		a.Close()
	}
	return out, nil
}

// Close stops following the answer and frees its room. Safe to call more than once.
func (a *Answer) Close() {
	if a.held {
		a.held = false
		<-a.e.streams
	}
	a.tracker, a.req = nil, nil
}

// LogSkip records an answer the guard let through without looking: why, the call's names, and any detail.
func (e *Engine) LogSkip(why string, log []any, kv ...any) {
	if e.log == nil {
		return
	}
	e.log.Log("uninspected", append(append([]any{"reason", why}, log...), kv...)...)
}

// logDecision records one check: names and ids (the session is a client's id or a hash), never content.
func (e *Engine) logDecision(phase string, names []any, session string, call provider.Call, v *detect.Verdict,
	err error, out Outcome, took time.Duration) {
	if e.log == nil {
		return
	}
	action, errText := "error", ""
	var controls, blockedBy []string
	var turn string
	if err != nil {
		errText = err.Error()
	} else {
		action, controls, blockedBy, turn = string(v.Action), v.Controls, v.BlockedBy, v.TurnID
	}
	decision := "allow"
	if out.Deny {
		decision = "deny"
	}
	kv := append([]any{"phase", phase}, names...)
	kv = append(kv, "api", string(call.Kind), "model", call.Model, "action", action, "decision", decision,
		"controls", nonNil(controls), "blocked_by", nonNil(blockedBy), "turn_id", turn, "session", session,
		"latency_ms", took.Milliseconds())
	if errText != "" {
		kv = append(kv, "error", errText, "on_straiker_error", string(e.onError))
	}
	e.log.Log("decision", kv...)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Body is the held request as the agent sent it.
func (h Held) Body() []byte { return h.p.body }

// Following is how many answers the guard is following now.
func (e *Engine) Following() int { return len(e.streams) }
