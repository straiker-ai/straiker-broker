// Package detect asks Straiker Defend for a verdict on a model call: POST /api/v3/detect with the guard's
// integration key, the model request as the agent sent it (the input phase), or the answer so far in the relay
// envelope (the output phase), and the agent's identity in X-S6r-* headers. It reads the verdict whether it comes
// back as Defend's neutral DetectResponse or as the Kong-shaped reply it gives gateway integrations.
package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Action is Defend's verdict.
type Action string

const (
	Allow  Action = "allow"
	Detect Action = "detect" // allowed, with what was found recorded by Defend
	Block  Action = "block"
)

const (
	// phaseResponseSync tells Defend the answer is still held, so a block stops it (and its tool calls).
	phaseResponseSync = "response-sync"
	maxReplyBytes     = 1 << 20
)

// agentIDRE is what Defend takes verbatim as X-S6r-Agent-Id; anything else it drops.
var agentIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Identity is who made the call, as the gateway verified it.
type Identity struct {
	Agent   string // the gateway's id for the agent, which Straiker's registry knows it by (OpenShell: the sandbox id)
	Session string // the agent's conversation, when its client names one
}

// Verdict is Defend's answer.
type Verdict struct {
	Action     Action
	Controls   []string // the controls that fired
	BlockedBy  []string // those that blocked
	Message    string   // the block message, for the person: set when blocked
	TurnID     string
	Killswitch bool
}

// ErrTimeout and ErrUnreachable are a call that got no reply.
var (
	ErrTimeout     = errors.New("no answer from Straiker in time")
	ErrUnreachable = errors.New("cannot reach Straiker")
)

// StatusError is a reply other than 200.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d from Straiker", e.Code) }

// Client calls one Straiker environment's detect endpoint.
type Client struct {
	endpoint  string
	key       string
	ingress   string
	http      *http.Client
	timeout   time.Duration
	userAgent string
}

// ingressRE is an arrival Defend reads from X-S6r-Ingress: gw-<gateway>.
var ingressRE = regexp.MustCompile(`^gw-[a-z0-9-]{1,48}$`)

// New is a client for the API at base (https://api.<env>.straiker.ai), authenticating with key and naming the
// gateway the calls arrive through as ingress (gw-<gateway>). Every call is bounded by timeout.
func New(base, key, ingress string, timeout time.Duration, rt http.RoundTripper, userAgent string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the Straiker API must be an https:// URL, not %q", base)
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("the Straiker integration key is required")
	}
	if timeout <= 0 {
		return nil, errors.New("the Straiker timeout must be positive")
	}
	if !ingressRE.MatchString(ingress) {
		return nil, fmt.Errorf("the arrival must be gw-<gateway>, not %q", ingress)
	}
	return &Client{
		endpoint:  strings.TrimSuffix(base, "/") + "/api/v3/detect",
		key:       strings.TrimSpace(key),
		ingress:   ingress,
		http:      &http.Client{Transport: rt, CheckRedirect: noRedirect},
		timeout:   timeout,
		userAgent: userAgent,
	}, nil
}

// noRedirect keeps the key from following a redirect anywhere.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Input checks a model request: the provider's body, verbatim.
func (c *Client) Input(ctx context.Context, id Identity, request []byte) (*Verdict, error) {
	return c.post(ctx, id, request)
}

// Output checks the model's answer so far, with the request it answers.
func (c *Client) Output(ctx context.Context, id Identity, model string, request []byte, answer string) (*Verdict, error) {
	body, err := OutputEnvelope(model, request, answer)
	if err != nil {
		return nil, err
	}
	return c.post(ctx, id, body)
}

// OutputEnvelope is the relay envelope for an answer still being held: Defend scores its tool calls as ones that
// have not run yet.
func OutputEnvelope(model string, request []byte, answer string) ([]byte, error) {
	if !json.Valid(request) {
		return nil, errors.New("the request is not JSON")
	}
	return json.Marshal(struct {
		Phase   string          `json:"straiker_phase"`
		SSE     string          `json:"sse"`
		Model   string          `json:"model,omitempty"`
		Request json.RawMessage `json:"request"`
	}{phaseResponseSync, answer, model, request})
}

func (c *Client) post(ctx context.Context, id Identity, body []byte) (*Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setHeaders(req.Header, c.key, c.userAgent, c.ingress, id)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, scrub(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return nil, scrub(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: resp.StatusCode}
	}
	return ParseVerdict(data)
}

func setHeaders(h http.Header, key, userAgent, ingress string, id Identity) {
	h.Set("Authorization", "Bearer "+key)
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("User-Agent", userAgent)
	h.Set("X-S6r-Ingress", ingress)
	switch {
	case agentIDRE.MatchString(id.Agent):
		h.Set("X-S6r-Agent-Id", id.Agent)
	case id.Agent != "": // not an id Defend takes verbatim: it still names one agent
		h.Set("X-S6r-Agent", id.Agent)
	}
	if s := strings.TrimSpace(id.Session); s != "" && len(s) <= 256 {
		h.Set("X-S6r-Session", s)
	}
}

// scrub keeps the URL's error and drops anything else a transport error may quote.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrTimeout
		}
		return fmt.Errorf("%w: %v", ErrUnreachable, ue.Err)
	}
	return err
}

// reply is either shape Defend answers in: its neutral DetectResponse, or the Kong-shaped body it renders for a
// gateway integration (hookSpecificOutput, with the neutral fields under "straiker").
type reply struct {
	verdictFields
	Hook *struct {
		PermissionDecision string `json:"permissionDecision"`
		Reason             string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
	StopReason string         `json:"stopReason"`
	Straiker   *verdictFields `json:"straiker"`
}

type verdictFields struct {
	Action       string   `json:"action"`
	Controls     []string `json:"controls"`
	BlockedBy    []string `json:"blocked_by"`
	BlockMessage string   `json:"block_message"`
	TurnID       string   `json:"turn_id"`
	Killswitch   bool     `json:"killswitch"`
}

// ParseVerdict reads a 200 reply. A reply that says neither allow nor block is an error, never an allow.
func ParseVerdict(data []byte) (*Verdict, error) {
	var r reply
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.New("the reply from Straiker is not JSON")
	}
	f := r.verdictFields
	if r.Straiker != nil {
		f = *r.Straiker
	}
	v := &Verdict{Action: Action(f.Action), Controls: f.Controls, BlockedBy: f.BlockedBy, TurnID: f.TurnID,
		Killswitch: f.Killswitch}
	if r.Hook != nil {
		switch r.Hook.PermissionDecision {
		case "deny":
			v.Action = Block
		case "allow":
			if v.Action == "" {
				v.Action = Allow
			}
		default:
			return nil, fmt.Errorf("the reply from Straiker has permissionDecision %q", r.Hook.PermissionDecision)
		}
	}
	switch v.Action {
	case Allow, Detect:
	case Block:
		v.Message = firstNonEmpty(f.BlockMessage, r.StopReason, hookReason(r))
	default:
		return nil, fmt.Errorf("the reply from Straiker has action %q", v.Action)
	}
	return v, nil
}

func hookReason(r reply) string {
	if r.Hook == nil {
		return ""
	}
	return r.Hook.Reason
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
