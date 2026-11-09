package openshell

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell/extauth"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/extensionv1"
	pb "github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/middlewarev1"
)

const (
	// ManifestName names the guard to OpenShell, in its diagnostics.
	ManifestName = "straiker/guard"
	// contract is the supervisor-middleware protocol capability, version 1.0.
	contract = "openshell.supervisor-middleware.contract"
	// MaxPayload is OpenShell's largest body (or streamed unit, or replacement): 4 MiB.
	MaxPayload = 4 << 20
	// MaxMessage fits a maximum payload and the rest of its message.
	MaxMessage = MaxPayload + 512<<10
	// maxFindings is OpenShell's cap on findings per result.
	maxFindings = 32
)

type middlewareServer struct {
	pb.UnimplementedSupervisorMiddlewareServer
	e        *guard.Engine
	audience string
	version  string
}

// Describe returns the guard's manifest: HTTP requests before credentials and HTTP responses before return, each
// up to OpenShell's 4 MiB, and the audience the guard verifies. A gateway it cannot interoperate with is refused.
func (s *middlewareServer) Describe(_ context.Context, req *pb.MiddlewareDescribeRequest) (*pb.MiddlewareManifest, error) {
	if err := negotiate(req.GetGateway()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &pb.MiddlewareManifest{
		Name:           ManifestName,
		ServiceVersion: s.version,
		Bindings: []*pb.MiddlewareBinding{
			{Operation: pb.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
				Phase: pb.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS, MaxPayloadBytes: MaxPayload},
			{Operation: pb.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE,
				Phase: pb.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN, MaxPayloadBytes: MaxPayload},
		},
		ExpectedAudience: s.audience,
		Extension: &extensionv1.PeerMetadata{
			ProtocolVersion:       &extensionv1.ProtocolVersion{Major: 1, Minor: 0},
			ImplementationName:    ManifestName,
			ImplementationVersion: s.version,
			SupportedCapabilities: []string{contract},
			RequiredCapabilities:  []string{contract},
		},
	}, nil
}

// negotiate accepts a gateway speaking protocol 1.x that requires nothing beyond the base contract.
func negotiate(gw *extensionv1.PeerMetadata) error {
	switch {
	case gw == nil || gw.GetProtocolVersion() == nil:
		return fmt.Errorf("the gateway sent no protocol metadata: the guard speaks supervisor-middleware protocol 1.0")
	case gw.GetProtocolVersion().GetMajor() != 1:
		return fmt.Errorf("the gateway speaks supervisor-middleware protocol %d.x; the guard speaks 1.0",
			gw.GetProtocolVersion().GetMajor())
	}
	for _, c := range gw.GetRequiredCapabilities() {
		if c != contract {
			return fmt.Errorf("the gateway requires capability %q, which the guard does not support", c)
		}
	}
	return nil
}

// ValidateConfig checks one policy attachment's config before the gateway accepts the policy.
func (s *middlewareServer) ValidateConfig(_ context.Context, req *pb.ValidateConfigRequest) (*pb.ValidateConfigResponse, error) {
	if _, err := ParseAttachment(req.GetConfig()); err != nil {
		return &pb.ValidateConfigResponse{Valid: false, Reason: err.Error()}, nil
	}
	return &pb.ValidateConfigResponse{Valid: true}, nil
}

// EvaluateHttpRequest checks a model request with Straiker before it leaves the sandbox. Anything that is not a
// model call is allowed unchecked.
func (s *middlewareServer) EvaluateHttpRequest(ctx context.Context, req *pb.HttpRequestEvaluation) (*pb.HttpRequestResult, error) {
	sandboxID, err := callerSandbox(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if req.GetPhase() != pb.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS {
		return nil, status.Errorf(codes.InvalidArgument, "the guard checks requests at PRE_CREDENTIALS, not %s", req.GetPhase())
	}
	att, err := ParseAttachment(req.GetConfig())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	t, rc := req.GetTarget(), req.GetContext()
	r := guard.Request{Agent: sandboxID, Session: session(req.GetHeaders()), Method: t.GetMethod(), Path: t.GetPath(),
		Body: req.GetBody(), Check: att.Request, Log: names(sandboxID, rc, t)}
	if att.Response && rc.GetRequestId() != "" {
		r.HoldAs = guard.HoldKey(sandboxID, rc.GetRequestId())
	}
	d := s.e.EvaluateRequest(ctx, r)
	res := requestResult(d.Outcome)
	if d.Held {
		// An encoded answer cannot be inspected, so ask the model for a plain one.
		res.HeaderMutations = append(res.HeaderMutations, &pb.HeaderMutation{Operation: &pb.HeaderMutation_Write{
			Write: &pb.WriteHeader{Name: "accept-encoding", Value: "identity",
				OnExisting: pb.ExistingHeaderAction_EXISTING_HEADER_ACTION_OVERWRITE}}})
	}
	return res, nil
}

// callerSandbox is the verified sandbox making an evaluation; a context naming another sandbox is refused.
func callerSandbox(ctx context.Context, rc *pb.RequestContext) (string, error) {
	c, ok := extauth.FromContext(ctx)
	switch {
	case !ok:
		return "", status.Error(codes.Unauthenticated, "unauthenticated")
	case c.CallerKind != extauth.CallerSupervisor:
		return "", status.Error(codes.PermissionDenied, "evaluations come from sandbox supervisors")
	case rc.GetSandboxId() != "" && rc.GetSandboxId() != c.SandboxID:
		return "", status.Error(codes.PermissionDenied, "the request context names another sandbox than the token")
	}
	return c.SandboxID, nil
}

// names are OpenShell's names for a call, for the guard's log: the sandbox is the token's, verified.
func names(sandboxID string, rc *pb.RequestContext, t *pb.HttpRequestTarget) []any {
	return []any{"sandbox_id", sandboxID, "sandbox", rc.GetSandbox(), "workspace", rc.GetWorkspace(),
		"request_id", rc.GetRequestId(), "host", t.GetHost(), "path", t.GetPath()}
}

// sessionHeaders name the agent's conversation, as clients send it.
var sessionHeaders = []string{"x-s6r-session", "x-claude-code-session-id"}

func session(headers []*pb.HttpHeader) string {
	for _, want := range sessionHeaders {
		for _, h := range headers {
			if strings.EqualFold(h.GetName(), want) && h.GetValue() != "" {
				return h.GetValue()
			}
		}
	}
	return ""
}

// requestResult is OpenShell's answer to a request for o.
func requestResult(o guard.Outcome) *pb.HttpRequestResult {
	d := pb.Decision_DECISION_ALLOW
	if o.Deny {
		d = pb.Decision_DECISION_DENY
	}
	r := &pb.HttpRequestResult{Decision: d, Reason: o.Reason, ReasonCode: o.ReasonCode, Findings: findings(o),
		Metadata: o.Metadata}
	if o.Replace != nil {
		r.Body, r.HasBody = o.Replace, true
	}
	return r
}

// bodyResult answers one body unit for o: block it, or release it as it is.
func bodyResult(o guard.Outcome, seq uint64) *pb.HttpResponseBodyResult {
	r := &pb.HttpResponseBodyResult{Sequence: seq, Reason: o.Reason, ReasonCode: o.ReasonCode, Findings: findings(o),
		Metadata: o.Metadata}
	if o.Deny {
		r.Action = &pb.HttpResponseBodyResult_BlockDelivery{BlockDelivery: &pb.HttpResponseBlockDelivery{}}
	} else {
		r.Action = &pb.HttpResponseBodyResult_PassThrough{PassThrough: &pb.HttpResponseBodyPassThrough{}}
	}
	return r
}

func findings(o guard.Outcome) []*pb.Finding {
	if len(o.Findings) == 0 {
		return nil
	}
	n := min(len(o.Findings), maxFindings)
	out := make([]*pb.Finding, 0, n)
	for _, f := range o.Findings[:n] {
		out = append(out, &pb.Finding{Type: f.Type, Label: f.Label, Count: f.Count, Severity: f.Severity})
	}
	return out
}
