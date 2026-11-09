package openshell

import (
	"context"
	"errors"
	"io"
	"mime"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
	pb "github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/middlewarev1"
)

type responseServer struct {
	pb.UnimplementedHttpResponsePreReturnServer
	e *guard.Engine
}

// Evaluate inspects one model answer before the sandbox gets it. A streamed answer is released piece by piece as
// it arrives, and checked as soon as a tool call in it is complete: a block then cuts the stream before the piece
// that completes the call, so the agent never receives a runnable call. A whole answer is checked before any of it
// is released.
func (s *responseServer) Evaluate(stream pb.HttpResponsePreReturn_EvaluateServer) error {
	ctx := stream.Context()
	ev, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	pf := ev.GetPreflight()
	if pf == nil {
		return status.Error(codes.FailedPrecondition, "a response stream starts with its preflight")
	}
	sandboxID, err := callerSandbox(ctx, pf.GetContext())
	if err != nil {
		return err
	}
	ins, res, err := s.preflight(sandboxID, pf)
	if err != nil {
		return err
	}
	if ins != nil {
		defer ins.answer.Close()
	}
	if err := stream.Send(&pb.HttpResponseEventResult{Result: &pb.HttpResponseEventResult_PreflightResult{PreflightResult: res}}); err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var r *pb.HttpResponseEventResult
		switch e := ev.GetEvent().(type) {
		case *pb.HttpResponseEvent_SessionEnd:
			return nil
		case *pb.HttpResponseEvent_Body:
			if ins == nil || ins.stopped {
				return status.Error(codes.FailedPrecondition, "a body unit after the guard stopped inspecting")
			}
			br, err := ins.body(ctx, e.Body)
			if err != nil {
				return err
			}
			r = &pb.HttpResponseEventResult{Result: &pb.HttpResponseEventResult_BodyResult{BodyResult: br}}
		case *pb.HttpResponseEvent_Trailers:
			if ins == nil || !ins.ended {
				return status.Error(codes.FailedPrecondition, "trailers before the final body unit")
			}
			r = &pb.HttpResponseEventResult{Result: &pb.HttpResponseEventResult_TrailersResult{
				TrailersResult: &pb.HttpResponseTrailersResult{}}}
		default:
			return status.Error(codes.FailedPrecondition, "an unexpected response event")
		}
		if err := stream.Send(r); err != nil {
			return err
		}
	}
}

// inspection is one answer being inspected, in OpenShell's sequence of body units.
type inspection struct {
	e       *guard.Engine
	answer  *guard.Answer
	pf      *pb.HttpResponsePreflight
	next    uint64
	stopped bool // blocked, or given up on: no more body units come
	ended   bool // the final body unit is answered
}

// preflight decides whether to inspect an answer, and how. Only the answer to a model request the guard saw is
// inspected; an error answer, or one OpenShell cannot expose (compressed, partial), is skipped.
func (s *responseServer) preflight(sandboxID string, pf *pb.HttpResponsePreflight) (*inspection, *pb.HttpResponsePreflightResult, error) {
	att, err := ParseAttachment(pf.GetConfig())
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	skip := &pb.HttpResponsePreflightResult{Action: &pb.HttpResponsePreflightResult_Skip{Skip: &pb.HttpResponsePreflightSkip{}}}
	if !att.Response {
		return nil, skip, nil
	}
	key := guard.HoldKey(sandboxID, pf.GetContext().GetRequestId())
	held, ok := s.e.TakeHeld(key)
	if pf.GetStatusCode() < 200 || pf.GetStatusCode() > 299 {
		return nil, skip, nil
	}
	if !ok {
		if !s.e.WasHeld(key) {
			return nil, skip, nil // not a model request the guard checked
		}
		// Its request was dropped for room or age before this answer came: the answer can't be checked.
		s.e.LogSkip("busy", skipNames(pf), "held", "dropped", "on_straiker_error", string(s.e.OnError()))
		if s.e.OnError() == guard.FailClosed {
			return nil, &pb.HttpResponsePreflightResult{ReasonCode: guard.CodeBusy,
				Action: &pb.HttpResponsePreflightResult_BlockDelivery{BlockDelivery: &pb.HttpResponseBlockDelivery{}}}, nil
		}
		return nil, skip, nil
	}
	sse := mediaType(header(pf.GetHeaders(), "content-type")) == "text/event-stream"
	mode, ok := bodyMode(pf.GetPermittedBodyModes(), sse)
	if !ok {
		s.e.LogSkip("uninspectable", skipNames(pf), "content-encoding", header(pf.GetHeaders(), "content-encoding"),
			"on_straiker_error", string(s.e.OnError()))
		if s.e.OnError() == guard.FailClosed {
			return nil, &pb.HttpResponsePreflightResult{ReasonCode: guard.CodeBusy,
				Action: &pb.HttpResponsePreflightResult_BlockDelivery{BlockDelivery: &pb.HttpResponseBlockDelivery{}}}, nil
		}
		return nil, skip, nil
	}
	ans, err := s.e.Follow(held, sse, names(sandboxID, pf.GetContext(), pf.GetTarget()))
	if errors.Is(err, guard.ErrBusy) {
		s.e.LogSkip("busy", skipNames(pf), "on_straiker_error", string(s.e.OnError()))
		if s.e.OnError() == guard.FailClosed {
			return nil, &pb.HttpResponsePreflightResult{ReasonCode: guard.CodeBusy,
				Action: &pb.HttpResponsePreflightResult_BlockDelivery{BlockDelivery: &pb.HttpResponseBlockDelivery{}}}, nil
		}
		return nil, skip, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return &inspection{e: s.e, answer: ans, pf: pf, next: 1}, &pb.HttpResponsePreflightResult{
		Action: &pb.HttpResponsePreflightResult_Inspect{Inspect: &pb.HttpResponsePreflightInspect{BodyMode: mode}}}, nil
}

// bodyMode prefers the whole body for a JSON answer (a block then replaces it with OpenShell's 403), and streams an
// event stream, or a body too large to hold whole.
func bodyMode(permitted []pb.HttpResponseBodyMode, sse bool) (pb.HttpResponseBodyMode, bool) {
	has := func(m pb.HttpResponseBodyMode) bool {
		for _, p := range permitted {
			if p == m {
				return true
			}
		}
		return false
	}
	switch {
	case !sse && has(pb.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES):
		return pb.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES, true
	case has(pb.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES):
		return pb.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_STREAM_BYTES, true
	}
	return 0, false
}

// body answers one unit: checked when it completes a tool call or ends the answer, then blocked or released.
func (i *inspection) body(ctx context.Context, u *pb.HttpResponseBodyUnit) (*pb.HttpResponseBodyResult, error) {
	if u.GetSequence() != i.next {
		return nil, status.Errorf(codes.FailedPrecondition, "body unit %d, want %d", u.GetSequence(), i.next)
	}
	i.next++
	seq, end := u.GetSequence(), u.GetEndOfStream()
	out, err := i.answer.Feed(ctx, u.GetData(), end)
	if errors.Is(err, guard.ErrTooLarge) {
		i.e.LogSkip("too_large", skipNames(i.pf), "max_bytes", i.e.MaxAnswer(), "on_straiker_error", string(i.e.OnError()))
		i.stopped = true
		if i.e.OnError() == guard.FailClosed {
			return &pb.HttpResponseBodyResult{Sequence: seq, ReasonCode: guard.CodeBusy,
				Action: &pb.HttpResponseBodyResult_BlockDelivery{BlockDelivery: &pb.HttpResponseBlockDelivery{}}}, nil
		}
		return &pb.HttpResponseBodyResult{Sequence: seq, Action: &pb.HttpResponseBodyResult_SkipRemaining{
			SkipRemaining: &pb.HttpResponseBodySkipRemaining{Current: &pb.HttpResponseBodySkipRemaining_PassThrough{
				PassThrough: &pb.HttpResponseBodyPassThrough{}}}}}, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case out.Deny:
		i.stopped = true
	case end:
		i.stopped, i.ended = true, true
	}
	return bodyResult(out, seq), nil
}

// skipNames are a preflight's names, for a skipped answer: the context's sandbox, as OpenShell sent it.
func skipNames(pf *pb.HttpResponsePreflight) []any {
	rc, t := pf.GetContext(), pf.GetTarget()
	return []any{"sandbox_id", rc.GetSandboxId(), "sandbox", rc.GetSandbox(), "workspace", rc.GetWorkspace(),
		"request_id", rc.GetRequestId(), "host", t.GetHost(), "path", t.GetPath()}
}

func header(headers []*pb.HttpHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.GetName(), name) {
			return h.GetValue()
		}
	}
	return ""
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt, _, _ = strings.Cut(contentType, ";")
	}
	return strings.ToLower(strings.TrimSpace(mt))
}
