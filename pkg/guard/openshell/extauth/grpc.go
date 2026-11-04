package extauth

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

type claimsKey struct{}

var errMissing = errors.New("no bearer token")

// FromContext is the verified caller of the call ctx belongs to; ok is false outside an authenticated call.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}

// WithClaims attaches verified claims to ctx (what the interceptors do; also a seam for tests).
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// Interceptors authenticate every unary and streaming call with v. A rejected call gets Unauthenticated, with no
// detail for the caller; onReject hears why, for the log.
func Interceptors(v *Verifier, onReject func(method string, err error)) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	auth := func(ctx context.Context, method string) (context.Context, error) {
		c, err := v.authenticate(ctx)
		if err != nil {
			if onReject != nil {
				onReject(method, err)
			}
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}
		return WithClaims(ctx, c), nil
	}
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		ctx, err := auth(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		ctx, err := auth(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return h(srv, &authedStream{ServerStream: ss, ctx: ctx})
	}
	return unary, stream
}

// TapHandle refuses a call without a valid gateway token from its headers alone, before gRPC reads its message: the
// interceptors run only after a unary call's whole message is received and decoded. The interceptors still run, and
// attach the claims.
func TapHandle(v *Verifier, onReject func(method string, err error)) tap.ServerInHandle {
	return func(ctx context.Context, info *tap.Info) (context.Context, error) {
		if _, err := v.authenticate(metadata.NewIncomingContext(ctx, info.Header)); err != nil {
			if onReject != nil {
				onReject(info.FullMethodName, err)
			}
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}
		return ctx, nil
	}
}

func (v *Verifier) authenticate(ctx context.Context) (*Claims, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	vals := md.Get("authorization")
	if len(vals) != 1 {
		return nil, errMissing
	}
	scheme, token, ok := strings.Cut(vals[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, errMissing
	}
	return v.Verify(strings.TrimSpace(token))
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
