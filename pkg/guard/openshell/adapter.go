// Package openshell is the guard's adapter for NVIDIA OpenShell: a supervisor middleware OpenShell's sandbox
// supervisors call over gRPC (TLS, with a gateway-signed token) for each HTTP request before credentials are
// injected, and for each response before the sandbox gets it. It verifies the caller is a supervisor of the sandbox
// it names, and hands the call to the guard's core; the agent is the sandbox, by OpenShell's sandbox id.
package openshell

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/straiker-ai/straiker-broker/pkg/guard"
	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell/extauth"
	pb "github.com/straiker-ai/straiker-broker/pkg/guard/openshell/pb/middlewarev1"
)

const (
	// RegistrationName is the name the guard is registered under in the gateway's TOML and attached by in policy.
	RegistrationName = "straiker-guard"
	// DefaultAudience is the token audience the guard accepts unless told otherwise.
	DefaultAudience = "urn:openshell:extension:middleware:" + RegistrationName

	keyGatewayID   = "gateway_id"
	keyGatewayJWKS = "gateway_jwks"
	keyAudience    = "audience"

	jwksRefresh = 10 * time.Minute
	httpTimeout = 5 * time.Second
	// maxStreams bounds concurrent calls per gateway connection: far above one gateway's model calls in flight.
	maxStreams = 1024
)

var gatewayIDRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Adapter is the guard's OpenShell adapter.
type Adapter struct{}

// Name is the gateway.
func (Adapter) Name() string { return "openshell" }

// Ingress is the arrival Defend reads the guard's calls as.
func (Adapter) Ingress() string { return "gw-openshell" }

// Settings are the gateway's id, its signing keys and the token audience.
func (Adapter) Settings() []guard.Setting {
	return []guard.Setting{
		{Key: keyAudience, Flag: "audience", Default: DefaultAudience,
			Usage: "token audience the guard accepts (default " + DefaultAudience + ")"},
		{Key: keyGatewayID, Flag: "gateway-id", Usage: "the OpenShell gateway's id (its tokens' iss is openshell-gateway:<id>)"},
		{Key: keyGatewayJWKS, Flag: "gateway-jwks", Path: true,
			Usage: "the gateway's JWKS or public key: a file, or https://<gateway>/.well-known/jwks.json"},
	}
}

// Validate checks the gateway's settings.
func (Adapter) Validate(s map[string]string) error {
	switch jwks := s[keyGatewayJWKS]; {
	case !gatewayIDRE.MatchString(s[keyGatewayID]):
		return errors.New("gateway_id (the OpenShell gateway's id, as in its tokens' iss openshell-gateway:<id>) is required")
	case jwks == "":
		return errors.New("gateway_jwks (the gateway's JWKS or public key: a file, or its https:// " +
			"/.well-known/jwks.json) is required")
	case strings.HasPrefix(jwks, "http://"):
		return errors.New("gateway_jwks must be a file or an https:// URL")
	case strings.ContainsAny(s[keyAudience], " \t\r\n"):
		return errors.New("audience must be one token audience")
	}
	return nil
}

// CheckFiles reads the gateway's keys when they are a file.
func (Adapter) CheckFiles(s map[string]string) error {
	keys, err := extauth.NewKeys(s[keyGatewayJWKS], nil)
	if err != nil || keys.IsURL() {
		return err
	}
	return keys.Refresh(context.Background())
}

// Describe names the gateway the guard serves.
func (Adapter) Describe(s map[string]string) string {
	return fmt.Sprintf("OpenShell gateway %s (audience %s)", s[keyGatewayID], s[keyAudience])
}

// SetupHint is the gateway's TOML registration for the guard at endpoint, its CA saved beside the gateway.
func (Adapter) SetupHint(endpoint string) string {
	return fmt.Sprintf(`# Save that CA where the OpenShell gateway runs, e.g. as /etc/openshell/straiker-guard-ca.pem,
# and register the guard in the gateway's configuration:
#
# [[openshell.supervisor.middleware]]
# name = %q
# grpc_endpoint = "https://%s"
# tls_ca_cert_path = "/etc/openshell/straiker-guard-ca.pem"
# max_payload_bytes = %d
# timeout = %q   # above the guard's --straiker-timeout (%s); OpenShell's 500ms default is too short
# audience = %q
`, RegistrationName, endpoint, MaxPayload, guard.GatewayTimeout.String(), guard.DefaultTimeout.String(), DefaultAudience)
}

// Serve verifies each call's gateway token and serves OpenShell's middleware services until ctx ends. The health
// endpoint reports ready once the gateway's signing keys are loaded.
func (Adapter) Serve(ctx context.Context, rt guard.Runtime) error {
	s := rt.Config.Gateway
	keys, err := extauth.NewKeys(s[keyGatewayJWKS], &http.Client{Transport: rt.Transport, Timeout: httpTimeout})
	if err != nil {
		return err
	}
	if err := keys.Refresh(ctx); err != nil {
		if !keys.IsURL() {
			return err
		}
		// The gateway serves its keys only once it runs, and it starts after its middleware: retry in the background.
		rt.Log.Log("gateway_keys", "status", "not loaded yet", "source", s[keyGatewayJWKS], "error", err.Error())
	}
	go keys.Run(ctx, jwksRefresh, func(err error) {
		rt.Log.Log("gateway_keys", "status", "refresh failed", "source", s[keyGatewayJWKS], "error", err.Error())
	})
	rt.SetReady(readiness(keys))
	verifier, err := extauth.NewVerifier(s[keyGatewayID], s[keyAudience], keys)
	if err != nil {
		return err
	}
	reject := func(method string, err error) {
		rt.Log.Log("unauthenticated", "method", method, "error", err.Error())
	}
	unary, stream := extauth.Interceptors(verifier, reject)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(rt.TLS)),
		grpc.MaxRecvMsgSize(MaxMessage), grpc.MaxSendMsgSize(MaxMessage),
		// Unauthenticated calls are refused from their headers, before a message is read; streams per connection are
		// bounded, so nobody can make the guard buffer unbounded messages.
		grpc.InTapHandle(extauth.TapHandle(verifier, reject)), grpc.MaxConcurrentStreams(maxStreams),
		grpc.UnaryInterceptor(unary), grpc.StreamInterceptor(stream),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	)
	Register(srv, rt.Engine, s[keyAudience], rt.Version)
	return guard.ServeGRPC(ctx, srv, rt.Listener)
}

// readiness is ready once the guard can verify the gateway's tokens.
func readiness(keys *extauth.Keys) func() (bool, string) {
	return func() (bool, string) {
		if !keys.Ready() {
			return false, "the gateway's signing keys are not loaded yet"
		}
		return true, ""
	}
}

// Register adds OpenShell's middleware services, answered by e, to srv.
func Register(srv *grpc.Server, e *guard.Engine, audience, version string) {
	pb.RegisterSupervisorMiddlewareServer(srv, &middlewareServer{e: e, audience: audience, version: version})
	pb.RegisterHttpResponsePreReturnServer(srv, &responseServer{e: e})
}
