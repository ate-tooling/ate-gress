// Package extproc serves Envoy's ext_proc protocol for the Substrate egress
// gateway's additional egress processor.
//
// The gateway calls it once per HTTP request on its cleartext and TLS MITM
// legs, after Substrate's own egress policy has allowed the request and
// injected any credentials, with request headers only and the actor's SPIFFE
// ID as a request attribute. The filter is configured with
// failure_mode_allow: false, so an error here, a timeout, or ate-gress being
// unreachable denies the request.
package extproc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// IdentityAttribute is the CEL request attribute that carries the actor's
// SPIFFE ID, as the gateway's filter configuration names it.
const IdentityAttribute = "filter_state['dev.ate.actor.identity']"

// ReasonHeader is the response header a denial names its reason in.
const ReasonHeader = "x-ate-gress-reason"

// deniedBody is the body of every denial. It says nothing about the policy.
const deniedBody = "egress route denied\n"

// maxLoggedPath bounds the path recorded in a decision log.
const maxLoggedPath = 512

// Server implements the ExternalProcessor service.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer

	store   *policy.Store
	parser  *identity.Parser
	log     *slog.Logger
	metrics *Metrics
	now     func() time.Time
}

// NewServer returns a Server deciding against store.
func NewServer(store *policy.Store, parser *identity.Parser, log *slog.Logger, metrics *Metrics) *Server {
	return &Server{store: store, parser: parser, log: log, metrics: metrics, now: time.Now}
}

// Process handles one ext_proc stream, which Envoy opens per HTTP request.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		resp, err := s.respond(ctx, req)
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *Server) respond(ctx context.Context, req *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, error) {
	switch r := req.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return s.requestHeaders(ctx, req, r.RequestHeaders), nil

	// The filter asks for request headers only. Should Envoy send any other
	// phase, continue it unchanged: the request headers were already decided,
	// and a request that was denied never reaches a later phase.
	case *extprocv3.ProcessingRequest_RequestBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}}, nil
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}}, nil
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}}, nil
	case *extprocv3.ProcessingRequest_ResponseBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}, nil
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported ext_proc message %T", r)
	}
}

func (s *Server) requestHeaders(ctx context.Context, req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	start := s.now()
	pr, d := s.decide(req, h)
	s.metrics.observe(d, s.now().Sub(start))
	s.logDecision(ctx, pr, d)
	if !d.Allowed {
		return deny(d.Reason)
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{}}}
}

// parsedRequest is what decide learned about a request, for the decision log.
type parsedRequest struct {
	policy.Request
	identity  string
	requestID string
}

func (s *Server) decide(req *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) (parsedRequest, policy.Decision) {
	var pr parsedRequest
	var ok bool
	pr.Method, pr.Authority, pr.Path, pr.requestID, ok = pseudoHeaders(h.GetHeaders().GetHeaders())
	if !ok {
		return pr, policy.Decision{Reason: policy.ReasonHeaders}
	}
	pr.identity, ok = identityAttribute(req)
	if !ok {
		return pr, policy.Decision{Reason: policy.ReasonIdentity}
	}
	actor, err := s.parser.Parse(pr.identity)
	if err != nil {
		return pr, policy.Decision{Reason: policy.ReasonIdentity}
	}
	pr.Actor = actor
	live := s.store.Live()
	if live == nil {
		return pr, policy.Decision{Reason: policy.ReasonNotReady}
	}
	return pr, live.Decide(pr.Request)
}

// pseudoHeaders returns :method, :authority, and :path, and x-request-id if
// present. It fails if a pseudo-header is missing, empty, or repeated.
func pseudoHeaders(headers []*corev3.HeaderValue) (method, authority, path, requestID string, ok bool) {
	var seen [3]bool
	for _, hv := range headers {
		var slot int
		switch hv.GetKey() {
		case ":method":
			slot = 0
		case ":authority":
			slot = 1
		case ":path":
			slot = 2
		case "x-request-id":
			requestID = headerValue(hv)
			continue
		default:
			continue
		}
		if seen[slot] {
			return "", "", "", "", false
		}
		seen[slot] = true
		v := headerValue(hv)
		switch slot {
		case 0:
			method = v
		case 1:
			authority = v
		case 2:
			path = v
		}
	}
	ok = method != "" && authority != "" && path != ""
	return method, authority, path, requestID, ok
}

// headerValue returns the header's value. Envoy sends raw_value, which is
// bytes; older Envoys, and some test clients, send value.
func headerValue(hv *corev3.HeaderValue) string {
	if raw := hv.GetRawValue(); len(raw) > 0 {
		return string(raw)
	}
	return hv.GetValue()
}

// identityAttribute returns the actor identity attribute. The attributes are
// keyed by the name of the filter that requested them, which the gateway
// configuration owns, so every entry is searched; if two disagree, there is no
// identity.
func identityAttribute(req *extprocv3.ProcessingRequest) (string, bool) {
	var id string
	for _, attrs := range req.GetAttributes() {
		v, ok := attrs.GetFields()[IdentityAttribute]
		if !ok {
			continue
		}
		s := v.GetStringValue()
		if s == "" || id != "" && s != id {
			return "", false
		}
		id = s
	}
	return id, id != ""
}

func deny(reason policy.Reason) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				header("content-type", "text/plain; charset=utf-8"),
				header(ReasonHeader, string(reason)),
			}},
			Body: []byte(deniedBody),
			// Envoy records this as %RESPONSE_CODE_DETAILS% in the gateway's
			// access log; it may not contain whitespace.
			Details: "ate_gress_denied_" + string(reason),
		},
	}}
}

func header(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: k, RawValue: []byte(v)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// logDecision records denials and audited requests at Info, as well as
// allowed requests a policy with logAllowed claims, and other allowed
// requests at Debug. It records no header values: the request may carry a
// credential Substrate injected.
func (s *Server) logDecision(ctx context.Context, pr parsedRequest, d policy.Decision) {
	level := slog.LevelDebug
	if !d.Allowed || d.Audited || d.LogAllowed {
		level = slog.LevelInfo
	}
	if !s.log.Enabled(ctx, level) {
		return
	}
	path, _, _ := strings.Cut(pr.Path, "?")
	if len(path) > maxLoggedPath {
		path = path[:maxLoggedPath]
	}
	actor := pr.identity
	if pr.Actor != (identity.Actor{}) {
		actor = pr.Actor.String()
	}
	s.log.LogAttrs(ctx, level, "egress route decision",
		slog.String("decision", outcome(d)),
		slog.String("reason", string(d.Reason)),
		slog.String("actor", actor),
		slog.String("method", pr.Method),
		slog.String("authority", pr.Authority),
		slog.String("path", path),
		slog.String("policy", d.Policy),
		slog.String("pattern", d.Pattern),
		slog.String("request_id", pr.requestID),
	)
}

// outcome is the decision label: allow, deny, or audit (allowed, but a
// policy in Audit mode would have denied it).
func outcome(d policy.Decision) string {
	switch {
	case d.Audited:
		return "audit"
	case d.Allowed:
		return "allow"
	default:
		return "deny"
	}
}
