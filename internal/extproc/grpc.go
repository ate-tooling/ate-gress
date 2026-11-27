package extproc

import (
	"crypto/tls"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// GRPCServer returns a gRPC server that serves s over mutual TLS, and the
// health service registered on it. The health service starts NOT_SERVING;
// the caller marks it SERVING once the first snapshot is in effect.
func (s *Server) GRPCServer(tlsConfig *tls.Config) (*grpc.Server, *health.Server) {
	gs := grpc.NewServer(
		grpc.Creds(s.metrics.credentials(tlsConfig)),
		// A client that cannot finish a handshake promptly is not Envoy.
		grpc.ConnectionTimeout(5*time.Second),
		// Requests are headers only; nothing legitimate comes near this.
		grpc.MaxRecvMsgSize(1<<20),
		// Envoy keeps ext_proc connections open and idle between bursts.
		// Probe them so a vanished peer is noticed, and tolerate Envoy's own
		// keepalives without treating them as abuse.
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
	)
	extprocv3.RegisterExternalProcessorServer(gs, s)

	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	hs.SetServingStatus(extprocv3.ExternalProcessor_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_NOT_SERVING)
	healthpb.RegisterHealthServer(gs, hs)
	return gs, hs
}

// SetServing marks hs, as returned by Server.GRPCServer, SERVING or NOT_SERVING.
func SetServing(hs *health.Server, serving bool) {
	st := healthpb.HealthCheckResponse_NOT_SERVING
	if serving {
		st = healthpb.HealthCheckResponse_SERVING
	}
	hs.SetServingStatus("", st)
	hs.SetServingStatus(extprocv3.ExternalProcessor_ServiceDesc.ServiceName, st)
}
