package extproc

import (
	"context"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
)

// Runnable serves a gRPC server until its context ends, then drains it. It
// satisfies controller-runtime's manager.Runnable and runs on every replica.
type Runnable struct {
	Listener net.Listener
	Server   *grpc.Server
	Health   *health.Server
	Log      *slog.Logger
	// DrainDelay is how long to keep serving after shutdown begins with
	// health NOT_SERVING. The gateway finds ate-gress through DNS, so it keeps
	// dialing a terminating pod until its next DNS refresh; the delay must
	// cover that.
	DrainDelay time.Duration
	// StopTimeout bounds GracefulStop; streams still open after it are
	// closed, and the gateway fails their requests closed.
	StopTimeout time.Duration
}

// NeedLeaderElection reports false: every replica serves requests.
func (r *Runnable) NeedLeaderElection() bool { return false }

// Start serves until ctx is done.
func (r *Runnable) Start(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() { errc <- r.Server.Serve(r.Listener) }()
	r.Log.InfoContext(ctx, "serving ext_proc", slog.String("address", r.Listener.Addr().String()))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	SetServing(r.Health, false)
	r.Log.Info("draining ext_proc", slog.Duration("delay", r.DrainDelay))
	time.Sleep(r.DrainDelay)

	stopped := make(chan struct{})
	go func() {
		r.Server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(r.StopTimeout):
		r.Log.Warn("ext_proc streams still open after the stop timeout; closing them")
		r.Server.Stop()
	}
	return nil
}
