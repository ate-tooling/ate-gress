// Command ate-gress is an Envoy ext_proc service that restricts the HTTP
// routes Agent Substrate actors may reach, as EgressRoutePolicy objects
// describe. Substrate's egress gateway calls it through its additional egress
// ext_proc extension point.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/controller"
	"github.com/ate-tooling/ate-gress/internal/extproc"
	"github.com/ate-tooling/ate-gress/internal/identity"
	"github.com/ate-tooling/ate-gress/internal/policy"
	"github.com/ate-tooling/ate-gress/internal/tlsconfig"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type options struct {
	grpcAddress      string
	metricsAddress   string
	probeAddress     string
	credentialBundle string
	clientCAs        string
	allowedClients   stringList
	trustDomain      string
	leaderElect      bool
	leaderElectionNS string
	logLevel         slog.Level
	drainDelay       time.Duration
	stopTimeout      time.Duration
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("ate-gress", flag.ContinueOnError)
	fs.StringVar(&o.grpcAddress, "grpc-address", ":9443", "Address to serve ext_proc on.")
	fs.StringVar(&o.metricsAddress, "metrics-address", ":8080", "Address to serve Prometheus metrics on; 0 disables.")
	fs.StringVar(&o.probeAddress, "health-probe-address", ":8081", "Address to serve /healthz and /readyz on.")
	fs.StringVar(&o.credentialBundle, "credential-bundle", "/run/servicedns.podcert.ate.dev/credential-bundle.pem",
		"PEM file holding the serving key and certificate chain.")
	fs.StringVar(&o.clientCAs, "client-ca-file", "/run/podidentity.podcert.ate.dev/trust-bundle.pem",
		"PEM file of the CAs that sign the gateway's client certificate.")
	fs.Var(&o.allowedClients, "allowed-client-id",
		"SPIFFE ID the gateway's client certificate must carry; repeatable. Defaults to Substrate's atenet-egress.")
	fs.StringVar(&o.trustDomain, "actor-trust-domain", identity.DefaultTrustDomain, "Trust domain of actor SPIFFE IDs.")
	fs.BoolVar(&o.leaderElect, "leader-elect", true, "Elect a leader to write policy status. Every replica serves requests either way.")
	fs.StringVar(&o.leaderElectionNS, "leader-election-namespace", "", "Namespace for the leader election lease; defaults to the pod's.")
	fs.TextVar(&o.logLevel, "log-level", slog.LevelInfo, "Minimum log level: DEBUG logs every decision, INFO denials, audits, and allowed requests of policies with logAllowed.")
	fs.DurationVar(&o.drainDelay, "drain-delay", 10*time.Second,
		"How long to keep serving after SIGTERM, so the gateway's DNS refresh stops sending new streams first.")
	fs.DurationVar(&o.stopTimeout, "stop-timeout", 10*time.Second, "How long to wait for open streams to finish after the drain delay.")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if len(o.allowedClients) == 0 {
		o.allowedClients = stringList{"spiffe://cluster.local/ns/ate-system/sa/atenet-egress"}
	}
	return o, nil
}

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	o, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: o.logLevel}))
	// DEBUG is for decision logs; controller-runtime's own debug output
	// (every lease renewal, every reflector event) would drown them.
	ctrl.SetLogger(logr.FromSlogHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: max(o.logLevel, slog.LevelInfo)})))
	if err := run(ctrl.SetupSignalHandler(), o, log); err != nil {
		log.Error("ate-gress failed", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(ctx context.Context, o options, log *slog.Logger) error {
	log.Info("starting ate-gress", slog.String("version", version))
	parser, err := identity.NewParser(o.trustDomain)
	if err != nil {
		return err
	}
	tlsCfg, err := tlsconfig.Server(tlsconfig.Config{
		CredentialBundle: o.credentialBundle,
		ClientCAs:        o.clientCAs,
		AllowedClientIDs: o.allowedClients,
	})
	if err != nil {
		return fmt.Errorf("loading TLS material: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: o.metricsAddress},
		HealthProbeBindAddress:        o.probeAddress,
		LeaderElection:                o.leaderElect,
		LeaderElectionID:              "ate-gress.ategress.ate-tooling.github.io",
		LeaderElectionNamespace:       o.leaderElectionNS,
		LeaderElectionReleaseOnCancel: true,
		// The ext_proc runnable's drain and stop must fit.
		GracefulShutdownTimeout: new(o.drainDelay + o.stopTimeout + 5*time.Second),
	})
	if err != nil {
		return fmt.Errorf("creating the manager: %w", err)
	}

	store := &policy.Store{}
	server := extproc.NewServer(store, parser, log, extproc.NewMetrics(ctrlmetrics.Registry))
	gs, hs := extproc.NewGRPCServer(tlsCfg, server)
	lis, err := net.Listen("tcp", o.grpcAddress)
	if err != nil {
		return err
	}
	if err := mgr.Add(&extproc.Runnable{
		Listener: lis, Server: gs, Health: hs, Log: log,
		DrainDelay: o.drainDelay, StopTimeout: o.stopTimeout,
	}); err != nil {
		return err
	}
	if err := ctrlmetrics.Registry.Register(extproc.NewPolicyCollector(store)); err != nil {
		return err
	}
	if err := mgr.Add(&controller.SnapshotBuilder{
		Cache:           mgr.GetCache(),
		Store:           store,
		Log:             log,
		Metrics:         controller.NewSnapshotMetrics(ctrlmetrics.Registry),
		OnFirstSnapshot: func() { extproc.SetServing(hs, true) },
	}); err != nil {
		return err
	}
	if err := (&controller.StatusReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		return err
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	// Not ready until a snapshot is in effect: before then every request
	// would be denied, so the pod should not receive any.
	if err := mgr.AddReadyzCheck("snapshot", func(*http.Request) error {
		if !store.Ready() {
			return errors.New("no policy snapshot in effect yet")
		}
		return nil
	}); err != nil {
		return err
	}
	return mgr.Start(ctx)
}
