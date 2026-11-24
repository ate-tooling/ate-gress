# Sizing

What one ate-gress replica costs, measured, and what to request for it.

The short version: one core decides about 85,000 requests a second, a few
hundred a second cost a few hundredths of a core, memory is about 50 MiB
whatever the policy set, and the number of policies changes neither. Run
replicas for availability, not throughput, and size each one to carry the
whole gateway alone.

## How it was measured

`make load-test` runs [`test/load`](../test/load/load_test.go). It builds
the real binary from `cmd/ate-gress`, starts an envtest API server holding a
generated policy set, runs ate-gress against it as a separate process, and
drives it over gRPC with mutual TLS the way Substrate's gateway does: a new
ext_proc stream for every request, carrying the request headers and the
actor identity attribute, over 4 long-lived HTTP/2 connections. It reads the
process's own CPU and memory from its `/metrics`.

- **Policies**: 10, 100 and 1000, each claiming its own host for its own
  atespace, with three path templates over two routes.
- **Requests**: 70% allowed by a route, 20% denied with `no_route` (which
  logs at `INFO`, under the default rate limit), 10% to an unclaimed host,
  spread over the policies, 8 actors per atespace.
- **Rates**: open loop at 100, 1000, 5000, 20000 and 50000 requests a second
  for 10s each, then `max`: 128 workers sending as fast as they are answered.
  Open loop means a request is sent when it is due, whether or not earlier
  ones were answered, so a replica that falls behind shows as latency, not as
  a client that politely slows down.
- **ate-gress is limited to one core** (`GOMAXPROCS=1`), so the numbers are
  per core; the load generator uses the others.
- **Latency** is the client's round trip, from opening the stream to its
  end, over loopback. **Start lag** is how late requests started against the
  schedule; it stays far below the round trip until the load generator
  itself cannot keep up, so the rates were really offered.

The CPU columns are the ate-gress process's CPU seconds over the step,
divided by its length, and divided again by the requests decided.

## Results

Hardware: Apple M5 Pro (18 cores, in two performance levels of 6 and 12), 64 GB,
macOS 27.0.1; Go 1.27.4; ate-gress at the commit that added this document.
Every request got the decision it should have and none failed, in both runs.

### macOS, natively

| policies | target req/s | achieved req/s | p50 | p90 | p99 | p99.9 | max | p99 start lag | CPU (cores) | CPU µs/req | RSS MiB | heap MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | idle | | | | | | | | 0.001 | | 38 | 6.7 |
| 10 | 100 | 100 | 314µs | 425µs | 585µs | 907µs | 965µs | 2.1ms | 0.03 | 269 | 44 | 7.0 |
| 10 | 1000 | 1000 | 226µs | 280µs | 559µs | 1.4ms | 2.5ms | 245µs | 0.18 | 182 | 44 | 8.8 |
| 10 | 5000 | 5000 | 75µs | 89µs | 238µs | 409µs | 2.0ms | 60µs | 0.31 | 62 | 45 | 6.1 |
| 10 | 20000 | 20000 | 80µs | 179µs | 570µs | 2.4ms | 6.1ms | 72µs | 0.74 | 37 | 45 | 8.2 |
| 10 | 50000 | 49988 | 141µs | 1.4ms | 2.6ms | 4.3ms | 7.5ms | 520µs | 0.95 | 19 | 46 | 8.9 |
| 10 | max | 89684 | 1.1ms | 2.7ms | 3.3ms | 5.0ms | 9.4ms | | 0.97 | 11 | 46 | 7.8 |
| 100 | idle | | | | | | | | 0.001 | | 40 | 7.9 |
| 100 | 100 | 100 | 336µs | 457µs | 617µs | 838µs | 2.1ms | 2.1ms | 0.03 | 300 | 44 | 8.6 |
| 100 | 1000 | 1000 | 233µs | 296µs | 723µs | 2.1ms | 3.0ms | 285µs | 0.19 | 193 | 44 | 9.5 |
| 100 | 5000 | 5000 | 77µs | 94µs | 275µs | 1.1ms | 27ms | 62µs | 0.32 | 64 | 46 | 7.5 |
| 100 | 20000 | 19999 | 79µs | 140µs | 422µs | 1.3ms | 3.5ms | 51µs | 0.74 | 37 | 46 | 8.0 |
| 100 | 50000 | 49983 | 139µs | 1.5ms | 2.6ms | 3.8ms | 5.2ms | 220µs | 0.95 | 19 | 46 | 10.4 |
| 100 | max | 90922 | 1.1ms | 2.7ms | 3.3ms | 4.3ms | 7.2ms | | 0.98 | 11 | 47 | 10.6 |
| 1000 | idle | | | | | | | | 0.029 | | 50 | 12.5 |
| 1000 | 100 | 100 | 332µs | 458µs | 643µs | 1.5ms | 2.5ms | 2.1ms | 0.03 | 293 | 54 | 18.8 |
| 1000 | 1000 | 1000 | 226µs | 279µs | 490µs | 1.2ms | 2.6ms | 227µs | 0.18 | 185 | 54 | 17.1 |
| 1000 | 5000 | 5000 | 77µs | 91µs | 249µs | 713µs | 4.8ms | 60µs | 0.32 | 63 | 54 | 14.7 |
| 1000 | 20000 | 19999 | 79µs | 135µs | 463µs | 1.7ms | 4.2ms | 52µs | 0.74 | 37 | 55 | 15.2 |
| 1000 | 50000 | 49988 | 134µs | 1.8ms | 3.1ms | 4.4ms | 6.5ms | 527µs | 0.95 | 19 | 55 | 14.2 |
| 1000 | max | 89741 | 1.2ms | 2.7ms | 4.0ms | 4.8ms | 8.6ms | | 0.98 | 11 | 58 | 13.8 |

### Linux, in Docker Desktop's VM on the same machine

Linux 6.12 (linuxkit), arm64, 18 vCPUs, 7.7 GiB; the same test in the
`golang:1.27.4` image.

| policies | target req/s | achieved req/s | p50 | p90 | p99 | p99.9 | max | p99 start lag | CPU (cores) | CPU µs/req | RSS MiB | heap MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | idle | | | | | | | | 0.000 | | 40 | 6.4 |
| 10 | 100 | 100 | 274µs | 485µs | 784µs | 1.2ms | 1.2ms | 3.1ms | 0.02 | 190 | 45 | 9.5 |
| 10 | 1000 | 1000 | 140µs | 202µs | 423µs | 689µs | 1.5ms | 1.6ms | 0.07 | 70 | 45 | 6.2 |
| 10 | 5000 | 4999 | 199µs | 281µs | 641µs | 1.1ms | 2.3ms | 1.6ms | 0.16 | 33 | 45 | 7.4 |
| 10 | 20000 | 19999 | 136µs | 333µs | 1.0ms | 2.6ms | 5.9ms | 1.1ms | 0.68 | 34 | 46 | 9.1 |
| 10 | 50000 | 49957 | 285µs | 1.8ms | 3.1ms | 5.3ms | 11ms | 3.0ms | 0.89 | 18 | 46 | 7.5 |
| 10 | max | 89123 | 1.1ms | 2.9ms | 3.4ms | 4.0ms | 7.7ms | | 0.99 | 11 | 47 | 8.1 |
| 100 | idle | | | | | | | | 0.002 | | 42 | 7.9 |
| 100 | 100 | 100 | 272µs | 473µs | 819µs | 1.0ms | 1.1ms | 3.1ms | 0.02 | 190 | 47 | 8.9 |
| 100 | 1000 | 1000 | 145µs | 188µs | 370µs | 793µs | 1.8ms | 1.6ms | 0.07 | 70 | 46 | 10.1 |
| 100 | 5000 | 4999 | 204µs | 284µs | 613µs | 1.2ms | 6.4ms | 1.6ms | 0.17 | 34 | 46 | 7.8 |
| 100 | 20000 | 19999 | 139µs | 304µs | 705µs | 2.1ms | 2.7ms | 967µs | 0.69 | 34 | 47 | 8.9 |
| 100 | 50000 | 49966 | 273µs | 1.7ms | 2.7ms | 3.7ms | 6.2ms | 865µs | 0.89 | 18 | 48 | 10.4 |
| 100 | max | 88118 | 1.1ms | 3.1ms | 3.6ms | 4.2ms | 6.2ms | | 0.99 | 11 | 49 | 10.2 |
| 1000 | idle | | | | | | | | 0.034 | | 49 | 12.2 |
| 1000 | 100 | 100 | 273µs | 477µs | 834µs | 1.0ms | 3.2ms | 3.3ms | 0.02 | 200 | 54 | 18.9 |
| 1000 | 1000 | 1000 | 148µs | 193µs | 393µs | 906µs | 2.2ms | 1.6ms | 0.07 | 72 | 52 | 12.4 |
| 1000 | 5000 | 5000 | 207µs | 291µs | 696µs | 1.2ms | 1.9ms | 1.6ms | 0.17 | 34 | 54 | 14.5 |
| 1000 | 20000 | 19999 | 140µs | 299µs | 739µs | 2.7ms | 7.1ms | 931µs | 0.69 | 35 | 54 | 13.9 |
| 1000 | 50000 | 49968 | 283µs | 2.4ms | 3.9ms | 5.9ms | 9.6ms | 2.9ms | 0.88 | 18 | 54 | 13.5 |
| 1000 | max | 82544 | 1.2ms | 3.3ms | 4.8ms | 6.3ms | 9.7ms | | 0.99 | 12 | 55 | 13.9 |

The start lag in the Linux run is the VM's timer granularity in the load
generator, not ate-gress falling behind: every rate was achieved.

## What the numbers say

- **Throughput.** One core saturates at 82,000 to 91,000 requests a second.
  At 50,000 it is 90 to 95% busy and the p99 round trip is still about 3ms,
  against the gateway's 2s timeout.
- **CPU per request falls with load.** At a few hundred requests a second
  each request wakes an idle process, and that costs 190 to 300µs of CPU; at
  saturation requests are batched and cost about 11µs. Deciding itself takes
  about 130ns (`make bench`); the rest is TLS, HTTP/2 and gRPC. So the
  low-rate rows are the ones to size by, not the saturated ones:

  | requests a second, per replica | CPU to plan for |
  |---:|---:|
  | 100 | 0.03 cores |
  | 1,000 | 0.1 to 0.2 cores |
  | 5,000 | 0.35 cores |
  | 20,000 | 0.75 cores |

- **Policies do not matter for speed.** A request is matched against the
  policies claiming its host, found by a map lookup, so 10, 100 and 1000
  policies decide at the same rate and latency.
- **Memory is small and nearly flat.** About 45 MiB resident with 10 or 100
  policies and about 55 MiB with 1000, of which the Go heap is 7 to 19 MiB.
  The 1000-policy idle row also includes the status writer settling 1000
  `Accepted` conditions after the start.

## Recommendations

- **Replicas: 2, or 3 across zones.** Every replica must be able to carry
  the gateway's whole HTTP request rate alone, because during a rollout, a
  drain or a failure it may have to. With `topologySpread.zone=true` and 3
  replicas, losing a zone leaves two. More replicas buy nothing else.
- **No autoscaler.** The chart has no HorizontalPodAutoscaler. ate-gress
  fails by being unavailable, not by being slow, and one core covers more
  requests than a gateway sends; an autoscaler would add pod churn on the
  request path and nothing a fixed `replicas` does not already give.
- **`resources.requests.cpu`: the table above, for your peak HTTP request
  rate through the gateway**, the count of requests, not connections. The
  chart's default of `50m` covers a few hundred a second. The request is
  what the scheduler reserves, and what keeps ate-gress from being starved
  on a busy node, which is the one way it gets slow
  ([AteGressDecisionLatencyHigh](runbook.md#ategressdecisionlatencyhigh)).
- **No CPU limit.** A limit throttles in 100ms periods, which turns a burst
  into stalls on the path of every HTTP request. Leave it unset, as the chart
  does, or set it well above the request.
- **Memory: request `64Mi`, limit `256Mi`, the chart's defaults.** They are
  above what a 1000-policy set uses with room for bursts of streams. The
  chart sets `GOMEMLIMIT` to the limit, so the garbage collector works harder
  before the kernel kills the pod. Raise both for much larger policy sets.
- **A priority class** at or above the gateway's (`priorityClassName`), so
  ate-gress is not evicted or preempted before the workloads that depend on
  it.

## What does not transfer from a laptop

- **Cores differ.** An M5 Pro core is faster than most cloud vCPUs, and a
  vCPU on x86 is usually a hyperthread. Expect more CPU per request in a
  cluster, by an amount this test cannot tell you. Run `make load-test` on a
  machine like your nodes; `LOAD_GOMAXPROCS` sets the cores ate-gress gets.
- **No network.** Everything ran over loopback. In a cluster each request
  crosses the pod network between the gateway and ate-gress, which adds a
  round trip, plus whatever the CNI and its NetworkPolicy enforcement cost.
  That hop, not ate-gress, is most of the latency the gateway sees.
- **No Envoy.** The test calls ate-gress the way the gateway's filter does,
  which [`test/envoy`](../test/envoy) pins with a real Envoy, but does not
  go through one. Driving load through Envoy on this machine would measure
  Docker Desktop's port forwarding into its VM and an Envoy sharing cores
  with the load generator; the gateway's own cost per request is Substrate's
  to size.
- **Shared machine.** The load generator ran on the same machine and used
  the cores ate-gress did not, competing for caches and memory bandwidth.
- **One core.** In a pod without a CPU limit, Go uses every core of the node,
  so a replica saturates later than here; with a limit, Go 1.25 and later
  sizes itself to it.
- **Logging.** The mix logs denials under the default rate limit. A
  `logAllowed` policy logs every allowed request it claims, without a limit,
  and `logLevel: DEBUG` logs every decision; both cost a JSON line per
  request and are not measured here.
- **macOS and Linux differ at low rates**, where waking the process is the
  cost: the Linux VM spent 70µs of CPU per request at 1000 a second, macOS
  185µs. Saturated, they agree.
