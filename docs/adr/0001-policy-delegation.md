# ADR 0001: Letting atespace owners write their own route policies

- **Status:** Proposed
- **Date:** 2026-11-23

Nothing in this document is implemented. It records a design question, the
options, and a recommendation for the maintainers to accept, change or
reject.

## Context

`EgressRoutePolicy` is cluster-scoped. Whoever can write one can change what
every actor in the installation may reach, so in practice only cluster
administrators write them. Teams that own an atespace ask to manage the
routes of their own actors without a ticket to the platform team.

### Facts the design has to fit

**Atespaces are not Kubernetes namespaces.** An `Atespace` is a global
resource in Substrate's `ateapi` gRPC API. Substrate's glossary says so in as
many words: "Atespaces are global-scoped, not Kubernetes namespaces."
Kubernetes has no object for one, and no RBAC over one.

**Substrate's own `EgressPolicy` is not a Kubernetes object either.** It is
a singleton subresource of an `Actor`, named `default`, stored by Substrate's
API server. An atespace *editor* may create, update and delete the egress
policies of the actors in that atespace (Substrate's
`docs/guides/authorization.md`).

**Substrate has its own authorization.** Roles (owner, editor, viewer) are
granted globally or per atespace through `AccessPolicy` resources in the same
API. Kubernetes RBAC knows nothing of them. ate-gress has no client for that
API and cannot ask it who owns an atespace.

**A CRD's scope cannot change.** `EgressRoutePolicy` is `scope: Cluster`.
Delegation therefore means a new, namespaced Kind, plus some way to say which
namespace speaks for which atespace.

**An atespace editor can already take a host away from ate-gress.**
ate-gress sees only the gateway's HTTP legs. A host that an actor's
`EgressPolicy` reaches through a `tls_passthrough` rule never gets to it, and
atespace editors write those rules. What they lose by doing so is the
credential Substrate injects: a passthrough rule has no effects, so nothing
is injected. So a cluster route policy constrains an atespace's *owners*
only where access depends on an injected credential. It constrains the
atespace's *actors* everywhere, as long as they hold no editor role over
their own `EgressPolicy`. This ADR is about
letting owners constrain their actors. It does not make cluster policies
binding on owners where they are not today.

### What `Decide` does with more than one policy

This is the crux, so it is worked through from the code
(`internal/policy/policy.go`).

For a request from actor *a* to host *h*, let **C** be the policies that list
*h* and whose selector matches *a*: the policies that *claim* *h* for *a*.
Let **E** be the `Enforce` policies in C and **A** the `Audit` ones.

| C | Outcome |
|---|---|
| empty | allowed, reason `unclaimed` |
| E is not empty | allowed if the path is canonical and a route of **some policy in E** matches; otherwise denied. Policies in A have no effect on the outcome |
| E is empty, A is not | allowed. Recorded as an audit unless a route of some policy in A matches |

A policy the compiler rejected is in C too, with no routes: it claims like a
lockdown.

Three properties follow.

1. **Routes are a union.** Within E, a request is allowed if any policy
   allows it. No policy can take away what another allows. There is no deny
   rule.
2. **Claiming is the only way to narrow.** The single step that turns
   "allowed" into "denied" is E going from empty to not empty for the pair
   (*a*, *h*): the first `Enforce` claim.
3. **After the first claim, every further policy can only widen.** Once E is
   not empty, adding a policy to it adds routes to the union and can do
   nothing else.

Now add a policy T, written by a tenant, to a set written by the cluster
administrator, under today's semantics:

| Cluster policies for (*a*, *h*) | Effect of tenant policy T claiming *h* |
|---|---|
| None claim *h* | T **narrows**: from everything the `EgressPolicy` allows, to T's routes |
| Only `Audit` policies claim *h* | T narrows as above. The cluster's audit policy stops reporting for these actors, because an `Enforce` claim now decides |
| An `Enforce` policy claims *h*, with routes | T **widens**: the actor may use the cluster's routes or T's |
| An `Enforce` lockdown claims *h*, with no routes | T **widens**: T's routes are the only routes, and they are allowed |

So if tenant policies simply joined the pool, a tenant could widen exactly
the hosts the administrator chose to restrict, including undoing a lockdown,
and could never narrow them. It is the wrong half of each. A tenant `Audit`
policy is not harmless either: on a host only cluster `Audit` policies
claim, a tenant `Audit` policy with a route for everything stops those
requests from being recorded as audits.

Two smaller effects of sharing a pool:

- `logAllowed` on a tenant policy turns on `INFO` logging, in a shared
  component, for every allowed request of its actors to its hosts.
- A denial reports the first claiming policy in name order, so a tenant's
  choice of name can decide which policy an administrator's log line blames.

### What a tenant policy must not be able to do

- Select actors outside its own atespace.
- Allow a request the cluster's policies deny.
- Change the outcome, the audit record, or the log of a request from another
  atespace.
- Make ate-gress slower or less available for other atespaces.

## Options

### Option 1: do not delegate

Keep one cluster-scoped Kind. Tenants propose policies through whatever
review process the platform team runs.

- No new attack surface, no new semantics.
- Every route change stays a platform-team change. That is the cost that
  prompted this ADR.

### Option 2: a namespaced Kind in the same pool

Add a namespaced Kind and a namespace-to-atespace mapping. Force each tenant
policy's selector to its atespace. Compile tenant and cluster policies into
one snapshot, decided as today.

- Smallest change: `Decide` is untouched.
- Unsafe, by the table above. A tenant can allow anything on any host, for
  its own actors, that a cluster policy restricts. Forcing the selector keeps
  the damage inside the atespace, but inside the atespace a cluster policy
  no longer means anything.
- It could be patched by refusing tenant policies on hosts a cluster
  `Enforce` policy claims for that atespace. Then whether a tenant policy is
  valid depends on every cluster policy, changes when one is added, and has
  to be re-decided in the compiler: admission alone cannot be trusted, and
  admission cannot see the other objects anyway. A tenant policy that was in
  effect yesterday would silently drop out today.

### Option 3: two layers, both of which must allow

Add a namespaced Kind and a mapping, and keep tenant policies in their own
layer. A request is decided twice, with the same `Decide` semantics each
time:

- the **cluster layer**: all `EgressRoutePolicy` objects, as today;
- the **tenant layer**: the tenant policies of the namespaces bound to the
  actor's atespace, and no others.

The request is allowed only if **both** layers allow it. A layer that does
not claim the host allows, as today.

| Cluster layer | Tenant layer | Outcome |
|---|---|---|
| denies | anything | denied, with the cluster layer's reason and policy |
| allows or does not claim | denies | denied, with the tenant layer's reason and policy |
| allows or does not claim | allows or does not claim | allowed |

A request is recorded as an audit if either layer would record one and
neither denies.

Checked against the requirements:

- **Cannot widen.** A tenant policy takes part only in the tenant layer, and
  the tenant layer can only turn an allow into a deny. Whatever the cluster
  layer denies stays denied. This holds by construction, with no check that
  compares policies.
- **Can narrow, on any host.** Including a host a cluster policy claims: the
  result is the cluster's routes intersected with the tenant's. Under
  option 2 this was the case that widened.
- **Cannot reach other atespaces.** The tenant layer for an actor is built
  only from namespaces bound to that actor's atespace. A tenant policy has no
  `atespaces` selector at all; it may select by actor `names` within its own.
- **Cannot silence the cluster's audit or log.** Each layer audits on its
  own, and `logAllowed` in the cluster layer is computed from cluster
  policies only.
- **Inside a layer nothing changes.** Policies only allow, routes are a
  union, and a host with no routes is a lockdown. Two namespaces bound to the
  same atespace share a tenant layer and can widen each other's policies
  within it, exactly as two cluster policies can today.

Costs:

- `Decide` changes, and with it the reference implementation, the fuzz
  target, and the threat model. The second lookup roughly doubles the cost of
  a decision on hosts both layers claim (about 130ns today).
- A tenant cannot get *more* than the cluster layer gives. If the
  administrator locks a host down and wants one team to manage it, the
  administrator writes a cluster policy that allows that team's atespace the
  ceiling, and the team narrows below it. Spelling "everything" as a ceiling
  is awkward today: `/` and `/**` do not cover paths with a trailing slash.
- Operators have two places to look when a request is denied. The decision
  log must say which layer denied.

### Option 4: delegation grants

Add a cluster-scoped grant object in which the administrator lists, per
atespace, the hosts a tenant may write routes for and the widest routes it
may write. Tenant policies are valid only inside a grant.

- Explicit, and the administrator sees every delegation in one place.
- Checking that a tenant's templates are inside a grant's templates is a
  containment proof between two template sets. It is decidable for this
  grammar, but it is new security-critical code, and it runs at compile time
  on every change to either object.
- Option 3 gets the same result without the proof, by evaluating both sets
  against the actual request. A grant is a cluster policy that allows the
  ceiling.

## The mapping from namespace to atespace

Options 2 to 4 all need it, and it is the new trust root: whoever controls
the mapping controls which Kubernetes users speak for which atespace.

- **A label or annotation on the Namespace.** Simple, but it ties policy
  authority to whoever may edit Namespace metadata, which varies between
  clusters and is often broader than cluster-admin (namespace provisioners,
  project controllers).
- **A flag or config file on ate-gress.** Controlled by whoever deploys
  ate-gress, but changing it is a rollout, and it is invisible to `kubectl`.
- **A cluster-scoped binding object**, naming one namespace and one
  atespace. It has its own RBAC, separate from Namespace metadata and from
  the policies; it is listable; and it can carry status.

Whichever is used:

- The mapping is by atespace *name*. ate-gress cannot confirm that the
  atespace exists, or that the people with RBAC in the namespace are the
  atespace's owners in Substrate. The administrator who writes the binding
  asserts both. An atespace that is deleted and created again under the same
  name inherits the binding.
- A namespace maps to at most one atespace. A tenant policy in a namespace
  with no binding has no effect and is reported as not accepted.
- The atespace name must be an exact name, not a glob.

## Recommendation

Adopt **option 3** with a **cluster-scoped binding object**: a new
namespaced policy Kind with the same host and route schema as
`EgressRoutePolicy` and no `atespaces` selector, evaluated as a second layer
that can only deny.

It is the only option in which "a tenant cannot widen what the cluster set"
is true by the shape of the evaluation and not by a check that has to be
kept correct as the grammar grows. It also gives tenants the one power they
lack under every pooled design: to narrow a host the cluster already claims.

Option 1 remains the right answer until someone needs this enough to build
and review option 3. Option 2 should not be built.

## Consequences

If this is accepted:

- A new policy Kind and a binding Kind in the same API group. The existing
  Kind is unchanged, and a cluster with no bindings behaves exactly
  as today. See [the compatibility policy](../compatibility.md).
- `Snapshot.Decide` gains a layer. Per
  [CONTRIBUTING.md](../../CONTRIBUTING.md), that needs: the reference
  implementation rewritten for two layers; a fuzz target over both;
  threat-model rows for "a tenant policy widening a cluster policy", "a
  tenant policy selecting another atespace" and "a binding to an atespace the
  namespace's users do not own"; and the zero-allocation property kept.
- The snapshot is indexed by atespace for the tenant layer. Tenant policies
  need per-namespace limits on count and size, enforced by the compiler, so
  that one tenant cannot grow the snapshot or the rebuild time for all.
- The decision log needs to name the layer and the policy's namespace. Any
  new metric label for the layer must stay bounded, so not the namespace.
- The status writer sets `Accepted` on tenant policies, with a reason for
  "namespace not bound".
- The controller's RBAC grows to read the new Kinds in every namespace.

Left open:

- **The Kind names.**
- **Whether a tenant policy may use `Audit` and `logAllowed`.** `Audit` is
  useful for a tenant rolling out its own policy and is harmless in a
  separate layer. `logAllowed` lets a tenant raise the log volume of a shared
  component; it may need a per-binding switch.
- **What happens to a tenant policy the compiler rejects.** A rejected
  cluster policy fails closed: it keeps its claims and drops its routes, so
  it denies everything on its hosts, with reason `invalid_policy`, unless
  another `Enforce` policy allows the request. Leaving it out instead, as
  releases up to 0.1.0-rc.4 did, released its hosts and made its restriction
  disappear. The same rule in the tenant layer would deny a
  tenant's atespace those hosts until the tenant fixes its policy. Whether
  that is the right rule there is still to decide.
- **How an administrator spells "this atespace may do anything on this
  host"** as a ceiling, given that no template covers trailing slashes at
  every depth.
- **Whether Substrate will offer this itself.** Substrate describes the
  extension point as something that "may be converted to an API in the
  future". If route rules become part of Substrate's `EgressPolicy`, they
  would be owned by atespace editors natively, and this Kind would be
  redundant.
