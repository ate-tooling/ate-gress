package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// maxMessage is the longest condition message the API accepts.
const maxMessage = 32768

// StatusReconciler sets each EgressRoutePolicy's Accepted condition. It runs on
// the leader only. A policy compiles independently of the others, so compiling
// it alone gives the verdict every replica's snapshot reaches for it.
type StatusReconciler struct {
	client.Client
}

// SetupWithManager registers the reconciler with mgr.
func (r *StatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EgressRoutePolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("egressroutepolicy-status").
		Complete(r)
}

// +kubebuilder:rbac:groups=ategress.ate-tooling.github.io,resources=egressroutepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ategress.ate-tooling.github.io,resources=egressroutepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile compiles one policy and records the outcome.
func (r *StatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p v1alpha1.EgressRoutePolicy
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	_, results := policy.Compile([]v1alpha1.EgressRoutePolicy{p})

	cond := metav1.Condition{
		Type:               v1alpha1.ConditionAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             v1alpha1.ReasonAccepted,
		Message:            "The policy is in effect.",
		ObservedGeneration: p.Generation,
	}
	if err := results[0].Err; err != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = v1alpha1.ReasonInvalid
		cond.Message = err.Error()
		if len(cond.Message) > maxMessage {
			cond.Message = cond.Message[:maxMessage]
		}
	}

	before := p.DeepCopy()
	meta.SetStatusCondition(&p.Status.Conditions, cond)
	p.Status.ObservedGeneration = p.Generation
	if equalStatus(before.Status, p.Status) {
		return ctrl.Result{}, nil
	}
	// The optimistic lock makes a concurrent spec change fail the patch, and
	// the returned error requeues with backoff to compile the new generation.
	return ctrl.Result{}, r.Status().Patch(ctx, &p, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}

func equalStatus(a, b v1alpha1.EgressRoutePolicyStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message ||
			x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}
