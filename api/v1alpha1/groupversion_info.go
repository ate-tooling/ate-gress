// Package v1alpha1 holds the EgressRoutePolicy API.
//
// It is the storage version and the one version ate-gress itself reads and
// writes. Package v1beta1 has the same schema, and the API server serves each
// object as either. It stays the storage version for as long as a rollback to
// a chart without v1beta1 must work: the API server refuses a CRD that drops
// a version objects were ever stored in. docs/design.md has the plan.
//
// +kubebuilder:object:generate=true
// +groupName=ategress.ate-tooling.github.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of the EgressRoutePolicy API.
	GroupVersion = schema.GroupVersion{Group: "ategress.ate-tooling.github.io", Version: "v1alpha1"}

	// SchemeBuilder registers the API types with a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the API types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &EgressRoutePolicy{}, &EgressRoutePolicyList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
