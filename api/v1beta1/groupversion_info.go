// Package v1beta1 holds the EgressRoutePolicy API.
//
// Its types are a copy of v1alpha1's and must stay one: the CRD has no
// conversion webhook, so the API server serves a stored object as either
// version by changing only its apiVersion. A field or a validation rule in one
// version and not the other would be dropped or bypassed through the other.
// api/versions_test.go fails if the generated schemas differ.
//
// +kubebuilder:object:generate=true
// +groupName=ategress.ate-tooling.github.io
package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of the EgressRoutePolicy API.
	GroupVersion = schema.GroupVersion{Group: "ategress.ate-tooling.github.io", Version: "v1beta1"}

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
