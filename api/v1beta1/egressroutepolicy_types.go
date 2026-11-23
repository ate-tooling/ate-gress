package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EnforcementMode says what happens to a request a policy does not allow.
// +kubebuilder:validation:Enum=Enforce;Audit
type EnforcementMode string

const (
	// EnforcementModeEnforce denies the request.
	EnforcementModeEnforce EnforcementMode = "Enforce"
	// EnforcementModeAudit allows the request and records that it would have
	// been denied, so a policy can be rolled out before it is enforced.
	EnforcementModeAudit EnforcementMode = "Audit"
)

// Method is an HTTP request method a route allows.
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;PATCH;DELETE;OPTIONS
type Method string

// EgressRoutePolicySpec restricts the HTTP requests the selected actors may
// send to the hosts it lists.
//
// A policy claims each host it lists for the actors it selects. A request to a
// host that no policy selecting the actor claims is left to Substrate's
// EgressPolicy, which has already allowed it. A request to a claimed host is
// allowed only if a route in some Enforce policy claiming that host matches
// it. Policies only ever allow: a host listed with no routes denies every
// request to it.
type EgressRoutePolicySpec struct {
	// EnforcementMode is Enforce (the default) or Audit.
	// +kubebuilder:default=Enforce
	// +optional
	EnforcementMode EnforcementMode `json:"enforcementMode,omitempty"`

	// ActorSelector chooses the actors the policy applies to. An empty
	// selector selects every actor.
	// +optional
	ActorSelector ActorSelector `json:"actorSelector,omitzero"`

	// LogAllowed logs allowed requests at INFO, as denials and audits always
	// are: every request the selected actors send to the hosts this policy
	// lists, whichever policy's route allowed it. The record has the actor,
	// method, authority, the path without its query, and the policy and
	// template that matched. Without it, allowed requests are logged only at
	// DEBUG. Header values are never logged.
	// +optional
	LogAllowed bool `json:"logAllowed,omitempty"`

	// Hosts lists the hosts the policy claims and the routes allowed on each.
	// +listType=map
	// +listMapKey=host
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Hosts []HostRoutes `json:"hosts"`
}

// ActorSelector matches actors by atespace and name. Each list holds globs in
// which "*" matches any run of characters; an empty list matches everything.
// An actor is selected when both its atespace and its name match.
type ActorSelector struct {
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9*-]{1,63}$`
	// +optional
	Atespaces []string `json:"atespaces,omitempty"`

	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9*-]{1,63}$`
	// +optional
	Names []string `json:"names,omitempty"`
}

// HostRoutes lists the routes allowed on one host.
type HostRoutes struct {
	// Host is the exact, lowercase hostname, without a port. It is compared
	// with the request's :authority, which the gateway has already matched to
	// the hostname the actor's TLS SNI named.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	Host string `json:"host"`

	// Routes are the requests allowed on Host. An empty list allows none.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Routes []Route `json:"routes,omitempty"`
}

// Route allows requests whose method is in Methods and whose path matches one
// of Paths.
type Route struct {
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	Methods []Method `json:"methods"`

	// Paths are path templates. Each segment is a literal, "*" (exactly one
	// segment), or "**" (one or more segments, last only). A template may end
	// in "/" to match that one trailing slash: "/v2/" matches "/v2/" only,
	// and "*" and "**" never match the empty segment it leaves. The query
	// string is not matched. Literals may not contain "%".
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=1024
	//
	// The pattern below is the whole template grammar, as an OpenAPI pattern
	// rather than CEL so that it costs nothing against the CEL budget: "/";
	// or segments that are each "*" or a literal, optionally followed by one
	// trailing "/"; or such segments followed by a last "**". A literal is
	// pchar without "*" or "%", and is not "." or "..": it is either three or
	// more dots, or has a non-dot character.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MaxLength=1024
	// +kubebuilder:validation:items:Pattern=`^(/|(/([.]*[A-Za-z0-9_~!$&'()+,;=:@-][A-Za-z0-9_~!$&'()+,;=:@.-]*|[.][.][.]+|[*]))+/?|(/([.]*[A-Za-z0-9_~!$&'()+,;=:@-][A-Za-z0-9_~!$&'()+,;=:@.-]*|[.][.][.]+|[*]))*/[*][*])$`
	Paths []string `json:"paths"`

	// CaseInsensitive matches literal segments ASCII case-insensitively, for
	// upstreams such as GitHub whose account and repository names are.
	// +optional
	CaseInsensitive bool `json:"caseInsensitive,omitempty"`
}

// ConditionAccepted is True when the policy compiled and is in effect, and
// False, with the reason, when it was rejected and allows nothing.
const ConditionAccepted = "Accepted"

// Reasons for ConditionAccepted.
const (
	ReasonAccepted = "Accepted"
	ReasonInvalid  = "Invalid"
)

// EgressRoutePolicyStatus is the observed state of an EgressRoutePolicy.
type EgressRoutePolicyStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EgressRoutePolicy restricts the HTTP routes Substrate actors may reach.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=erp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.enforcementMode`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EgressRoutePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EgressRoutePolicySpec `json:"spec"`
	// +optional
	Status EgressRoutePolicyStatus `json:"status,omitzero"`
}

// EgressRoutePolicyList is a list of EgressRoutePolicy.
//
// +kubebuilder:object:root=true
type EgressRoutePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressRoutePolicy `json:"items"`
}
