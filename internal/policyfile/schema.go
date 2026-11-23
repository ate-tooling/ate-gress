package policyfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	openapierrors "k8s.io/kube-openapi/pkg/validation/errors"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"k8s.io/kube-openapi/pkg/validation/strfmt"
	openapivalidate "k8s.io/kube-openapi/pkg/validation/validate"
	"sigs.k8s.io/yaml"

	"github.com/ate-tooling/ate-gress/config/crd"
)

// FieldError is one thing the API server would reject a manifest for.
type FieldError struct {
	// Field is the path of the offending field, such as
	// "spec.hosts[0].routes[1].paths[2]", or empty when the error is not
	// about one field.
	Field   string
	Message string
	// Duplicate is set when the error is a value listed twice in a list the
	// schema declares a set, or a key repeated in one it declares a map.
	Duplicate bool
}

func (e FieldError) String() string {
	if e.Field == "" {
		return e.Message
	}
	return e.Field + ": " + e.Message
}

// schemas returns the OpenAPI schema of each version the embedded
// CustomResourceDefinition serves: the one generated from the API types, and
// the one a cluster installs.
var schemas = sync.OnceValues(func() (map[string]*spec.Schema, error) {
	var def struct {
		Spec struct {
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema json.RawMessage `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(crd.EgressRoutePolicies, &def); err != nil {
		return nil, fmt.Errorf("embedded CustomResourceDefinition: %w", err)
	}
	out := make(map[string]*spec.Schema, len(def.Spec.Versions))
	for _, v := range def.Spec.Versions {
		s := &spec.Schema{}
		if err := json.Unmarshal(v.Schema.OpenAPIV3Schema, s); err != nil {
			return nil, fmt.Errorf("embedded CustomResourceDefinition, version %s: %w", v.Name, err)
		}
		out[v.Name] = s
	}
	return out, nil
})

// validate checks obj, a decoded manifest, as the API server checks a create:
// the object's name, the version's OpenAPI schema, and the uniqueness the
// schema's list types declare. It runs the schema with the validator the API
// server runs it with.
//
// Two things the API server does are not repeated. It applies defaults before
// validating; the only default is enforcementMode, and an absent one is valid
// and compiles to the same Enforce. It evaluates CEL rules; the schema has
// none, and TestSchemaAssumptions fails when one is added.
func validate(version string, obj map[string]any) ([]FieldError, error) {
	all, err := schemas()
	if err != nil {
		return nil, err
	}
	schema, ok := all[version]
	if !ok {
		return nil, fmt.Errorf("the CustomResourceDefinition has no version %q", version)
	}

	errs := validateName(obj)
	result := openapivalidate.NewSchemaValidator(schema, nil, "", strfmt.Default).Validate(obj)
	for _, e := range result.Errors {
		var v *openapierrors.Validation
		if !errors.As(e, &v) {
			errs = append(errs, FieldError{Message: e.Error()})
			continue
		}
		field := strings.TrimPrefix(v.Name, ".")
		errs = append(errs, FieldError{Field: field, Message: trimFieldPrefix(v.Error(), field)})
	}
	return append(errs, validateListTypes(schema, obj, "")...), nil
}

// trimFieldPrefix removes the field name the validator starts its messages
// with ("spec.hosts in body must be of type array"), which Field already
// carries.
func trimFieldPrefix(msg, field string) string {
	if field == "" {
		return msg
	}
	msg = strings.TrimPrefix(msg, field)
	msg = strings.TrimPrefix(msg, " in body")
	return strings.TrimSpace(msg)
}

// validateName checks metadata.name as the API server does for a custom
// resource. A manifest with only generateName is valid there, but names a
// policy nothing offline can refer to, so it is refused here.
func validateName(obj map[string]any) []FieldError {
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if name == "" {
		return []FieldError{{Field: "metadata.name", Message: "Required value"}}
	}
	var errs []FieldError
	for _, msg := range apivalidation.NameIsDNSSubdomain(name, false) {
		errs = append(errs, FieldError{Field: "metadata.name", Message: msg})
	}
	return errs
}

// validateListTypes checks x-kubernetes-list-type: the items of a set are
// unique, and so are the keys of a map's items. The OpenAPI validator ignores
// these extensions; the API server checks them in a separate pass, as this
// is.
func validateListTypes(schema *spec.Schema, v any, path string) []FieldError {
	if schema == nil {
		return nil
	}
	var errs []FieldError
	switch v := v.(type) {
	case map[string]any:
		for name, value := range v {
			if prop, ok := schema.Properties[name]; ok {
				errs = append(errs, validateListTypes(&prop, value, join(path, name))...)
			}
		}
	case []any:
		listType, _ := schema.Extensions.GetString("x-kubernetes-list-type")
		switch listType {
		case "set":
			for i, item := range v {
				for _, prior := range v[:i] {
					if reflect.DeepEqual(item, prior) {
						errs = append(errs, FieldError{
							Field: fmt.Sprintf("%s[%d]", path, i), Duplicate: true,
							Message: fmt.Sprintf("Duplicate value: %s", compact(item)),
						})
						break
					}
				}
			}
		case "map":
			keys, _ := schema.Extensions.GetStringSlice("x-kubernetes-list-map-keys")
			for i, item := range v {
				for _, prior := range v[:i] {
					if key, same := sameKeys(keys, item, prior); same {
						errs = append(errs, FieldError{
							Field: fmt.Sprintf("%s[%d]", path, i), Duplicate: true,
							Message: fmt.Sprintf("Duplicate value: %s", compact(key)),
						})
						break
					}
				}
			}
		}
		if schema.Items != nil && schema.Items.Schema != nil {
			for i, item := range v {
				errs = append(errs, validateListTypes(schema.Items.Schema, item, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return errs
}

// sameKeys reports whether a and b, items of a list of type map, agree on
// every key, and returns those keys' values.
func sameKeys(keys []string, a, b any) (map[string]any, bool) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if !aok || !bok || len(keys) == 0 {
		return nil, false
	}
	key := make(map[string]any, len(keys))
	for _, k := range keys {
		if !reflect.DeepEqual(am[k], bm[k]) {
			return nil, false
		}
		key[k] = am[k]
	}
	return key, true
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
