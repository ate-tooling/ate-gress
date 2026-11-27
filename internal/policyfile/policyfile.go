// Package policyfile reads EgressRoutePolicy manifests from files and checks
// them against the CustomResourceDefinition's schema, as the API server does
// at admission.
//
// It is the one place ategressctl resolves the API's versions: a manifest's
// apiVersion selects the schema it is checked against and how it is decoded
// into Policy, the type the compiler takes, which is the stored version's.
// Serving another version means another entry in versions, and nothing
// outside this package changes.
package policyfile

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	kjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"

	"github.com/ate-tooling/ate-gress/api/v1alpha1"
	"github.com/ate-tooling/ate-gress/api/v1beta1"
	"github.com/ate-tooling/ate-gress/internal/policy"
)

// Policy is the type policy.Compile takes, and Host, Route and Method are the
// types of its parts. Tools name them through this package so that the API
// version they are built on is chosen here alone.
type (
	Policy = v1alpha1.EgressRoutePolicy
	Host   = v1alpha1.HostRoutes
	Route  = v1alpha1.Route
	Method = v1alpha1.Method
)

const (
	// Group is the API group of EgressRoutePolicy.
	Group = v1alpha1.Group
	// Kind is the kind this package reads.
	Kind     = "EgressRoutePolicy"
	listKind = "EgressRoutePolicyList"
)

// versions maps each API version this package accepts to its decoder. Every
// version must also be in the CustomResourceDefinition, which supplies its
// schema, and TestVersions fails when the two disagree.
//
// A decoder reads the manifest into its own version's type, strictly, so that
// a field that version lacks is reported, and then converts the result to
// Policy the way the API server would.
var versions = map[string]func(data []byte) (Policy, []error, error){
	v1alpha1.GroupVersion.Version: func(data []byte) (Policy, []error, error) {
		var p v1alpha1.EgressRoutePolicy
		strict, err := kjson.UnmarshalStrict(data, &p)
		return p, strict, err
	},
	v1beta1.GroupVersion.Version: func(data []byte) (Policy, []error, error) {
		var p v1beta1.EgressRoutePolicy
		strict, err := kjson.UnmarshalStrict(data, &p)
		converted, cerr := convertNone(p)
		return converted, strict, cmp.Or(err, cerr)
	},
}

// convertNone converts a policy of another served version to Policy as the
// API server does under the CustomResourceDefinition's conversion strategy
// None: the object is kept as written and only its apiVersion changes.
//
// That is sound only while the versions' schemas are identical, which
// api/versions_test.go requires. Should they diverge, a field the other
// version has and Policy lacks makes this an error rather than a field
// silently dropped: the divergence needs a real conversion here, and a
// conversion webhook in the cluster.
func convertNone(in any) (Policy, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return Policy{}, err
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Policy{}, err
	}
	from, _ := obj["apiVersion"].(string)
	obj["apiVersion"] = v1alpha1.GroupVersion.String()
	if raw, err = json.Marshal(obj); err != nil {
		return Policy{}, err
	}
	var out Policy
	strict, err := kjson.UnmarshalStrict(raw, &out)
	if err == nil && len(strict) > 0 {
		err = errors.Join(strict...)
	}
	if err != nil {
		return Policy{}, fmt.Errorf("converting %s to %s: %w", from, v1alpha1.GroupVersion, err)
	}
	return out, nil
}

// Document is one EgressRoutePolicy read from a file.
type Document struct {
	// File is the file the policy came from, and Index the position of its
	// YAML document in that file, from 1.
	File  string
	Index int
	// Order is the position of the document in the Set.
	Order int
	// Policy is the decoded policy. Fields the schema rejected may be zero.
	Policy Policy
	// Invalid lists what the API server would reject the manifest for. A
	// policy with any is not one a cluster can hold.
	Invalid []FieldError
}

// Name returns the policy's metadata.name.
func (d *Document) Name() string { return d.Policy.Name }

// Source returns "file" or "file#index", for messages.
func (d *Document) Source() string {
	if d.Index <= 1 {
		return d.File
	}
	return fmt.Sprintf("%s#%d", d.File, d.Index)
}

// Set is the policies read from a list of paths.
type Set struct {
	documents []Document
	// Skipped counts the documents under a directory that were not
	// EgressRoutePolicy objects.
	Skipped int
}

// Len returns the number of policies in s.
func (s *Set) Len() int { return len(s.documents) }

// All yields the documents of s, in the order they were read.
func (s *Set) All() iter.Seq[*Document] {
	return func(yield func(*Document) bool) {
		for i := range s.documents {
			if !yield(&s.documents[i]) {
				return
			}
		}
	}
}

// Document returns the document of the policy named name, or nil. Load
// refuses two policies of one name; a policy without a name has none.
func (s *Set) Document(name string) *Document {
	if name == "" {
		return nil
	}
	i := slices.IndexFunc(s.documents, func(d Document) bool { return d.Name() == name })
	if i < 0 {
		return nil
	}
	return &s.documents[i]
}

// Compile builds the snapshot ate-gress would serve from s, and the
// compiler's result for each policy, in the order of All. A policy without a
// name is left out, since the API server refuses it; its result is zero.
func (s *Set) Compile() (*policy.Snapshot, []policy.Result) {
	var named []Policy
	var index []int
	for i, d := range s.documents {
		if d.Name() != "" {
			named = append(named, d.Policy)
			index = append(index, i)
		}
	}
	snap, compiled := policy.Compile(named)
	results := make([]policy.Result, len(s.documents))
	for j, i := range index {
		results[i] = compiled[j]
	}
	return snap, results
}

// Policies returns the policies in s, in the order they were read.
func (s *Set) Policies() []Policy {
	out := make([]Policy, len(s.documents))
	for i := range s.documents {
		out[i] = s.documents[i].Policy
	}
	return out
}

// Valid reports whether the API server would accept every policy in s.
func (s *Set) Valid() bool {
	return !slices.ContainsFunc(s.documents, func(d Document) bool { return len(d.Invalid) > 0 })
}

// Load reads the policies in paths. A path is a file of one or more YAML or
// JSON documents, "-" for stdin, or a directory, which is searched
// recursively for .yaml, .yml and .json files.
//
// A named file must hold only EgressRoutePolicy objects, or lists of them. A
// directory may hold other things, such as test files and other manifests,
// and those are skipped. An object in the EgressRoutePolicy API group that
// this package cannot read is an error either way, so a mistyped kind or an
// unknown version is never skipped silently.
//
// Load returns an error for what makes the input unusable: an unreadable
// file, malformed YAML, no policy at all, or two policies with one name. What
// the API server would reject a single policy for is reported in its
// Document instead.
func Load(paths []string, stdin io.Reader) (*Set, error) {
	if len(paths) == 0 {
		return nil, errors.New("no policy files given")
	}
	set := &Set{}
	for _, p := range paths {
		if err := set.loadPath(p, stdin); err != nil {
			return nil, err
		}
	}
	if len(set.documents) == 0 {
		return nil, fmt.Errorf("no %s found in %s", Kind, strings.Join(paths, ", "))
	}
	seen := make(map[string]string, len(set.documents))
	for i := range set.documents {
		d := &set.documents[i]
		if d.Name() == "" {
			continue // reported in d.Invalid
		}
		if prior, dup := seen[d.Name()]; dup {
			return nil, fmt.Errorf("policy %q is defined in both %s and %s", d.Name(), prior, d.Source())
		}
		seen[d.Name()] = d.Source()
	}
	return set, nil
}

func (s *Set) loadPath(p string, stdin io.Reader) error {
	if p == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		return s.loadFile("<stdin>", data, false)
	}
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return s.loadFile(p, data, false)
	}
	return filepath.WalkDir(p, func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden directories hold things like .git, never policies.
			if file != p && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(file) {
		case ".yaml", ".yml", ".json":
		default:
			return nil
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		return s.loadFile(file, data, true)
	})
}

// loadFile reads the documents in one file. lenient is set for a file found
// under a directory, where documents of other kinds are skipped.
func (s *Set) loadFile(file string, data []byte, lenient bool) error {
	before := len(s.documents)
	docs := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for index := 1; ; index++ {
		doc, err := docs.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		// YAMLToJSONStrict refuses a key written twice, which the API server
		// refuses too.
		raw, err := yaml.YAMLToJSONStrict(doc)
		if err != nil {
			if lenient {
				s.Skipped++
				continue
			}
			return fmt.Errorf("%s: document %d: %w", file, index, err)
		}
		var obj any
		// This decoder reads numbers as int64 or float64, as the API server's
		// does, which the schema's integer checks depend on.
		if err := utiljson.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("%s: document %d: %w", file, index, err)
		}
		if obj == nil {
			continue // an empty or comment-only document
		}
		if err := s.loadObject(file, index, obj, lenient); err != nil {
			return fmt.Errorf("%s: document %d: %w", file, index, err)
		}
	}
	if !lenient && len(s.documents) == before {
		return fmt.Errorf("%s: no %s found", file, Kind)
	}
	return nil
}

func (s *Set) loadObject(file string, index int, obj any, lenient bool) error {
	m, ok := obj.(map[string]any)
	if !ok {
		if lenient {
			s.Skipped++
			return nil
		}
		return errors.New("not an object")
	}
	apiVersion, _ := m["apiVersion"].(string)
	kind, _ := m["kind"].(string)
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		gv = schema.GroupVersion{}
	}
	switch {
	case gv.Group == Group && kind == listKind, apiVersion == "v1" && kind == "List":
		// What `kubectl get egressroutepolicies -o yaml` prints.
		items, _ := m["items"].([]any)
		for _, item := range items {
			if err := s.loadObject(file, index, item, lenient); err != nil {
				return err
			}
		}
		return nil
	case gv.Group != Group:
		if lenient {
			s.Skipped++
			return nil
		}
		return fmt.Errorf("apiVersion %q, kind %q is not an %s in %s", apiVersion, kind, Kind, Group)
	case kind != Kind:
		return fmt.Errorf("kind %q in %s is not %s", kind, Group, Kind)
	}
	decode, known := versions[gv.Version]
	if !known {
		return fmt.Errorf("apiVersion %q is not a version ategressctl knows (%s)", apiVersion, strings.Join(knownVersions(), ", "))
	}

	doc := Document{File: file, Index: index}
	// The API server drops nulls before it defaults and validates, so that
	// "field: null" reads as an absent field.
	dropNulls(m)
	invalid, err := validate(gv.Version, m)
	if err != nil {
		return err
	}
	doc.Invalid = invalid

	raw, err := utiljson.Marshal(m)
	if err != nil {
		return err
	}
	p, strict, err := decode(raw)
	doc.Policy = p
	// A field of the wrong type fails both the schema and the decoder; the
	// schema's message names the field, so the decoder's is kept only when
	// it is all there is.
	if err != nil && len(doc.Invalid) == 0 {
		doc.Invalid = append(doc.Invalid, FieldError{Message: err.Error()})
	}
	// Unknown fields: the API server prunes them, but kubectl's default
	// strict field validation refuses the manifest, and a pruned field is a
	// typo that silently changes what the policy means.
	for _, e := range strict {
		fe := FieldError{Message: e.Error()}
		var pathed kjson.FieldError
		if errors.As(e, &pathed) {
			fe.Field = pathed.FieldPath()
			fe.Message = strings.TrimSpace(strings.Replace(fe.Message, fmt.Sprintf("%q", fe.Field), "", 1))
		}
		doc.Invalid = append(doc.Invalid, fe)
	}
	// The schema is walked in map order; report in a stable one.
	slices.SortStableFunc(doc.Invalid, func(a, b FieldError) int {
		return cmp.Or(cmp.Compare(a.Field, b.Field), cmp.Compare(a.Message, b.Message))
	})
	doc.Order = len(s.documents)
	s.documents = append(s.documents, doc)
	return nil
}

func knownVersions() []string {
	out := make([]string, 0, len(versions))
	for v := range versions {
		out = append(out, Group+"/"+v)
	}
	slices.Sort(out)
	return out
}

func dropNulls(v any) {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			if e == nil {
				delete(v, k)
				continue
			}
			dropNulls(e)
		}
	case []any:
		for _, e := range v {
			dropNulls(e)
		}
	}
}
