CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.20.1
GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
# The image bundles shellcheck, which actionlint runs on workflow scripts;
# a bare `go run` build silently skips that check where shellcheck is missing.
ACTIONLINT ?= docker run --rm -v "$(CURDIR):/repo:ro" -w /repo rhysd/actionlint:1.7.12
SHELLCHECK ?= docker run --rm -v "$(CURDIR):/mnt:ro" -w /mnt koalaman/shellcheck:v0.11.0
GOVULNCHECK ?= go run golang.org/x/vuln/cmd/govulncheck@v1.8.0
ZIZMOR ?= docker run --rm -v "$(CURDIR):/src:ro" -w /src ghcr.io/zizmorcore/zizmor:1.18.0
ENVTEST_K8S_VERSION ?= 1.37.0
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.24
CHART := charts/ate-gress
IMG ?= ghcr.io/ate-tooling/ate-gress:dev
FUZZTIME ?= 10s

.PHONY: generate
generate: ## Regenerate deepcopy code, the CRD, and RBAC.
	$(CONTROLLER_GEN) object crd rbac:roleName=ate-gress paths=./... \
		output:crd:artifacts:config=config/crd output:rbac:artifacts:config=config/rbac
	cp config/crd/*.yaml $(CHART)/crds/
	sed -n '/^rules:/,$$p' config/rbac/role.yaml | tail -n +2 > $(CHART)/files/clusterrole-rules.yaml

.PHONY: test
test: ## Unit tests, and the controller tests against an envtest API server.
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(CURDIR)/bin/envtest -p path)" \
		go test -race -count=3 -shuffle=on ./...

.PHONY: fuzz
fuzz: ## Run each fuzz target for FUZZTIME.
	go test -run='^$$' -fuzz=FuzzCanonicalize -fuzztime=$(FUZZTIME) ./internal/pathmatch
	go test -run='^$$' -fuzz=FuzzMatch -fuzztime=$(FUZZTIME) ./internal/pathmatch
	go test -run='^$$' -fuzz=FuzzCovers -fuzztime=$(FUZZTIME) ./internal/pathmatch
	go test -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME) ./internal/identity
	go test -run='^$$' -fuzz=FuzzDecide -fuzztime=$(FUZZTIME) ./internal/policy
	go test -run='^$$' -fuzz=FuzzSchemaAgreesWithCompiler -fuzztime=$(FUZZTIME) ./internal/policy

.PHONY: bench
bench: ## Benchmarks for the request path.
	go test -run='^$$' -bench=. -benchmem ./internal/pathmatch ./internal/identity ./internal/policy ./internal/extproc

ENVOY_IMAGE ?= envoyproxy/envoy:v1.39.5

.PHONY: test-envoy
test-envoy: ## Run ate-gress behind a real Envoy configured like Substrate's egress gateway.
	ATEGRESS_ENVOY_IMAGE=$(ENVOY_IMAGE) go test -count=1 -tags=envoy ./test/envoy/...

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run ./...
	$(ACTIONLINT)
	$(SHELLCHECK) hack/*.sh
	helm lint $(CHART)

.PHONY: lint-workflows
lint-workflows: ## Audit the GitHub workflows (CI runs the same check).
	$(ZIZMOR) --offline --persona=pedantic .github

.PHONY: vulncheck
vulncheck:
	$(GOVULNCHECK) ./...

.PHONY: verify
verify: generate lint test ## Fail if generated files or go.mod are stale.
	go mod tidy
	git diff --exit-code -- api config $(CHART) go.mod go.sum

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -o bin/ate-gress ./cmd/ate-gress

VERSION ?= dev

.PHONY: build-ategressctl
build-ategressctl: ## Build the policy testing CLI into bin/ategressctl.
	CGO_ENABLED=0 go build -trimpath -ldflags="-X main.version=$(VERSION)" -o bin/ategressctl ./cmd/ategressctl

.PHONY: docker-build
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMG) .

# The release workflow runs these; locally they are for trying a change to
# the release process.
.PHONY: chart-package
chart-package: ## Package the chart as a release would: make chart-package VERSION=0.1.0 DIGEST=sha256:...
	hack/package-chart.sh $(VERSION) $(DIGEST) dist

.PHONY: ategressctl-dist
ategressctl-dist: ## Build the ategressctl release binaries: make ategressctl-dist VERSION=0.1.0
	hack/build-ategressctl.sh $(VERSION) dist

.PHONY: verify-release
verify-release: ## Verify a published release's signatures and attestations: make verify-release VERSION=0.1.0
	hack/verify-release.sh $(VERSION)
