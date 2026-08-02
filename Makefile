SHELL := /usr/bin/env bash
IMAGE ?= ghcr.io/twhalley/attestation-gate/app
CLUSTER ?= attestation-gate

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create the kind cluster, install policy-controller, apply policies
	CLUSTER=$(CLUSTER) ./test/setup.sh

.PHONY: test
test: ## Run the five admission cases against the running cluster
	IMAGE=$(IMAGE) ./test/run.sh

.PHONY: scan
scan: ## Build both image variants and compare CVE counts, packages and size
	./scripts/scan-diff.sh

.PHONY: vex
vex: ## Show a VEX statement suppressing an unreachable CVE (needs a registry image)
	./scripts/vex-demo.sh

.PHONY: verify
verify: ## Verify the trusted image's signature and provenance from the CLI
	cosign verify \
	  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	  --certificate-identity https://github.com/twhalley/attestation-gate/.github/workflows/build-sign-attest.yml@refs/heads/main \
	  $(IMAGE):trusted
	cosign verify-attestation --type slsaprovenance \
	  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
	  --certificate-identity https://github.com/twhalley/attestation-gate/.github/workflows/build-sign-attest.yml@refs/heads/main \
	  $(IMAGE):trusted

.PHONY: clean
clean: ## Delete the kind cluster and local scan output
	kind delete cluster --name $(CLUSTER) || true
	rm -rf .scan
