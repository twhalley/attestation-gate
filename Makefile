SHELL := /usr/bin/env bash
IMAGE ?= ghcr.io/twhalley/attestation-gate/app
CLUSTER ?= attestation-gate
IDENTITY := https://github.com/twhalley/attestation-gate/.github/workflows/build-sign-attest.yml@refs/heads/main
ISSUER := https://token.actions.githubusercontent.com

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create the kind cluster, install policy-controller, apply policies
	CLUSTER=$(CLUSTER) ./test/setup.sh

.PHONY: test
test: ## Run the six admission cases against the running cluster
	IMAGE=$(IMAGE) ./test/run.sh

.PHONY: scan
scan: ## Compare CVE counts, packages and size across both base images
	./scripts/scan-diff.sh

.PHONY: hardening
hardening: ## Compare PIE/RELRO/canary/FORTIFY across both base images
	./scripts/hardening-diff.sh

.PHONY: verify-base
verify-base: ## Verify the signatures of the Chainguard base images
	./scripts/verify-base-images.sh

.PHONY: apko
apko: ## Build a minimal Python image declaratively, with a generated SBOM
	./scripts/apko-build.sh

.PHONY: vex
vex: ## Show a VEX statement suppressing an unreachable CVE (needs a registry image)
	./scripts/vex-demo.sh

.PHONY: deps
deps: ## Regenerate requirements.txt with hashes from requirements.in
	podman run --rm --entrypoint sh -v "$(PWD)/app:/w:z" -w /w \
	  cgr.dev/chainguard/python:latest-dev -c '\
	    python -m venv /tmp/v >/dev/null 2>&1; \
	    /tmp/v/bin/pip install --quiet --disable-pip-version-check uv >/dev/null 2>&1; \
	    /tmp/v/bin/uv pip compile --generate-hashes --no-header --quiet \
	      --output-file=/dev/stdout requirements.in'

.PHONY: verify
verify: ## Verify the trusted image's signature, provenance and SBOM from the CLI
	cosign verify \
	  --certificate-oidc-issuer $(ISSUER) --certificate-identity $(IDENTITY) \
	  $(IMAGE):trusted
	cosign verify-attestation --type slsaprovenance \
	  --certificate-oidc-issuer $(ISSUER) --certificate-identity $(IDENTITY) \
	  $(IMAGE):trusted
	cosign verify-attestation --type spdxjson \
	  --certificate-oidc-issuer $(ISSUER) --certificate-identity $(IDENTITY) \
	  $(IMAGE):trusted

.PHONY: clean
clean: ## Delete the kind cluster and local build output
	kind delete cluster --name $(CLUSTER) || true
	rm -rf .scan .base-digests
