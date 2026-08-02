#!/usr/bin/env bash
# Stand up a kind cluster with sigstore policy-controller enforcing the
# policies in policy/. Safe to re-run.
set -euo pipefail

CLUSTER="${CLUSTER:-attestation-gate}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

for bin in kind kubectl helm; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

# kind defaults to Docker. On a Podman-only host it fails with a bare
# "docker not found" rather than falling back.
if ! command -v docker >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
  export KIND_EXPERIMENTAL_PROVIDER=podman
  log "using the podman provider for kind"
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "kind cluster '$CLUSTER' already exists"
else
  log "creating kind cluster '$CLUSTER'"
  kind create cluster --name "$CLUSTER" --wait 120s
fi

kubectl config use-context "kind-${CLUSTER}" >/dev/null

log "installing sigstore policy-controller"
helm repo add sigstore https://sigstore.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update >/dev/null
helm upgrade --install policy-controller sigstore/policy-controller \
  --namespace cosign-system --create-namespace \
  --wait --timeout 5m

# Fail closed on images that no policy covers. Without this, an image outside
# every glob is admitted by default -- which quietly defeats the gate the
# moment someone pushes to a registry path nobody wrote a policy for.
log "setting no-match-policy=deny"
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system --type merge \
  --patch '{"data":{"no-match-policy":"deny"}}'

log "applying policies"
kubectl apply -f "${REPO_ROOT}/policy/"

log "waiting for policies to be reconciled"
kubectl wait --for=condition=Ready clusterimagepolicy/require-trusted-signature --timeout=60s || true
kubectl wait --for=condition=Ready clusterimagepolicy/require-slsa-provenance --timeout=60s || true

log "ready. namespace 'gated' is enforcing; run test/run.sh next."
