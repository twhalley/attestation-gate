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

# `helm --wait` returns when the pods are Ready, which is not the same as the
# validating webhook for ClusterImagePolicy being reachable. Applying too early
# fails with a bare `Error from server (InternalError)` that names the file and
# explains nothing.
log "waiting for the policy-controller webhook to serve"
kubectl -n cosign-system wait --for=condition=Available deployment --all --timeout=180s || true
kubectl -n cosign-system wait --for=condition=Ready pod --all --timeout=180s || true

log "applying policies"
for attempt in 1 2 3 4 5 6; do
  if kubectl apply -f "${REPO_ROOT}/policy/"; then
    break
  fi
  if [ "$attempt" -eq 6 ]; then
    echo "policies still failing to apply after ${attempt} attempts" >&2
    kubectl -n cosign-system get pods
    exit 1
  fi
  log "webhook not ready yet, retrying (${attempt}/6)"
  sleep 10
done

log "waiting for policies to be reconciled"
for cip in require-trusted-signature require-slsa-provenance require-sbom; do
  kubectl wait --for=condition=Ready "clusterimagepolicy/${cip}" --timeout=60s || true
done

log "ready. namespace 'gated' is enforcing; run test/run.sh next."
