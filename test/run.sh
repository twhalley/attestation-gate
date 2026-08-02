#!/usr/bin/env bash
# The point of the repository: prove the gate rejects what it should, and
# rejects it for the reason claimed.
#
# Every case attempts a real Pod creation against a real admission webhook.
# Run test/setup.sh first.
set -uo pipefail

IMAGE="${IMAGE:-ghcr.io/twhalley/attestation-gate/app}"
NS="${NS:-gated}"
PASS=0
FAIL=0
ROWS=()

# name | image ref | expected decision | expected policy in the message | what it proves
#
# The fourth field is what stops this suite from passing for the wrong reason.
# Where it is set, that named policy must be the one that failed.
#
# It is only set for the two cases that can isolate a single policy. Every
# policy here is anchored to the same workflow identity, so an image that is
# unsigned, signed by the wrong identity, or signed outside the transparency
# log fails all three at once -- and policy-controller reports only the first
# failure it hits. Demanding a specific policy name for those cases would be
# asserting an implementation detail of the webhook's evaluation order.
#
# Those cases still assert that a real policy verdict was reached (the message
# must contain "failed policy:"), which is what distinguishes an evaluated
# rejection from a structural one.
CASES=(
  "trusted|${TRUSTED_REF:-${IMAGE}:trusted}|admit||Signed by the release workflow, with SLSA provenance and an SBOM"
  "unsigned|${UNSIGNED_REF:-${IMAGE}:unsigned}|reject||No signature at all"
  "no-provenance|${NOPROV_REF:-${IMAGE}:no-provenance}|reject|require-slsa-provenance|Signed, with an SBOM, but no provenance attestation"
  "no-sbom|${NOSBOM_REF:-${IMAGE}:no-sbom}|reject|require-sbom|Signed with valid provenance, but no SBOM attestation"
  "rogue|${ROGUE_REF:-${IMAGE}:rogue}|reject||Validly signed and attested by the WRONG workflow identity"
  "keysigned|${KEYSIGNED_REF:-${IMAGE}:keysigned}|reject||Real signature, never written to the Rekor transparency log"
)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

command -v kubectl >/dev/null 2>&1 || { echo "missing required tool: kubectl" >&2; exit 1; }

kubectl get namespace "$NS" >/dev/null 2>&1 || {
  echo "namespace '$NS' not found -- run test/setup.sh first" >&2; exit 1; }

# policy-controller refuses to evaluate an image referenced by tag: signatures
# bind to digests, and a tag can point somewhere else by the time the kubelet
# pulls it. Resolving here rather than deploying by tag is also just correct
# practice -- see GOTCHAS.md.
resolve() { # ref -> ref@sha256:...
  local ref="$1"
  case "$ref" in *@sha256:*) printf '%s' "$ref"; return ;; esac

  local digest=""
  if command -v crane >/dev/null 2>&1; then
    digest=$(crane digest "$ref" 2>/dev/null || true)
  elif command -v skopeo >/dev/null 2>&1; then
    digest=$(skopeo inspect --format '{{.Digest}}' "docker://${ref}" 2>/dev/null || true)
  fi

  if [ -z "$digest" ]; then
    echo "could not resolve ${ref} to a digest." >&2
    echo "Install crane or skopeo, or pass digests via TRUSTED_REF/UNSIGNED_REF/..." >&2
    exit 1
  fi
  printf '%s@%s' "${ref%%:*}" "$digest"
}

# Every test pod is made Pod Security Admission `restricted`-compliant on
# purpose. The namespace enforces both PSA and the sigstore gate, and if these
# pods failed PSA then all the negative cases would be "rejected" without the
# signature policy ever being consulted.
overrides() { # pod-name image-ref
  cat <<EOF
{
  "spec": {
    "securityContext": {
      "runAsNonRoot": true,
      "runAsUser": 65532,
      "seccompProfile": { "type": "RuntimeDefault" }
    },
    "containers": [{
      "name": "$1",
      "image": "$2",
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "capabilities": { "drop": ["ALL"] }
      }
    }]
  }
}
EOF
}

log "cleaning up any pods from a previous run"
kubectl -n "$NS" delete pod --all --ignore-not-found --wait=true >/dev/null 2>&1 || true

for entry in "${CASES[@]}"; do
  IFS='|' read -r name ref expected expect_policy why <<<"$entry"

  ref="$(resolve "$ref")" || exit 1

  log "case: ${name} (expect ${expected})"
  output=$(kubectl -n "$NS" run "gate-${name}" \
             --image="$ref" \
             --restart=Never \
             --labels="gate-case=${name}" \
             --overrides="$(overrides "gate-${name}" "$ref")" \
             2>&1)
  rc=$?

  if [ $rc -eq 0 ]; then actual="admit"; else actual="reject"; fi

  message=$(printf '%s' "$output" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-240)

  if [ "$actual" != "$expected" ]; then
    bad "${name}: expected ${expected}, got ${actual}"
    FAIL=$((FAIL + 1)); result="FAIL"

  elif [ "$actual" = "reject" ] && ! printf '%s' "$message" | grep -q 'policy.sigstore.dev'; then
    # Right outcome, wrong controller. Pod Security Admission also guards this
    # namespace; a rejection from it says nothing about the signature gate.
    bad "${name}: rejected, but not by policy.sigstore.dev -- proves nothing"
    FAIL=$((FAIL + 1)); result="FAIL (wrong controller)"

  elif [ "$actual" = "reject" ] && printf '%s' "$message" | grep -q 'must be an image digest'; then
    # Right controller, but it refused to evaluate the reference at all. This
    # is a structural error dressed as a security verdict, and it is exactly
    # how a suite like this ends up green while testing nothing.
    bad "${name}: rejected on the reference, not on its signatures -- proves nothing"
    FAIL=$((FAIL + 1)); result="FAIL (not evaluated)"

  elif [ "$actual" = "reject" ] && ! printf '%s' "$message" | grep -q 'failed policy:'; then
    # A rejection that is not a policy verdict. Covers every remaining way the
    # webhook can say no without having checked a signature.
    bad "${name}: rejected without reaching a policy verdict -- proves nothing"
    FAIL=$((FAIL + 1)); result="FAIL (no verdict)"

  elif [ "$actual" = "reject" ] && [ -n "$expect_policy" ] \
       && ! printf '%s' "$message" | grep -q "$expect_policy"; then
    bad "${name}: rejected, but not by ${expect_policy}"
    FAIL=$((FAIL + 1)); result="FAIL (wrong policy)"

  else
    ok "${name}: ${actual}${expect_policy:+ (${expect_policy})}"
    PASS=$((PASS + 1)); result="PASS"
  fi

  [ "$actual" = "reject" ] && printf '     %s\n' "$message"

  ROWS+=("| \`${name}\` | ${expected} | ${actual} | ${result} | ${why} |")
done

# The admitted image must also actually run. A gate that admits an image which
# cannot start is not proving much.
if [ "$FAIL" -eq 0 ]; then
  log "waiting for the admitted pod to reach Running"
  if kubectl -n "$NS" wait --for=condition=Ready pod/gate-trusted --timeout=180s >/dev/null 2>&1; then
    ok "gate-trusted is Running"
  else
    bad "gate-trusted was admitted but never became Ready"
    kubectl -n "$NS" describe pod gate-trusted | tail -25
    echo
    echo "Most likely cause: the cluster cannot pull the image. Make the GHCR" >&2
    echo "package public, or add an imagePullSecret to the ${NS} namespace." >&2
    FAIL=$((FAIL + 1))
  fi
fi

summary() {
  echo "## Admission gate results"
  echo
  echo "| Case | Expected | Actual | Result | What it proves |"
  echo "|---|---|---|---|---|"
  printf '%s\n' "${ROWS[@]}"
  echo
  echo "**${PASS} passed, ${FAIL} failed**"
}

echo
summary
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && summary >> "$GITHUB_STEP_SUMMARY"

kubectl -n "$NS" delete pod --all --ignore-not-found >/dev/null 2>&1 || true

[ "$FAIL" -eq 0 ] || exit 1
