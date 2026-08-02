#!/usr/bin/env bash
# The point of the repository: prove the gate rejects what it should.
#
# Every case attempts a real Pod creation against a real admission webhook.
# The assertion is on the admission decision, which is the thing under test.
# Run test/setup.sh first.
set -uo pipefail

IMAGE="${IMAGE:-ghcr.io/twhalley/attestation-gate/app}"
NS="${NS:-gated}"
PASS=0
FAIL=0
ROWS=()

# case name | image ref | expected decision | what it proves
CASES=(
  "trusted|${TRUSTED_REF:-${IMAGE}:trusted}|admit|Signed by the release workflow and carrying SLSA provenance"
  "unsigned|${UNSIGNED_REF:-${IMAGE}:unsigned}|reject|No signature at all"
  "no-provenance|${NOPROV_REF:-${IMAGE}:no-provenance}|reject|Correctly signed, but no provenance attestation"
  "rogue|${ROGUE_REF:-${IMAGE}:rogue}|reject|Validly signed and attested by the WRONG workflow identity"
  "keysigned|${KEYSIGNED_REF:-${IMAGE}:keysigned}|reject|Real signature, never written to the Rekor transparency log"
)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }

command -v kubectl >/dev/null 2>&1 || { echo "missing required tool: kubectl" >&2; exit 1; }

kubectl get namespace "$NS" >/dev/null 2>&1 || {
  echo "namespace '$NS' not found -- run test/setup.sh first" >&2; exit 1; }

log "cleaning up any pods from a previous run"
kubectl -n "$NS" delete pod --all --ignore-not-found --wait=true >/dev/null 2>&1 || true

for entry in "${CASES[@]}"; do
  IFS='|' read -r name ref expected why <<<"$entry"

  log "case: ${name} (expect ${expected})"
  output=$(kubectl -n "$NS" run "gate-${name}" \
             --image="$ref" \
             --restart=Never \
             --labels="gate-case=${name}" 2>&1)
  rc=$?

  if [ $rc -eq 0 ]; then
    actual="admit"
  else
    actual="reject"
  fi

  # Collapse the webhook's message onto one line for the report.
  message=$(printf '%s' "$output" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-200)

  if [ "$actual" = "$expected" ]; then
    ok "${name}: ${actual}"
    PASS=$((PASS + 1))
    result="PASS"
  else
    bad "${name}: expected ${expected}, got ${actual}"
    FAIL=$((FAIL + 1))
    result="FAIL"
  fi

  [ "$actual" = "reject" ] && printf '     %s\n' "$message"

  ROWS+=("| \`${name}\` | ${expected} | ${actual} | ${result} | ${why} |")
done

# The admitted image must also actually run. A gate that admits an image which
# cannot start is not proving much.
if [ "$FAIL" -eq 0 ]; then
  log "waiting for the admitted pod to reach Running"
  if kubectl -n "$NS" wait --for=condition=Ready pod/gate-trusted --timeout=120s >/dev/null 2>&1; then
    ok "gate-trusted is Running"
  else
    bad "gate-trusted was admitted but never became Ready"
    kubectl -n "$NS" describe pod gate-trusted | tail -25
    echo
    echo "Most likely cause: the GHCR package is private, so the kubelet cannot" >&2
    echo "pull it. Make ghcr.io/twhalley/attestation-gate/app public, or add an" >&2
    echo "imagePullSecret to the ${NS} namespace. See README.md, 'One-time setup'." >&2
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
