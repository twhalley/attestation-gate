#!/usr/bin/env bash
# Demonstrate a VEX statement suppressing a CVE that is present but not
# reachable -- the honest answer to "zero CVEs doesn't mean zero risk".
#
# Scans a registry image twice, once without VEX and once with, and reports the
# difference. Requires a *registry* reference: Grype identifies VEX products by
# the image's repository digest, which local-only images do not have.
#
#   ./scripts/vex-demo.sh [image-ref] [cve-id]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_REF="${1:-${VEX_IMAGE:-ghcr.io/twhalley/attestation-gate/baseline:latest}}"
CVE="${2:-${VEX_CVE:-}}"
OUT="${REPO_ROOT}/.scan"
TEMPLATE="${REPO_ROOT}/vex/not-in-execute-path.template.json"

for bin in grype jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

mkdir -p "$OUT"
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

log "scanning ${IMAGE_REF} (no VEX)"
grype "registry:${IMAGE_REF}" -o json --quiet > "${OUT}/vex-before.json"

DIGEST=$(jq -r '.source.target.repoDigests[0] // empty' "${OUT}/vex-before.json" | sed 's/.*@//')
if [ -z "$DIGEST" ]; then
  echo "no repository digest on ${IMAGE_REF}." >&2
  echo "VEX products are matched by digest, so this needs an image pulled from a" >&2
  echo "registry -- not a locally built tag. See GOTCHAS.md." >&2
  exit 1
fi

# purl name is the final path segment of the repository, per the OCI purl spec.
IMAGE_NAME=$(printf '%s' "$IMAGE_REF" | sed 's/[:@].*//' | awk -F/ '{print $NF}')

# Default to whichever Perl CVE the scan actually found, so the demo does not
# rot when the vulnerability database changes.
if [ -z "$CVE" ]; then
  CVE=$(jq -r 'first(.matches[] | select(.artifact.name | test("^perl")) | .vulnerability.id) // empty' \
        "${OUT}/vex-before.json")
fi
if [ -z "$CVE" ]; then
  echo "no perl CVE found in ${IMAGE_REF}; pass a CVE id explicitly." >&2
  exit 1
fi

log "asserting ${CVE} not_affected on ${IMAGE_NAME}@${DIGEST}"
sed -e "s|__CVE__|${CVE}|g" \
    -e "s|__DIGEST__|${DIGEST}|g" \
    -e "s|__IMAGE_NAME__|${IMAGE_NAME}|g" \
    -e "s|__TIMESTAMP__|$(date -u +%Y-%m-%dT%H:%M:%SZ)|g" \
    "$TEMPLATE" > "${OUT}/statement.openvex.json"

log "re-scanning with VEX applied"
grype "registry:${IMAGE_REF}" \
  -c "${REPO_ROOT}/.grype.yaml" \
  --vex "${OUT}/statement.openvex.json" \
  -o json --quiet > "${OUT}/vex-after.json"

count()   { jq --arg c "$CVE" '[.matches[] | select(.vulnerability.id == $c)] | length' "$1"; }
ignored() { jq --arg c "$CVE" '[(.ignoredMatches // [])[] | select(.vulnerability.id == $c)] | length' "$1"; }

BEFORE=$(count "${OUT}/vex-before.json")
AFTER=$(count "${OUT}/vex-after.json")
SUPPRESSED=$(ignored "${OUT}/vex-after.json")

report() {
  echo "## VEX: ${CVE}"
  echo
  echo "| | Reported | Suppressed as \`not_affected\` |"
  echo "|---|---:|---:|"
  echo "| Without VEX | ${BEFORE} | 0 |"
  echo "| With VEX | ${AFTER} | ${SUPPRESSED} |"
  echo
  echo "The CVE is still *present* in the image. The statement asserts it is not"
  echo "*reachable*, with a justification and an impact statement attached, and"
  echo "\`.grype.yaml\` records the decision to honour that justification."
  echo "Suppression is an auditable claim, not a silenced finding."
}

echo
report
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && report >> "$GITHUB_STEP_SUMMARY"

if [ "$BEFORE" -eq 0 ] || [ "$SUPPRESSED" -eq 0 ]; then
  echo "VEX demo did not suppress anything -- check the product identity." >&2
  exit 1
fi
