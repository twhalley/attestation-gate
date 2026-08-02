#!/usr/bin/env bash
# Build the apko image and show what makes it different from a Dockerfile build.
#
# The interesting output is not the image, it is the SBOM: apko emits it as a
# build artefact because it knows exactly which packages it installed. Every
# other image in this repository gets an SBOM the other way round -- syft
# inspects a finished filesystem and infers what is probably in there. One of
# those is a record; the other is a guess that is usually right.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/.scan/apko"
TAG="${TAG:-attestation-gate/apko-python:local}"

command -v apko >/dev/null 2>&1 || { echo "missing required tool: apko" >&2; exit 1; }

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

rm -rf "$OUT"; mkdir -p "$OUT"

log "building ${TAG} from apko/python.apko.yaml"
apko build \
  --sbom-path "$OUT" \
  "${REPO_ROOT}/apko/python.apko.yaml" \
  "$TAG" \
  "${OUT}/image.tar"

SBOM="${OUT}/sbom-x86_64.spdx.json"
if [ ! -f "$SBOM" ]; then
  echo "expected an SBOM at ${SBOM}; apko's output layout may have changed" >&2
  exit 1
fi

PKGS=$(jq '.packages | length' "$SBOM")
SIZE=$(stat -c '%s' "${OUT}/image.tar" | numfmt --to=iec --suffix=B)

report() {
  echo "## apko: a declaratively composed image"
  echo
  echo "| | |"
  echo "|---|---|"
  echo "| Packages in SBOM | ${PKGS} |"
  echo "| Image tarball | ${SIZE} |"
  echo "| Dockerfile | none |"
  echo "| RUN steps executed | none |"
  echo "| SBOM provenance | emitted by the builder, not inferred by a scanner |"
  echo
  echo "No shell runs during this build. There is no arbitrary-code-execution"
  echo "stage to compromise, the package list *is* the SBOM, and the same inputs"
  echo "produce the same digest. This is a scaled-down version of how the"
  echo "\`cgr.dev/chainguard/*\` images used elsewhere here are built."
}

echo
report
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && report >> "$GITHUB_STEP_SUMMARY"

echo
log "load it with: podman load -i ${OUT}/image.tar"
