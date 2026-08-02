#!/usr/bin/env bash
# Verify the signatures of the base images this repository builds ON, before
# building on them.
#
# The gate proves our image came from our workflow. Our workflow trusts
# cgr.dev/chainguard/* implicitly -- and an unverified base image is an
# unverified dependency with root in your build. This closes that, and it is
# the control most "we sign our images" pipelines are missing: they authenticate
# their output and never authenticate their input.
#
# Base images are read out of the Dockerfiles rather than listed here, so this
# cannot silently drift away from what is actually built.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Chainguard's public signing identity. Confirmed against the live signature
# rather than copied from documentation:
#   cosign verify cgr.dev/chainguard/python:latest \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#     --certificate-identity-regexp '.*'
CG_ISSUER="https://token.actions.githubusercontent.com"
CG_IDENTITY="https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"

command -v cosign >/dev/null 2>&1 || { echo "missing required tool: cosign" >&2; exit 1; }

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mVERIFIED\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31mFAILED\033[0m   %s\n' "$*"; }

# Every distinct cgr.dev image referenced by a FROM line in any Dockerfile.
mapfile -t IMAGES < <(
  grep -rhiE '^[[:space:]]*FROM[[:space:]]+cgr\.dev/' \
    "${REPO_ROOT}/app/Dockerfile" "${REPO_ROOT}/baseline/Dockerfile" 2>/dev/null \
  | awk '{print $2}' | sort -u
)

if [ "${#IMAGES[@]}" -eq 0 ]; then
  echo "no cgr.dev base images found in the Dockerfiles" >&2
  exit 1
fi

FAIL=0
DIGESTS=()

for image in "${IMAGES[@]}"; do
  log "verifying ${image}"
  if output=$(cosign verify \
        --certificate-oidc-issuer "$CG_ISSUER" \
        --certificate-identity "$CG_IDENTITY" \
        "$image" 2>&1); then
    ok "$image"
    # Record what the tag resolved to at verification time. The tag is mutable
    # and Chainguard rebuilds daily -- this is the only durable reference to
    # what was actually verified, and it belongs in the provenance.
    digest=$(printf '%s' "$output" \
             | grep -o '"sha256:[a-f0-9]\{64\}"' | head -1 | tr -d '"' || true)
    [ -n "$digest" ] && DIGESTS+=("${image}@${digest}")
  else
    bad "$image"
    printf '%s\n' "$output" | tail -5
    FAIL=$((FAIL + 1))
  fi
done

if [ "${#DIGESTS[@]}" -gt 0 ]; then
  printf '%s\n' "${DIGESTS[@]}" > "${REPO_ROOT}/.base-digests"
  echo
  log "resolved digests (written to .base-digests)"
  printf '  %s\n' "${DIGESTS[@]}"
fi

if [ "$FAIL" -ne 0 ]; then
  echo
  echo "Refusing to build on an unverified base image." >&2
  exit 1
fi

# Deliberately NOT pinning these digests into the Dockerfiles.
#
# Chainguard rebuilds these images daily to pick up fixes; pinning a digest
# freezes you at one day's CVE posture until something bumps it, which is the
# patching treadmill wearing a supply-chain hat. The defensible position is to
# track the tag, verify the signature on every build, and record the digest that
# was actually used in the provenance -- reproducibility after the fact rather
# than staleness by design. Pinning is the right call the moment you have
# automated digest bumps (Renovate et al) to go with it.
echo
log "all base images verified"
