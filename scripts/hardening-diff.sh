#!/usr/bin/env bash
# Measure binary hardening in both images instead of asserting it.
#
# This is the evidence-based answer to "should I rebuild Python from source
# with my own hardening flags?". Before doing that, check whether the
# distribution already does it -- because if it does, a hand-rolled rebuild
# buys nothing and costs you the daily rebuilds you were getting for free.
#
# Checks, per ELF object:
#   PIE       ET_DYN + PT_INTERP, so the loader can randomise the base address
#   RELRO     PT_GNU_RELRO, plus BIND_NOW for "full" (GOT mapped read-only)
#   Canary    __stack_chk_fail referenced, so stack smashes are detected
#   FORTIFY   *_chk variants linked, so libc gets compile-time bounds info
#   NX        PT_GNU_STACK without the execute bit
#
# Requires: podman (or docker), readelf.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/.scan"
WORK="${OUT}/hardening"

BASELINE_TAG="attestation-gate/baseline:local"
HARDENED_TAG="attestation-gate/hardened:local"

DOCKER="${DOCKER:-}"
if [ -z "$DOCKER" ]; then
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    DOCKER=podman
  else
    DOCKER=docker
  fi
fi

for bin in "$DOCKER" readelf; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

rm -rf "$WORK"; mkdir -p "$WORK"

# Only the objects that matter: the interpreter, its shared library, and the
# crypto stack. Extracting whole filesystems would work but the baseline is
# over a gigabyte and the answer would not change.
PATTERNS=(
  '*/python3*'
  '*libpython3*'
  '*libssl.so*'
  '*libcrypto.so*'
)

extract() { # tag name
  local tag="$1" name="$2" dir="${WORK}/$2" cid
  mkdir -p "$dir"
  cid=$("$DOCKER" create "$tag" 2>/dev/null)
  # `|| true`: tar exits non-zero when a pattern matches nothing, which is a
  # normal outcome here (the images have genuinely different contents).
  "$DOCKER" export "$cid" 2>/dev/null \
    | tar -x -C "$dir" --wildcards --no-anchored "${PATTERNS[@]}" 2>/dev/null || true
  "$DOCKER" rm -f "$cid" >/dev/null 2>&1 || true
}

is_elf() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

check() { # file -> "PIE RELRO CANARY FORTIFY NX"
  local f="$1" hdr prog dyn syms
  hdr=$(readelf -hW  "$f" 2>/dev/null || true)
  prog=$(readelf -lW "$f" 2>/dev/null || true)
  dyn=$(readelf -dW  "$f" 2>/dev/null || true)
  syms=$(readelf -sW "$f" 2>/dev/null || true)

  local pie=no relro=none canary=no fortify=no nx=no

  # A shared library is ET_DYN too, so PIE for an executable means ET_DYN with
  # an interpreter. Libraries are position-independent by construction.
  if grep -q 'Type:[[:space:]]*DYN' <<<"$hdr"; then
    if grep -q 'INTERP' <<<"$prog" || [[ "$f" == *".so"* ]]; then pie=yes; fi
  fi

  if grep -q 'GNU_RELRO' <<<"$prog"; then
    if grep -qE 'BIND_NOW|FLAGS.*NOW' <<<"$dyn"; then relro=full; else relro=partial; fi
  fi

  grep -q '__stack_chk_fail' <<<"$syms" && canary=yes
  grep -qE '__[a-z_]+_chk@' <<<"$syms" && fortify=yes

  # GNU_STACK flags column: RW is good, RWE means an executable stack.
  if grep -q 'GNU_STACK' <<<"$prog"; then
    grep -qE 'GNU_STACK.*RWE' <<<"$prog" || nx=yes
  else
    nx=yes # no GNU_STACK segment: kernel default is non-executable
  fi

  echo "$pie $relro $canary $fortify $nx"
}

declare -A TOTAL SCORE
analyse() { # name
  local name="$1" dir="${WORK}/$1" n=0
  local pie=0 relro_full=0 canary=0 fortify=0 nx=0
  : > "${WORK}/${name}.rows"

  while IFS= read -r -d '' f; do
    is_elf "$f" || continue
    read -r p r c fo x <<<"$(check "$f")"
    n=$((n+1))
    [ "$p"  = yes  ] && pie=$((pie+1))
    [ "$r"  = full ] && relro_full=$((relro_full+1))
    [ "$c"  = yes  ] && canary=$((canary+1))
    [ "$fo" = yes  ] && fortify=$((fortify+1))
    [ "$x"  = yes  ] && nx=$((nx+1))
    printf '%s|%s|%s|%s|%s|%s\n' "${f#"$dir"/}" "$p" "$r" "$c" "$fo" "$x" \
      >> "${WORK}/${name}.rows"
  done < <(find "$dir" -type f -print0 2>/dev/null)

  TOTAL[$name]=$n
  SCORE["${name}_pie"]=$pie
  SCORE["${name}_relro"]=$relro_full
  SCORE["${name}_canary"]=$canary
  SCORE["${name}_fortify"]=$fortify
  SCORE["${name}_nx"]=$nx
}

log "building images if needed"
"$DOCKER" image exists "$BASELINE_TAG" 2>/dev/null \
  || "$DOCKER" build -q -f "${REPO_ROOT}/baseline/Dockerfile" -t "$BASELINE_TAG" "$REPO_ROOT" >/dev/null
"$DOCKER" image exists "$HARDENED_TAG" 2>/dev/null \
  || "$DOCKER" build -q -f "${REPO_ROOT}/app/Dockerfile" -t "$HARDENED_TAG" "${REPO_ROOT}/app" >/dev/null

log "extracting ELF objects from baseline"
extract "$BASELINE_TAG" baseline
log "extracting ELF objects from hardened"
extract "$HARDENED_TAG" hardened

log "analysing"
analyse baseline
analyse hardened

pct() { # count total
  [ "$2" -eq 0 ] && { echo "n/a"; return; }
  echo "$(( $1 * 100 / $2 ))% ($1/$2)"
}

report() {
  echo "## Binary hardening"
  echo
  echo "ELF objects examined: the Python interpreter, libpython, and the OpenSSL"
  echo "libraries, extracted from each image. Measured with \`readelf\` by"
  echo "\`scripts/hardening-diff.sh\`."
  echo
  echo "| Mitigation | Baseline (\`python:3.12\`) | Hardened (\`cgr.dev/chainguard/python\`) |"
  echo "|---|---:|---:|"
  echo "| PIE | $(pct "${SCORE[baseline_pie]}" "${TOTAL[baseline]}") | $(pct "${SCORE[hardened_pie]}" "${TOTAL[hardened]}") |"
  echo "| Full RELRO | $(pct "${SCORE[baseline_relro]}" "${TOTAL[baseline]}") | $(pct "${SCORE[hardened_relro]}" "${TOTAL[hardened]}") |"
  echo "| Stack canary | $(pct "${SCORE[baseline_canary]}" "${TOTAL[baseline]}") | $(pct "${SCORE[hardened_canary]}" "${TOTAL[hardened]}") |"
  echo "| FORTIFY_SOURCE | $(pct "${SCORE[baseline_fortify]}" "${TOTAL[baseline]}") | $(pct "${SCORE[hardened_fortify]}" "${TOTAL[hardened]}") |"
  echo "| NX stack | $(pct "${SCORE[baseline_nx]}" "${TOTAL[baseline]}") | $(pct "${SCORE[hardened_nx]}" "${TOTAL[hardened]}") |"
  echo
  echo "Caveat on reading these: the two images do not contain the same set of"
  echo "objects, so this is \"what proportion of what is present is hardened\","
  echo "not a per-file diff. That is the right question for attack surface --"
  echo "an unhardened library that is not in the image cannot be attacked --"
  echo "but it is not a claim that any individual file changed."
  echo
  echo "Read this before deciding to rebuild an interpreter with your own"
  echo "\`CFLAGS\`. Where the distribution already enables a mitigation, a"
  echo "hand-rolled rebuild adds no security and makes you the party responsible"
  echo "for patching it -- which is the treadmill the minimal base image was"
  echo "supposed to get you off. Where it does not, you have found something"
  echo "worth reporting upstream."
}

echo
report
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && report >> "$GITHUB_STEP_SUMMARY"
report > "${OUT}/hardening.md"

echo
log "per-object detail in ${WORK}/*.rows"
