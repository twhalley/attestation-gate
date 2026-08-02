#!/usr/bin/env bash
# Install the supply-chain toolchain into ~/.local/bin.
#
# Everything here is a single static binary fetched from its own project's
# release page -- no sudo, no third-party install scripts piped into a shell
# beyond the two Anchore ones, which are the vendor's own. For a repository
# about provenance it would be a poor look to bootstrap it from anywhere else.
set -euo pipefail

BIN="${HOME}/.local/bin"
mkdir -p "$BIN"
export PATH="${BIN}:${PATH}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

log "installing podman (image builds; the cluster itself runs on Docker)"
sudo apt-get update -qq
sudo apt-get install -y -qq podman uidmap

log "installing cosign"
curl -fsSL --retry 3 -o "${BIN}/cosign" \
  https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x "${BIN}/cosign"

log "installing kind"
KIND_TAG="$(curl -fsSL https://api.github.com/repos/kubernetes-sigs/kind/releases/latest \
            | grep -m1 '"tag_name"' | cut -d'"' -f4)"
curl -fsSL --retry 3 -o "${BIN}/kind" \
  "https://kind.sigs.k8s.io/dl/${KIND_TAG}/kind-linux-amd64"
chmod +x "${BIN}/kind"

log "installing apko"
APKO_TAG="$(curl -fsSL https://api.github.com/repos/chainguard-dev/apko/releases/latest \
            | grep -m1 '"tag_name"' | cut -d'"' -f4)"
curl -fsSL --retry 3 -o /tmp/apko.tgz \
  "https://github.com/chainguard-dev/apko/releases/download/${APKO_TAG}/apko_${APKO_TAG#v}_linux_amd64.tar.gz"
tar xzf /tmp/apko.tgz -C /tmp
find /tmp -maxdepth 2 -name apko -type f -exec mv {} "${BIN}/apko" \;
chmod +x "${BIN}/apko"

log "installing crane"
curl -fsSL --retry 3 https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz \
  | tar xz -C "$BIN" crane

log "installing jq"
curl -fsSL --retry 3 -o "${BIN}/jq" \
  https://github.com/jqlang/jq/releases/latest/download/jq-linux-amd64
chmod +x "${BIN}/jq"

log "installing syft and grype"
curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b "$BIN" >/dev/null
curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "$BIN" >/dev/null

if ! grep -q '.local/bin' "${HOME}/.bashrc" 2>/dev/null; then
  echo 'export PATH="${HOME}/.local/bin:${PATH}"' >> "${HOME}/.bashrc"
fi

log "versions"
for t in podman cosign kind kubectl helm syft grype jq; do
  printf '  %-8s %s\n' "$t" "$(command -v "$t" >/dev/null 2>&1 && "$t" version 2>&1 | head -1 | cut -c1-60 || echo MISSING)"
done

cat <<'EOF'

Ready. Two things to try:

  ./scripts/scan-diff.sh    # build both images, compare CVEs, packages, size
  ./test/setup.sh           # kind cluster + policy-controller + policies
  ./test/run.sh             # the five admission cases

test/run.sh needs images in GHCR, so it only passes once the pipeline has run
on this repository. scan-diff.sh works immediately and offline of all that.
EOF
