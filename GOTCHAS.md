# Gotchas

Things that broke while building this, and what the fix actually was. Most of
these cost more time than the code did.

---

## Signing and policy

### All my variants passed, including the ones that shouldn't have

Signatures attach to a **digest**, not a tag. The first version of
`build-sign-attest.yml` built the same Dockerfile four times with different
tags — which produced four *identical digests*, one image with four tags. Signing
one signed them all, and every negative test passed vacuously.

Fix: give each variant a distinct `variant=` label so the config layer differs
and the digest differs. If your negative tests pass on the first attempt, check
that they are actually testing different images.

### Two authorities in one policy is an OR, not an AND

`ClusterImagePolicy.spec.authorities` is satisfied if **any one** authority
passes. Putting "must be signed" and "must have provenance" as two authorities
in one policy means an image with only a signature is admitted.

Across separate `ClusterImagePolicy` objects the relationship is AND. That is
why `policy/` contains two files rather than one. This is the single easiest
way to build a gate that looks strict and enforces nothing.

### An authority with an `attestations` block stops checking plain signatures

Related to the above: once you add `attestations` to an authority, that
authority is about attestations. If you want both a bare signature and an
attestation enforced, that is two policies.

### `docker/build-push-action` adds its own attestations by default

BuildKit's provenance/SBOM attestations turn the pushed artefact into an image
index with an extra attestation manifest. Cosign and policy-controller cope, but
the manifest you inspect stops looking like the manifest you expected, and
`cosign verify` output becomes confusing. Set `provenance: false` and
`sbom: false` when you want to reason about exactly one attestation.

### `cosign sign` needs `id-token: write`

Keyless signing exchanges the Actions OIDC token for a Fulcio certificate.
Without `permissions: id-token: write` on the job, cosign falls back to an
interactive browser flow and hangs until the job times out. The error does not
mention permissions.

### The Fulcio subject is the workflow ref, not the repository

`https://github.com/OWNER/REPO/.github/workflows/FILE.yml@refs/heads/main`.
Renaming the workflow file, or building from a tag instead of a branch, changes
the identity and every policy pinning the old subject starts rejecting. Pin
deliberately; use `subjectRegExp` only when you have thought about what else it
matches.

### `no-match-policy` defaults matter more than the policies

An image that matches no policy glob is not covered by any policy, and the
default behaviour decides whether that means "allow". Setting it to `deny` is
what makes the gate a gate rather than a suggestion.

### `predicateType: slsaprovenance` is accepted, then ignored

Policy-controller wants the full RFC 3986 URI —
`https://slsa.dev/provenance/v0.2`. The `slsaprovenance` shorthand that
`cosign attest --type` accepts is deprecated here, and `kubectl apply` only
*warns*:

```
Warning: invalid value: slsaprovenance: spec.authorities[0].attestations.predicateType
Warning: deprecated value, please use RFC 3986 conformant values
```

The resource is created, the policy reports Ready, and the shorthand is easy to
scroll past in apply output. Read the warnings on apply; a policy that is Ready
is not necessarily a policy that is checking what you think.

### The namespace label is the actual on/off switch

`policy.sigstore.dev/include: "true"`. Everything in `policy/` is inert in a
namespace without it. Easy to lose an afternoon to a policy that is working
perfectly in a namespace nobody is enforcing.

---

## Distroless / minimal base images

### There is no shell, so `kubectl exec` is gone

`kubectl exec -it pod -- sh` fails with `exec: "sh": executable file not found`.
Use an ephemeral debug container that brings its own userland:

```
kubectl debug -it pod/gate-trusted --image=cgr.dev/chainguard/busybox --target=gatedemo
```

`--target` is what puts you in the same process namespace as the running
container; without it you get a shell that can see the pod's network but not
its processes.

### The `-dev` tag is a build stage, not a debug convenience

`cgr.dev/chainguard/go:latest` has a toolchain and a shell; `:latest-dev`
variants exist for images that otherwise have neither. They are for the builder
stage of a multi-stage build. Shipping a `-dev` tag to production silently
undoes the reason you picked the base image.

### `CGO_ENABLED=0` is not optional on `static`

`cgr.dev/chainguard/static` has no dynamic loader. A cgo-linked binary fails at
startup with `no such file or directory` — which is about the *interpreter*, not
the binary, and reads like the file is missing when it is right there. If you
need cgo, use `cgr.dev/chainguard/glibc-dynamic` instead.

### Non-root cannot bind ports below 1024

The hardened image runs as UID 65532, so `:80` fails with `permission denied`.
Listen on 8080 and let the Service map 80 → 8080. Adding
`NET_BIND_SERVICE` works but gives back a capability you removed on purpose.

### Missing CA certificates

Minimal images without `ca-certificates` fail every outbound TLS call with
`x509: certificate signed by unknown authority`. `cgr.dev/chainguard/static`
includes them; scratch does not. This is the most common reason a "working"
image fails only when it first calls an external API.

### No timezone database

`time.LoadLocation("Europe/London")` fails on a minimal base. Either use UTC
throughout — which you probably should — or, in Go, `import _ "time/tzdata"` to
embed the database in the binary.

### glibc vs musl

Chainguard images are glibc-based, Alpine is musl. A binary built in an Alpine
builder and copied into a glibc runtime (or the reverse) fails at startup in
ways that look like corruption. Build and run on the same libc, or link
statically and stop caring.

### Nothing writes to the filesystem

No `/tmp` scratch space you should rely on, and a read-only root filesystem is
the expected posture. Mount an `emptyDir` for anything that genuinely needs to
write.

### The entrypoint differs from the image you migrated off

Fat base images often have a shell entrypoint that expands environment
variables and globs. Distroless images `exec` the binary directly, so
`ENTRYPOINT ["/app", "--flag=$SOME_VAR"]` passes the literal string `$SOME_VAR`.
Resolve configuration inside the process, not in the entrypoint.

---

## VEX

Three things all have to be true before Grype suppresses anything, and none of
them produce an error when they are wrong — the CVE simply stays in the report,
which looks exactly like the VEX document being ignored for no reason.

### 1. `--vex` alone does nothing

VEX statuses are only honoured where an `ignore` rule opts into them:

```yaml
# .grype.yaml
ignore:
  - vex-status: not_affected
    vex-justification: vulnerable_code_not_in_execute_path
```

Without the rule, the document parses fine and changes nothing. This is
arguably correct design — accepting a supplier's "not affected" claim should be
a decision you record — but it is not obvious from the flag.

### 2. The justification has to match exactly

The ignore rule matches on the justification string. A statement using
`vulnerable_code_not_present` is not covered by a rule naming
`vulnerable_code_not_in_execute_path`. Silent no-op again.

### 3. The product must be identified by repository digest

Grype matches VEX products against the image's `repoDigests`, using the OCI
purl form:

```
pkg:oci/<image-name>@sha256:<digest>
```

A locally built image has **no repository digest** — `repoDigests` is `[]` — so
no VEX statement can ever match it. The document has to target an image that
was pulled from a registry. This is why `scripts/vex-demo.sh` insists on a
registry reference and resolves the digest at run time rather than hardcoding
one.

The consequence worth thinking about: a VEX statement is pinned to one image
digest, so it goes stale on every rebuild. Maintaining VEX by hand does not
scale, which is the whole reason `vexctl` and generated-per-release VEX exist.

### The cluster cannot pull private GHCR packages

`ErrImagePull` on the one variant that was supposed to be admitted. GHCR
packages are private by default even when the repository is public. Either make
the package public or create an `imagePullSecret` in the `gated` namespace.
The admission tests still pass without this — admission happens before the pull —
but the "and it actually runs" check does not.

### Rejections are on Pod creation, not Deployment creation

Creating a Deployment with a bad image succeeds; the Deployment is admitted and
the *Pod* it creates is rejected. The failure surfaces in the ReplicaSet's
events, not in the response to your `kubectl apply`. `test/run.sh` creates bare
Pods so the rejection lands in the command's own output where it can be asserted
on.
