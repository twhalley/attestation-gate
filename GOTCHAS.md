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

### BuildKit adds its own attestations by default

If you build with `docker/build-push-action`, BuildKit's provenance/SBOM
attestations turn the pushed artefact into an image index with an extra
attestation manifest. Cosign and policy-controller cope, but the manifest you
inspect stops looking like the manifest you expected and `cosign verify` output
becomes confusing. Set `provenance: false` and `sbom: false` when you want to
reason about exactly one attestation.

This repository sidesteps it by building with `podman build` and pushing with
`podman push --digestfile`, which produces a plain manifest and hands back the
digest directly. The security argument for Podman here is separate and simpler:
rootless and daemonless, so no build step holds a socket equivalent to host
root. For a pipeline whose only output is a trust claim, the build tool having
less authority is worth the swap on its own.

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
kubectl debug -it pod/gate-trusted --image=cgr.dev/chainguard/busybox --target=gate-trusted
```

`--target` is what puts you in the same process namespace as the running
container; without it you get a shell that can see the pod's network but not
its processes.

### The `-dev` tag is a build stage, not a debug convenience

`cgr.dev/chainguard/python:latest-dev` carries pip, a shell and a package
manager; `cgr.dev/chainguard/python:latest` carries none of them. The `-dev`
tag exists for the builder stage of a multi-stage build. Shipping it to
production silently undoes the reason you picked the base image — and it is an
easy accident, because `-dev` is also the tag that makes your debugging work.

### The `-dev` image is non-root, so it cannot write to `/`

The obvious first attempt fails immediately:

```
RUN python -m venv /venv
→ Error: [Errno 13] Permission denied: '/venv'
```

`cgr.dev/chainguard/python:latest-dev` has pip and a shell, but it still runs
as `nonroot`. Either add `USER root` to the build stage, or — better — build
the venv somewhere the build user already owns, like `/home/nonroot/venv`.
Reaching for `USER root` works and costs nothing at runtime, since the build
stage is discarded, but it is worth not developing the reflex.

### The venv path must be identical in both stages

This is the Python distroless trap, and it is genuinely nasty. A virtualenv
hardcodes its own absolute path into the shebang of every console script:

```
$ head -1 /venv/bin/gunicorn
#!/venv/bin/python
```

Install at `/venv` and `COPY --from=build /venv /opt/venv`, and that shebang
now points at an interpreter that does not exist. The failure is:

```
exec /opt/venv/bin/gunicorn: no such file or directory
```

…naming a file that is plainly there. The missing file is the *interpreter in
the shebang*, not the script. Same class of error as the old cgo-on-scratch
problem, and equally confusing the first time.

Keep the venv at one path across both stages, or use `--copies` and rewrite the
shebangs. This repository uses `/home/nonroot/venv` in both.

### Native wheels need the compiler in the builder, not the runtime

Anything without a pure-Python wheel (`cryptography`, `psycopg2`, `numpy`)
compiles at install time. That needs a toolchain and headers — which is what
the `-dev` image is for. If the build stage has them and the runtime stage does
not, you are doing it right. If you find yourself adding `gcc` to the *runtime*
image, the multi-stage split has broken down somewhere.

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

`zoneinfo.ZoneInfo("Europe/London")` raises `ZoneInfoNotFoundError` on a
minimal base. Either use UTC throughout — which you probably should — or add
`tzdata` to `requirements.txt`, which ships the database as a wheel.

### glibc vs musl decides which wheels you get

Chainguard images are glibc-based; Alpine is musl. PyPI publishes `manylinux`
wheels for glibc and `musllinux` wheels for musl, and plenty of packages ship
only the former. Move a build to Alpine and packages that installed instantly
start compiling from source — or fail outright for want of a toolchain. Staying
on glibc is the boring, correct choice for Python.

### `.pyc` files versus a read-only root filesystem

Python writes bytecode caches next to source on first import. With
`readOnlyRootFilesystem: true` that fails, and depending on the import it either
warns or crashes. Set `PYTHONDONTWRITEBYTECODE=1`, and pre-compile in the
builder stage if you care about the startup cost you just gave up.

Related: set `PYTHONUNBUFFERED=1`, or logs sit in a buffer and vanish when the
container is killed — which is precisely when you wanted them.

### Nothing writes to the filesystem

No `/tmp` scratch space you should rely on, and a read-only root filesystem is
the expected posture. Mount an `emptyDir` for anything that genuinely needs to
write — including, for some libraries, `~/.cache`.

### The entrypoint differs from the image you migrated off

Fat base images often have a shell entrypoint that expands environment
variables and globs. Distroless images `exec` the binary directly, so
`ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:$PORT", …]` passes the literal
string `$PORT`. Resolve configuration inside the process, not in the entrypoint.

Also worth knowing: `cgr.dev/chainguard/python` already sets `ENTRYPOINT
["python"]`. Override it with an absolute path — there is no shell to search
`PATH` on your behalf, so `ENTRYPOINT ["gunicorn", …]` fails even though
`PATH` contains the venv.

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

### Two admission controllers means your negative tests can pass for the wrong reason

The `gated` namespace enforces Pod Security Admission (`restricted`) *and* the
sigstore policy. PSA runs first. A test pod without a compliant
`securityContext` is rejected by PSA before the signature webhook is ever
consulted:

```
Error from server (Forbidden): pods "psa-bad" is forbidden:
violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false …
```

Every negative case still "passes" — the pod was rejected, which is what the
assertion checked. The signature gate could be entirely broken and the suite
would stay green.

Two fixes, both applied here: give every test pod a `restricted`-compliant
`securityContext` so posture is constant and provenance is the only variable,
and assert on *which* controller rejected it:

```bash
elif [ "$actual" = "reject" ] && ! grep -q 'policy.sigstore.dev' <<<"$message"; then
  bad "rejected, but not by policy.sigstore.dev -- this case proves nothing"
```

Generalised: a negative test is only evidence if you know *why* it failed.

### Rejections are on Pod creation, not Deployment creation

Creating a Deployment with a bad image succeeds; the Deployment is admitted and
the *Pod* it creates is rejected. The failure surfaces in the ReplicaSet's
events, not in the response to your `kubectl apply`. `test/run.sh` creates bare
Pods so the rejection lands in the command's own output where it can be asserted
on.
