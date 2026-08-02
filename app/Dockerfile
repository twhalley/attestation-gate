# Hardened variant: Chainguard builder, Chainguard static runtime.
#
# The runtime layer has no shell, no package manager and no libc beyond what a
# static Go binary needs. That is what makes the CVE count in the scan-diff
# report fall to (or near) zero -- there is almost nothing left to have a CVE.

FROM cgr.dev/chainguard/go:latest AS build

ARG VERSION=dev
ARG VARIANT=hardened

WORKDIR /src
COPY go.mod ./
COPY main.go ./

# CGO_ENABLED=0 is required: cgr.dev/chainguard/static has no dynamic loader.
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.variant=${VARIANT}" \
      -o /out/gatedemo .

FROM cgr.dev/chainguard/static:latest

COPY --from=build /out/gatedemo /gatedemo

# chainguard/static already defaults to the nonroot user (65532). Stated
# explicitly so the security posture is readable from the Dockerfile alone.
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/gatedemo"]
