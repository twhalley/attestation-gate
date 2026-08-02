# Baseline variant: deliberately bad, and honestly so.
#
# This is not a strawman -- it is what a large number of production Go services
# actually ship: build image used as runtime image, running as root, with a
# full Debian userland, a shell and a package manager still present.
#
# It exists to be measured against app/Dockerfile in the scan-diff workflow.

FROM golang:1.23

ARG VERSION=dev
ARG VARIANT=baseline

WORKDIR /src
COPY app/go.mod ./
COPY app/main.go ./

RUN CGO_ENABLED=0 go build \
      -ldflags="-X main.version=${VERSION} -X main.variant=${VARIANT}" \
      -o /usr/local/bin/gatedemo .

# No USER directive: this runs as root, like the image it is imitating.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gatedemo"]
