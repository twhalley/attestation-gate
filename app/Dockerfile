# Hardened variant: Chainguard Python, multi-stage, virtualenv copied forward.
#
# Python is meaningfully harder to make minimal than a compiled language. There
# is no static binary to copy -- the interpreter, the standard library and every
# dependency have to come along. The pattern below is the one that works:
# install into a venv in a stage that HAS pip and a shell, then copy only the
# venv into a runtime stage that has neither.

# The -dev tag is a BUILD stage, not a debugging convenience. It carries pip,
# a shell and a package manager. Shipping it to production silently undoes the
# entire reason for choosing this base image.
FROM cgr.dev/chainguard/python:latest-dev AS build

ARG VERSION=dev
ARG VARIANT=hardened

# The venv path is identical in both stages, and that is load-bearing. A venv
# hardcodes its own absolute path into every console script's shebang, so
# installing at /venv and copying to /opt/venv produces a `gunicorn` whose
# first line points at an interpreter that is not there. The failure surfaces
# as "no such file or directory" naming a file that plainly exists.
ENV VENV=/home/nonroot/venv

WORKDIR /app

# Dependencies first, so the layer caches independently of application code.
COPY requirements.txt ./
RUN python -m venv "$VENV" \
 && "$VENV"/bin/pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py ./

# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest

ARG VERSION=dev
ARG VARIANT=hardened

WORKDIR /app

COPY --from=build /home/nonroot/venv /home/nonroot/venv
COPY --from=build /app/app.py ./

ENV APP_VERSION=${VERSION} \
    APP_VARIANT=${VARIANT} \
    # No .pyc written at runtime: the root filesystem is meant to be read-only,
    # and a writable __pycache__ is a writable directory inside the image.
    PYTHONDONTWRITEBYTECODE=1 \
    # Unbuffered, or logs vanish when the container is killed.
    PYTHONUNBUFFERED=1 \
    PATH="/home/nonroot/venv/bin:$PATH"

# chainguard/python already defaults to the nonroot user (65532). Stated
# explicitly so the posture is readable from the Dockerfile alone.
USER 65532:65532

EXPOSE 8080

# Absolute path to the venv interpreter. The base image's own ENTRYPOINT is
# `python`, and there is no shell here to resolve PATH for us.
ENTRYPOINT ["/home/nonroot/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
