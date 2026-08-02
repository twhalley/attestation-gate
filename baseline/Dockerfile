# Baseline variant: deliberately bad, and honestly so.
#
# This is not a strawman. It is the shape of a very large number of production
# Python services: the full python:3.12 Debian image, pip installing as root
# into the system interpreter, no venv, no multi-stage, and a shell, a package
# manager and a compiler toolchain all still present in the shipped artefact.
#
# It exists to be measured against app/Dockerfile in the scan-diff workflow.

FROM python:3.12

ARG VERSION=dev
ARG VARIANT=baseline

WORKDIR /app

COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/app.py ./

ENV APP_VERSION=${VERSION} \
    APP_VARIANT=${VARIANT}

# No USER directive: this runs as root, like the images it is imitating.
EXPOSE 8080
ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]
