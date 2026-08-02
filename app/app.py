"""A deliberately boring HTTP service.

The service is not the point of this repository. It exists so there is a real
artefact -- with real third-party dependencies, and therefore a real SBOM and a
real vulnerability surface -- to build, sign, attest, and then admit or reject.
"""

import os
import platform
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify

app = Flask(__name__)

# Baked in at build time so the two image variants are distinguishable at
# runtime without needing a shell to look around inside the container.
VERSION = os.environ.get("APP_VERSION", "dev")
VARIANT = os.environ.get("APP_VARIANT", "unknown")


@app.get("/healthz")
def healthz():
    return "ok\n", 200


@app.get("/")
def index():
    return jsonify(
        version=VERSION,
        variant=VARIANT,
        # uid 0 here would mean the hardening did not take effect.
        uid=os.getuid(),
        python=platform.python_version(),
        # A read-only root filesystem is the expected posture; this reports
        # whether the process could actually write, rather than assuming.
        writable_root=os.access("/", os.W_OK),
        executable=sys.executable,
        time=datetime.now(timezone.utc).isoformat(),
    )


if __name__ == "__main__":
    # Development only. Production serving is gunicorn, via the image
    # entrypoint. Port is >1024 deliberately: the hardened image runs as a
    # non-root UID and cannot bind a privileged port. See GOTCHAS.md.
    app.run(host="0.0.0.0", port=8080)
