from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

READY_TIMEOUT_SECONDS = 7


def probe_host() -> str:
    """Pick a Host header that TrustedHostMiddleware accepts.

    Production usually trusts only the public domain, so a fixed "localhost"
    would be rejected with 400 and the container would always look unhealthy.
    """
    entries = [
        item.strip()
        for item in os.getenv("MRK_TRUSTED_HOSTS", "localhost").split(",")
        if item.strip()
    ]
    for entry in entries:
        if "*" not in entry:
            return entry
    for entry in entries:
        if entry.startswith("*.") and len(entry) > 2:
            return f"healthcheck.{entry[2:]}"
    return "localhost"


def _check_once(port: int) -> bool:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/health/ready",
        headers={"Host": probe_host(), "User-Agent": "mrk-container-healthcheck/1"},
    )
    try:
        # The URL is fixed to loopback and the only variable is a range-checked integer port.
        # Readiness may take up to ~6 s (three 1 s component probes + a 3 s database
        # check); stay just under the image's HEALTHCHECK --timeout=8s.
        with urllib.request.urlopen(request, timeout=READY_TIMEOUT_SECONDS) as response:  # noqa: S310
            body = json.load(response)
            return response.status == 200 and body.get("status") == "ready"
    except (OSError, ValueError, urllib.error.URLError):
        return False


def main() -> int:
    try:
        port = int(os.getenv("MRK_PORT", "8080"))
        attempts = int(os.getenv("MRK_HEALTHCHECK_ATTEMPTS", "1"))
    except ValueError:
        return 1
    if not 1 <= port <= 65535 or not 1 <= attempts <= 60:
        return 1
    for attempt in range(attempts):
        if _check_once(port):
            return 0
        if attempt + 1 < attempts:
            time.sleep(1)
    return 1


if __name__ == "__main__":
    sys.exit(main())
