from __future__ import annotations

import http.client
import json
from typing import Any


def check_http_component(host: str, port: int, path: str, timeout: float = 1.0) -> bool:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        response.read(4096)
        return 200 <= response.status < 300
    except OSError:
        return False
    finally:
        connection.close()


def fetch_json_component(
    host: str, port: int, path: str, timeout: float = 1.0
) -> dict[str, Any] | None:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(65537)
        if not 200 <= response.status < 300 or len(body) > 65536:
            return None
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        connection.close()
