from __future__ import annotations

import argparse
import http.client
import json
import math
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return math.inf
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded HTTP load/soak probe for MRK")
    parser.add_argument("--url", default="http://127.0.0.1:8080/health/live")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--max-p95-ms", type=float, default=500.0)
    args = parser.parse_args()
    if not 1 <= args.duration <= 3600:
        parser.error("duration must be between 1 and 3600 seconds")
    if not 1 <= args.concurrency <= 256:
        parser.error("concurrency must be between 1 and 256")
    if not 0 <= args.max_error_rate <= 1:
        parser.error("max-error-rate must be between 0 and 1")
    parsed = urlsplit(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        parser.error("url must use http or https and include a hostname")
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"

    stop_at = time.monotonic() + args.duration
    lock = threading.Lock()
    latencies: list[float] = []
    errors: dict[str, int] = {}

    def worker() -> None:
        connection: http.client.HTTPConnection | None = None
        try:
            while time.monotonic() < stop_at:
                started = time.perf_counter()
                error: str | None = None
                try:
                    if connection is None:
                        connection_type = (
                            http.client.HTTPSConnection
                            if parsed.scheme == "https"
                            else http.client.HTTPConnection
                        )
                        connection = connection_type(
                            parsed.hostname,
                            parsed.port,
                            timeout=args.timeout,
                        )
                    connection.request(
                        "GET",
                        request_target,
                        headers={"User-Agent": "mrk-load-probe/1"},
                    )
                    response = connection.getresponse()
                    response.read()
                    if not 200 <= response.status < 300:
                        error = f"http_{response.status}"
                    if response.will_close:
                        connection.close()
                        connection = None
                except (OSError, TimeoutError, http.client.HTTPException) as exc:
                    error = type(exc).__name__
                    if connection is not None:
                        connection.close()
                        connection = None
                elapsed_ms = (time.perf_counter() - started) * 1000
                with lock:
                    latencies.append(elapsed_ms)
                    if error:
                        errors[error] = errors.get(error, 0) + 1
        finally:
            if connection is not None:
                connection.close()

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(worker) for _ in range(args.concurrency)]
        for future in futures:
            future.result()
    elapsed = time.monotonic() - started
    requests = len(latencies)
    failures = sum(errors.values())
    error_rate = failures / requests if requests else 1.0
    p95 = _percentile(latencies, 0.95)
    report = {
        "url": args.url,
        "duration_seconds": round(elapsed, 3),
        "concurrency": args.concurrency,
        "requests": requests,
        "requests_per_second": round(requests / elapsed, 2) if elapsed else 0,
        "errors": errors,
        "error_rate": round(error_rate, 6),
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
            "p50": round(_percentile(latencies, 0.50), 3),
            "p95": round(p95, 3),
            "p99": round(_percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3) if latencies else None,
        },
        "passed": requests > 0 and error_rate <= args.max_error_rate and p95 <= args.max_p95_ms,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
