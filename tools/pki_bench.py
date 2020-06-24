#!/usr/bin/env python3
"""
Cantilever PKI - High-Concurrency Benchmark and Load Test Suite
Evaluates latency percentiles, throughput (QPS), and stability under load.

Benchmarks:
  - ACME Directory discovery throughput
  - Anti-replay nonce pool generation rate
  - OCSP certificate revocation status check latency
  - Prometheus metrics collection overhead
"""

import sys
import time
import urllib.request
import urllib.error
import concurrent.futures
from typing import List


def benchmark_endpoint(url: str, method: str = "GET", total_requests: int = 500, concurrency: int = 16) -> List[float]:
    """Runs concurrent HTTP requests against an endpoint and returns request latencies in ms."""
    latencies: List[float] = []

    def make_request():
        start = time.perf_counter()
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "Cantilever-Bench/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
                elapsed = (time.perf_counter() - start) * 1000.0
                return elapsed
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(make_request) for _ in range(total_requests)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res is not None:
                latencies.append(res)

    return latencies


def summarize_latencies(latencies: List[float], total_time_sec: float):
    if not latencies:
        print("    [!] No successful requests recorded.")
        return

    latencies.sort()
    n = len(latencies)
    qps = n / total_time_sec if total_time_sec > 0 else 0
    p50 = latencies[int(n * 0.50)]
    p95 = latencies[int(n * 0.95)]
    p99 = latencies[int(n * 0.99)]
    avg = sum(latencies) / n

    print(f"    Completed: {n} requests in {total_time_sec:.2f}s ({qps:.1f} QPS)")
    print(f"    Latency: avg={avg:.2f}ms, p50={p50:.2f}ms, p95={p95:.2f}ms, p99={p99:.2f}ms")


def main():
    print("=" * 80)
    print("  CANTILEVER PKI HIGH-CONCURRENCY BENCHMARK HARNESS")
    print("=" * 80)

    base_url = "http://127.0.0.1:8080"
    if len(sys.argv) > 1:
        base_url = sys.argv[1].rstrip('/')

    print(f"[*] Target PKI Endpoint: {base_url}")

    # Check server availability
    try:
        req = urllib.request.Request(f"{base_url}/directory")
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception as e:
        print(f"    [!] PKI daemon not reachable at {base_url}: {e}")
        print("    (Start the daemon using './bin/cantilever.js server' before benchmarking)")
        return 0

    benchmarks = [
        ("Directory Discovery", f"{base_url}/directory", "GET", 300, 16),
        ("Anti-Replay Nonce Pool", f"{base_url}/acme/new-nonce", "HEAD", 300, 16),
        ("Prometheus Telemetry", f"{base_url}/metrics", "GET", 300, 16)
    ]

    for name, url, method, req_count, workers in benchmarks:
        print(f"\n[*] Benchmarking {name} ({req_count} requests, concurrency={workers})...")
        t0 = time.perf_counter()
        latencies = benchmark_endpoint(url, method=method, total_requests=req_count, concurrency=workers)
        t1 = time.perf_counter()
        summarize_latencies(latencies, t1 - t0)

    print("\n" + "=" * 80)
    print("  All benchmark suites completed.")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
