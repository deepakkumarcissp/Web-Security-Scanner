#!/usr/bin/env python3
"""Repeatable, loopback-only expected-positive API injection benchmark for Juice Shop.

This is a benchmark oracle, not a production scanner. It sends one control request
and one known training-lab payload to the local Juice Shop login endpoint. It never
prints or persists authentication tokens.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def validate_base_url(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if parsed.scheme != "http" or not loopback or parsed.username or parsed.password:
        raise ValueError("Only plain HTTP loopback targets are allowed (for example http://127.0.0.1:1003).")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Provide only the loopback base URL, without a path, query, or fragment.")
    return value.rstrip("/")


def post_json(url: str, payload: dict, timeout: float = 5.0) -> tuple[int, str]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as exc:
        return exc.code, exc.read(65536).decode("utf-8", "replace")
    with response:
        return response.status, response.read(65536).decode("utf-8", "replace")


def run_benchmark(base_url: str) -> dict:
    base_url = validate_base_url(base_url)
    endpoint = base_url + "/rest/user/login"
    control_status, control_body = post_json(endpoint, {
        "email": "dkcissp-benchmark-invalid@example.invalid",
        "password": "dkcissp-benchmark-invalid-password",
    })
    test_status, test_body = post_json(endpoint, {
        "email": "' OR 1=1--",
        "password": "dkcissp-benchmark-invalid-password",
    })
    control_rejected = control_status == 401 and "Invalid email or password" in control_body
    test_authenticated = test_status == 200 and '"authentication"' in test_body and '"token"' in test_body
    return {
        "benchmark": "juice_shop_login_injection_expected_positive",
        "target": endpoint,
        "control": {"http_status": control_status, "rejected_as_invalid_credentials": control_rejected},
        "test": {"http_status": test_status, "authentication_response_observed": test_authenticated},
        "expected_positive_pass": bool(control_rejected and test_authenticated),
        "interpretation": (
            "Known training-lab injection behavior reproduced; this validates the benchmark oracle only, "
            "not detection by Wapiti, sqlmap, or the DKCISSP scanner."
        ),
        "secrets_suppressed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:1003",
                        help="Loopback Juice Shop base URL only (default: http://127.0.0.1:1003)")
    args = parser.parse_args()
    try:
        result = run_benchmark(args.target)
    except (ValueError, URLError, TimeoutError, OSError) as exc:
        print(json.dumps({"expected_positive_pass": False, "error": str(exc)[:300]}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["expected_positive_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
