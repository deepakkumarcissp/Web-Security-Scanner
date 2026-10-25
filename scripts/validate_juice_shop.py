#!/usr/bin/env python3
"""Run a bounded Standard-profile smoke test against a loopback OWASP Juice Shop lab.

The script never launches containers, changes firewall settings, or enables Active scans.
Start Juice Shop and the scanner yourself; both URLs must resolve to loopback addresses.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def require_loopback(url: str, label: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTP(S) URL")
    host = parsed.hostname.lower().rstrip(".")
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        raise ValueError(f"{label} must use localhost or a loopback IP; refusing non-local target: {host}")
    return url.rstrip("/")


def request_json(url: str, method: str = "GET", payload: dict | None = None, timeout: int = 10):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}


def assess_validation(scan_status: str, tool_status: dict) -> tuple[bool, list[str]]:
    """Only pass when the scan completes and the required Nuclei check completes cleanly.

    ZAP is intentionally optional; its absence or API mismatch is reported but does not
    invalidate this smoke test. A completed scan alone is not proof that required checks ran.
    """
    failures = []
    if scan_status != "completed":
        failures.append(f"Scanner did not complete successfully (status: {scan_status or 'unknown'})")
    nuclei = tool_status.get("Nuclei", {}) if isinstance(tool_status, dict) else {}
    nuclei_state = nuclei.get("status") if isinstance(nuclei, dict) else None
    if nuclei_state != "completed":
        failures.append(f"Required Nuclei check did not complete cleanly (status: {nuclei_state or 'missing'})")
    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", default="http://127.0.0.1:1005", help="Local DKCISSP scanner base URL")
    parser.add_argument("--target", default="http://127.0.0.1:1003", help="Local Juice Shop base URL")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum scan wait in seconds (default: 600)")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--output-dir", default="validation-reports")
    args = parser.parse_args()
    try:
        scanner = require_loopback(args.scanner, "Scanner URL")
        target = require_loopback(args.target, "Juice Shop URL")
        if args.timeout < 30 or args.timeout > 1800:
            raise ValueError("--timeout must be between 30 and 1800 seconds")
        health = request_json(scanner + "/api/health")
        if health.get("status") != "ok":
            raise RuntimeError(f"Scanner health check failed: {health}")
        with urlopen(target, timeout=10) as response:
            if response.status < 200 or response.status >= 400:
                raise RuntimeError(f"Juice Shop returned HTTP {response.status}")
        scan_started_at = time.monotonic()
        started = request_json(scanner + "/api/scans", "POST", {
            "target": target, "profile": "standard", "authorized": True,
        })
        scan_id = started.get("id")
        if not isinstance(scan_id, int):
            raise RuntimeError(f"Scanner did not return a scan ID: {started}")
        deadline = time.monotonic() + args.timeout
        detail = None
        while time.monotonic() < deadline:
            detail = request_json(f"{scanner}/api/scans/{scan_id}")
            state = detail.get("scan", {}).get("status")
            if state in {"completed", "failed", "cancelled"}:
                break
            time.sleep(max(0.5, args.poll_interval))
        else:
            raise TimeoutError(f"Scan {scan_id} did not finish within {args.timeout} seconds")
        duration_seconds = round(time.monotonic() - scan_started_at, 2)
        scan = detail.get("scan", {})
        findings = detail.get("findings", [])
        tool_status = scan.get("tool_status", {})
        if isinstance(tool_status, str):
            try:
                tool_status = json.loads(tool_status)
            except json.JSONDecodeError:
                tool_status = {"raw": tool_status}
        counts: dict[str, int] = {}
        for finding in findings:
            severity = str(finding.get("severity", "Unknown"))
            counts[severity] = counts.get(severity, 0) + 1
        validation_passed, validation_failures = assess_validation(scan.get("status", "unknown"), tool_status)
        report = {
            "validation": "dkcissp-juice-shop-standard-smoke-test",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "scanner_version": health.get("version"),
            "scanner_url": scanner,
            "lab_target": target,
            "profile": "standard",
            "scan_id": scan_id,
            "scan_status": scan.get("status"),
            "duration_seconds": duration_seconds,
            "validation_status": "PASS" if validation_passed else "FAIL",
            "validation_failures": validation_failures,
            "required_checks": {"Nuclei": tool_status.get("Nuclei", {}).get("status", "missing") if isinstance(tool_status.get("Nuclei", {}), dict) else "invalid_status"},
            "finding_count": len(findings),
            "severity_counts": counts,
            "tool_status": tool_status,
            "findings": findings,
            "validation_boundary": "PASS means the scan completed and the required Nuclei check completed cleanly. This is not proof of detection completeness: finding counts are not a detection-rate benchmark, expected-issue assertions and false-positive review remain separate work, and optional integrations such as ZAP may still report warnings.",
        }
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"juice-shop-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-scan-{scan_id}.json"
        out_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": "PASS" if validation_passed else "FAIL",
                          "scan_id": scan_id, "status": scan.get("status"),
                          "duration_seconds": duration_seconds,
                          "validation_failures": validation_failures,
                          "finding_count": len(findings), "severity_counts": counts,
                          "report": str(out_file), "tool_status": tool_status}, indent=2))
        return 0 if validation_passed else 1
    except (ValueError, RuntimeError, TimeoutError, HTTPError, URLError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"result": "FAIL", "error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
