#!/usr/bin/env python3
"""One-command local reflected-XSS benchmark using the real DKCISSP Wapiti adapter.

Starts the intentionally vulnerable fixture on an ephemeral loopback port only.
This does not target any external system and keeps scanner state in a temporary DB.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def load_fixture_handler():
    path = ROOT / "scripts" / "local_vuln_benchmark_fixture.py"
    spec = importlib.util.spec_from_file_location("dkcissp_xss_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VulnerableFixtureHandler


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="dkcissp-xss-e2e-") as db_dir:
        os.environ["DKCISSP_DB"] = str(Path(db_dir) / "benchmark.sqlite3")
        server = ThreadingHTTPServer(("127.0.0.1", 0), load_fixture_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}/"
        try:
            payload = "<script>alert(1)</script>"
            with urlopen(base, timeout=2) as response:
                homepage = response.read().decode("utf-8", "replace")
            with urlopen(base + "search?q=" + quote("safe-query"), timeout=2) as response:
                control = response.read().decode("utf-8", "replace")
            with urlopen(base + "search?q=" + quote(payload), timeout=2) as response:
                positive = response.read().decode("utf-8", "replace")
            oracle_passed = (
                "DKCISSP local-only vulnerable fixture" in homepage
                and "safe-query" in control
                and payload in positive
            )

            sys.path.insert(0, str(ROOT))
            import app
            findings, status = app.perform_wapiti_check(base, timeout_seconds=90)
            xss_findings = [
                item for item in findings
                if ("xss" in str(item[1]).lower() or "cross site scripting" in str(item[1]).lower())
                and "/search" in str(item[2]).lower()
            ]
            passed = oracle_passed and status.get("status") == "completed" and bool(xss_findings)
            result = {
                "benchmark": "dkcissp_local_reflected_xss_e2e",
                "target": base,
                "oracle_passed": oracle_passed,
                "scanner_detection_passed": passed,
                "wapiti_status": status,
                "expected_signal": "reflected XSS on GET /search parameter q",
                "xss_finding_count": len(xss_findings),
                "findings": [
                    {
                        "severity": item[0],
                        "title": item[1],
                        "affected_url": item[2],
                        "evidence": item[3],
                        "confidence": item[5],
                    }
                    for item in findings
                ],
                "live_scanner_database_used": False,
                "scope": "ephemeral loopback fixture only",
            }
            print(json.dumps(result, indent=2))
            return 0 if passed else 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
