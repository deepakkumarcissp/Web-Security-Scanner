#!/usr/bin/env python3
"""One-command end-to-end SQLi benchmark: local vulnerable SQLite API + DKCISSP SQLMap adapter."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:18081"


def load_benchmark_oracle():
    path = ROOT / "scripts" / "benchmark_juice_shop_sqli.py"
    spec = importlib.util.spec_from_file_location("local_sqli_benchmark_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_benchmark


def wait_for_fixture(process: subprocess.Popen, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urlopen(BASE_URL + "/health", timeout=0.5) as response:
                if response.status == 200:
                    return True
        except (OSError, URLError, TimeoutError):
            time.sleep(0.2)
    return False


def main() -> int:
    # Isolate the scanner's SQLite state from any local or live scanner database.
    with tempfile.TemporaryDirectory(prefix="dkcissp-sqli-e2e-") as db_dir:
        os.environ["DKCISSP_DB"] = str(Path(db_dir) / "benchmark.sqlite3")
        fixture_path = ROOT / "scripts" / "local_sqli_api_benchmark_fixture.py"
        process = subprocess.Popen(
            [sys.executable, str(fixture_path), "--host", "127.0.0.1", "--port", "18081",
             "--database", str(Path(db_dir) / "vulnerable-app.sqlite3")],
            cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_for_fixture(process):
                print(json.dumps({
                    "passed": False,
                    "error": "Local fixture did not start. Check whether port 18081 is already in use.",
                    "target": BASE_URL,
                }, indent=2))
                return 2

            oracle = load_benchmark_oracle()(BASE_URL)
            if not oracle.get("expected_positive_pass"):
                print(json.dumps({"passed": False, "oracle": oracle, "error": "Expected-positive control failed."}, indent=2))
                return 1

            sys.path.insert(0, str(ROOT))
            import app
            findings, status = app.perform_sqlmap_check(BASE_URL, timeout_seconds=45)
            sql_findings = [item for item in findings if "SQL Injection" in str(item[1])]
            passed = bool(status.get("status") == "completed" and sql_findings)
            result = {
                "benchmark": "dkcissp_openapi_json_sql_injection_e2e",
                "target": BASE_URL + "/rest/user/login",
                "oracle_passed": True,
                "scanner_detection_passed": passed,
                "sqlmap_status": status,
                "finding_count": len(sql_findings),
                "findings": [
                    {"severity": item[0], "title": item[1], "affected_url": item[2],
                     "evidence": item[3], "confidence": item[5]}
                    for item in sql_findings
                ],
                "interpretation": "A positive result requires the expected-positive control and at least one explicit SQLMap injection-point finding.",
                "live_scanner_database_used": False,
            }
            print(json.dumps(result, indent=2))
            return 0 if passed else 1
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    sys.exit(main())
