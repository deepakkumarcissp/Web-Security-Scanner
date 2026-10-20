from __future__ import annotations

import csv
import io
import json
import os
import re
import socket
import shutil
import subprocess
import sqlite3
import ssl
import threading
import time
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DKCISSP_DB", ROOT / "data.sqlite3"))
app = FastAPI(
    title="DKCISSP Web Security Scanner",
    version="0.1.0",
    description="Local-first web security checks, schedules, and CSV reports",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL, profile TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, finished_at TEXT, summary TEXT
            );
            CREATE TABLE IF NOT EXISTS findings(
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                target TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
                affected_url TEXT NOT NULL, evidence TEXT NOT NULL,
                remediation TEXT NOT NULL, confidence TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS schedules(
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                target TEXT NOT NULL, profile TEXT NOT NULL, frequency TEXT NOT NULL,
                next_run TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            """
        )


init_db()


class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")
    authorized: bool = False


class ScheduleRequest(ScanRequest):
    name: str = Field(default="Scheduled scan", min_length=1, max_length=100)
    frequency: str = Field(default="daily", pattern="^(daily|weekly)$")
    run_at: str | None = None


def validate_target(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raise HTTPException(400, "Target must start with http:// or https://")
    parsed = urlparse(raw)
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Invalid target URL")
    if any(ch in raw for ch in "\r\n\x00"):
        raise HTTPException(400, "Invalid URL characters")
    return raw.rstrip("/")


def add_finding(conn, scan_id, target, severity, title, url, evidence, remediation, confidence="High"):
    conn.execute(
        """INSERT INTO findings
        (scan_id,target,severity,title,affected_url,evidence,remediation,confidence,discovered_at)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (scan_id, target, severity, title, url, evidence, remediation, confidence, now()),
    )



def perform_zap_passive_check(target: str) -> list[tuple]:
    """Ask a locally running ZAP instance to fetch only the exact authorized URL, then read passive alerts."""
    api_root = "http://127.0.0.1:8080"
    api_key = os.environ.get("ZAP_API_KEY", "")
    def zap_get(path: str, params: dict) -> dict:
        query = dict(params)
        if api_key:
            query["apikey"] = api_key
        req = Request(
            api_root + path + "?" + urlencode(query),
            headers={"Accept": "application/json", "User-Agent": "DKCISSP-WebSecurityScanner/0.1"},
        )
        with urlopen(req, timeout=4) as response:
            return json.loads(response.read(1_000_000).decode("utf-8", "replace"))

    try:
        # No spider and no active scan: one exact-URL fetch only.
        zap_get("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "false"})
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                pending = zap_get("/JSON/pscan/view/recordsToScan/", {}).get("recordsToScan", "0")
                if int(pending) <= 0:
                    break
            except (ValueError, TypeError):
                break
            time.sleep(0.4)
        payload = zap_get("/JSON/core/view/alerts/", {"baseurl": target, "start": "0", "count": "100"})
        alerts = payload.get("alerts", [])
    except Exception:
        # ZAP is optional; the built-in passive checks must still complete.
        return []

    normalized = []
    for alert in alerts:
        risk = str(alert.get("risk", "Informational")).lower()
        severity = {"high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}.get(risk, "Info")
        title = str(alert.get("alert", "OWASP ZAP passive alert"))[:240]
        evidence_parts = [
            str(alert.get("description", "")).strip(),
            ("Evidence: " + str(alert.get("evidence", ""))).strip() if alert.get("evidence") else "",
            ("Parameter: " + str(alert.get("param", ""))).strip() if alert.get("param") else "",
        ]
        evidence = " ".join(part for part in evidence_parts if part)[:1800] or "Reported by OWASP ZAP passive scanner."
        remediation = str(alert.get("solution", "") or "Review the ZAP alert and validate its applicability.")[:1800]
        confidence = str(alert.get("confidence", "Medium"))
        normalized.append((severity, "OWASP ZAP: " + title, str(alert.get("url") or target), evidence, remediation, confidence))
    return normalized

def perform_testssl_check(target: str, timeout_seconds: int = 75) -> tuple[list[tuple], dict]:
    """Run a bounded testssl.sh fast assessment for an authorized HTTPS target."""
    if not target.lower().startswith("https://"):
        return [], {"status": "skipped", "reason": "TLS assessment requires an HTTPS target"}
    binary = shutil.which(TOOL_CATALOG["testssl"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "testssl.sh is not installed"}

    findings: list[tuple] = []
    with tempfile.TemporaryDirectory(prefix="dkcissp-testssl-") as temp_dir:
        json_path = str(Path(temp_dir) / "results.json")
        try:
            result = subprocess.run(
                [binary, "--quiet", "--fast", "--jsonfile-pretty", json_path, target],
                capture_output=True, text=True, timeout=timeout_seconds, check=False,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}

        if not os.path.isfile(json_path):
            # testssl can return a non-zero code for target/network errors; do not
            # misrepresent raw console text as validated security findings.
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "testssl.sh did not produce its JSON report"}
        try:
            with open(json_path, encoding="utf-8", errors="replace") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "testssl.sh produced an unreadable JSON report"}

    entries = report if isinstance(report, list) else report.get("scanResult", []) if isinstance(report, dict) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        severity_raw = str(entry.get("severity", "")).strip().lower()
        finding_text = str(entry.get("finding", "")).strip()
        test_id = str(entry.get("id", "TLS check")).strip()
        if not finding_text:
            continue
        if severity_raw in {"critical", "high"}:
            severity = "High"
        elif severity_raw in {"medium", "warning"}:
            severity = "Medium"
        elif severity_raw in {"low"}:
            severity = "Low"
        elif severity_raw in {"info", "informational", "ok", "best practice"}:
            continue
        else:
            # Avoid converting unknown/OK result categories into findings.
            continue
        title = ("testssl.sh: " + test_id)[:240]
        evidence = finding_text[:1800]
        remediation = str(entry.get("cve", "") or "Review the TLS result and configure supported protocols and cipher suites according to your security policy.")[:1800]
        findings.append((severity, title, target, evidence, remediation, "Medium"))

    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings)}


def perform_scan(scan_id: int, target: str, profile: str) -> None:
    findings = []
    try:
        req = Request(
            target,
            headers={
                "User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized testing)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
            method="GET",
        )
        context = ssl.create_default_context()
        try:
            with urlopen(req, timeout=12, context=context) as response:
                status_code = response.status
                headers = {k.lower(): v for k, v in response.headers.items()}
                final_url = response.geturl()
                body = response.read(500_000).decode("utf-8", "replace")
        except HTTPError as exc:
            status_code = exc.code
            headers = {k.lower(): v for k, v in exc.headers.items()}
            final_url = exc.geturl()
            body = exc.read(200_000).decode("utf-8", "replace")
        except (URLError, TimeoutError, ssl.SSLError, socket.timeout) as exc:
            with connect() as conn:
                conn.execute(
                    "UPDATE scans SET status=?,finished_at=?,summary=? WHERE id=?",
                    ("failed", now(), json.dumps({"error": str(exc)}), scan_id),
                )
            return

        def finding(severity, title, evidence, remediation, confidence="High"):
            findings.append((severity, title, final_url, evidence, remediation, confidence))

        if final_url.startswith("https://") and "strict-transport-security" not in headers:
            finding(
                "Medium", "Strict-Transport-Security header missing",
                "HTTPS response does not include Strict-Transport-Security.",
                "Configure HSTS after confirming all required subdomains support HTTPS.",
            )
        if "content-security-policy" not in headers:
            finding(
                "Medium", "Content-Security-Policy header missing",
                "Response does not include Content-Security-Policy.",
                "Define and test a restrictive CSP appropriate to the application.",
            )
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            finding(
                "Low", "X-Content-Type-Options missing or weak",
                f"Observed: {headers.get('x-content-type-options', 'not present')}",
                "Set X-Content-Type-Options: nosniff.",
            )
        if "referrer-policy" not in headers:
            finding(
                "Low", "Referrer-Policy header missing",
                "Response does not include Referrer-Policy.",
                "Set an appropriate policy, for example strict-origin-when-cross-origin.",
            )
        if "permissions-policy" not in headers:
            finding(
                "Info", "Permissions-Policy header missing",
                "Response does not include Permissions-Policy.",
                "Consider restricting browser features the application does not use.",
            )
        server_header = headers.get("server")
        if server_header and re.search(r"\d", server_header):
            finding(
                "Info", "Server header may disclose version", f"Server: {server_header}",
                "Reduce unnecessary version disclosure where practical.", "Medium",
            )
        if "x-powered-by" in headers:
            finding(
                "Low", "Technology disclosure header present",
                f"X-Powered-By: {headers['x-powered-by']}",
                "Remove unnecessary X-Powered-By disclosure.",
            )
        if target.startswith("http://"):
            finding(
                "High", "Target uses HTTP without transport encryption",
                "The supplied target URL uses HTTP. This check did not test whether HTTPS is available.",
                "Use HTTPS and redirect HTTP traffic to HTTPS; verify sensitive endpoints and cookies.",
            )
        cookies = headers.get("set-cookie", "")
        if cookies and final_url.startswith("https://") and "secure" not in cookies.lower():
            finding(
                "Medium", "Cookie may lack Secure attribute", cookies[:220],
                "Set Secure on cookies that should only be sent over HTTPS.", "Medium",
            )
        if cookies and "httponly" not in cookies.lower():
            finding(
                "Low", "Cookie may lack HttpOnly attribute", cookies[:220],
                "Set HttpOnly for session cookies that do not require JavaScript access.", "Medium",
            )
        if profile in ("standard", "deep"):
            if re.search(r"<form\b", body, re.I) and "content-security-policy" not in headers:
                finding(
                    "Info", "HTML form detected without CSP",
                    "A form was found in the sampled HTML; this is contextual, not proof of an exploitable issue.",
                    "Review form protections and define a suitable Content-Security-Policy.", "Low",
                )
            if re.search(r"<title>\s*Index of /", body, re.I):
                finding(
                    "Medium", "Directory listing appears enabled",
                    "Page title resembles a directory index. Validate manually before treating as confirmed.",
                    "Disable directory listing or restrict access.", "Medium",
                )

        # If ZAP is configured locally, merge its passive-only alerts into the same finding store.
        # This remains optional; absence of ZAP never blocks the built-in scan.
        # testssl.sh is an optional, bounded HTTPS check. It is invoked without a shell,
        # only for explicitly authorized scans, and its status is recorded in the scan summary.
        tls_status = {"status": "not_run", "reason": "TLS check not requested by profile"}
        if profile in ("standard", "deep"):
            if target.lower().startswith("https://"):
                tls_findings, tls_status = perform_testssl_check(target)
                findings.extend(tls_findings)
            else:
                tls_status = {"status": "skipped", "reason": "TLS assessment requires an HTTPS target"}

        findings.extend(perform_zap_passive_check(target))
        deduped = []
        seen = set()
        for item in findings:
            key = (item[0], item[1], item[2])
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        findings = deduped

        with connect() as conn:
            for item in findings:
                add_finding(conn, scan_id, target, *item)
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=? WHERE id=?",
                (
                    "completed", now(),
                    json.dumps({
                        "http_status": status_code, "final_url": final_url,
                        "checks": "passive HTTP/header checks plus optional testssl.sh and ZAP passive checks",
                        "tls_check": tls_status, "finding_count": len(findings),
                    }),
                    scan_id,
                ),
            )
    except Exception as exc:
        with connect() as conn:
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=? WHERE id=?",
                ("failed", now(), json.dumps({"error": str(exc)}), scan_id),
            )


def start_scan(target: str, profile: str) -> int:
    with connect() as conn:
        cursor = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
            (target, profile, "running", now()),
        )
        scan_id = cursor.lastrowid
    threading.Thread(target=perform_scan, args=(scan_id, target, profile), daemon=True).start()
    return scan_id


def scheduler_loop() -> None:
    while True:
        try:
            current = datetime.now(timezone.utc)
            with connect() as conn:
                schedules = conn.execute("SELECT * FROM schedules WHERE enabled=1").fetchall()
                for schedule in schedules:
                    try:
                        due = datetime.fromisoformat(schedule["next_run"])
                    except ValueError:
                        continue
                    if due <= current:
                        start_scan(schedule["target"], schedule["profile"])
                        delta = timedelta(days=1 if schedule["frequency"] == "daily" else 7)
                        conn.execute(
                            "UPDATE schedules SET next_run=? WHERE id=?",
                            ((current + delta).isoformat(timespec="seconds"), schedule["id"]),
                        )
        except Exception:
            pass
        time.sleep(20)


threading.Thread(target=scheduler_loop, daemon=True).start()


@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "product": "DKCISSP Web Security Scanner", "version": app.version}


@app.get("/api/dashboard")
def dashboard():
    with connect() as conn:
        scans = [dict(row) for row in conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 8")]
        counts = {row["severity"]: row["n"] for row in conn.execute(
            "SELECT severity,COUNT(*) n FROM findings GROUP BY severity"
        )}
        total = conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        targets = [dict(row) for row in conn.execute(
            "SELECT target,COUNT(*) findings,MAX(discovered_at) last_seen FROM findings GROUP BY target ORDER BY findings DESC LIMIT 5"
        )]
        high_findings = [dict(row) for row in conn.execute(
            "SELECT * FROM findings WHERE severity='High' ORDER BY id DESC LIMIT 5"
        )]
        total_scans = conn.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
        return {
            "scans": scans, "severity": counts, "total_findings": total,
            "targets": targets, "high_findings": high_findings, "total_scans": total_scans,
        }


@app.post("/api/scans")
def create_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this target.")
    target = validate_target(request.target)
    scan_id = start_scan(target, request.profile)
    return {
        "id": scan_id, "status": "running",
        "message": "Low-impact HTTP/header checks started; standard/deep HTTPS scans also run testssl.sh when installed, with a bounded timeout. Local ZAP passive alerts are optional.",
    }


@app.get("/api/scans")
def list_scans():
    with connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM scans ORDER BY id DESC")]


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    with connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(404, "Scan not found")
        findings = [
            dict(row) for row in conn.execute(
                """SELECT * FROM findings WHERE scan_id=?
                ORDER BY CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1
                WHEN 'Low' THEN 2 ELSE 3 END,id""",
                (scan_id,),
            )
        ]
        return {"scan": dict(scan), "findings": findings}


@app.get("/api/findings")
def list_findings(severity: str | None = None):
    with connect() as conn:
        if severity:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM findings WHERE severity=? ORDER BY id DESC", (severity,)
            )]
        return [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY id DESC")]


def safe_csv_cell(value):
    """Prevent spreadsheet apps from interpreting untrusted finding text as formulas."""
    if not isinstance(value, str):
        return value
    significant = value.lstrip(" \\t\\r\\n")
    if significant.startswith(("=", "+", "-", "@", "\\t", "\\r")):
        return "'" + value
    return value


@app.get("/api/export/findings.csv")
def export_findings():
    fields = [
        "id", "scan_id", "target", "severity", "title", "affected_url",
        "evidence", "remediation", "confidence", "discovered_at",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    with connect() as conn:
        for row in conn.execute("SELECT " + ",".join(fields) + " FROM findings ORDER BY id DESC"):
            writer.writerow({key: safe_csv_cell(value) for key, value in dict(row).items()})
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="dkcissp-findings.csv"'},
    )


@app.post("/api/schedules")
def create_schedule(request: ScheduleRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this target.")
    target = validate_target(request.target)
    delta = timedelta(days=1 if request.frequency == "daily" else 7)
    if request.run_at:
        try:
            due = datetime.fromisoformat(request.run_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(400, "run_at must be a valid ISO date/time") from exc
        if due.tzinfo is None:
            raise HTTPException(400, "run_at must include a timezone; send an ISO timestamp")
        due = due.astimezone(timezone.utc)
        if due <= datetime.now(timezone.utc):
            raise HTTPException(400, "Scheduled time must be in the future")
    else:
        due = datetime.now(timezone.utc) + delta
    with connect() as conn:
        cursor = conn.execute(
            """INSERT INTO schedules(name,target,profile,frequency,next_run,enabled,created_at)
            VALUES(?,?,?,?,?,1,?)""",
            (request.name, target, request.profile, request.frequency, due.isoformat(timespec="seconds"), now()),
        )
        return {
            "id": cursor.lastrowid, "name": request.name, "target": target,
            "profile": request.profile, "frequency": request.frequency,
            "next_run": due.isoformat(timespec="seconds"), "enabled": True,
        }


@app.get("/api/schedules")
def list_schedules():
    with connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM schedules ORDER BY id DESC")]


@app.patch("/api/schedules/{schedule_id}")
def toggle_schedule(schedule_id: int):
    with connect() as conn:
        row = conn.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Schedule not found")
        enabled = 0 if row["enabled"] else 1
        conn.execute("UPDATE schedules SET enabled=? WHERE id=?", (enabled, schedule_id))
        return {"id": schedule_id, "enabled": bool(enabled)}


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: int):
    with connect() as conn:
        cursor = conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
        if not cursor.rowcount:
            raise HTTPException(404, "Schedule not found")
    return {"deleted": True, "id": schedule_id}


# Scanner-tool management is deliberately allow-listed. No user-supplied shell commands.
TOOL_CATALOG = {
    "curl": {"label": "curl", "binary": "curl", "package": "curl", "version_args": ["--version"], "purpose": "HTTP connectivity and endpoint diagnostics"},
    "zaproxy": {"label": "OWASP ZAP", "binary": "zaproxy", "package": "zaproxy", "version_args": ["-version"], "purpose": "Web crawler and passive security scanner"},
    "whatweb": {"label": "WhatWeb", "binary": "whatweb", "package": "whatweb", "version_args": ["--version"], "purpose": "Technology fingerprinting"},
    "testssl": {"label": "testssl.sh", "binary": "testssl.sh", "package": "testssl.sh", "version_args": ["--version"], "purpose": "TLS and HTTPS configuration assessment"},
}


def _tool_version(tool: dict) -> str | None:
    try:
        result = subprocess.run(
            [tool["binary"], *tool["version_args"]],
            capture_output=True, text=True, timeout=4, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        output = (result.stdout or result.stderr).strip().splitlines()
        return output[0][:180] if output else ("Available (version output unavailable)" if result.returncode == 0 else None)
    except (OSError, subprocess.TimeoutExpired):
        return None


def scanner_tools_status() -> list[dict]:
    tools = []
    for key, spec in TOOL_CATALOG.items():
        path = shutil.which(spec["binary"])
        version = _tool_version(spec) if path else None
        tools.append({
            "id": key, "name": spec["label"], "purpose": spec["purpose"],
            "installed": bool(path), "status": "ready" if path and version else ("installed_check_failed" if path else "missing"),
            "path": path, "version": version,
            "install_method": "Kali/Debian package manager",
            "package": spec["package"],
        })
    # ZAP service/API availability is checked independently of the executable.
    zap_api = None
    try:
        with urlopen("http://127.0.0.1:8080/JSON/core/view/version/", timeout=1.5) as response:
            zap_api = json.loads(response.read(4096).decode("utf-8", "replace"))
    except Exception:
        pass
    for item in tools:
        if item["id"] == "zaproxy":
            item["service_status"] = "running" if zap_api and zap_api.get("version") else "not_running"
            item["service_version"] = zap_api.get("version") if zap_api else None
    return tools


class ToolInstallRequest(BaseModel):
    approved: bool = False


@app.get("/api/tools")
def list_tools():
    return {
        "tools": scanner_tools_status(),
        "install_supported": bool(shutil.which("pkexec")),
        "note": "Status is verified from executable/version checks. Installs are limited to the fixed package allow-list and require explicit approval.",
    }


@app.post("/api/tools/install/{tool_id}")
def install_tool(tool_id: str, request: ToolInstallRequest, client: FastAPIRequest):
    if tool_id not in TOOL_CATALOG:
        raise HTTPException(404, "Tool is not in the approved installer allow-list.")
    if not request.approved:
        raise HTTPException(400, "Explicit installation approval is required.")
    # Never allow remote callers to trigger privileged package operations.
    if client.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(403, "Tool installation is available only from the local machine.")
    spec = TOOL_CATALOG[tool_id]
    if shutil.which(spec["binary"]):
        return {"ok": True, "message": f"{spec['label']} is already installed.", "tools": scanner_tools_status()}
    pkexec = shutil.which("pkexec")
    apt = shutil.which("apt-get")
    if not pkexec or not apt:
        return {
            "ok": False,
            "message": f"Automatic installation is unavailable. On Kali, run: sudo apt update && sudo apt install {spec['package']}",
            "manual_command": f"sudo apt update && sudo apt install {spec['package']}",
        }
    try:
        result = subprocess.run(
            [pkexec, apt, "install", "-y", "--no-install-recommends", spec["package"]],
            capture_output=True, text=True, timeout=240, check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Package installation timed out. Check the package manager before retrying.")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "Package installation failed").strip()[-1200:]
        return {"ok": False, "message": detail, "tools": scanner_tools_status()}
    statuses = scanner_tools_status()
    installed = next((t for t in statuses if t["id"] == tool_id), None)
    return {
        "ok": bool(installed and installed["installed"]),
        "message": "Installation command completed; executable status was checked again.",
        "tools": statuses,
    }
