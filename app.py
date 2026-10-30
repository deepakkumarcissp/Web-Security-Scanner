from __future__ import annotations

import csv
import io
import html
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
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlencode, urljoin, urldefrag
from html.parser import HTMLParser
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler

import access
import auth
import browser
import planner
import platforms
import signals
from fastapi import FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field, SecretStr

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
                created_at TEXT NOT NULL, finished_at TEXT, summary TEXT,
                progress INTEGER NOT NULL DEFAULT 0,
                current_stage TEXT NOT NULL DEFAULT 'Queued',
                tool_status TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS findings(
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
                target TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
                affected_url TEXT NOT NULL, evidence TEXT NOT NULL,
                remediation TEXT NOT NULL, confidence TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                lifecycle_status TEXT NOT NULL DEFAULT 'open'
                    CHECK(lifecycle_status IN ('open','accepted','remediated','false_positive','retest_required')),
                lifecycle_notes TEXT NOT NULL DEFAULT '',
                lifecycle_updated_at TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS schedules(
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                target TEXT NOT NULL, profile TEXT NOT NULL, frequency TEXT NOT NULL,
                next_run TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tool_requests(
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, tool_id TEXT NOT NULL,
                trigger_type TEXT NOT NULL DEFAULT 'profile', trigger_detail TEXT NOT NULL DEFAULT '',
                finding_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','declined','approved','installing','running','completed','failed')),
                created_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT NOT NULL DEFAULT '',
                result_message TEXT NOT NULL DEFAULT '',
                UNIQUE(scan_id, tool_id), FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE TABLE IF NOT EXISTS assets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                asset_type TEXT NOT NULL,
                scope_status TEXT NOT NULL DEFAULT 'needs_review'
                    CHECK(scope_status IN ('in_scope','out_of_scope','needs_review')),
                discovery_source TEXT NOT NULL DEFAULT 'manual',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                approval_reference TEXT NOT NULL DEFAULT '',
                reviewed_at TEXT,
                review_decision TEXT NOT NULL DEFAULT 'pending'
                    CHECK(review_decision IN ('pending','approved','rejected','not_required'))
            );
            """
        )
        scan_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        if "progress" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN progress INTEGER NOT NULL DEFAULT 0")
        if "current_stage" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN current_stage TEXT NOT NULL DEFAULT 'Queued'")
        if "tool_status" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN tool_status TEXT NOT NULL DEFAULT '{}'")
        finding_columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        if "lifecycle_status" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'open'")
        if "lifecycle_notes" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_notes TEXT NOT NULL DEFAULT ''")
        if "lifecycle_updated_at" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_updated_at TEXT")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(assets)")}
        if "approval_reference" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN approval_reference TEXT NOT NULL DEFAULT ''")
        if "reviewed_at" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN reviewed_at TEXT")
        if "review_decision" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN review_decision TEXT NOT NULL DEFAULT 'pending'")


init_db()


class AuthConfig(BaseModel):
    """Login details for an authenticated scan. Secrets are SecretStr, so they print as ********** and are never stored."""
    kind: str = Field(pattern="^(form|json|bearer|cookie|header|basic)$")
    login_url: str = Field(default="", max_length=2048)
    username: str = Field(default="", max_length=200)
    password: SecretStr = Field(default=SecretStr(""), max_length=500)
    username_field: str = Field(default="", pattern=r"^[A-Za-z0-9_.\-\[\]]{0,80}$")
    password_field: str = Field(default="", pattern=r"^[A-Za-z0-9_.\-\[\]]{0,80}$")
    token: SecretStr = Field(default=SecretStr(""), max_length=8000)
    cookie: SecretStr = Field(default=SecretStr(""), max_length=8000)
    header_name: str = Field(default="", pattern=r"^[A-Za-z0-9\-]{0,80}$")
    header_value: SecretStr = Field(default=SecretStr(""), max_length=8000)
    verify_url: str = Field(default="", max_length=2048)
    success_text: str = Field(default="", max_length=200)
    logged_out_text: str = Field(default="", max_length=200)
    identity_text: str = Field(default="", max_length=200)


class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep|active)$")
    authorized: bool = False
    active_testing_approved: bool = False
    auth: AuthConfig | None = None
    authenticated_testing_approved: bool = False
    auth_second: AuthConfig | None = None
    second_account_role: str = Field(default="peer", pattern="^(peer|more_privileged)$")


class ScheduleRequest(ScanRequest):
    name: str = Field(default="Scheduled scan", min_length=1, max_length=100)
    frequency: str = Field(default="daily", pattern="^(daily|weekly)$")
    run_at: str | None = None


class AssetRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    authorized: bool = False
    scope_status: str = Field(default="needs_review", pattern="^(in_scope|out_of_scope|needs_review)$")
    notes: str = Field(default="", max_length=1000)


class AssetScopeUpdate(BaseModel):
    authorized: bool = False
    scope_status: str = Field(pattern="^(in_scope|out_of_scope|needs_review)$")
    notes: str | None = Field(default=None, max_length=1000)
    approval_reference: str | None = Field(default=None, max_length=200)


class AssetDiscoveryRequest(BaseModel):
    authorized: bool = False
    max_results: int = Field(default=50, ge=1, le=100)


class FindingLifecycleUpdate(BaseModel):
    status: str = Field(pattern="^(open|accepted|remediated|false_positive|retest_required)$")
    notes: str = Field(default="", max_length=2000)


def validate_target(raw: str) -> str:
    raw = raw.strip()
    if any(ch in raw for ch in "\r\n\x00"):
        raise HTTPException(400, "Invalid URL characters")
    if not raw.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "Target must start with http:// or https://")
    try:
        parsed = urlparse(raw)
        # Accessing .port validates its syntax and numeric range; urlparse alone
        # accepts malformed ports such as ':not-a-port' without raising.
        port = parsed.port
    except ValueError:
        raise HTTPException(400, "Invalid target URL or port")
    if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or (port is not None and not 1 <= port <= 65535)):
        raise HTTPException(400, "Invalid target URL")
    return raw.rstrip("/")


def is_same_origin_url(candidate: str, origin_url: str) -> bool:
    """Return whether a URL belongs to the exact HTTP(S) scheme/host/port origin."""
    try:
        candidate_parts = urlparse(candidate)
        origin_parts = urlparse(origin_url)
        candidate_port = candidate_parts.port or (443 if candidate_parts.scheme.lower() == "https" else 80)
        origin_port = origin_parts.port or (443 if origin_parts.scheme.lower() == "https" else 80)
    except ValueError:
        return False
    return bool(
        candidate_parts.scheme.lower() in {"http", "https"}
        and origin_parts.scheme.lower() in {"http", "https"}
        and candidate_parts.username is None and candidate_parts.password is None
        and origin_parts.username is None and origin_parts.password is None
        and candidate_parts.hostname and origin_parts.hostname
        and candidate_parts.scheme.lower() == origin_parts.scheme.lower()
        and candidate_parts.hostname.lower().rstrip(".") == origin_parts.hostname.lower().rstrip(".")
        and candidate_port == origin_port
    )


class _PageLinkParser(HTMLParser):
    """Extract navigational/resource URLs without executing page scripts."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for key in ("href", "src", "action"):
            value = values.get(key)
            if value:
                self.links.append(value.strip())


def extract_same_origin_links(base_url: str, html: str) -> list[str]:
    """Return normalized HTTP(S) links on the exact same origin as base_url."""
    base = urlparse(base_url)
    if base.scheme not in {"http", "https"} or not base.hostname:
        return []
    base_port = base.port or (443 if base.scheme == "https" else 80)
    parser = _PageLinkParser()
    try:
        parser.feed(html[:500_000])
    except Exception:
        return []
    found = []
    seen = set()
    for raw in parser.links:
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        absolute, _fragment = urldefrag(urljoin(base_url, raw))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != base.scheme or parsed.hostname.lower().rstrip(".") != base.hostname.lower().rstrip(".") or port != base_port:
            continue
        # Drop fragments and normalize empty paths; retain query strings because they
        # can identify distinct application routes/parameters.
        normalized = parsed._replace(fragment="").geturl()
        if normalized not in seen:
            seen.add(normalized)
            found.append(normalized)
    return found


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    """Reject redirects that would expand a passive scan beyond its starting origin."""
    def __init__(self, origin_url: str):
        super().__init__()
        parsed = urlparse(origin_url)
        self.scheme = parsed.scheme.lower()
        self.hostname = (parsed.hostname or "").lower().rstrip(".")
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            parsed = urlparse(newurl)
            explicit_port = parsed.port
        except ValueError:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        port = explicit_port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme.lower() != self.scheme or
                (parsed.hostname or "").lower().rstrip(".") != self.hostname or port != self.port):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def same_origin_opener(origin_url: str, jar=None):
    handlers = [_SameOriginRedirectHandler(origin_url), HTTPSHandler(context=ssl.create_default_context())]
    if jar is not None:
        handlers.append(HTTPCookieProcessor(jar))
    return build_opener(*handlers)


def discover_same_origin_pages(root_url: str, root_html: str, max_pages: int = 12, max_depth: int = 2, opener=None, url_filter=None) -> dict:
    """Bounded, low-rate, same-origin page discovery; never submits forms or executes JS."""
    root = root_url.rstrip("/") or root_url
    root_origin = urlparse(root)
    discovered = [root]
    depths = {root: 0}
    queue = [(url, 0) for url in extract_same_origin_links(root, root_html)]
    forms = list(signals.parse_forms(root_html, root_url))
    scripts = list(signals.script_urls(root_html, root_url))
    seen = {root}
    opener = opener or same_origin_opener(root)
    while queue and len(discovered) < max_pages:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
            continue
        if url_filter and url_filter(url):   # for example links that would log out or delete something
            continue
        seen.add(url)
        parsed = urlparse(url)
        root_port = root_origin.port or (443 if root_origin.scheme == "https" else 80)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme != root_origin.scheme or parsed.hostname != root_origin.hostname or port != root_port):
            continue
        request = Request(url, headers={"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized passive discovery)",
                                        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"})
        try:
            with opener.open(request, timeout=4) as response:
                final_url = response.geturl()
                final = urlparse(final_url)
                final_port = final.port or (443 if final.scheme == "https" else 80)
                if (final.scheme != root_origin.scheme or final.hostname != root_origin.hostname or final_port != root_port):
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                    discovered.append(url)
                    depths[url] = depth
                    time.sleep(0.2)
                    continue
                body = response.read(250_000).decode("utf-8", "replace")
        except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError, ValueError):
            continue
        discovered.append(url)
        depths[url] = depth
        forms.extend(signals.parse_forms(body, url))
        scripts.extend(script for script in signals.script_urls(body, url) if script not in scripts)
        if depth < max_depth:
            queue.extend((link, depth + 1) for link in extract_same_origin_links(url, body) if link not in seen)
        time.sleep(0.2)
    return {"urls": discovered[:max_pages], "pages_visited": max(0, len(discovered) - 1),
            "forms": forms[:60], "scripts": scripts[:30],
            "max_pages": max_pages, "max_depth": max_depth,
            "mode": "same-origin passive links only; forms not submitted; JavaScript not executed"}


def add_finding(conn, scan_id, target, severity, title, url, evidence, remediation, confidence="High"):
    conn.execute(
        """INSERT INTO findings
        (scan_id,target,severity,title,affected_url,evidence,remediation,confidence,discovered_at)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (scan_id, target, severity, title, url, evidence, remediation, confidence, now()),
    )



def zap_api_settings() -> tuple[str, str]:
    """Read local ZAP endpoint and API key without exposing secrets to callers."""
    api_root = os.environ.get("DKCISSP_ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
    parsed = urlparse(api_root)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("DKCISSP_ZAP_API_URL must be an HTTP(S) base URL without credentials, query, or fragment")
    api_key = os.environ.get("DKCISSP_ZAP_API_KEY", os.environ.get("ZAP_API_KEY", ""))
    return api_root, api_key


def diagnose_zap_api() -> dict:
    """Probe only the configured ZAP API version endpoint and return actionable, secret-free status."""
    try:
        api_root, api_key = zap_api_settings()
    except ValueError as exc:
        return {"status": "configuration_error", "message": str(exc), "endpoint": "invalid configuration"}
    endpoint = api_root + "/JSON/core/view/version/"
    if api_key:
        endpoint += "?" + urlencode({"apikey": api_key})
    try:
        req = Request(endpoint, headers={"Accept": "application/json", "User-Agent": "DKCISSP-WebSecurityScanner/0.1"})
        with urlopen(req, timeout=2) as response:
            payload = json.loads(response.read(4096).decode("utf-8", "replace"))
        if isinstance(payload, dict) and payload.get("version"):
            return {"status": "ready", "message": "OWASP ZAP API responded successfully.", "endpoint": api_root,
                    "version": str(payload["version"])[:80]}
        return {"status": "api_mismatch", "message": "The endpoint responded, but it did not return the expected ZAP version field; another service may be using this port.", "endpoint": api_root}
    except HTTPError as exc:
        if exc.code in {401, 403}:
            status, message = "auth_failed", "The endpoint denied the API request. Check the ZAP API key and access settings."
        elif exc.code == 404:
            status, message = "api_mismatch", "The endpoint returned 404 for the ZAP API path. Another service may be using this port."
        else:
            status, message = "api_unreachable", f"The endpoint returned HTTP {exc.code}. Check the ZAP API endpoint and configuration."
        return {"status": status, "message": message, "endpoint": api_root}
    except (URLError, TimeoutError, OSError):
        return {"status": "api_unreachable", "message": "No usable ZAP API response. Confirm ZAP is running and the configured endpoint/port is correct; do not stop other services to free the port.", "endpoint": api_root}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"status": "api_mismatch", "message": "The endpoint did not return valid JSON from the ZAP version API. Another service may be using this port.", "endpoint": api_root}


def zap_passive_queue_settings() -> tuple[float, float]:
    """Return (timeout, poll interval) seconds for the ZAP passive queue, bounded to safe ranges."""
    def bounded(name: str, default: float, low: float, high: float) -> float:
        try:
            value = float(os.environ.get(name, default))
        except ValueError:
            return default
        return min(max(value, low), high) if value == value else default
    return (bounded("DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS", 30.0, 1.0, 180.0),
            bounded("DKCISSP_ZAP_PASSIVE_POLL_SECONDS", 0.5, 0.1, 2.0))


def perform_zap_passive_check(target: str, targets: list[str] | None = None) -> tuple[list[tuple], dict]:
    """Fetch only same-origin URLs in local ZAP and return passive alerts plus truthful status."""
    diagnostic = diagnose_zap_api()
    if diagnostic.get("status") != "ready":
        return [], {"status": diagnostic.get("status", "api_unavailable"),
                    "reason": diagnostic.get("message", "OWASP ZAP API is not ready"),
                    "endpoint": diagnostic.get("endpoint")}
    try:
        api_root, api_key = zap_api_settings()
    except ValueError as exc:
        return [], {"status": "configuration_error", "reason": str(exc)[:300]}

    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)
    safe_targets = []
    for candidate in (targets or [target])[:12]:
        parsed = urlparse(candidate)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme == root.scheme and parsed.hostname and root.hostname and
                parsed.hostname.lower().rstrip(".") == root.hostname.lower().rstrip(".") and
                port == root_port and parsed.scheme in {"http", "https"} and candidate not in safe_targets):
            safe_targets.append(candidate)
    if target not in safe_targets:
        safe_targets.insert(0, target)
    safe_targets = safe_targets[:12]

    def zap_get(path: str, params: dict) -> dict:
        query = dict(params)
        if api_key:
            query["apikey"] = api_key
        req = Request(api_root + path + "?" + urlencode(query),
                      headers={"Accept": "application/json", "User-Agent": "DKCISSP-WebSecurityScanner/0.1"})
        with urlopen(req, timeout=4) as response:
            return json.loads(response.read(1_000_000).decode("utf-8", "replace"))

    scanned = []
    failures = []
    for page_url in safe_targets:
        try:
            zap_get("/JSON/core/action/accessUrl/", {"url": page_url, "followRedirects": "false"})
            scanned.append(page_url)
        except Exception as exc:
            failures.append(f"{page_url}: {str(exc)[:120]}")
    if not scanned:
        return [], {"status": "error", "reason": "ZAP could not fetch any approved same-origin URL",
                    "urls_requested": len(safe_targets), "urls_scanned": 0, "errors": failures[:3]}

    # ZAP analyses fetched responses asynchronously. Alerts are only trustworthy once the
    # passive-scan queue has been observed empty on two consecutive polls.
    timeout_seconds, poll_seconds = zap_passive_queue_settings()
    queue_status = "timeout"
    queue_reason = f"Passive-scan queue did not drain within {timeout_seconds:g} seconds; alerts may be incomplete"
    empty_polls = 0
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            pending = zap_get("/JSON/pscan/view/recordsToScan/", {}).get("recordsToScan", "0")
            empty_polls = empty_polls + 1 if int(pending) <= 0 else 0
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError):
            queue_status = "error"
            queue_reason = "Could not confirm passive-scan queue status; alerts may be incomplete"
            break
        if empty_polls >= 2:
            queue_status, queue_reason = "drained", ""
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(poll_seconds)
    if queue_reason:
        failures.append(queue_reason)
    queue_fields = {"passive_queue_status": queue_status, "passive_timeout_seconds": timeout_seconds}

    # Filter alerts to the exact scheme/host/port origin, not a broad host prefix.
    origin = f"{root.scheme}://{root.netloc}/"
    try:
        payload = zap_get("/JSON/core/view/alerts/", {"baseurl": origin, "start": "0", "count": "100"})
        alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    except Exception as exc:
        return [], {"status": "completed_with_warnings", "reason": "ZAP fetched approved URLs but could not retrieve alerts",
                    "urls_requested": len(safe_targets), "urls_scanned": len(scanned), "errors": [str(exc)[:200]],
                    **queue_fields}

    normalized = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        alert_url = str(alert.get("url") or target)
        parsed_alert = urlparse(alert_url)
        alert_port = parsed_alert.port or (443 if parsed_alert.scheme == "https" else 80)
        if (parsed_alert.scheme != root.scheme or not parsed_alert.hostname or
                parsed_alert.hostname.lower().rstrip(".") != (root.hostname or "").lower().rstrip(".") or
                alert_port != root_port):
            continue
        risk = str(alert.get("risk", "Informational")).lower()
        severity = {"high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}.get(risk, "Info")
        title = str(alert.get("alert", "OWASP ZAP passive alert"))[:240]
        evidence_parts = [str(alert.get("description", "")).strip()]
        if alert.get("evidence"):
            evidence_parts.append("Evidence: " + str(alert.get("evidence", "")))
        if alert.get("param"):
            evidence_parts.append("Parameter: " + str(alert.get("param", "")))
        evidence = " ".join(part for part in evidence_parts if part)[:1800] or "Reported by OWASP ZAP passive scanner."
        remediation = str(alert.get("solution", "") or "Review the ZAP alert and validate its applicability.")[:1800]
        confidence = str(alert.get("confidence", "Medium"))
        normalized.append((severity, "OWASP ZAP: " + title, alert_url[:2048], evidence, remediation, confidence))

    status = "completed_with_warnings" if failures else "completed"
    result = {"status": status, "urls_requested": len(safe_targets), "urls_scanned": len(scanned),
              "finding_count": len(normalized), "errors": failures[:3],
              "mode": "passive only; no spider or active scan; same-origin URLs only", **queue_fields}
    if failures:
        result["reason"] = "; ".join(failures[:3])[:300]
    return normalized, result

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



def select_nuclei_templates(max_templates: int = 60, platform_tags=None, platform_max: int = 0) -> tuple[list[str], dict]:
    """Select a bounded, locally installed set of low-impact HTTP templates.

    Template tags alone are not a safety boundary. This selector also excludes
    known intrusive categories, headless/flow/code templates, and templates that
    declare more than five requests. A hard cap prevents a full community-template
    corpus from making each assessment run for many minutes.
    """
    configured = os.environ.get("DKCISSP_NUCLEI_TEMPLATES", "").strip()
    candidates = []
    roots = [Path(configured).expanduser()] if configured else [
        Path.home() / ".local" / "nuclei-templates" / "http",
        Path.home() / "nuclei-templates" / "http",
        Path("/root/nuclei-templates/http"),
    ]
    def is_directory(candidate: Path) -> bool:
        try:
            return candidate.is_dir()
        except OSError:
            return False
    root = next((candidate for candidate in roots if is_directory(candidate)), None)
    if root is None:
        return [], {"status": "unavailable", "reason": "Local HTTP Nuclei templates were not found"}

    allowed_tags = {"misconfig", "misconfiguration", "exposure", "headers", "ssl", "config", "token", "tech", "cve", "vulnerability", "panel", "discovery"}
    excluded_tags = {"dos", "fuzz", "bruteforce", "brute-force", "intrusive", "headless", "token-spray", "default-login", "default-credentials", "filefuzz", "takeover"}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    category_order = ["misconfig", "misconfiguration", "exposure", "ssl", "headers", "config", "cve", "vulnerability", "token", "panel", "tech", "discovery"]
    platform_set = {str(tag).lower() for tag in (platform_tags or [])} if platform_max > 0 else set()
    platform_candidates = []
    scanned = 0
    for path in root.rglob("*.yaml"):
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:12000]
        except OSError:
            continue
        # Restrict to HTTP templates; reject flow/headless/code and templates
        # carrying explicit high-risk tags or excessive request counts.
        if not re.search(r"(?m)^http\s*:", text) or re.search(r"(?m)^(flow|headless|javascript|code)\s*:", text):
            continue
        # Do not execute state-changing HTTP methods, raw handcrafted requests,
        # or payload-driven fuzzing in this bounded default profile.
        # Real templates list requests as "- method: POST" / "- raw:", so an optional leading "- " must be allowed.
        if re.search(r"(?im)^\s*(?:-\s*)?method\s*:\s*['\"]?(POST|PUT|PATCH|DELETE|OPTIONS)\b", text):
            continue
        if re.search(r"(?m)^\s*(?:-\s*)?(payloads|attack|raw)\s*:", text):
            continue
        id_match = re.search(r"(?m)^id\s*:\s*['\"]?([^\s'\"]+)", text)
        tags_match = re.search(r"(?m)^\s*tags\s*:\s*([^\n]+)", text)
        severity_match = re.search(r"(?m)^\s*severity\s*:\s*([^\s#]+)", text)
        request_match = re.search(r"(?m)^\s*max-request\s*:\s*(\d+)", text)
        if not id_match or not tags_match:
            continue
        tags = {tag.strip().lower() for tag in re.split(r"[,\s]+", tags_match.group(1).strip(" []\"'")) if tag.strip()}
        if tags & excluded_tags:
            continue
        platform_hit = sorted(tags & platform_set)
        if not platform_hit and not (tags & allowed_tags):
            continue
        max_requests = int(request_match.group(1)) if request_match else 1
        if max_requests > 5:
            continue
        severity = (severity_match.group(1).strip("'\"").lower() if severity_match else "unknown")
        if platform_hit:
            # Templates written for a platform the scan detected; they passed every safety filter above.
            platform_candidates.append((severity_rank.get(severity, 5), id_match.group(1), str(path), platform_hit[0]))
            continue
        primary_category = next((tag for tag in category_order if tag in tags), "other")
        candidates.append((primary_category, severity_rank.get(severity, 5), id_match.group(1), str(path), tags))

    # Balance categories first so a large number of CVE templates cannot crowd out
    # configuration, exposure, TLS/header, and technology checks. Within each group,
    # higher-severity templates are selected first and identifiers keep selection stable.
    groups = {}
    for candidate in candidates:
        groups.setdefault(candidate[0], []).append(candidate)
    for group in groups.values():
        group.sort(key=lambda item: (item[1], item[2]))
    selected = []
    while len(selected) < max_templates:
        made_progress = False
        for category in category_order + ["other"]:
            group = groups.get(category, [])
            if group:
                selected.append(group.pop(0))
                made_progress = True
                if len(selected) >= max_templates:
                    break
        if not made_progress:
            break
    # Platform-targeted templates: highest severity first, spread across the detected platforms so one platform
    # with hundreds of templates cannot crowd out the others. They are added on top of the general selection.
    by_tag = {}
    for candidate in sorted(platform_candidates):
        by_tag.setdefault(candidate[3], []).append(candidate)
    platform_selected, order = [], sorted(by_tag, key=lambda tag: (by_tag[tag][0][0], tag))   # most severe template first
    while order and len(platform_selected) < platform_max:
        for tag in list(order):
            if by_tag[tag]:
                platform_selected.append(by_tag[tag].pop(0))
                if len(platform_selected) >= platform_max:
                    break
            else:
                order.remove(tag)
    platform_counts = {}
    for item in platform_selected:
        platform_counts[item[3]] = platform_counts.get(item[3], 0) + 1
    selected_paths = [item[2] for item in platform_selected] + [item[3] for item in selected]
    return selected_paths, {
        "status": "ready" if selected_paths else "unavailable",
        "platform_tags": sorted(platform_set), "platform_templates_selected": platform_counts,
        "platform_templates_available": {tag: len(group) + platform_counts.get(tag, 0) for tag, group in by_tag.items()},
        "template_root": str(root), "templates_considered": scanned,
        "templates_eligible": len(candidates), "templates_selected": len(selected_paths),
        "max_templates": max_templates,
        "selected_tags": sorted(allowed_tags), "excluded_tags": sorted(excluded_tags),
        "selection_note": "Local HTTP templates only; excludes explicit high-risk tags, flow/headless/code templates, and templates declaring over five requests.",
    }


def nuclei_target_urls(target: str, urls, limit: int) -> list[str]:
    """The few URLs worth running every template against: the origin first, then distinct pages and API endpoints.

    Nuclei sends each template to each URL, so the URL count multiplies the work. Static files (scripts, styles,
    images) and repeats of the same path with different query strings add requests without adding coverage.
    """
    static = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|mp4|webm|pdf|json|xml|txt)(\?|$)", re.I)
    chosen, paths = [target], {urlparse(target).path.rstrip("/")}
    for url in urls or []:
        parsed = urlparse(str(url))
        path = parsed.path.rstrip("/")
        if str(url) == target or path in paths or static.search(parsed.path) or len(chosen) >= limit:
            continue
        paths.add(path)
        chosen.append(str(url))
    return chosen


def perform_nuclei_check(target: str, timeout_seconds: int = 60, targets: list[str] | None = None,
                         max_templates: int = 30, platform_tags=None, platform_max: int = 0, session=None) -> tuple[list[tuple], dict]:
    """Run bounded Nuclei checks and retain valid partial results if the runtime limit is reached."""
    binary = shutil.which(TOOL_CATALOG["nuclei"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "Nuclei is not installed"}
    selection_args = {"max_templates": max(1, min(max_templates, 60))}
    if platform_tags and platform_max > 0:
        selection_args.update(platform_tags=platform_tags, platform_max=min(platform_max, 40))
    selected_templates, selection_status = select_nuclei_templates(**selection_args)
    if not selected_templates:
        return [], {"status": "unavailable", "reason": selection_status.get("reason", "No templates passed the safety filter"),
                    "template_selection": selection_status}

    # Keep target-list input within the exact origin of the user-supplied URL.
    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)
    safe_targets = []
    for candidate in (targets or [target])[:12]:
        parsed = urlparse(candidate)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme == root.scheme and parsed.hostname and root.hostname and
                parsed.hostname.lower().rstrip(".") == root.hostname.lower().rstrip(".") and port == root_port and
                parsed.scheme in {"http", "https"} and candidate not in safe_targets):
            safe_targets.append(candidate)
    if target not in safe_targets:
        safe_targets.insert(0, target)
    safe_targets = safe_targets[:12]
    findings: list[tuple] = []
    with tempfile.TemporaryDirectory(prefix="dkcissp-nuclei-") as temp_dir:
        jsonl_path = str(Path(temp_dir) / "results.jsonl")
        templates_path = str(Path(temp_dir) / "selected-templates.txt")
        targets_path = str(Path(temp_dir) / "targets.txt")
        with open(templates_path, "w", encoding="utf-8") as template_file:
            template_file.write("\n".join(selected_templates) + "\n")
        with open(targets_path, "w", encoding="utf-8") as target_file:
            target_file.write("\n".join(safe_targets) + "\n")
        command = [
            binary, "-list", targets_path,
            "-templates", templates_path,
            "-pt", "http",
            "-severity", "info,low,medium,high,critical,unknown",
            "-rl", "5", "-c", "3", "-timeout", "4", "-retries", "0",
            "-duc", "-disable-redirects", "-no-interactsh", "-silent",
            "-jsonl-export", jsonl_path,
        ]
        if session is not None:  # the session travels in a private file, never on the command line
            command += ["-H", write_private_file(str(Path(temp_dir) / "session-headers.txt"), session.headers_file_text(target))]
        timed_out = False
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout_seconds,
                check=False, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            result = SimpleNamespace(returncode=124)
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300], "template_selection": selection_status}

        if not os.path.isfile(jsonl_path) or os.path.getsize(jsonl_path) == 0:
            if timed_out:
                status = "timeout"
                reason = "Nuclei reached its time limit before producing findings"
            elif result.returncode == 0:
                # Nuclei may omit the JSONL file entirely when there are no matches.
                # A successful exit without a report is a clean zero-finding result,
                # not a tool failure.
                status = "completed"
                reason = "Nuclei completed successfully and reported no matches"
            else:
                status = "error"
                reason = "Nuclei exited non-zero without producing its JSONL report"
            return [], {"status": status, "return_code": result.returncode,
                        "timeout_seconds": timeout_seconds if timed_out else None,
                        "reason": reason, "finding_count": 0, "partial_results_retained": False,
                        "template_selection": selection_status, "target_count": len(safe_targets),
                        "rate_limit_per_second": 5, "concurrency": 3,
                        "redirects_disabled": True, "interactsh_disabled": True,
                        "authenticated": session is not None}
        malformed = 0
        with open(jsonl_path, encoding="utf-8", errors="replace") as report_file:
            for line in report_file:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if not isinstance(item, dict):
                    malformed += 1
                    continue
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                severity_raw = str(info.get("severity", "")).strip().lower()
                severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "unknown": "Info"}
                severity = severity_map.get(severity_raw)
                if not severity:
                    continue
                title = str(info.get("name") or item.get("template-id") or "Nuclei finding")[:240]
                template_id = str(item.get("template-id") or "unknown-template")[:160]
                matched_at = str(item.get("matched-at") or item.get("host") or target)[:2048]
                extracted = item.get("extracted-results")
                matcher = str(item.get("matcher-name") or "")[:160]
                evidence_parts = [f"Template: {template_id}"]
                if matcher:
                    evidence_parts.append(f"Matcher: {matcher}")
                if isinstance(extracted, list) and extracted:
                    evidence_parts.append("Extracted: " + ", ".join(str(x)[:200] for x in extracted[:5]))
                if item.get("curl-command"):
                    evidence_parts.append("Request details omitted from stored evidence for safety.")
                remediation = str(info.get("remediation") or "Review the template evidence, validate applicability, and apply the vendor-recommended fix.")[:1800]
                findings.append((severity, "Nuclei: " + title, matched_at, "; ".join(evidence_parts)[:1800], remediation, "Medium"))

    deduped = []
    seen = set()
    for finding in findings:
        key = (finding[0], finding[1], finding[2])
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    status = ("partial_timeout" if timed_out and deduped else "timeout" if timed_out else
              "completed" if result.returncode == 0 else "completed_with_warnings")
    return deduped, {"status": status,
                     "return_code": result.returncode, "finding_count": len(deduped),
                     "partial_results_retained": bool(timed_out and deduped),
                     "malformed_records": malformed, "template_selection": selection_status,
                     "target_count": len(safe_targets), "target_limit": 12,
                     "rate_limit_per_second": 5, "concurrency": 3, "redirects_disabled": True,
                     "interactsh_disabled": True, "timeout_seconds": timeout_seconds, "authenticated": session is not None}


def perform_browser_crawl(target: str, start_urls: list[str], session=None, profile: str = "standard") -> tuple[list[tuple], dict]:
    """Render the app in a headless browser (GET only; see browser.py for the safety rules)."""
    deep = profile in ("deep", "active")
    findings, status = browser.crawl(target, start_urls, session=session, max_pages=14 if deep else 10, budget_seconds=75 if deep else 45)
    status.setdefault("authenticated", session is not None)
    return findings, status


def parse_nikto_report(report, target: str) -> list[tuple]:
    """Normalize Nikto JSON findings conservatively; Nikto messages rarely provide severity."""
    if isinstance(report, list):
        entries = report
    elif isinstance(report, dict):
        entries = next((report.get(key) for key in ("findings", "vulnerabilities", "items", "data")
                        if isinstance(report.get(key), list)), [])
    else:
        entries = []
    findings = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        message = str(entry.get("msg") or entry.get("message") or entry.get("description") or entry.get("title") or "").strip()
        if not message:
            continue
        path = str(entry.get("url") or entry.get("uri") or "")
        if path.startswith(("http://", "https://")):
            affected = path
        else:
            affected = urljoin(target.rstrip("/") + "/", path.lstrip("/")) if path else target
        if not is_same_origin_url(affected, target):
            continue
        method = str(entry.get("method") or "GET").upper()[:12]
        reference = str(entry.get("OSVDB") or entry.get("osvdb") or entry.get("id") or "")[:120]
        evidence = f"Nikto reported: {message}"
        if reference:
            evidence += f"; reference: {reference}"
        evidence += f"; method: {method}"
        key = (message.lower(), affected)
        if key in seen:
            continue
        seen.add(key)
        # Do not infer High/Critical from free-text scanner output. The report needs
        # validation and CVE/vendor evidence before severity can be raised.
        severity = "Info" if re.search(r"server banner|server header|version.*disclos|banner.*disclos", message, re.I) else "Low"
        findings.append((severity, "Nikto: " + message[:220], affected[:2048], evidence[:1800],
                         "Validate this observation manually, confirm the affected component and version, then apply the vendor-recommended remediation or remove unnecessary exposure.",
                         "Medium"))
    return findings


def perform_nikto_check(target: str, timeout_seconds: int = 50) -> tuple[list[tuple], dict]:
    """Run a time-bounded Nikto server-misconfiguration pass for Deep scans only."""
    binary = shutil.which(TOOL_CATALOG["nikto"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "Nikto is not installed"}
    with tempfile.TemporaryDirectory(prefix="dkcissp-nikto-") as temp_dir:
        report_path = str(Path(temp_dir) / "nikto.json")
        command = [binary, "-host", target, "-Format", "json", "-output", report_path,
                   "-maxtime", f"{max(5, min(timeout_seconds - 5, 45))}s", "-Pause", "0.1",
                   "-Tuning", "123b", "-nointeractive", "-nolookup", "-nocheck", "-ask", "no"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds,
                                    check=False, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}
        if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "Nikto did not produce a JSON report; no findings were inferred from console text"}
        try:
            with open(report_path, encoding="utf-8", errors="replace") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "Nikto produced an unreadable JSON report"}
    findings = parse_nikto_report(report, target)
    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings),
                      "timeout_seconds": timeout_seconds,
                      "safety": "Deep profile only; same supplied target; bounded runtime and request delay; tuning excludes injection, DoS, command execution, upload, and authentication-bypass test groups; no redirect-following flag"}


SENSITIVE_HIGH = re.compile(r"(^|/)(\.git|\.svn|\.hg|\.env[^/]*|\.htpasswd|id_rsa[^/]*|wp-config\.php[^/]*|credentials|passwords?\.txt)(/|$)", re.I)
SENSITIVE_MEDIUM = re.compile(r"(backup|\.bak|\.sql|dump|phpinfo|phpmyadmin|adminer|actuator|server-status|server-info|\.zip|\.tar|"
                              r"(^|/)(admin|administrator|console|manager|dashboard|cpanel|debug|trace|swagger|graphiql|api-docs|logs?|"
                              r"config(uration)?(\.[a-z]+)?|settings\.php|web\.config|composer\.(json|lock)|package\.json|docker-compose\.yml|dockerfile)(/|$))", re.I)


def parse_ffuf_report(report, target: str) -> tuple[list[tuple], list[str]]:
    """Normalise ffuf JSON into findings plus same-origin URLs that answered 200 (to feed later stages)."""
    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)
    results = report.get("results") if isinstance(report, dict) else None
    if not isinstance(results, list):
        return [], []
    ranked, found_urls, seen = [], [], set()
    for item in results:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (parsed.scheme != root.scheme or (parsed.hostname or "").lower() != (root.hostname or "").lower() or port != root_port):
            continue  # only the approved origin
        try:
            status = int(item.get("status"))
        except (TypeError, ValueError):
            continue
        if url in seen:
            continue
        seen.add(url)
        path = parsed.path.lstrip("/")
        length = item.get("length", "?")
        location = str(item.get("redirectlocation") or "")
        # A server redirecting /admin to /admin/ is how most web servers answer for an existing directory.
        directory_redirect = status in (301, 302, 307, 308) and urlparse(location).path.rstrip("/") == parsed.path.rstrip("/") and location.rstrip("/") != ""
        if directory_redirect:
            status = 200
        evidence = f"HTTP {status}, {length} bytes, found by a content-discovery request; the response body was not inspected."
        if status in (200, 204) and SENSITIVE_HIGH.search(path):
            ranked.append((0, ("High", "Sensitive file or directory appears exposed: /" + path, url, evidence,
                               "Remove the file from the web root or block access to it, then rotate any secrets it may contain. Verify manually.", "Medium")))
        elif status in (200, 204) and SENSITIVE_MEDIUM.search(path):
            ranked.append((1, ("Medium", "Potentially sensitive path is reachable: /" + path, url, evidence,
                               "Restrict access (authentication, network controls) or remove the path if it is not needed. Verify manually.", "Medium")))
        elif status in (200, 204):
            ranked.append((2, ("Info", "Hidden or unlinked content found: /" + path, url, evidence,
                               "Confirm the content is meant to be public; remove or protect anything that is not.", "Low")))
        elif status in (401, 403):
            ranked.append((3, ("Info", f"Protected path exists: /{path} (HTTP {status})", url, evidence,
                               "No action needed if access control is intended; confirm it cannot be bypassed.", "Low")))
        elif status in (301, 302, 307, 308):
            ranked.append((3, ("Info", f"Path exists and redirects elsewhere: /{path}", url,
                               f"HTTP {status} redirect to {location[:200] or 'another location'}; the response body was not inspected.",
                               "Confirm the redirect target is intended; paths that redirect to a login page usually need authentication.", "Low")))
        if status == 200 and not directory_redirect:
            found_urls.append(url)
    ranked.sort(key=lambda pair: pair[0])
    return [finding for _, finding in ranked[:40]], found_urls


def perform_ffuf_check(target: str, timeout_seconds: int = 60, extra_paths=None, session=None) -> tuple[list[tuple], dict]:
    """Bounded hidden-content discovery against the supplied origin only, using the built-in wordlist."""
    binary = shutil.which(TOOL_CATALOG["ffuf"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "ffuf is not installed"}
    wordlist = ROOT / "wordlists" / "common-paths.txt"
    if not wordlist.is_file():
        return [], {"status": "error", "reason": "The built-in content-discovery wordlist is missing"}
    base = target.rstrip("/")
    with tempfile.TemporaryDirectory(prefix="dkcissp-ffuf-") as temp_dir:
        report_path = str(Path(temp_dir) / "ffuf.json")
        wordlist_path = str(wordlist)
        extras = [p for p in (extra_paths or []) if re.fullmatch(r"[A-Za-z0-9_./!~@%+-]{1,120}", str(p))][:120]
        skipped_for_safety = 0
        if extras or session is not None:  # the general list plus platform paths, de-duplicated (and, when logged in, stripped of risky paths)
            lines = [l for l in wordlist.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
            merged = list(dict.fromkeys(lines + [e.lstrip("/") for e in extras]))
            if session is not None:   # a path like /logout or /delete would end the session or change data
                safe = [m for m in merged if not auth.is_unsafe_url("/" + m)]
                skipped_for_safety, merged = len(merged) - len(safe), safe
            wordlist_path = str(Path(temp_dir) / "wordlist.txt")
            Path(wordlist_path).write_text("\n".join(merged) + "\n", encoding="utf-8")
        if session is not None:   # the logged-in request (with its cookies/headers) is read from a private file
            request_file = write_private_file(str(Path(temp_dir) / "session-request.txt"), session.raw_request(base + "/FUZZ"))
            target_args = ["-request", request_file, "-request-proto", urlparse(base).scheme]
        else:
            target_args = ["-u", base + "/FUZZ", "-H", "User-Agent: DKCISSP-WebSecurityScanner/0.1 (+authorized content discovery)"]
        command = [binary, *target_args, "-w", wordlist_path, "-ic", "-ac", "-s", "-noninteractive",
                   "-rate", "10", "-t", "4", "-timeout", "6", "-maxtime", str(max(10, timeout_seconds - 10)),
                   "-mc", "200,204,301,302,307,308,401,403",
                   "-of", "json", "-o", report_path]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False,
                                    env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}
        if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "ffuf did not produce a JSON report; no findings were inferred from console text"}
        try:
            with open(report_path, encoding="utf-8", errors="replace") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode, "reason": "ffuf produced an unreadable JSON report"}
    findings, found_urls = parse_ffuf_report(report, target)
    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings), "found_urls": found_urls[:40],
                      "timeout_seconds": timeout_seconds, "authenticated": session is not None, "paths_skipped_for_safety": skipped_for_safety,
                      "safety": "Deep/Active profiles only; same supplied origin; GET requests from a short built-in wordlist; 10 requests/second, 4 threads; no redirects followed; no recursion"}


SAFE_URL = re.compile(r"^https?://[^\s\x00-\x1f\x7f]+$")


def select_test_urls(target: str, urls, limit: int = 4) -> list[str]:
    """Same-origin URLs with query parameters worth testing, one per endpoint+parameter-name shape.

    Values come from crawled pages, so they are untrusted: only plain http(s) URLs without whitespace or
    control characters are ever passed to an external tool, always as a single argument after a flag.
    """
    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)
    chosen, shapes = [], set()
    for url in urls or []:
        url = str(url)
        if len(url) > 2000 or not SAFE_URL.match(url):
            continue
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (not parsed.query or parsed.scheme != root.scheme or (parsed.hostname or "").lower() != (root.hostname or "").lower()
                or port != root_port):
            continue
        shape = (parsed.path, tuple(sorted(pair.split("=", 1)[0] for pair in parsed.query.split("&"))))
        if shape in shapes:
            continue
        shapes.add(shape)
        chosen.append(url)
        if len(chosen) >= limit:
            break
    return chosen


def parse_sqlmap_log(text: str, url: str) -> list[tuple]:
    """Findings from sqlmap's structured session log ('Parameter: id (GET)' blocks); console chatter is never parsed."""
    findings = []
    dbms = re.search(r"^back-end DBMS: (.+)$", text, re.M)
    blocks = re.split(r"(?m)^Parameter: ", text)[1:]
    for block in blocks:
        header, _, rest = block.partition("\n")
        match = re.match(r"(.+?) \(([^)]+)\)\s*$", header.strip())
        if not match:
            continue
        name, where = match.group(1)[:80], match.group(2)[:40]
        rest = rest.split("\n---")[0]
        techniques = re.findall(r"Type: (.+)\n\s*Title: (.+)", rest)
        payload = re.search(r"Payload: (.+)", rest)
        if not techniques:
            continue
        evidence = "sqlmap confirmed injection using: " + "; ".join(f"{t.strip()} ({ti.strip()})" for t, ti in techniques[:4])
        if payload:
            evidence += ". Example payload: " + payload.group(1).strip()[:200]
        if dbms:
            evidence += ". Back-end DBMS: " + dbms.group(1).strip()[:80]
        findings.append(("High", f"SQL injection: parameter '{name}' ({where}) appears injectable", url[:2048], evidence[:1800],
                         "Use parameterized queries or prepared statements for every database call, validate input, and run the database account with least privilege. Retest after the fix.",
                         "High"))
    return findings


def perform_sqlmap_check(target: str, urls, timeout_seconds: int = 240, session=None) -> tuple[list[tuple], dict]:
    """Detection-only SQL injection testing of a few same-origin parameterised URLs (Active profile only)."""
    test_urls = select_test_urls(target, urls)
    if not test_urls:
        return [], {"status": "skipped", "reason": "No same-origin URLs with query parameters were found to test"}
    binary = shutil.which(TOOL_CATALOG["sqlmap"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "sqlmap is not installed"}
    per_url = max(30, min(timeout_seconds // len(test_urls), 90))
    findings, timed_out, errors = [], 0, []
    with tempfile.TemporaryDirectory(prefix="dkcissp-sqlmap-") as temp_dir:
        for index, url in enumerate(test_urls):
            out_dir = str(Path(temp_dir) / f"run{index}")
            if session is not None:  # the logged-in request is read from a private file
                request_file = write_private_file(str(Path(temp_dir) / f"request{index}.txt"), session.raw_request(url))
                target_args = ["-r", request_file] + (["--force-ssl"] if urlparse(url).scheme == "https" else [])
            else:
                target_args = ["-u", url, "--user-agent=DKCISSP-WebSecurityScanner/0.1 (+authorized active testing)"]
            command = [binary, *target_args, "--batch", "--level=1", "--risk=1", "--technique=BEU", "--threads=1",
                       "--timeout=10", "--retries=1", "--delay=0.2", "--ignore-redirects", "--flush-session",
                       "--disable-coloring", "--output-dir=" + out_dir]
            terminal = None
            try:
                if session is not None:   # sqlmap only reads a request file (-r) when its stdin is a terminal, so give it a pseudo-terminal
                    import pty
                    terminal = pty.openpty()
                subprocess.run(command, capture_output=True, text=True, timeout=per_url, check=False,
                               env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"}, stdin=terminal[1] if terminal else None)
            except subprocess.TimeoutExpired:
                timed_out += 1
            except OSError as exc:
                errors.append(str(exc)[:200])
                continue
            finally:
                for descriptor in terminal or ():
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            for log_path in Path(out_dir).glob("*/log"):  # partial results survive a timeout
                try:
                    findings.extend(parse_sqlmap_log(log_path.read_text(encoding="utf-8", errors="replace"), url))
                except OSError:
                    errors.append("Could not read sqlmap's session log")
    status = "completed"
    reason = f"{len(test_urls)} URL(s) tested with detection-only settings (level 1, risk 1, no data extraction)"
    if errors and not findings:
        status, reason = "error", errors[0]
    elif timed_out:
        status = "partial_timeout" if findings else "timeout"
        reason = f"time limit reached on {timed_out} of {len(test_urls)} URL(s); results so far are kept"
    return findings, {"status": status, "reason": reason, "finding_count": len(findings), "urls_tested": len(test_urls), "authenticated": session is not None,
                      "safety": "Active profile only; same-origin parameterised URLs; level 1, risk 1; boolean, error and union techniques only (no stacked queries); no data extraction; 0.2 s delay; redirects not followed"}


def query_parameter_names(url: str, limit: int = 8) -> list[str]:
    """Plain parameter names from a URL's query string (letters, digits, _ - . [ ] only), in order, deduplicated."""
    names = []
    for pair in urlparse(url).query.split("&"):
        name = pair.split("=", 1)[0]
        if name and re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", name) and not name.startswith("-") and name not in names:
            names.append(name)
    return names[:limit]


def parse_dalfox_lines(text: str, target: str) -> list[tuple]:
    """Findings from dalfox's JSON-lines output (one result per line, so a timeout keeps earlier results)."""
    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)
    findings, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "")
        param = str(item.get("param") or "")[:80]
        data = str(item.get("data") or "")
        parsed = urlparse(data)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if kind not in ("V", "R") or (parsed.scheme != root.scheme or (parsed.hostname or "").lower() != (root.hostname or "").lower() or port != root_port):
            continue
        key = (kind, param, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        where = str(item.get("inject_type") or "response")[:60]
        evidence = f"Injection context: {where}. Payload: {str(item.get('payload') or '')[:200]}. Evidence: {str(item.get('evidence') or '')[:300]}"
        if kind == "V":
            findings.append(("High", f"Cross-site scripting: parameter '{param}' executes a verified payload", data[:2048], evidence[:1800],
                             "Encode output for its HTML/JavaScript/attribute context, validate input, and add a strict Content-Security-Policy. Retest after the fix.", "High"))
        else:
            findings.append(("Medium", f"Input reflected without encoding (possible XSS): parameter '{param}'", data[:2048], evidence[:1800],
                             "Encode reflected input for its output context and confirm manually whether a payload can execute.", "Medium"))
    return findings


def perform_dalfox_check(target: str, urls, timeout_seconds: int = 540, session=None) -> tuple[list[tuple], dict]:
    """Detection-only reflected-XSS testing of a few same-origin parameterised URLs (Active profile only)."""
    test_urls = select_test_urls(target, urls, limit=3)
    if not test_urls:
        return [], {"status": "skipped", "reason": "No same-origin URLs with query parameters were found to test"}
    binary = shutil.which(TOOL_CATALOG["dalfox"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "dalfox is not installed"}
    per_url = max(60, min(timeout_seconds // len(test_urls), 180))
    use_session = session is not None and session.cookie_only   # a bearer token or API key cannot be given to dalfox without a command line
    findings, timed_out, errors = [], 0, []
    with tempfile.TemporaryDirectory(prefix="dkcissp-dalfox-") as temp_dir:
        for index, url in enumerate(test_urls):
            out_path = str(Path(temp_dir) / f"dalfox{index}.jsonl")
            names = query_parameter_names(url)
            if not names:
                continue
            command = [binary, "url", url, "--silence", "--no-color", "--no-spinner", "--format", "jsonl", "--output", out_path,
                       "--timeout", "10", "--delay", "150", "--worker", "3", "--skip-bav", "--skip-mining-all",
                       "--skip-headless", "--skip-grepping", "--skip-discovery",
                       *[arg for name in names for arg in ("-p", name)], "--limit-result", "1", "--limit-result-type", "v",
                       "--user-agent", "DKCISSP-WebSecurityScanner/0.1 (+authorized active testing)"]
            if use_session:
                command += ["--cookie-from-raw", write_private_file(str(Path(temp_dir) / f"cookies{index}.txt"), session.raw_request(url))]
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=per_url, check=False,
                               env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
            except subprocess.TimeoutExpired:
                timed_out += 1
            except OSError as exc:
                errors.append(str(exc)[:200])
                continue
            if os.path.isfile(out_path):
                try:
                    with open(out_path, encoding="utf-8", errors="replace") as handle:
                        findings.extend(parse_dalfox_lines(handle.read(), target))
                except OSError:
                    errors.append("Could not read dalfox's result file")
    status = "completed"
    reason = f"{len(test_urls)} URL(s) tested; no browser or blind-callback features used"
    if errors and not findings:
        status, reason = "error", errors[0]
    elif timed_out:
        # An unfinished payload run is an incomplete test, not a clean result.
        status = "partial_timeout" if findings else "timeout"
        reason = f"time limit reached before dalfox finished testing {timed_out} of {len(test_urls)} URL(s); findings so far are kept, but those URLs were not fully tested"
    if session is not None and not use_session:
        reason += "; this tool can only use cookie sessions, so it ran without your login"
    return findings, {"status": status, "reason": reason, "finding_count": len(findings), "urls_tested": len(test_urls), "authenticated": use_session,
                      "safety": "Active profile only; same-origin parameterised URLs; reflected payloads only; no headless browser, parameter mining, blind-XSS callbacks or BAV; 3 workers, 150 ms delay; stops at the first verified result per URL"}


WPSCAN_INTERESTING = {  # wpscan "interesting finding" type -> (severity, plain title, advice)
    "debug_log": ("Medium", "WordPress debug log is publicly readable", "Delete the debug log, disable WP_DEBUG_LOG on production, and block access to wp-content/debug.log."),
    "backup_db": ("High", "WordPress database backup is exposed", "Remove the backup from the web root and rotate any credentials it contains."),
    "config_backup": ("High", "WordPress configuration backup is exposed", "Remove the file from the web root and rotate the database and secret keys it contains."),
    "db_export": ("High", "WordPress database export is exposed", "Remove the export from the web root and rotate any credentials it contains."),
    "emergency_pwd_reset_script": ("High", "WordPress emergency password-reset script is present", "Delete the script immediately; it can let anyone reset the admin password."),
    "upload_directory_listing": ("Medium", "WordPress uploads directory listing is enabled", "Disable directory listing (Options -Indexes) so uploaded files cannot be browsed."),
    "xmlrpc": ("Low", "WordPress XML-RPC is enabled", "Disable XML-RPC if it is not needed, or restrict it; it enables brute-force amplification and pingback abuse."),
    "readme": ("Info", "WordPress readme file is exposed", "Remove readme.html and license.txt from production; they reveal the exact WordPress version."),
    "wp_cron": ("Info", "WordPress WP-Cron is externally reachable", "Prefer a real system cron and block external wp-cron.php requests to avoid load-based abuse."),
    "multisite": ("Info", "WordPress Multisite is enabled", "Review network-wide plugin and user permissions."),
    "registration": ("Low", "WordPress user registration is open", "Disable open registration unless it is required, and review the default role."),
}


def _wpscan_vulnerability_findings(label: str, vulnerabilities, url: str) -> list[tuple]:
    findings = []
    for vuln in vulnerabilities if isinstance(vulnerabilities, list) else []:
        if not isinstance(vuln, dict) or not vuln.get("title"):
            continue
        refs = vuln.get("references") if isinstance(vuln.get("references"), dict) else {}
        cves = ", ".join("CVE-" + str(c) if not str(c).upper().startswith("CVE-") else str(c) for c in (refs.get("cve") or [])[:4])
        cvss = vuln.get("cvss") if isinstance(vuln.get("cvss"), dict) else {}
        try:
            score = float(cvss.get("score"))
        except (TypeError, ValueError):
            score = None
        severity = "High" if score is not None and score >= 7 else "Medium"
        evidence = f"Known vulnerability in {label}: {str(vuln['title'])[:200]}."
        if vuln.get("fixed_in"):
            evidence += f" Fixed in {str(vuln['fixed_in'])[:40]}."
        if cves:
            evidence += f" {cves}."
        if score is not None:
            evidence += f" CVSS {score}."
        findings.append((severity, f"WordPress vulnerability: {str(vuln['title'])[:180]}", url[:2048], evidence[:1800],
                         "Update the affected component to the fixed version (or remove it), then retest. Confirm the installed version first; matching is by detected version.", "High" if vuln.get("fixed_in") else "Medium"))
    return findings


def _wpscan_component_findings(kind: str, slug: str, comp: dict) -> list[tuple]:
    findings = []
    location = str(comp.get("location") or "")
    version = ((comp.get("version") or {}) if isinstance(comp.get("version"), dict) else {}).get("number")
    label = f"{kind} '{slug}'" + (f" {version}" if version else "")
    findings.append(("Info", f"WordPress {kind} detected: {slug}" + (f" {version}" if version else ""), location[:2048],
                     f"wpscan identified the {kind} '{slug}'" + (f", version {version}" if version else ", version not determined") + f" ({str(comp.get('found_by') or 'detection')[:80]}).",
                     "Keep it updated and remove components that are not needed.", "Medium"))
    if comp.get("outdated") is True:
        latest = comp.get("latest_version")
        findings.append(("Medium", f"WordPress {kind} is outdated: {slug}", location[:2048],
                         f"Installed {version or 'unknown'}, latest {latest or 'unknown'}.", f"Update the {kind} to the latest version, or remove it if unused.", "Medium"))
    if comp.get("directory_listing") is True:
        findings.append(("Medium", f"Directory listing enabled for {kind} '{slug}'", location[:2048],
                         "wpscan reports that the component directory can be browsed.", "Disable directory listing on the web server.", "Medium"))
    if comp.get("error_log_url"):
        findings.append(("Medium", f"Error log exposed for {kind} '{slug}'", str(comp["error_log_url"])[:2048],
                         "An error log file is reachable and may disclose paths and internal details.", "Delete the log and block access to log files.", "Medium"))
    findings.extend(_wpscan_vulnerability_findings(label, comp.get("vulnerabilities"), location))
    return findings


def parse_wpscan_report(report, target: str) -> list[tuple]:
    """Normalise wpscan's JSON report into findings (core version, plugins, themes, exposures, users)."""
    if not isinstance(report, dict):
        return []
    root = urlparse(target)
    root_port = root.port or (443 if root.scheme == "https" else 80)

    def same_origin(url: str) -> bool:
        parsed = urlparse(str(url))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme == root.scheme and (parsed.hostname or "").lower() == (root.hostname or "").lower() and port == root_port

    findings = []
    version = report.get("version") if isinstance(report.get("version"), dict) else None
    if version and version.get("number"):
        number = str(version["number"])[:40]
        findings.append(("Info", f"WordPress core version detected: {number}", target[:2048],
                         f"wpscan identified WordPress {number} ({str(version.get('found_by') or 'detection')[:80]}); status: {str(version.get('status') or 'unknown')[:40]}.",
                         "Keep WordPress core on a supported, current release and hide the exact version where practical.", "Medium"))
        if str(version.get("status") or "").lower() in ("insecure", "outdated"):
            findings.append(("Medium", f"WordPress core is {str(version['status']).lower()}: {number}", target[:2048],
                             f"wpscan classes WordPress {number} as {str(version['status']).lower()}.", "Update WordPress core to the latest release, then retest.", "Medium"))
        findings.extend(_wpscan_vulnerability_findings(f"WordPress core {number}", version.get("vulnerabilities"), target))
    theme = report.get("main_theme") if isinstance(report.get("main_theme"), dict) else None
    plugins = report.get("plugins") if isinstance(report.get("plugins"), dict) else {}
    themes = report.get("themes") if isinstance(report.get("themes"), dict) else {}
    seen_themes = set()
    for slug, comp in list(themes.items())[:30]:
        if isinstance(comp, dict) and same_origin(comp.get("location") or target):
            seen_themes.add(slug)
            findings.extend(_wpscan_component_findings("theme", str(slug)[:80], comp))
    if theme and str(theme.get("slug")) not in seen_themes and same_origin(theme.get("location") or target):
        findings.extend(_wpscan_component_findings("theme", str(theme.get("slug"))[:80], theme))
    for slug, comp in list(plugins.items())[:60]:
        if isinstance(comp, dict) and same_origin(comp.get("location") or target):
            findings.extend(_wpscan_component_findings("plugin", str(slug)[:80], comp))
    for item in report.get("interesting_findings") if isinstance(report.get("interesting_findings"), list) else []:
        if not isinstance(item, dict):
            continue
        rule = WPSCAN_INTERESTING.get(str(item.get("type")))
        url = str(item.get("url") or target)
        if not rule or not same_origin(url):
            continue
        severity, title, advice = rule
        findings.append((severity, title, url[:2048], (str(item.get("to_s") or title)[:300] + "."), advice, "Medium" if severity != "Info" else "Low"))
    users = report.get("users") if isinstance(report.get("users"), dict) else {}
    if users:
        names = ", ".join(sorted(str(name)[:40] for name in users)[:10])
        findings.append(("Low", f"WordPress user names can be enumerated ({len(users)} found)", target[:2048],
                         f"wpscan retrieved user name(s) without logging in: {names}.",
                         "Block author-archive and REST user enumeration, use non-obvious login names, and enforce strong passwords with rate limiting or 2FA.", "High"))
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    unique, seen = [], set()
    for finding in sorted(findings, key=lambda f: order.get(f[0], 4)):
        key = (finding[0], finding[1], finding[2])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique[:80]


def perform_wpscan_check(target: str, timeout_seconds: int = 300, profile: str = "standard") -> tuple[list[tuple], dict]:
    """WordPress-specific checks. Standard is passive; Deep/Active add bounded active detection and user enumeration."""
    binary = shutil.which(TOOL_CATALOG["wpscan"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "WPScan is not installed"}
    deep = profile in ("deep", "active")
    # The API token (known-vulnerability data) travels only in the child's environment, never in arguments or logs.
    token = (os.environ.get("DKCISSP_WPSCAN_API_TOKEN") or os.environ.get("WPSCAN_API_TOKEN") or "").strip()
    child_env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb"}
    if token:
        child_env["WPSCAN_API_TOKEN"] = token
    else:
        child_env.pop("WPSCAN_API_TOKEN", None)
    with tempfile.TemporaryDirectory(prefix="dkcissp-wpscan-") as temp_dir:
        report_path = str(Path(temp_dir) / "wpscan.json")
        command = [binary, "--url", target, "--no-banner", "--format", "json", "--output", report_path,
                   "--detection-mode", "mixed" if deep else "passive", "--plugins-detection", "passive", "--themes-detection", "passive",
                   "--max-threads", "2", "--request-timeout", "20", "--connect-timeout", "10",
                   "--user-agent", "DKCISSP-WebSecurityScanner/0.1 (+authorized WordPress assessment)",
                   "-e", "ap,at,u1-10,cb,dbe,bf" if deep else "ap,at"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False,
                                    env=child_env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}
        if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "wpscan did not produce a JSON report; no findings were inferred from console text"}
        try:
            with open(report_path, encoding="utf-8", errors="replace") as handle:
                report = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode, "reason": "wpscan produced an unreadable JSON report"}
    if isinstance(report, dict) and (report.get("scan_aborted") or report.get("update_aborted")):
        message = str(report.get("scan_aborted") or report.get("update_aborted"))[:300].replace("\n", " ")
        if "does not seem to be running wordpress" in message.lower():
            return [], {"status": "skipped", "reason": "wpscan did not confirm that the target runs WordPress"}
        return [], {"status": "error", "reason": "wpscan could not run: " + message
                    + (" Its vulnerability database could not be downloaded; check internet access or run 'wpscan --update'." if "update" in message.lower() or report.get("update_aborted") else "")}
    findings = parse_wpscan_report(report, target)
    status = {"status": "completed" if result.returncode in (0, 5) else "completed_with_warnings", "return_code": result.returncode,
              "finding_count": len(findings), "api_token_configured": bool(token), "timeout_seconds": timeout_seconds,
              "mode": "passive detection" if not deep else "mixed detection with user enumeration",
              "safety": "Runs only when WordPress is detected; same supplied origin; 2 threads; plugin and theme detection is passive (no slug brute-forcing); token passed via environment only"}
    if not token:
        status["status"] = "completed_with_warnings"
        status["reason"] = ("No WPScan API token is configured, so components were identified but known-vulnerability data was not included. "
                            "Set DKCISSP_WPSCAN_API_TOKEN (a free token is available at wpscan.com/register) to include it.")
    return findings, status


DROOPESCAN_CMS = {"drupal": "Drupal", "joomla": "Joomla", "silverstripe": "SilverStripe", "moodle": "Moodle"}


def parse_droopescan_output(text: str, cms_id: str, target: str) -> list[tuple]:
    """Findings from droopescan's JSON output (it prints one JSON object per URL, and only when it found something)."""
    name = DROOPESCAN_CMS.get(cms_id, cms_id)
    findings = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            result = json.loads(line)
        except ValueError:
            continue
        if not isinstance(result, dict):
            continue
        version = result.get("version") if isinstance(result.get("version"), dict) else {}
        versions = [str(v)[:40] for v in (version.get("finds") or []) if isinstance(v, (str, int, float))][:12]
        if versions:
            shown = versions[0] if len(versions) == 1 else f"{versions[0]} to {versions[-1]} ({len(versions)} candidates)"
            findings.append(("Info", f"{name} version identified: {shown}", target[:2048],
                             f"droopescan fingerprinted the {name} core files; candidate version(s): {', '.join(versions[:6])}. Fingerprint matching can be ambiguous, so confirm the exact version.",
                             f"Keep {name} on a supported, fully patched release and check its security advisories for the identified version.", "Medium"))
        for kind, label in (("plugins", "module/plugin"), ("themes", "theme")):
            section = result.get(kind) if isinstance(result.get(kind), dict) else {}
            for item in (section.get("finds") or [])[:30]:
                if isinstance(item, dict) and (item.get("name") or item.get("url")):
                    component = str(item.get("name") or item.get("url"))[:100]
                    findings.append(("Info", f"{name} {label} detected: {component}", str(item.get("url") or target)[:2048],
                                     f"droopescan found the {name} {label} '{component}' by probing its standard location.",
                                     f"Keep the {label} updated and remove it if it is not needed.", "Medium"))
        interesting = result.get("interesting urls") if isinstance(result.get("interesting urls"), dict) else {}
        for item in (interesting.get("finds") or [])[:20]:
            if not isinstance(item, dict) or not item.get("url"):
                continue
            description = str(item.get("description") or "Default file")[:160]
            url = str(item["url"])[:2048]
            installer = bool(re.search(r"install|setup", description + " " + url, re.I))
            findings.append(("Medium" if installer else "Low", f"Default {name} file reachable: {description}", url,
                             f"droopescan could request {url}; default files and installers reveal the platform and version and can be abused.",
                             "Remove default documentation, changelog and installer files from production, or block them at the web server.", "Medium"))
    seen, unique = set(), []
    for finding in findings:
        key = (finding[0], finding[1], finding[2])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def perform_droopescan_check(target: str, cms_ids, profile: str = "standard", timeout_seconds: int = 240) -> tuple[list[tuple], dict]:
    """Version, module and exposed-file checks for the detected Drupal / Joomla / SilverStripe / Moodle site."""
    cms_ids = [c for c in dict.fromkeys(cms_ids) if c in DROOPESCAN_CMS][:2]
    if not cms_ids:
        return [], {"status": "skipped", "reason": "No Drupal, Joomla, SilverStripe or Moodle site was detected"}
    binary = shutil.which(TOOL_CATALOG["droopescan"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "droopescan is not installed"}
    deep = profile in ("deep", "active")
    per_cms = max(60, timeout_seconds // len(cms_ids))
    base = target.rstrip("/") + "/"
    findings, timed_out, not_confirmed, errors = [], 0, 0, []
    for cms in cms_ids:
        command = [binary, "scan", cms, "-u", base, "-o", "json", "--hide-progressbar", "-t", "2", "--timeout", "10",
                   "--timeout-host", str(per_cms - 10), "-n", "500" if deep else "100", "--no-follow-redirects",
                   "--user-agent", "DKCISSP-WebSecurityScanner/0.1 (+authorized CMS assessment)"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=per_cms, check=False,
                                    env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"}, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            timed_out += 1
            continue
        except OSError as exc:
            errors.append(str(exc)[:200])
            continue
        parsed = parse_droopescan_output(result.stdout, cms, target)
        findings.extend(parsed)
        if not parsed and re.search(r"not running", (result.stdout or "") + (result.stderr or ""), re.I):
            not_confirmed += 1
    if errors and not findings:
        return [], {"status": "error", "reason": errors[0]}
    if not_confirmed == len(cms_ids) and not findings:
        return [], {"status": "skipped", "reason": "droopescan did not confirm that the target runs " + ", ".join(DROOPESCAN_CMS[c] for c in cms_ids)}
    status = "completed"
    reason = f"{', '.join(DROOPESCAN_CMS[c] for c in cms_ids)} checked with a {'500' if deep else '100'}-name module and theme list, 2 threads"
    if timed_out:
        status = "partial_timeout" if findings else "timeout"
        reason = f"time limit reached on {timed_out} of {len(cms_ids)} CMS run(s); findings so far are kept"
    return findings, {"status": status, "reason": reason, "finding_count": len(findings), "cms": cms_ids,
                      "safety": "Runs only when the CMS is detected; same supplied origin; HEAD requests, 2 threads, bounded module and theme dictionary; no redirects followed; no authentication or password attacks"}


API_PROBE_PATHS = ("swagger.json", "swagger/v1/swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs", "api-docs", "api/swagger.json",
                   "api/openapi.json", "swagger-ui/", "swagger-ui.html", "docs", "graphql", "api/graphql", "graphiql")
GRAPHQL_PATHS = ("graphql", "api/graphql", "graphiql")
FORMS_API_BUDGET_SECONDS = 60


def analyze_forms_and_apis(target: str, discovery: dict, root_html: str, platform_ids, final_url: str | None = None,
                           opener=None, authenticated: bool = False) -> tuple[list[tuple], dict, dict]:
    """Read forms, scripts and API descriptions on the approved origin. GET requests only; nothing is submitted.

    Returns (findings, status, extras). extras holds URLs worth feeding to later stages and the facts the planner needs.
    """
    base = final_url or target
    deadline = time.monotonic() + FORMS_API_BUDGET_SECONDS
    opener = opener or same_origin_opener(base)
    headers = {"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized API discovery)", "Accept": "application/json,text/javascript,*/*;q=0.5"}
    stats = {"requests": 0, "failed": 0, "budget_reached": False}

    def fetch(url: str, limit: int, timeout: int = 5):
        if time.monotonic() > deadline:
            stats["budget_reached"] = True
            return None
        stats["requests"] += 1
        try:
            with opener.open(Request(url, headers=headers), timeout=timeout) as response:
                data = response.read(limit)
                return response.status, str(response.headers.get("Content-Type", "")).lower(), data.decode("utf-8", "replace")
        except HTTPError as exc:
            try:
                body = exc.read(2000).decode("utf-8", "replace")
            except Exception:
                body = ""
            return exc.code, str(exc.headers.get("Content-Type", "")).lower() if exc.headers else "", body
        except (URLError, TimeoutError, OSError, ssl.SSLError, ValueError):
            stats["failed"] += 1
            return None
        finally:
            time.sleep(0.1)

    findings, facts = [], {"graphql": False, "api_requires_auth": False}
    forms = discovery.get("forms") or signals.parse_forms(root_html, base)
    findings.extend(signals.form_findings(forms, target))
    facts.update(signals.form_facts(forms))

    # 1. API paths named in the site's own JavaScript (static reading; the scripts are not executed).
    scripts = list(dict.fromkeys(list(discovery.get("scripts") or []) + signals.script_urls(root_html, base)))
    ranked = sorted(scripts, key=lambda u: (0 if re.search(r"main|app|bundle|index|runtime|chunk", u, re.I) else 1, len(u)))
    js_paths = []
    for script in ranked[:6]:
        result = fetch(script, 1_500_000, timeout=8)
        if result and result[0] == 200:
            for path in signals.extract_js_endpoints(result[2]):
                if path not in js_paths:
                    js_paths.append(path)
    js_paths = js_paths[:60]

    # 2. Well-known API documentation and GraphQL paths.
    origin = base.rstrip("/") + "/"
    docs, graphql_urls = [], []
    for path in API_PROBE_PATHS:
        url = urljoin(origin, path)
        if path in GRAPHQL_PATHS:
            result = fetch(url + "?query=%7B__typename%7D", 100_000)
            if result and result[0] in (200, 400) and signals.classify_graphql(result[2])["graphql"]:
                graphql_urls.append(url)
            continue
        result = fetch(url, 400_000)
        if not result or result[0] != 200:
            continue
        summary = signals.openapi_summary(result[2], origin)
        if summary:
            docs.append({**summary, "url": url})
        elif path.startswith("swagger-ui") or path == "docs":
            if re.search(r"swagger|redoc|openapi", result[2][:5000], re.I):
                docs.append({"title": "interactive API documentation", "version": "", "path_count": 0, "sample_paths": [], "testable_urls": [], "url": url})
    for doc in docs:
        detail = f" '{doc['title']}' {doc['version']}".rstrip() if doc["title"] else ""
        evidence = f"The API description{detail} at {doc['url']} can be read without logging in" + (
            f" and lists {doc['path_count']} paths, for example: {', '.join(doc['sample_paths'][:8])}." if doc["path_count"] else ".")
        findings.append(("Low", "API documentation is publicly accessible", doc["url"][:2048], evidence[:1800],
                         "Restrict API documentation to authenticated users or internal networks, and confirm no undocumented endpoints rely on obscurity.", "High"))
    for url in graphql_urls:
        facts["graphql"] = True
        findings.append(("Info", "GraphQL endpoint found", url, f"{url} answers GraphQL queries.",
                         "Confirm authentication, query depth and cost limits, and disable debugging interfaces in production.", "High"))
        introspect = fetch(url + "?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D", 200_000)
        if introspect and signals.classify_graphql(introspect[2])["introspection"]:
            findings.append(("Medium", "GraphQL introspection is enabled", url, f"{url} returned its schema to an introspection query, which hands an attacker a complete map of the API.",
                             "Disable introspection in production (or restrict it to authenticated developers).", "High"))

    # 3. Which of the script-named endpoints exist, and do they ask for a login?
    checked = []
    for path in [p for p in js_paths if "?" in p or not re.search(r"/(1|\d+)$", p)][:15]:
        url = urljoin(origin, path.lstrip("/"))
        result = fetch(url, 60_000)
        if result:
            checked.append({"path": path, "url": url, "status": result[0], "json": "json" in result[1] or result[2].lstrip()[:1] in "{["})
    answering = [c for c in checked if c["status"] == 200 and c["json"]]
    protected = [c for c in checked if c["status"] in (401, 403)]
    if protected:
        facts["api_requires_auth"] = True
    if js_paths:
        listing = "; ".join(f"{c['path']} (HTTP {c['status']})" for c in checked[:12]) or ", ".join(js_paths[:12])
        findings.append(("Info", f"API endpoints referenced in JavaScript: {len(js_paths)}", origin[:2048],
                         f"The site's scripts name {len(js_paths)} API path(s). Checked with GET: {len(answering)} answered with data, {len(protected)} require authentication. {listing}"[:1800],
                         "Review each endpoint for authentication, authorization and input validation; the scanner could only read them, not log in.", "Medium"))
    for item in answering[:8]:
        findings.append(("Info", f"API endpoint answers without authentication: {item['path']}", item["url"][:2048],
                         f"GET {item['url']} returned HTTP 200 with JSON data and no credentials were sent. Whether that is intended depends on the data.",
                         "Confirm this endpoint is meant to be public, and that it does not expose another user's data.", "Medium"))

    if authenticated:  # the same checks, but what they find is only reachable with the login: say so
        relabelled = []
        for severity, title, url, evidence, fix, confidence in findings:
            if title == "API documentation is publicly accessible":
                severity, title = "Info", "API documentation is accessible while logged in"
            elif title in ("GraphQL endpoint found", "GraphQL introspection is enabled"):
                title += " (logged in)"
            elif title.startswith("API endpoint answers without authentication:"):
                title = title.replace("answers without authentication", "answers to the logged-in user")
                evidence = evidence.replace("and no credentials were sent", "while logged in")
            elif title.startswith("API endpoints referenced in JavaScript"):
                title = title.replace("JavaScript", "JavaScript (logged in)", 1)
            relabelled.append((severity, title, url, evidence, fix, confidence))
        findings = relabelled
    api_urls = [u for doc in docs for u in doc["testable_urls"]]
    api_urls += [urljoin(origin, p.lstrip("/")) for p in js_paths if "?" in p]
    facts["api_endpoints"] = len(js_paths) + sum(d["path_count"] for d in docs)
    facts["is_spa"] = signals.looks_like_spa(root_html, platform_ids, len(discovery.get("urls") or []) - 1)
    extras = {"merge_urls": [c["url"] for c in answering], "api_urls": list(dict.fromkeys(api_urls))[:20], "facts": facts}
    status = {"status": "completed", "finding_count": len(findings), "forms": facts.get("forms", 0), "scripts_read": min(len(ranked), 6),
              "js_endpoints": len(js_paths), "api_docs": len(docs), "graphql": len(graphql_urls), "requests": stats["requests"],
              "safety": "GET requests only on the approved origin; nothing is submitted; scripts are read, never executed; at most about 40 requests and 60 seconds"}
    if stats["budget_reached"] or (stats["requests"] and stats["failed"] == stats["requests"]):
        status["status"] = "completed_with_warnings"
        status["reason"] = "the time budget was reached before every check finished" if stats["budget_reached"] else "none of the requests could be completed"
    return findings, status, extras


def parse_wapiti_report(report, target: str) -> list[tuple]:
    """Normalize Wapiti JSON without storing raw requests, cookies, or curl commands."""
    if not isinstance(report, dict):
        return []
    classifications = report.get("classifications", {}) if isinstance(report.get("classifications"), dict) else {}
    severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    findings = []
    seen = set()
    for group_name in ("vulnerabilities", "additionals"):
        groups = report.get(group_name, {})
        if not isinstance(groups, dict):
            continue
        for category, entries in groups.items():
            if not isinstance(entries, list):
                continue
            classification = classifications.get(category, {}) if isinstance(classifications.get(category), dict) else {}
            remediation = str(classification.get("sol") or "Validate the observation and apply the vendor-recommended remediation.")[:1800]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                path = str(entry.get("path") or "")
                affected = urljoin(target, path) if path else target
                if not is_same_origin_url(affected, target):
                    continue
                level = entry.get("level", 0 if group_name == "additionals" else 1)
                try:
                    level = int(level)
                except (TypeError, ValueError):
                    level = 1
                severity = "Info" if group_name == "additionals" else severity_map.get(level, "Low")
                title = ("Wapiti: " if group_name == "vulnerabilities" else "Wapiti observation: ") + str(category)[:220]
                detail = str(entry.get("info") or entry.get("message") or "Scanner reported this observation.")[:1000]
                method = str(entry.get("method") or "")[:12]
                parameter = str(entry.get("parameter") or "")[:160]
                module = str(entry.get("module") or "")[:80]
                evidence_parts = [detail]
                if method:
                    evidence_parts.append("Method: " + method)
                if parameter:
                    evidence_parts.append("Parameter: " + parameter)
                if module:
                    evidence_parts.append("Module: " + module)
                evidence = "; ".join(evidence_parts)[:1800]
                key = (title, affected, evidence)
                if key in seen:
                    continue
                seen.add(key)
                confidence = "Medium" if group_name == "vulnerabilities" else "Low"
                findings.append((severity, title, affected[:2048], evidence, remediation, confidence))
    return findings


def perform_wapiti_check(target: str, timeout_seconds: int = 90) -> tuple[list[tuple], dict]:
    """Run an explicitly approved, bounded active Wapiti assessment on the supplied URL scope."""
    binary = shutil.which(TOOL_CATALOG["wapiti"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "Wapiti is not installed"}
    modules = "backup,crlf,csrf,exec,file,htaccess,ldap,methods,redirect,sql,ssl,xss,xxe"
    with tempfile.TemporaryDirectory(prefix="dkcissp-wapiti-") as temp_dir:
        report_path = str(Path(temp_dir) / "report.json")
        command = [binary, "-u", target, "--scope", "folder", "-m", modules,
                   "-f", "json", "-o", report_path, "-d", "2",
                   "--max-links-per-page", "10", "--max-files-per-dir", "5",
                   "--max-parameters", "10", "--max-scan-time", "75",
                   "--max-attack-time", "8", "--tasks", "1", "-t", "4",
                   "-l", "1", "-S", "polite", "--no-bugreport", "--verify-ssl", "1", "-v", "0"]
        for excluded_path in ("logout", "signout", "session/logout", "account/delete", "unsubscribe", "checkout", "payment"):
            command.extend(["-x", urljoin(target.rstrip("/") + "/", excluded_path)])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds,
                                    check=False, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds,
                        "reason": "Wapiti reached its runtime limit before a report was available"}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}
        if not os.path.isfile(report_path) or os.path.getsize(report_path) == 0:
            return [], {"status": "error" if result.returncode else "completed",
                        "return_code": result.returncode, "finding_count": 0,
                        "reason": "Wapiti produced no JSON report" if result.returncode else "Wapiti completed without a report"}
        try:
            with open(report_path, encoding="utf-8", errors="replace") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "Wapiti produced an unreadable JSON report"}
    findings = parse_wapiti_report(report, target)
    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings),
                      "crawled_pages": (report.get("infos", {}) or {}).get("crawled_pages_nbr") if isinstance(report, dict) else None,
                      "timeout_seconds": timeout_seconds,
                      "modules": modules.split(","),
                      "safety": "Active payload testing explicitly approved by user; same-folder scope; depth 2; one crawler task; polite mode; no SSRF, upload, stored-XSS, brute-force, timing-SQL, or OAST modules"}


def perform_whatweb_check(target: str, timeout_seconds: int = 30) -> tuple[list[tuple], dict]:
    """Run WhatWeb at its stealthy single-request aggression level and normalize its JSON output."""
    binary = shutil.which(TOOL_CATALOG["whatweb"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "WhatWeb is not installed"}

    with tempfile.TemporaryDirectory(prefix="dkcissp-whatweb-") as temp_dir:
        json_path = str(Path(temp_dir) / "results.json")
        try:
            result = subprocess.run(
                [binary, "--quiet", "--no-errors", "--aggression=1", "--follow-redirect=never",
                 "--max-redirects=3", "--log-json=" + json_path, target],
                capture_output=True, text=True, timeout=timeout_seconds, check=False,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except subprocess.TimeoutExpired:
            return [], {"status": "timeout", "timeout_seconds": timeout_seconds}
        except OSError as exc:
            return [], {"status": "error", "reason": str(exc)[:300]}

        if not os.path.isfile(json_path):
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "WhatWeb did not produce its JSON report"}
        try:
            with open(json_path, encoding="utf-8", errors="replace") as report_file:
                report = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            return [], {"status": "error", "return_code": result.returncode,
                        "reason": "WhatWeb produced an unreadable JSON report"}

    entries = report if isinstance(report, list) else [report] if isinstance(report, dict) else []
    findings = []
    seen_plugins = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins", {})
        if not isinstance(plugins, dict):
            continue
        for plugin_name, plugin_data in plugins.items():
            name = str(plugin_name).strip()[:160]
            if not name or name.lower() in {"httpserver", "ip", "country", "title", "redirectlocation"}:
                continue
            version_values = []
            if isinstance(plugin_data, dict):
                versions = plugin_data.get("version", [])
                if isinstance(versions, list):
                    version_values = [str(value).strip()[:100] for value in versions if str(value).strip()]
                elif versions:
                    version_values = [str(versions).strip()[:100]]
            evidence = "Technology/plugin detected: " + name
            if version_values:
                evidence += "; observed version: " + ", ".join(version_values[:3])
            key = (name.lower(), tuple(version_values[:3]))
            if key in seen_plugins:
                continue
            seen_plugins.add(key)
            findings.append(("Info", "WhatWeb technology detected: " + name,
                             str(entry.get("target") or target)[:1000], evidence[:1800],
                             "Confirm whether this technology and version are expected; keep components patched and minimize unnecessary disclosure.",
                             "Low"))

    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings)}

def update_scan_progress(scan_id: int, progress: int, stage: str, tools: dict | None = None) -> None:
    """Persist truthful scan-stage progress so the UI can survive refreshes."""
    with connect() as conn:
        if tools is None:
            conn.execute("UPDATE scans SET progress=?,current_stage=? WHERE id=?", (progress, stage, scan_id))
        else:
            conn.execute("UPDATE scans SET progress=?,current_stage=?,tool_status=? WHERE id=?",
                         (progress, stage, json.dumps(tools), scan_id))


FINISHED_SCAN_STATUSES = ("completed", "completed_with_gaps")
# Stage statuses that do not mean "an expected check did not fully run".
# "skipped" is only used for stages a profile or target type deliberately excludes.
CLEAN_STAGE_STATUSES = {"completed", "skipped", "not_run", "ready"}


def assessment_gaps(tool_status: dict) -> list[dict]:
    """List stages that did not fully complete, so a scan is never reported as fully complete when they didn't."""
    gaps = []
    for name, state in tool_status.items():
        status = str((state or {}).get("status", "unknown"))
        if status not in CLEAN_STAGE_STATUSES:
            gaps.append({"tool": name, "status": status, "detail": str((state or {}).get("detail", ""))[:300]})
    return gaps


def write_private_file(path: str, text: str) -> str:
    """Write a file only its owner can read (used for credentials handed to external tools; never a command line)."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


COOKIE_ATTRIBUTES = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly", "priority", "partitioned"}


def redact_cookie_values(text: str) -> str:
    """Keep cookie names and attributes, drop the values: 'sid=abc; Path=/' becomes 'sid=[redacted]; Path=/'."""
    def replace(match):
        name = match.group(2)
        return match.group(0) if name.lower() in COOKIE_ATTRIBUTES else f"{match.group(1)}{name}=[redacted]"
    return re.sub(r"(^|[;,]\s*)([^=;,\s]+)=([^;,]*)", replace, str(text or ""))


def scrub_secrets(value, secrets) -> str:
    """Remove every known secret (password, token, session cookie value) from text before it is stored."""
    text = str(value if value is not None else "")
    for secret in sorted({str(x) for x in secrets if x and len(str(x)) >= 6}, key=len, reverse=True):
        for form in {secret, json.dumps(secret)[1:-1]}:   # as written, and as it would appear inside JSON
            text = text.replace(form, "[redacted]")
    return text


def response_set_cookies(headers) -> list[str]:
    """All Set-Cookie header values of a response (a plain dict has only one value per name)."""
    getter = getattr(headers, "get_all", None)
    values = getter("Set-Cookie") if getter else None
    if not values and hasattr(headers, "get"):
        single = headers.get("Set-Cookie") or headers.get("set-cookie")
        values = [single] if single else []
    return list(values or [])


def perform_scan(scan_id: int, target: str, profile: str, auth_settings=None, second_account=None) -> None:
    findings = []
    tool_status = {
        "Built-in HTTP & headers": {"status": "running", "detail": "Requesting the supplied URL and inspecting response headers"},
        "Authentication": {"status": "skipped", "detail": "No login credentials were provided"},
        "Endpoint discovery": {"status": "queued", "detail": "Waiting for the initial page response"},
        "Nuclei": {"status": "queued", "detail": "Waiting for built-in checks"},
        "Nikto": {"status": "queued", "detail": "Runs in Deep and Active profiles"},
        "Content discovery (ffuf)": {"status": "queued", "detail": "Runs in Deep and Active profiles"},
        "Forms & APIs (built-in)": {"status": "queued", "detail": "Runs in Standard, Deep and Active profiles"},
        "WordPress (wpscan)": {"status": "queued", "detail": "Runs when WordPress is detected"},
        "CMS checks (droopescan)": {"status": "queued", "detail": "Runs when Drupal, Joomla, SilverStripe or Moodle is detected"},
        "SQL injection (sqlmap)": {"status": "queued", "detail": "Runs only in the Active profile"},
        "XSS (dalfox)": {"status": "queued", "detail": "Runs only in the Active profile"},
        "Wapiti active checks": {"status": "queued", "detail": "Runs only after explicit active-testing approval"},
        "WhatWeb": {"status": "queued", "detail": "Waiting for built-in checks"},
        "TLS (testssl.sh)": {"status": "queued", "detail": "Waiting for built-in checks"},
        "OWASP ZAP passive": {"status": "queued", "detail": "Optional local integration"},
    }
    update_scan_progress(scan_id, 5, "Connecting to website", tool_status)
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
                set_cookie_names = platforms.cookie_names_from_headers(response_set_cookies(response.headers))
                final_url = response.geturl()
                body = response.read(500_000).decode("utf-8", "replace")
        except HTTPError as exc:
            status_code = exc.code
            headers = {k.lower(): v for k, v in exc.headers.items()}
            set_cookie_names = platforms.cookie_names_from_headers(response_set_cookies(exc.headers))
            final_url = exc.geturl()
            body = exc.read(200_000).decode("utf-8", "replace")
        except (URLError, TimeoutError, ssl.SSLError, socket.timeout) as exc:
            with connect() as conn:
                conn.execute(
                    "UPDATE scans SET status=?,finished_at=?,summary=? WHERE id=?",
                    ("failed", now(), json.dumps({"error": str(exc)}), scan_id),
                )
            return

        tool_status["Built-in HTTP & headers"] = {"status": "completed", "detail": f"HTTP {status_code}; response headers and sampled HTML inspected"}
        update_scan_progress(scan_id, 20, "Checking HTTP response, headers and cookies", tool_status)

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
                "Medium", "Cookie may lack Secure attribute", redact_cookie_values(cookies)[:220],
                "Set Secure on cookies that should only be sent over HTTPS.", "Medium",
            )
        if cookies and "httponly" not in cookies.lower():
            finding(
                "Low", "Cookie may lack HttpOnly attribute", redact_cookie_values(cookies)[:220],
                "Set HttpOnly for session cookies that do not require JavaScript access.", "Medium",
            )
        if profile in ("standard", "deep", "active"):
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

        # Authentication: log in once (never guessing) and keep the session for the stages that can use it.
        session, session_ok, auth_info, auth_pages, auth_discovery, landing_html, landing_final = None, False, None, [], None, "", final_url
        if auth_settings:
            tool_status["Authentication"] = {"status": "running", "detail": "Logging in once with the credentials you provided; browsing afterwards is read-only"}
            update_scan_progress(scan_id, 12, "Logging in", tool_status)
            session = auth.AuthSession(final_url, auth_settings, lambda jar: same_origin_opener(final_url, jar))
            try:
                session_ok = session.login()
            except Exception as exc:  # a login problem must never end the scan
                session.status, session.reason = "failed", f"The login could not be completed ({type(exc).__name__})."
            findings.extend(session.findings)
            auth_info = session.describe()
            if session_ok:
                tool_status["Authentication"] = {"status": "completed", "detail": f"Logged in ({auth_settings.kind}); {session.verified_by}"}
            else:
                tool_status["Authentication"] = {"status": "login_failed", "detail": session.reason + " The scan continued without a login."}
            identity_first = (auth_settings.identity_text or auth_settings.username)
            auth_settings = None  # the session keeps what it needs; this reference is dropped now
        second_session, second_ok, identity_second, second_role = None, False, "", "peer"
        if second_account and session_ok:
            settings2, second_role = second_account
            identity_second = settings2.identity_text or settings2.username
            tool_status["Second account"] = {"status": "running", "detail": "Logging in once as the second account, to compare what each user can open"}
            second_session = auth.AuthSession(final_url, settings2, lambda jar: same_origin_opener(final_url, jar))
            try:
                second_ok = second_session.login()
            except Exception as exc:
                second_session.status, second_session.reason = "failed", f"The login could not be completed ({type(exc).__name__})."
            auth_info["second_account"] = second_session.describe()
            tool_status["Second account"] = ({"status": "completed", "detail": f"Logged in ({settings2.kind}); {second_session.verified_by}"} if second_ok else
                                             {"status": "login_failed", "detail": second_session.reason + " Users could not be compared."})
            second_account = None
        discovery_status = {"status": "skipped", "reason": "Endpoint discovery is enabled for Standard/Deep/Active scans only", "urls": [final_url]}
        tool_status["Endpoint discovery"] = {"status": "skipped", "detail": "Not selected for this profile"}
        if profile in ("standard", "deep", "active"):
            tool_status["Endpoint discovery"] = {"status": "running", "detail": "Discovering same-origin links without submitting forms"}
            update_scan_progress(scan_id, 27, "Discovering same-origin pages", tool_status)
            discovery_status = discover_same_origin_pages(final_url, body)
            discovered_urls = discovery_status.get("urls", [final_url])
            tool_status["Endpoint discovery"] = {"status": "completed", "detail": f"Mapped {len(discovered_urls)} same-origin URL(s); bounded passive discovery"}
            if session_ok:
                try:  # the same bounded crawl again, as the logged-in user, skipping links that could log out or change data
                    _, _, landing_html, landing_final = session.request(session.landing_url)
                    auth_discovery = discover_same_origin_pages(landing_final, landing_html, opener=session.opener, url_filter=auth.is_unsafe_url)
                    auth_pages = [u for u in auth_discovery.get("urls", []) if u not in set(discovered_urls) and not auth.is_unsafe_url(u)]
                    tool_status["Endpoint discovery"]["detail"] += f"; {len(auth_pages)} more page(s) found while logged in"
                    discovery_status["urls"] = (auth_pages + list(discovered_urls))[:16]
                    discovery_status["forms"] = (discovery_status.get("forms") or []) + (auth_discovery.get("forms") or [])
                    discovery_status["scripts"] = list(dict.fromkeys((discovery_status.get("scripts") or []) + (auth_discovery.get("scripts") or [])))
                except Exception as exc:
                    tool_status["Endpoint discovery"]["detail"] += f"; the logged-in crawl failed ({type(exc).__name__})"
            # Extend low-impact response-header checks to discovered pages. Each URL is
            # fetched with a short timeout; only same-origin results are accepted.
            root_parsed = urlparse(final_url)
            root_port = root_parsed.port or (443 if root_parsed.scheme == "https" else 80)
            auth_page_set = set(auth_pages)
            for page_url in list(discovered_urls) + list(auth_pages):
                if page_url == final_url:
                    continue
                try:
                    page_req = Request(page_url, headers={"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized passive checks)", "Accept": "text/html,*/*;q=0.5"})
                    with (session.opener if page_url in auth_page_set else same_origin_opener(final_url)).open(page_req, timeout=4) as page_response:
                        page_final = urlparse(page_response.geturl())
                        page_port = page_final.port or (443 if page_final.scheme == "https" else 80)
                        if page_final.scheme != root_parsed.scheme or page_final.hostname != root_parsed.hostname or page_port != root_port:
                            continue
                        page_headers = {k.lower(): v for k, v in page_response.headers.items()}
                        page_body = page_response.read(100_000).decode("utf-8", "replace")
                        page_url_final = page_response.geturl()
                    if page_url_final.startswith("https://") and "strict-transport-security" not in page_headers:
                        findings.append(("Medium", "Strict-Transport-Security header missing", page_url_final, "HTTPS response does not include Strict-Transport-Security.", "Configure HSTS after confirming all required subdomains support HTTPS.", "High"))
                    if "content-security-policy" not in page_headers:
                        findings.append(("Medium", "Content-Security-Policy header missing", page_url_final, "Discovered same-origin response does not include Content-Security-Policy.", "Define and test a restrictive CSP appropriate to the application.", "High"))
                    if page_headers.get("x-content-type-options", "").lower() != "nosniff":
                        findings.append(("Low", "X-Content-Type-Options missing or weak", page_url_final, f"Observed: {page_headers.get('x-content-type-options', 'not present')}", "Set X-Content-Type-Options: nosniff.", "High"))
                    if "referrer-policy" not in page_headers:
                        findings.append(("Low", "Referrer-Policy header missing", page_url_final, "Discovered same-origin response does not include Referrer-Policy.", "Set an appropriate Referrer-Policy.", "High"))
                    page_cookies = page_headers.get("set-cookie", "")
                    if page_cookies and page_url_final.startswith("https://") and "secure" not in page_cookies.lower():
                        findings.append(("Medium", "Cookie may lack Secure attribute", page_url_final, redact_cookie_values(page_cookies)[:220], "Set Secure on cookies that should only be sent over HTTPS.", "Medium"))
                    if page_cookies and "httponly" not in page_cookies.lower():
                        findings.append(("Low", "Cookie may lack HttpOnly attribute", page_url_final, redact_cookie_values(page_cookies)[:220], "Set HttpOnly for session cookies that do not require JavaScript access.", "Medium"))
                    if re.search(r"<title>\s*Index of /", page_body, re.I):
                        findings.append(("Medium", "Directory listing appears enabled", page_url_final, "Page title resembles a directory index. Validate manually before treating as confirmed.", "Disable directory listing or restrict access.", "Medium"))
                except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError, ValueError):
                    continue

        # If ZAP is configured locally, merge its passive-only alerts into the same finding store.
        # This remains optional; absence of ZAP never blocks the built-in scan.
        # testssl.sh is an optional, bounded HTTPS check. It is invoked without a shell,
        # only for explicitly authorized scans, and its status is recorded in the scan summary.
        tls_status = {"status": "not_run", "reason": "TLS check not requested by profile"}
        whatweb_status = {"status": "not_run", "reason": "Technology discovery not requested by profile"}
        whatweb_findings = []
        ffuf_status = {"status": "not_run", "reason": "Content discovery runs in Deep and Active profiles only"}
        sqlmap_status = {"status": "not_run", "reason": "SQL injection testing runs only in the Active profile"}
        wpscan_status = {"status": "not_run", "reason": "WordPress checks run when WordPress is detected"}
        forms_api_status = locals().get("forms_api_status") or {"status": "not_run", "reason": "Forms and API analysis runs in Standard, Deep and Active profiles"}
        droopescan_status = {"status": "not_run", "reason": "CMS checks run when Drupal, Joomla, SilverStripe or Moodle is detected"}
        dalfox_status = {"status": "not_run", "reason": "XSS testing runs only in the Active profile"}
        nuclei_status = {"status": "not_run", "reason": "Nuclei checks are enabled for Standard/Deep/Active profiles only"}
        nikto_status = {"status": "not_run", "reason": "Nikto server checks are enabled for Deep/Active profiles only"}
        # Recognise the platform(s) from headers, cookies, markup and crawled URLs: it decides which extra paths and templates are worth using.
        platform_hits = platforms.detect_platforms(headers, body, set_cookie_names, discovery_status.get("urls", []))
        if profile in ("deep", "active"):
            ffuf_extra_paths = signals.platform_paths(sorted(platform_hits))
            tool_status["Content discovery (ffuf)"] = {"status": "running", "detail": "Searching for hidden files and paths with a short built-in wordlist" + (f" plus {len(ffuf_extra_paths)} platform-specific paths" if ffuf_extra_paths else "") + ", 10 requests/second"}
            update_scan_progress(scan_id, 31, "Searching for hidden content", tool_status)
            ffuf_findings, ffuf_status = perform_ffuf_check(target, timeout_seconds=(90 if profile == "active" else 60) + (20 if ffuf_extra_paths else 0), extra_paths=ffuf_extra_paths,
                                                            **({"session": session} if session_ok else {}))
            findings.extend(ffuf_findings)
            # Pages that answered 200 join the same-origin list so later stages cover them too (cap stays 12).
            merged = list(discovery_status.get("urls", [target]))
            for found in ffuf_status.get("found_urls", []):
                if found not in merged and len(merged) < 12:
                    merged.append(found)
            discovery_status["urls"] = merged
            tool_status["Content discovery (ffuf)"] = {"status": ffuf_status.get("status", "error"), "detail": f"{ffuf_status.get('finding_count', len(ffuf_findings))} finding(s); {ffuf_status.get('reason', 'check finished')}" + (" (logged in)" if ffuf_status.get("authenticated") else "")}
        else:
            tool_status["Content discovery (ffuf)"] = {"status": "skipped", "detail": "Runs in Deep and Active profiles"}
        # Single-page apps build their pages in the browser: render them in a headless browser (GET only) so their links, forms and API calls are seen.
        browser_status = {"status": "not_run", "reason": "The site does not look like a JavaScript single-page app"}
        browser_public_api, browser_auth_api = [], []
        tool_status["Browser crawl (Chromium)"] = {"status": "skipped", "detail": "Runs when the site is a JavaScript single-page app"}
        if profile in ("standard", "deep", "active") and signals.looks_like_spa(body, sorted(platform_hits), len(discovery_status.get("urls", [])) - 1):
            tool_status["Browser crawl (Chromium)"] = {"status": "running", "detail": "This looks like a JavaScript app: rendering its pages in a headless browser (GET only, nothing clicked or submitted)"}
            update_scan_progress(scan_id, 30, "Rendering the app in a browser", tool_status)
            try:
                b_findings, browser_status = perform_browser_crawl(final_url, [final_url], profile=profile)
            except Exception as exc:
                b_findings, browser_status = [], {"status": "error", "reason": f"The browser crawl failed ({type(exc).__name__})."}
            if browser_status.get("status") == "completed":
                findings.extend(b_findings)
                known = set(discovery_status.get("urls", []))
                new_public = [u for u in browser_status.get("urls", []) if u not in known]
                discovery_status["urls"] = (list(discovery_status.get("urls", [])) + new_public)[:16]
                discovered_urls = list(discovered_urls) + new_public
                discovery_status["forms"] = (discovery_status.get("forms") or []) + browser_status.get("forms", [])
                discovery_status["scripts"] = list(dict.fromkeys((discovery_status.get("scripts") or []) + browser_status.get("scripts", [])))
                browser_public_api = list(browser_status.get("api_urls", []))
                detail = f"{browser_status['reason']}; {len(new_public)} page(s) the plain crawler could not see"
                if session_ok:
                    try:
                        l_findings, l_status = perform_browser_crawl(final_url, list(dict.fromkeys([final_url, session.landing_url])), session=session, profile=profile)
                        if l_status.get("status") == "completed":
                            findings.extend(l_findings)
                            auth_known = set(auth_pages) | set(discovered_urls)
                            new_auth = [u for u in l_status.get("urls", []) if u not in auth_known]
                            auth_pages = list(auth_pages) + new_auth
                            discovery_status["urls"] = (list(new_auth) + list(discovery_status.get("urls", [])))[:16]
                            auth_discovery = auth_discovery or {"urls": [], "forms": [], "scripts": []}
                            auth_discovery["urls"] = list(dict.fromkeys(list(auth_discovery.get("urls", [])) + l_status.get("urls", [])))
                            auth_discovery["forms"] = (auth_discovery.get("forms") or []) + l_status.get("forms", [])
                            auth_discovery["scripts"] = list(dict.fromkeys((auth_discovery.get("scripts") or []) + l_status.get("scripts", [])))
                            browser_auth_api = list(l_status.get("api_urls", []))
                            browser_status["authenticated"] = True
                            browser_status["logged_in_pages"] = len(l_status.get("urls", []))
                            browser_status["blocked_writes"] = list(dict.fromkeys(browser_status.get("blocked_writes", []) + l_status.get("blocked_writes", [])))
                            detail += f"; logged in: {len(new_auth)} more page(s)"
                        else:
                            detail += f"; the logged-in browser crawl did not complete ({l_status.get('reason', 'unknown')})"
                    except Exception as exc:
                        detail += f"; the logged-in browser crawl failed ({type(exc).__name__})"
                    browser_status.setdefault("authenticated", False)
                tool_status["Browser crawl (Chromium)"] = {"status": "completed", "detail": detail + (" (logged in)" if browser_status.get("authenticated") else "")}
            elif browser_status.get("status") == "unavailable":
                tool_status["Browser crawl (Chromium)"] = {"status": "unavailable", "detail": browser_status.get("reason", "Chromium is not installed")}
            else:
                tool_status["Browser crawl (Chromium)"] = {"status": browser_status.get("status", "error"), "detail": browser_status.get("reason", "The browser crawl did not complete")}
        # Forms, scripts and API descriptions: read-only analysis that also feeds the endpoints it finds to the stages below.
        api_urls, signal_facts, public_api_urls = [], {}, []
        if profile in ("standard", "deep", "active"):
            tool_status["Forms & APIs (built-in)"] = {"status": "running", "detail": "Reading forms and scripts, and checking API documentation and GraphQL paths (GET requests only)"}
            update_scan_progress(scan_id, 33, "Analysing forms, scripts and APIs", tool_status)
            try:
                fa_findings, forms_api_status, fa_extras = analyze_forms_and_apis(target, discovery_status, body, sorted(platform_hits), final_url)
            except Exception as exc:  # this analysis is an extra: it must never fail the whole scan
                fa_findings, fa_extras = [], {"merge_urls": [], "api_urls": [], "facts": {}}
                forms_api_status = {"status": "error", "reason": "analysis failed: " + str(exc)[:200]}
            findings.extend(fa_findings)
            merged = list(discovery_status.get("urls", [target]))
            for extra_url in fa_extras.get("merge_urls", []):
                if extra_url not in merged and len(merged) < 12:
                    merged.append(extra_url)
            discovery_status["urls"] = merged
            api_urls, signal_facts = fa_extras.get("api_urls", []), fa_extras.get("facts", {})
            public_api_urls = list(api_urls)
            tool_status["Forms & APIs (built-in)"] = {"status": forms_api_status.get("status", "error"), "detail": f"{forms_api_status.get('finding_count', len(fa_findings))} finding(s); {forms_api_status.get('forms', 0)} form(s), {forms_api_status.get('js_endpoints', 0)} script endpoint(s), {forms_api_status.get('api_docs', 0)} API description(s); {forms_api_status.get('reason', 'check finished')}"}
            if session_ok and auth_discovery is not None:
                try:  # the same analysis as the logged-in user: forms, scripts and API paths that only exist behind the login
                    # Forms come from the logged-in crawl; script files include the public page's, since that is where the app's JavaScript is loaded.
                    logged_in_view = dict(auth_discovery, scripts=discovery_status.get("scripts"), forms=auth_discovery.get("forms"))
                    fa2_findings, fa2_status, fa2_extras = analyze_forms_and_apis(target, logged_in_view, landing_html, sorted(platform_hits), final_url,
                                                                                  opener=session.opener, authenticated=True)
                    findings.extend(fa2_findings)
                    merged = list(discovery_status.get("urls", [target]))
                    for extra_url in fa2_extras.get("merge_urls", []):
                        if extra_url not in merged and len(merged) < 16:
                            merged.append(extra_url)
                    discovery_status["urls"] = merged
                    api_urls = list(dict.fromkeys(list(api_urls) + list(fa2_extras.get("api_urls", []))))[:20]
                    for key, value in (fa2_extras.get("facts") or {}).items():
                        signal_facts[key] = (signal_facts.get(key) or value) if isinstance(value, bool) else max(signal_facts.get(key) or 0, value or 0)
                    tool_status["Forms & APIs (built-in)"]["detail"] += f"; logged-in pass: {len(fa2_findings)} finding(s)"
                except Exception as exc:
                    tool_status["Forms & APIs (built-in)"]["detail"] += f"; the logged-in pass failed ({type(exc).__name__})"
            api_urls = list(dict.fromkeys(list(api_urls) + browser_public_api + browser_auth_api))[:30]
            public_api_urls = list(dict.fromkeys(list(public_api_urls) + browser_public_api))
        else:
            tool_status["Forms & APIs (built-in)"] = {"status": "skipped", "detail": "Not selected for this profile"}
        if session_ok:  # is the session still alive after the crawl? Restore it at most twice, never guess anything new.
            try:
                if not session.still_logged_in():
                    if session.logins < 3 and session.login():
                        auth_info["session_note"] = "The session ended during the scan and was restored by logging in again."
                    else:
                        session_ok = False
                        auth_info["session_note"] = "The session ended during the scan and could not be restored."
                        tool_status["Authentication"] = {"status": "completed_with_warnings", "detail": "The session ended during the scan and could not be restored; later stages ran without it."}
            except Exception:
                pass
        access_status = None
        if session_ok and profile in ("standard", "deep", "active"):
            tool_status["Access control"] = {"status": "running", "detail": "Requesting the same pages as a visitor and as each account (GET only)"}
            update_scan_progress(scan_id, 33, "Comparing access between users", tool_status)
            try:
                crawl_first = list((auth_discovery or {}).get("urls", [])) + [u for u in api_urls if isinstance(u, str) and u.startswith(("http://", "https://"))]
                first = access.Account("account 1" if second_ok else "the logged-in account", session, crawl_first, identity_first)
                second = None
                if second_ok:
                    _, _, html2, final2 = second_session.request(second_session.landing_url)
                    crawl2 = discover_same_origin_pages(final2, html2, opener=second_session.opener, url_filter=auth.is_unsafe_url)
                    second = access.Account("account 2", second_session, list(crawl2.get("urls", [])), identity_second)
                visitor_opener = same_origin_opener(final_url)
                def visitor_fetch(url):
                    try:
                        with visitor_opener.open(Request(url, headers={"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized access-control comparison)"}), timeout=8) as response:
                            return access.Page(response.status, response.read(400_000).decode("utf-8", "replace"), response.geturl())
                    except HTTPError as exc:
                        return access.Page(exc.code, "", exc.geturl())
                    finally:
                        time.sleep(0.15)
                access_findings, access_status = access.run(final_url, first, second, second_role, list(discovered_urls) + list(public_api_urls), visitor_fetch, session)
                findings.extend(access_findings)
                tool_status["Access control"] = {"status": "completed", "detail": f"{access_status['reason']} (logged in)"}
            except Exception as exc:
                access_status = {"status": "error", "reason": f"The comparison failed ({type(exc).__name__})."}
                tool_status["Access control"] = {"status": "error", "detail": access_status["reason"]}
            if auth_info is not None and access_status:
                auth_info["access_control"] = {k: v for k, v in access_status.items() if k != "authenticated"}
        platform_tags = platforms.nuclei_tags_for(sorted(platform_hits))
        if profile in ("standard", "deep", "active"):
            nuclei_targets = nuclei_target_urls(target, discovery_status.get("urls", [target]), 5 if profile in ("deep", "active") else 6)
            nuclei_template_cap = 60 if profile in ("deep", "active") else 30
            nuclei_platform_cap = (40 if profile in ("deep", "active") else 20) if platform_tags else 0
            nuclei_timeout = (150 if profile in ("deep", "active") else 75) + (30 if platform_tags else 0)
            tool_status["Nuclei"] = {"status": "running", "detail": f"Running up to {nuclei_template_cap} safe templates" + (f" plus up to {nuclei_platform_cap} for the detected platform(s)" if nuclei_platform_cap else "") + f" across {len(nuclei_targets[:12])} same-origin URL(s); 5 requests/second maximum"}
            update_scan_progress(scan_id, 35, "Running Nuclei safe checks", tool_status)
            nuclei_findings, nuclei_status = perform_nuclei_check(target, timeout_seconds=nuclei_timeout,
                                                                  targets=nuclei_targets, max_templates=nuclei_template_cap,
                                                                  platform_tags=platform_tags, platform_max=nuclei_platform_cap,
                                                                  **({"session": session} if session_ok else {}))
            findings.extend(nuclei_findings)
            nuclei_state = nuclei_status.get("status", "completed")
            nuclei_detail = f"{nuclei_status.get('finding_count', len(nuclei_findings))} finding(s) across {nuclei_status.get('target_count', len(nuclei_targets))} same-origin URL(s)"
            if nuclei_state == "partial_timeout":
                nuclei_detail += "; time limit reached, partial findings retained"
            elif nuclei_state == "timeout":
                nuclei_detail += "; time limit reached before a report was produced"
            elif nuclei_status.get("reason"):
                nuclei_detail += "; " + str(nuclei_status["reason"])
            tool_status["Nuclei"] = {"status": nuclei_state, "detail": nuclei_detail + (" (logged in)" if nuclei_status.get("authenticated") else "")}
        if profile in ("deep", "active"):
            tool_status["Nikto"] = {"status": "running", "detail": "Checking common web-server exposures with a bounded request rate and runtime"}
            update_scan_progress(scan_id, 48, "Checking web-server exposures with Nikto", tool_status)
            nikto_findings, nikto_status = perform_nikto_check(target)
            findings.extend(nikto_findings)
            tool_status["Nikto"] = {"status": nikto_status.get("status", "completed"), "detail": f"{nikto_status.get('finding_count', len(nikto_findings))} finding(s); {nikto_status.get('reason', 'check finished')}"}
        else:
            tool_status["Nikto"] = {"status": "skipped", "detail": "Nikto runs only in Deep and Active profiles"}

        if profile in ("standard", "deep", "active"):
            tool_status["WhatWeb"] = {"status": "running", "detail": "Fingerprinting technologies from the supplied URL"}
            update_scan_progress(scan_id, 55, "Identifying website technologies", tool_status)
            whatweb_findings, whatweb_status = perform_whatweb_check(target)
            findings.extend(whatweb_findings)
            tool_status["WhatWeb"] = {"status": whatweb_status.get("status", "completed"), "detail": f"{whatweb_status.get('finding_count', len(whatweb_findings))} technology signal(s); {whatweb_status.get('reason', 'check finished')}"}
        if profile in ("standard", "deep", "active"):
            if target.lower().startswith("https://"):
                tool_status["TLS (testssl.sh)"] = {"status": "running", "detail": "Checking TLS configuration with a bounded runtime"}
                update_scan_progress(scan_id, 70, "Assessing TLS configuration", tool_status)
                tls_findings, tls_status = perform_testssl_check(target)
                findings.extend(tls_findings)
                tool_status["TLS (testssl.sh)"] = {"status": tls_status.get("status", "completed"), "detail": f"{tls_status.get('finding_count', len(tls_findings))} finding(s); {tls_status.get('reason', 'check finished')}"}
            else:
                tls_status = {"status": "skipped", "reason": "TLS assessment requires an HTTPS target"}
                tool_status["TLS (testssl.sh)"] = {"status": "skipped", "detail": "The supplied URL uses HTTP, not HTTPS"}
        else:
            tool_status["Nuclei"] = {"status": "skipped", "detail": "Not selected for this profile"}
            tool_status["WhatWeb"] = {"status": "skipped", "detail": "Not selected for this profile"}
            tool_status["TLS (testssl.sh)"] = {"status": "skipped", "detail": "Not selected for this profile"}

        tool_status["OWASP ZAP passive"] = {"status": "running", "detail": "Checking passive alerts across approved same-origin URLs"}
        update_scan_progress(scan_id, 84, "Checking optional OWASP ZAP passive alerts", tool_status)
        zap_targets = discovery_status.get("urls", [target])
        zap_findings, zap_status = perform_zap_passive_check(target, targets=zap_targets)
        findings.extend(zap_findings)
        tool_status["OWASP ZAP passive"] = {"status": zap_status.get("status", "error"), "detail": f"{zap_status.get('finding_count', len(zap_findings))} alert(s) across {zap_status.get('urls_scanned', 0)} URL(s); {zap_status.get('reason', zap_status.get('mode', 'integration status recorded'))}"}
        wapiti_status = {"status": "not_run", "reason": "Wapiti active testing is available only in the Active profile"}
        if profile == "active":
            tool_status["Wapiti active checks"] = {"status": "running", "detail": "Active tests approved; checking common injection, file, redirect, and configuration weaknesses with bounded scope and runtime"}
            update_scan_progress(scan_id, 91, "Running approved Wapiti active checks", tool_status)
            wapiti_findings, wapiti_status = perform_wapiti_check(target)
            findings.extend(wapiti_findings)
            tool_status["Wapiti active checks"] = {"status": wapiti_status.get("status", "error"), "detail": f"{wapiti_status.get('finding_count', len(wapiti_findings))} finding(s); {wapiti_status.get('reason', 'active check finished')}"}
        else:
            tool_status["Wapiti active checks"] = {"status": "skipped", "detail": "Requires the separate Active profile and explicit approval"}

        platform_hits = platforms.detect_platforms(headers, body, set_cookie_names, discovery_status.get("urls", []), [f[1] for f in whatweb_findings])
        wp_facts = planner.Facts(profile=profile, technologies=set(platform_hits))
        wp_rule = next(rule for rule in planner.RULES if rule.id == "wordpress")
        if planner.rule_applies(wp_rule, wp_facts):
            tool_status["WordPress (wpscan)"] = {"status": "running", "detail": "WordPress detected; checking core, plugins, themes and exposed files"}
            update_scan_progress(scan_id, 92, "Running WordPress checks", tool_status)
            wp_findings, wpscan_status = perform_wpscan_check(target, profile=profile)
            findings.extend(wp_findings)
            tool_status["WordPress (wpscan)"] = {"status": wpscan_status.get("status", "error"), "detail": f"{wpscan_status.get('finding_count', len(wp_findings))} finding(s); {wpscan_status.get('reason', 'check finished')}"}
        else:
            tool_status["WordPress (wpscan)"] = {"status": "skipped", "detail": "WordPress was not detected" if profile != "quick" else "Not selected for this profile"}
        cms_found = [pid for pid in DROOPESCAN_CMS if pid in platform_hits]
        if cms_found and profile != "quick":
            names = ", ".join(DROOPESCAN_CMS[c] for c in cms_found[:2])
            tool_status["CMS checks (droopescan)"] = {"status": "running", "detail": f"{names} detected; checking version, modules and default files"}
            update_scan_progress(scan_id, 93, "Running CMS-specific checks", tool_status)
            cms_findings, droopescan_status = perform_droopescan_check(target, cms_found, profile=profile)
            findings.extend(cms_findings)
            tool_status["CMS checks (droopescan)"] = {"status": droopescan_status.get("status", "error"), "detail": f"{droopescan_status.get('finding_count', len(cms_findings))} finding(s); {droopescan_status.get('reason', 'check finished')}"}
        else:
            tool_status["CMS checks (droopescan)"] = {"status": "skipped", "detail": "No Drupal, Joomla, SilverStripe or Moodle site was detected" if profile != "quick" else "Not selected for this profile"}
        if profile == "active":
            injection_urls = list(dict.fromkeys(list(discovery_status.get("urls", [target])) + list(api_urls)))
            for tool_id, runner, name in (("sqlmap", perform_sqlmap_check, "SQL injection (sqlmap)"), ("dalfox", perform_dalfox_check, "XSS (dalfox)")):
                tool_status[name] = {"status": "running", "detail": "Active tests approved; testing same-origin URLs that have query parameters"}
                update_scan_progress(scan_id, 94, f"Running approved {TOOL_CATALOG[tool_id]['label']} tests", tool_status)
                tool_findings, result = runner(target, injection_urls, **({"session": session} if session_ok else {}))
                findings.extend(tool_findings)
                tool_status[name] = {"status": result.get("status", "error"), "detail": f"{result.get('finding_count', len(tool_findings))} finding(s); {result.get('reason', 'check finished')}" + (" (logged in)" if result.get("authenticated") else "")}
                if tool_id == "sqlmap":
                    sqlmap_status = result
                else:
                    dalfox_status = result
        else:
            tool_status["SQL injection (sqlmap)"] = {"status": "skipped", "detail": "Runs only in the Active profile with explicit approval"}
            tool_status["XSS (dalfox)"] = {"status": "skipped", "detail": "Runs only in the Active profile with explicit approval"}

        # A missing tool is never installed silently: record a request naming what needed it.
        request_missing_tools(scan_id, profile, tool_status, {
            "nuclei": nuclei_status, "nikto": nikto_status, "whatweb": whatweb_status,
            "testssl": tls_status, "wapiti": wapiti_status, "ffuf": ffuf_status,
            "sqlmap": sqlmap_status, "dalfox": dalfox_status, "wpscan": wpscan_status, "droopescan": droopescan_status,
            "chromium": browser_status,
        })

        # Plan what else this target deserves, and say plainly what no engine here covers yet.
        facts = planner.Facts(
            profile=profile, https=target.lower().startswith("https://"),
            technologies=set(platform_hits), login_form=bool(signal_facts.get("login_form")), upload_form=bool(signal_facts.get("upload_form")),
            is_spa=bool(signal_facts.get("is_spa")), graphql=bool(signal_facts.get("graphql")),
            api_requires_auth=bool(signal_facts.get("api_requires_auth")), api_endpoints=int(signal_facts.get("api_endpoints") or 0),
            authenticated=bool(session_ok), auth_attempted=auth_info is not None, second_account=bool(access_status and access_status.get("second_account")),
            has_parameters=planner.has_query_parameters(discovery_status.get("urls", [])),
            url_count=len(discovery_status.get("urls", [])))
        coverage = planner.plan_coverage(facts, set(ENGINE_STAGES) | {"builtin-forms-api", "builtin-authenticated", "builtin-access-control"})
        coverage["platform_detection"] = platform_hits
        if auth_info is not None and session_ok:
            ran = ("completed", "completed_with_warnings", "partial_timeout", "timeout", "error")
            stages = [("Nuclei", nuclei_status), ("Content discovery (ffuf)", ffuf_status), ("SQL injection (sqlmap)", sqlmap_status), ("XSS (dalfox)", dalfox_status),
                      ("Nikto", nikto_status), ("WhatWeb", whatweb_status), ("TLS (testssl.sh)", tls_status), ("OWASP ZAP passive", zap_status),
                      ("Wapiti active checks", wapiti_status), ("Browser crawl (Chromium)", browser_status), ("WordPress (wpscan)", wpscan_status), ("CMS checks (droopescan)", droopescan_status)]
            auth_info["tools_with_login"] = [name for name, st in stages if st.get("status") in ran and st.get("authenticated")]
            auth_info["tools_without_login"] = [name for name, st in stages if st.get("status") in ran and not st.get("authenticated")]
            if auth_info["tools_without_login"]:
                coverage["not_covered"].append({"rule": "tools_without_login", "capability": "Logged-in coverage by external tools", "tool": "n/a",
                                                "reason": "Credentials were provided",
                                                "message": "These tools ran without your login, because they cannot use a session: " + ", ".join(auth_info["tools_without_login"])
                                                           + ". Their results cover only what is reachable without logging in."})
        if auth_info is not None and not session_ok:
            coverage["not_covered"].append({"rule": "login_failed", "capability": "Testing behind the login", "tool": "credentials",
                                            "reason": "Credentials were provided but could not be used",
                                            "message": "Credentials were provided, but " + (auth_info.get("reason") or "the login did not work") + " Everything behind the login was not tested."})
        available_templates = (nuclei_status.get("template_selection") or {}).get("platform_templates_available", {})
        for platform_id in sorted(platform_hits):
            platform = platforms.BY_ID[platform_id]
            if platform.hosted:
                coverage["not_covered"].append({"rule": "hosted_platform", "capability": f"{platform.name} platform", "tool": "n/a",
                                                "reason": f"{platform.name} was detected", "message": platform.note})
            elif (platform.nuclei_tags and nuclei_status.get("status") in ("completed", "completed_with_warnings", "partial_timeout")
                  and not sum(available_templates.get(tag, 0) for tag in platform.nuclei_tags) and not platform.dedicated_tool):
                coverage["not_covered"].append({"rule": "platform_templates", "capability": f"{platform.name}-specific checks", "tool": "nuclei",
                                                "reason": f"{platform.name} was detected",
                                                "message": f"{platform.name} was detected, but no local Nuclei templates exist for it, so only the general checks ran."})
            if platform.group != "frontend":
                findings.append(("Info", f"Platform detected: {platform.name}", target[:2048],
                                 f"Recognised from: {', '.join(platform_hits[platform_id]['evidence'])} ({platform_hits[platform_id]['confidence']} confidence).",
                                 "Keep the platform and its plugins/extensions patched, remove anything unused, and avoid advertising exact versions.", "Medium" if platform_hits[platform_id]['confidence'] == "high" else "Low"))

        update_scan_progress(scan_id, 97, "Combining and deduplicating findings", tool_status)
        deduped = []
        seen = set()
        for item in findings:
            key = (item[0], item[1], item[2])
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        findings = deduped

        gaps = assessment_gaps(tool_status)
        # Nothing secret is ever stored: scrub the password, tokens and session cookie values from everything written below.
        secrets_list = (session.secret_values() if session else []) + (second_session.secret_values() if second_session else [])
        clean = (lambda value: scrub_secrets(value, secrets_list)) if secrets_list else (lambda value: value)
        findings = [tuple(clean(part) if isinstance(part, str) else part for part in item) for item in findings]
        if auth_info is not None:
            auth_info["authenticated_pages"] = len(auth_pages)
        with connect() as conn:
            for item in findings:
                add_finding(conn, scan_id, target, *item)
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=?,progress=100,current_stage=?,tool_status=? WHERE id=?",
                (
                    "completed_with_gaps" if gaps else "completed", now(),
                    clean(json.dumps({
                        "http_status": status_code, "final_url": final_url,
                        "checks": "passive HTTP/header checks, bounded same-origin discovery, curated Nuclei checks, WhatWeb fingerprinting, optional TLS assessment, Deep/Active Nikto checks, optional ZAP passive alerts, and explicitly approved Active-profile Wapiti tests",
                        "tls_check": tls_status, "whatweb_check": whatweb_status,
                        "nuclei_check": nuclei_status, "nikto_check": nikto_status, "wapiti_check": wapiti_status, "zap_check": zap_status,
                        "endpoint_discovery": discovery_status, "ffuf_check": {k: v for k, v in ffuf_status.items() if k != "found_urls"},
                        "sqlmap_check": sqlmap_status, "dalfox_check": dalfox_status, "wpscan_check": wpscan_status, "droopescan_check": droopescan_status, "forms_api": forms_api_status, "coverage": coverage,
                        "platform_detection": platform_hits, "authentication": auth_info,
                        "finding_count": len(findings), "assessment_gaps": gaps,
                    })),
                    "Assessment complete with gaps" if gaps else "Assessment complete", clean(json.dumps(tool_status)), scan_id,
                ),
            )
    except Exception as exc:
        with connect() as conn:
            known = locals().get("session")
            hide = (lambda value: scrub_secrets(value, known.secret_values())) if known else (lambda value: value)
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=?,current_stage=?,tool_status=? WHERE id=?",
                ("failed", now(), hide(json.dumps({"error": str(exc)})), "Assessment failed", hide(json.dumps(tool_status)), scan_id),
            )


def max_concurrent_scans() -> int:
    """Bound concurrent workers; allow a small local-operator override."""
    try:
        configured = int(os.environ.get("DKCISSP_MAX_CONCURRENT_SCANS", "2"))
    except (TypeError, ValueError):
        configured = 2
    return max(1, min(configured, 8))


def running_scan_count(conn) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0])


def start_scan(target: str, profile: str, auth_settings=None, second_account=None) -> int:
    with connect() as conn:
        # Serialize the capacity check and insert so simultaneous requests cannot
        # all observe the same free slot and exceed the configured worker limit.
        conn.execute("BEGIN IMMEDIATE")
        active_scans = running_scan_count(conn)
        limit = max_concurrent_scans()
        if active_scans >= limit:
            raise HTTPException(429, f"Scanner capacity reached ({active_scans}/{limit} assessments running). Wait for a scan to finish before starting another.")
        cursor = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at,progress,current_stage,tool_status) VALUES(?,?,?,?,?,?,?)",
            (target, profile, "running", now(), 1, "Queued", json.dumps({})),
        )
        scan_id = cursor.lastrowid
    # auth_settings (if any) travels only in this thread's arguments: it is never written to the database.
    threading.Thread(target=perform_scan, args=(scan_id, target, profile) + ((auth_settings,) + ((second_account,) if second_account else ()) if auth_settings else ()), daemon=True).start()
    return scan_id


def auth_settings_from_request(config: "AuthConfig", target: str) -> "auth.AuthSettings":
    """Validate a login configuration and turn it into in-memory settings. Messages never contain a secret."""
    secret = lambda v: v.get_secret_value()
    settings = auth.AuthSettings(
        kind=config.kind, login_url=config.login_url.strip(), username=config.username, password=secret(config.password),
        username_field=config.username_field, password_field=config.password_field, token=secret(config.token), cookie=secret(config.cookie),
        header_name=config.header_name, header_value=secret(config.header_value), verify_url=config.verify_url.strip(),
        success_text=config.success_text, logged_out_text=config.logged_out_text, identity_text=config.identity_text.strip())
    needs = {"form": settings.username and settings.password, "json": settings.login_url and settings.username and settings.password,
             "bearer": settings.token, "cookie": settings.cookie, "header": settings.header_name and settings.header_value,
             "basic": settings.username and settings.password}
    labels = {"form": "a username and password", "json": "the login endpoint address, a username and a password", "bearer": "a token",
              "cookie": "a cookie value", "header": "a header name and value", "basic": "a username and password"}
    if not needs[settings.kind]:
        raise HTTPException(400, f"This login type needs {labels[settings.kind]}.")
    for label, url in (("login page", settings.login_url), ("verification page", settings.verify_url)):
        if url and (not url.lower().startswith(("http://", "https://")) or not auth.same_origin(url, target)):
            raise HTTPException(400, f"The {label} must be on the same site as the target. Credentials are never sent to another site.")
    if "\r" in settings.header_name or "\n" in settings.header_name or any(ch in settings.header_value + settings.cookie + settings.token for ch in "\r\n"):
        raise HTTPException(400, "Header values cannot contain line breaks.")
    return settings


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
                        # Scheduled work must respect the same worker cap as manual requests.
                        if running_scan_count(conn) >= max_concurrent_scans():
                            continue
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


@app.get("/api/assets")
def list_assets():
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM assets ORDER BY last_seen DESC, id DESC"
        )]


@app.post("/api/assets")
def create_asset(request: AssetRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to inventory this asset.")
    target = validate_target(request.target)
    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower()
    # Canonicalize host casing and remove the default port; preserve non-root paths.
    port = parsed.port
    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port and not ((parsed.scheme.lower() == "http" and port == 80) or
                     (parsed.scheme.lower() == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    normalized = parsed.scheme.lower() + "://" + netloc + (parsed.path.rstrip("/") or "")
    if parsed.query:
        normalized += "?" + parsed.query
    if parsed.fragment:
        normalized += "#" + parsed.fragment
    timestamp = now()
    asset_type = "ip_address" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname) else "web_url"
    with connect() as conn:
        existing = conn.execute("SELECT * FROM assets WHERE target=?", (normalized,)).fetchone()
        if existing:
            conn.execute("UPDATE assets SET last_seen=?, notes=? WHERE id=?",
                         (timestamp, request.notes, existing["id"]))
            row = conn.execute("SELECT * FROM assets WHERE id=?", (existing["id"],)).fetchone()
            return {**dict(row), "created": False}
        initial_decision = "approved" if request.scope_status == "in_scope" else ("rejected" if request.scope_status == "out_of_scope" else "pending")
        cursor = conn.execute(
            """INSERT INTO assets(target,asset_type,scope_status,discovery_source,first_seen,last_seen,notes,reviewed_at,review_decision)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (normalized, asset_type, request.scope_status, "manual", timestamp, timestamp, request.notes,
             timestamp if initial_decision in {"approved", "rejected"} else None, initial_decision),
        )
        row = conn.execute("SELECT * FROM assets WHERE id=?", (cursor.lastrowid,)).fetchone()
        return {**dict(row), "created": True}


@app.patch("/api/assets/{asset_id}/scope")
def update_asset_scope(asset_id: int, request: AssetScopeUpdate):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to change asset scope.")
    with connect() as conn:
        existing = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "Asset not found")
        discovered = existing["discovery_source"] != "manual"
        approval_reference = (request.approval_reference or "").strip()
        if discovered and request.scope_status == "in_scope" and not approval_reference:
            raise HTTPException(400, "Discovered candidates require an approval or change-ticket reference before entering In Scope.")
        timestamp = now()
        decision = "approved" if request.scope_status == "in_scope" else ("rejected" if request.scope_status == "out_of_scope" else "pending")
        reviewed_at = timestamp if decision in {"approved", "rejected"} else None
        notes = existing["notes"] if request.notes is None else request.notes
        conn.execute("""UPDATE assets SET scope_status=?,notes=?,approval_reference=?,reviewed_at=?,
            review_decision=?,last_seen=? WHERE id=?""",
            (request.scope_status, notes, approval_reference if decision == "approved" else "", reviewed_at, decision, timestamp, asset_id))
        return dict(conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone())



def valid_dns_name(hostname: str) -> bool:
    if len(hostname) > 253 or not hostname or hostname.endswith("."):
        return False
    labels = hostname.split(".")
    return all(1 <= len(label) <= 63 and
               re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
               for label in labels)


def query_certificate_transparency(root_domain: str, max_results: int) -> list[str]:
    """Fetch a bounded certificate-transparency result set; never probes discovered hosts."""
    endpoint = "https://crt.sh/?" + urlencode({"q": "%25." + root_domain, "output": "json"})
    req = Request(endpoint, headers={
        "Accept": "application/json",
        "User-Agent": "DKCISSP-WebSecurityScanner/0.1 (passive authorized inventory)",
    })
    with urlopen(req, timeout=12) as response:
        payload = response.read(1_000_001)
    if len(payload) > 1_000_000:
        raise HTTPException(502, "Certificate-transparency response exceeded the 1 MB safety limit.")
    try:
        records = json.loads(payload.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(502, "Certificate-transparency service returned invalid JSON.")
    if not isinstance(records, list):
        raise HTTPException(502, "Certificate-transparency service returned an unexpected response.")
    candidates = set()
    suffix = "." + root_domain
    for record in records:
        if not isinstance(record, dict):
            continue
        for raw_name in str(record.get("name_value", "") or record.get("common_name", "")).splitlines():
            hostname = raw_name.strip().lower().rstrip(".")
            if hostname.startswith("*."):
                hostname = hostname[2:]
            if hostname == root_domain or hostname.endswith(suffix):
                if valid_dns_name(hostname):
                    candidates.add(hostname)
    return sorted(name for name in candidates if name != root_domain)[:max_results]


@app.post("/api/assets/{asset_id}/discover")
def discover_subdomains(asset_id: int, request: AssetDiscoveryRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to discover subdomains for this asset.")
    with connect() as conn:
        root = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
    if not root:
        raise HTTPException(404, "Root asset not found")
    if root["scope_status"] != "in_scope":
        raise HTTPException(400, "Only an explicitly approved In Scope root asset can be used for discovery.")
    parsed = urlparse(root["target"])
    root_domain = (parsed.hostname or "").lower().rstrip(".")
    if not valid_dns_name(root_domain) or "." not in root_domain:
        raise HTTPException(400, "Passive subdomain discovery requires a fully qualified DNS root, not an IP address or local hostname.")
    try:
        candidates = query_certificate_transparency(root_domain, request.max_results)
    except HTTPException:
        raise
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise HTTPException(502, "Passive discovery could not reach the certificate-transparency service.") from exc
    timestamp = now()
    created = 0
    with connect() as conn:
        for hostname in candidates:
            target = "https://" + hostname
            exists = conn.execute("SELECT id FROM assets WHERE target=?", (target,)).fetchone()
            if exists:
                conn.execute("UPDATE assets SET last_seen=? WHERE id=?", (timestamp, exists["id"]))
                continue
            conn.execute(
                """INSERT INTO assets(target,asset_type,scope_status,discovery_source,first_seen,last_seen,notes)
                   VALUES(?,?,?,?,?,?,?)""",
                (target, "subdomain", "needs_review", "crt.sh", timestamp, timestamp,
                 "Passive certificate-transparency candidate; verify ownership and scope before scanning."),
            )
            created += 1
    return {"root_asset_id": asset_id, "source": "crt.sh", "candidates_found": len(candidates),
            "new_assets_added": created, "scope_status": "needs_review",
            "scans_started": 0, "message": "Candidates were added for review only; no hosts were contacted or scanned."}


@app.post("/api/scans")
def create_scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this target.")
    if request.profile == "active" and not request.active_testing_approved:
        raise HTTPException(400, "Active profile requires the separate active-testing approval confirmation.")
    target = validate_target(request.target)
    auth_settings = None
    if request.auth:
        if not request.authenticated_testing_approved:
            raise HTTPException(400, "An authenticated scan needs the separate confirmation that the scanner may act as this user.")
        auth_settings = auth_settings_from_request(request.auth, target)
    elif request.auth_second:
        raise HTTPException(400, "A second account needs the first account's login as well.")
    second_account = (auth_settings_from_request(request.auth_second, target), request.second_account_role) if request.auth_second and auth_settings else None
    # Simple one-URL workflow: the explicit authorization confirmation is enough for any entered target.
    with connect() as conn:
        active_scans = running_scan_count(conn)
    limit = max_concurrent_scans()
    if active_scans >= limit:
        raise HTTPException(429, f"Scanner capacity reached ({active_scans}/{limit} assessments running). Wait for a scan to finish before starting another.")
    if second_account:
        scan_id = start_scan(target, request.profile, auth_settings, second_account)
    else:
        scan_id = start_scan(target, request.profile, auth_settings) if auth_settings else start_scan(target, request.profile)
    return {
        "id": scan_id, "status": "running", "profile": request.profile,
        "message": "Assessment started with the selected profile. Standard adds bounded discovery and safe Nuclei checks; Deep adds bounded Nikto checks; Active additionally runs explicitly approved Wapiti payload tests. Optional ZAP passive alerts require a healthy local API.",
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
        requests = [tool_request_view(row) for row in conn.execute(
            "SELECT * FROM tool_requests WHERE scan_id=? ORDER BY id", (scan_id,))]
        return {"scan": dict(scan), "findings": findings, "tool_requests": requests}


def finding_fingerprint(finding: dict) -> tuple[str, str]:
    """Match repeat findings by normalized title and same-origin path, ignoring query noise."""
    title = re.sub(r"\s+", " ", str(finding.get("title", "")).strip().lower())
    parsed = urlparse(str(finding.get("affected_url", "")))
    path = re.sub(r"/{2,}", "/", parsed.path or "/").rstrip("/") or "/"
    return title, path


def finding_risk_points(severity: str) -> int:
    return {"critical": 10, "high": 8, "medium": 4, "low": 1, "info": 0,
            "informational": 0}.get(str(severity).strip().lower(), 0)


@app.get("/api/scans/{scan_id}/comparison")
def compare_scan(scan_id: int, baseline_id: int | None = None):
    """Compare completed scans of the same normalized target; this is a heuristic, not proof of remediation."""
    with connect() as conn:
        current = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not current:
            raise HTTPException(404, "Scan not found")
        if current["status"] not in FINISHED_SCAN_STATUSES:
            raise HTTPException(409, "Only completed scans can be compared")
        current_target = validate_target(current["target"])
        if baseline_id is None:
            baseline = conn.execute(
                """SELECT * FROM scans WHERE id<>? AND status IN ('completed','completed_with_gaps') AND profile=?
                ORDER BY COALESCE(finished_at,created_at) DESC,id DESC""",
                (scan_id, current["profile"]),
            ).fetchall()
            baseline = next((row for row in baseline if validate_target(row["target"]) == current_target), None)
        else:
            baseline = conn.execute("SELECT * FROM scans WHERE id=?", (baseline_id,)).fetchone()
            if not baseline:
                raise HTTPException(404, "Baseline scan not found")
            if baseline["status"] not in FINISHED_SCAN_STATUSES:
                raise HTTPException(409, "Baseline scan must be completed")
            if baseline["id"] == scan_id:
                raise HTTPException(400, "A scan cannot be compared with itself")
            if validate_target(baseline["target"]) != current_target:
                raise HTTPException(400, "Scans must use the same normalized target URL")
        if baseline is None:
            return {"scan_id": scan_id, "baseline": None, "target": current_target,
                    "message": "No earlier completed scan of this target and profile is available. Run another scan after remediation to measure change.",
                    "summary": {"new": 0, "resolved": 0, "persistent": 0, "severity_increased": 0,
                                "severity_decreased": 0, "risk_points_before": 0, "risk_points_after": 0,
                                "risk_reduction_percent": None}, "new_findings": [], "resolved_findings": [],
                    "persistent_findings": [], "limitations": ["The comparison matches normalized title and URL path; it is heuristic.",
                    "A resolved match means the detector did not report it in this scan, not proof that the underlying issue is fixed."]}
        baseline_findings = [dict(row) for row in conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (baseline["id"],))]
        current_findings = [dict(row) for row in conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))]
    from collections import defaultdict, deque
    old_by_key = defaultdict(deque)
    new_by_key = defaultdict(deque)
    for finding in baseline_findings:
        old_by_key[finding_fingerprint(finding)].append(finding)
    for finding in current_findings:
        new_by_key[finding_fingerprint(finding)].append(finding)
    new_items, resolved_items, persistent_items = [], [], []
    severity_increased = severity_decreased = 0
    for key in set(old_by_key) | set(new_by_key):
        old_items, fresh_items = old_by_key[key], new_by_key[key]
        while old_items and fresh_items:
            old, fresh = old_items.popleft(), fresh_items.popleft()
            before, after = finding_risk_points(old["severity"]), finding_risk_points(fresh["severity"])
            if after > before: severity_increased += 1
            elif after < before: severity_decreased += 1
            persistent_items.append({"title": fresh["title"], "affected_url": fresh["affected_url"],
                                     "severity_before": old["severity"], "severity_after": fresh["severity"],
                                     "severity_changed": old["severity"] != fresh["severity"],
                                     "risk_points_before": before, "risk_points_after": after,
                                     "finding_id": fresh["id"]})
        resolved_items.extend({"title": item["title"], "affected_url": item["affected_url"],
                               "severity": item["severity"], "finding_id": item["id"]} for item in old_items)
        new_items.extend({"title": item["title"], "affected_url": item["affected_url"],
                          "severity": item["severity"], "finding_id": item["id"]} for item in fresh_items)
    before_points = sum(finding_risk_points(f["severity"]) for f in baseline_findings)
    after_points = sum(finding_risk_points(f["severity"]) for f in current_findings)
    reduction = round((before_points - after_points) / before_points * 100, 1) if before_points else (100.0 if after_points == 0 else None)
    gap_caveats = ["Scan #%d finished with assessment gaps (a tool was unavailable, declined, timed out or errored), so absent findings may reflect untested areas, not fixes." % row["id"]
                   for row in (current, baseline) if row["status"] == "completed_with_gaps"]
    return {"scan_id": scan_id, "baseline": {"scan_id": baseline["id"], "target": baseline["target"],
            "profile": baseline["profile"], "finished_at": baseline["finished_at"]},
            "target": current_target, "profile": current["profile"], "finished_at": current["finished_at"],
            "summary": {"new": len(new_items), "resolved": len(resolved_items), "persistent": len(persistent_items),
                        "severity_increased": severity_increased, "severity_decreased": severity_decreased,
                        "risk_points_before": before_points, "risk_points_after": after_points,
                        "risk_reduction_percent": reduction},
            "new_findings": new_items, "resolved_findings": resolved_items,
            "persistent_findings": persistent_items,
            "limitations": ["Finding matching uses normalized title and URL path; renamed detections may appear new or resolved.",
                            "Risk points are an internal prioritization heuristic, not CVSS or a formal risk measurement.",
                            "A finding absent from a later scan is not proof that the underlying vulnerability is remediated.",
                            "For a meaningful comparison, use the same target and assessment profile after remediation."] + gap_caveats}


@app.patch("/api/findings/{finding_id}/lifecycle")
def update_finding_lifecycle(finding_id: int, request: FindingLifecycleUpdate):
    with connect() as conn:
        row = conn.execute("SELECT id FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Finding not found")
        conn.execute(
            "UPDATE findings SET lifecycle_status=?,lifecycle_notes=?,lifecycle_updated_at=? WHERE id=?",
            (request.status, request.notes.strip(), now(), finding_id),
        )
        updated = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(updated)


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
        "lifecycle_status", "lifecycle_notes", "lifecycle_updated_at",
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


@app.get("/api/export/findings.html", response_class=HTMLResponse)
def export_findings_html():
    fields = [
        "id", "scan_id", "target", "severity", "title", "affected_url",
        "evidence", "remediation", "confidence", "discovered_at",
        "lifecycle_status", "lifecycle_notes", "lifecycle_updated_at",
    ]
    with connect() as conn:
        findings = [dict(row) for row in conn.execute(
            "SELECT " + ",".join(fields) + " FROM findings ORDER BY id DESC"
        )]
    esc = lambda value: html.escape("" if value is None else str(value), quote=True)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    counts = {}
    for finding in findings:
        severity = str(finding.get("severity", "Unknown"))
        counts[severity] = counts.get(severity, 0) + 1
    summary_cards = "".join(
        f'<div class="metric"><span>{esc(label)}</span><strong>{count}</strong></div>'
        for label, count in [("Total findings", len(findings))] + sorted(counts.items(), key=lambda item: severity_order.get(item[0].lower(), 5))
    )
    if findings:
        rows = []
        for finding in findings:
            rows.append("<tr>" + "".join(
                f"<td>{esc(finding.get(key, ''))}</td>" for key in fields
            ) + "</tr>")
        table = "<div class=\"table-wrap\"><table><thead><tr>" + "".join(
            f"<th>{esc(field.replace('_', ' ').title())}</th>" for field in fields
        ) + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    else:
        table = '<p class="empty">No findings have been recorded yet.</p>'
    generated = esc(now())
    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DKCISSP Web Security Scanner — Findings Report</title>
<style>
:root{{color-scheme:light;--navy:#10213b;--red:#c6283d;--line:#dbe2ea;--muted:#5b6878}}
*{{box-sizing:border-box}}body{{margin:0;background:#f4f6f9;color:#172033;font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1500px;margin:32px auto;padding:0 20px}}header{{background:var(--navy);color:white;padding:28px;border-radius:14px}}
.brand{{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#d9e3f2}}h1{{margin:8px 0;font-size:28px}}.meta{{color:#d9e3f2}}
.metrics{{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}}.metric{{background:white;border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:140px;display:grid;gap:4px}}.metric span{{color:var(--muted);font-size:12px}}.metric strong{{font-size:24px;color:var(--navy)}}
.table-wrap{{overflow:auto;background:white;border:1px solid var(--line);border-radius:10px}}table{{border-collapse:collapse;width:100%;min-width:1200px}}th,td{{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line);max-width:380px;overflow-wrap:anywhere}}th{{background:#eaf0f7;color:var(--navy);position:sticky;top:0}}tr:last-child td{{border-bottom:0}}.empty{{background:white;padding:24px;border-radius:10px;color:var(--muted)}}footer{{color:var(--muted);margin:18px 0}}.actions{{display:flex;justify-content:flex-end;margin:14px 0}}button{{background:var(--red);color:white;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer}}@media print{{body{{background:white}}main{{max-width:none;margin:0;padding:0}}header{{border-radius:0;print-color-adjust:exact;-webkit-print-color-adjust:exact}}.actions{{display:none}}.table-wrap{{overflow:visible}}table{{min-width:0;font-size:9px}}th,td{{padding:5px;max-width:none}}th{{position:static}}}}
</style></head><body><main><header><div class="brand">DKCISSP — Where Security Becomes Simple</div><h1>Website Security Findings Report</h1><div class="meta">Generated {generated} · {len(findings)} finding(s)</div></header>
<section class="metrics" aria-label="Finding summary">{summary_cards}</section><div class="actions"><button onclick="window.print()">Print / Save as PDF</button></div><h2>Findings and remediation</h2>{table}
<footer>Assessment signals require validation in context. A finding is not, by itself, proof of exploitability. Handle this report as potentially sensitive security information.</footer></main></body></html>'''
    return HTMLResponse(
        document,
        headers={"Content-Disposition": 'attachment; filename="dkcissp-findings-report.html"',
                 "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"},
    )


@app.post("/api/schedules")
def create_schedule(request: ScheduleRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to test this target.")
    if request.profile == "active":
        raise HTTPException(400, "Active payload testing cannot be scheduled; start it manually with explicit approval.")
    if request.auth or request.auth_second:
        raise HTTPException(400, "Authenticated scans cannot be scheduled: credentials are never stored.")
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
    "nuclei": {"label": "Nuclei", "binary": "nuclei", "package": "nuclei", "version_args": ["-version"], "purpose": "Template-based checks for known exposures and misconfigurations"},
    "nikto": {"label": "Nikto", "binary": "nikto", "package": "nikto", "version_args": ["-Version"], "purpose": "Deep-profile checks for common web-server files and misconfigurations"},
    "sqlmap": {"label": "sqlmap", "binary": "sqlmap", "package": "sqlmap", "version_args": ["--version"], "purpose": "Active SQL injection testing of URL parameters (Active profile only)"},
    "dalfox": {"label": "dalfox", "binary": "dalfox", "package": "dalfox", "version_args": ["version"], "purpose": "Active cross-site scripting testing of URL parameters (Active profile only)"},
    "droopescan": {"label": "droopescan", "binary": "droopescan", "package": "droopescan", "version_args": ["stats"], "version_regex": r"v\d+(?:\.\d+)+", "purpose": "Drupal, Joomla, SilverStripe and Moodle version, module and exposed-file checks (only when one of them is detected)"},
    "wpscan": {"label": "WPScan", "binary": "wpscan", "package": "wpscan", "version_args": ["--version", "--no-banner"], "purpose": "WordPress core, plugin, theme and user-exposure checks (only when WordPress is detected)"},
    "ffuf": {"label": "ffuf", "binary": "ffuf", "package": "ffuf", "version_args": ["-V"], "purpose": "Hidden content and path discovery with a built-in wordlist"},
    "chromium": {"label": "Chromium (headless)", "binary": "chromium", "package": "chromium", "version_args": ["--version"], "purpose": "Browser-based crawling of JavaScript single-page apps (renders pages, reads links, forms and API calls; GET only)"},
    "wapiti": {"label": "Wapiti", "binary": "wapiti", "package": "wapiti", "version_args": ["--version"], "purpose": "Explicitly approved active tests for web-application vulnerabilities"},
}


def _tool_version(tool: dict) -> str | None:
    try:
        result = subprocess.run(
            [tool["binary"], *tool["version_args"]],
            capture_output=True, text=True, timeout=4, check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        full = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if tool.get("version_regex"):  # tools whose first output line is a banner rather than a version
            match = re.search(tool["version_regex"], full)
            if match:
                return match.group(0)[:180]
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
    # ZAP executable and API are separate checks; an unrelated service on its port is not ZAP.
    zap_api = diagnose_zap_api()
    for item in tools:
        if item["id"] == "zaproxy":
            item["service_status"] = zap_api["status"]
            item["service_message"] = zap_api["message"]
            item["service_endpoint"] = zap_api.get("endpoint")
            item["service_version"] = zap_api.get("version")
            # Some ZAP package launchers do not emit a usable CLI version string.
            # A successful authenticated API version response is stronger evidence
            # that the actual scanner service is ready than the launcher output.
            if item["installed"] and zap_api["status"] == "ready":
                item["status"] = "ready"
                item["version"] = item["version"] or f"OWASP ZAP API {zap_api.get('version', 'available')}"
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


# ---------------------------------------------------------------------------
# Tool approval flow
#
# A scan never installs software on its own. When a tool a profile needs is missing, the scan
# records a request that names what needed it, keeps going, and finishes with a gap. The assessor
# then approves the install (the missing stage runs and its findings are merged into the same scan)
# or declines it (the report states that the area was not assessed, and why).
# Only tools in TOOL_CATALOG that have a scan stage here can be requested; package names never
# come from scan output or user input.
# ---------------------------------------------------------------------------
ENGINE_STAGES = {
    "nuclei": {"stage": "Nuclei", "summary_key": "nuclei_check"},
    "nikto": {"stage": "Nikto", "summary_key": "nikto_check"},
    "whatweb": {"stage": "WhatWeb", "summary_key": "whatweb_check"},
    "testssl": {"stage": "TLS (testssl.sh)", "summary_key": "tls_check"},
    "wapiti": {"stage": "Wapiti active checks", "summary_key": "wapiti_check"},
    "ffuf": {"stage": "Content discovery (ffuf)", "summary_key": "ffuf_check"},
    "wpscan": {"stage": "WordPress (wpscan)", "summary_key": "wpscan_check"},
    "droopescan": {"stage": "CMS checks (droopescan)", "summary_key": "droopescan_check"},
    "sqlmap": {"stage": "SQL injection (sqlmap)", "summary_key": "sqlmap_check"},
    "dalfox": {"stage": "XSS (dalfox)", "summary_key": "dalfox_check"},
    "chromium": {"stage": "Browser crawl (Chromium)", "summary_key": "browser_crawl"},
}
LOCAL_CLIENTS = {"127.0.0.1", "::1", "testclient"}


def _spawn(function, *args) -> None:
    """Run background work on a thread. Tests replace this to run the work inline."""
    threading.Thread(target=function, args=args, daemon=True).start()


def tool_request_view(row) -> dict:
    spec = TOOL_CATALOG.get(row["tool_id"], {})
    return {
        **dict(row), "tool_name": spec.get("label", row["tool_id"]), "purpose": spec.get("purpose", ""),
        "package": spec.get("package", ""), "install_source": "Kali package repository (apt)",
    }


def _trigger_text(row) -> str:
    return str(row["trigger_detail"] or "the selected assessment profile")


def create_tool_request(scan_id: int, tool_id: str, trigger_type: str, trigger_detail: str, finding_id: int | None = None):
    if tool_id not in ENGINE_STAGES or tool_id not in TOOL_CATALOG:
        raise ValueError("Tool is not in the approved install allow-list.")
    with connect() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO tool_requests(scan_id,tool_id,trigger_type,trigger_detail,finding_id,created_at)
            VALUES(?,?,?,?,?,?)""",
            (scan_id, tool_id, trigger_type, trigger_detail[:500], finding_id, now()),
        )
        return conn.execute("SELECT * FROM tool_requests WHERE scan_id=? AND tool_id=?", (scan_id, tool_id)).fetchone()


def request_missing_tools(scan_id: int, profile: str, tool_status: dict, statuses: dict) -> list[int]:
    """Turn 'tool not installed' stage results into approval requests and mark the stage accordingly."""
    created = []
    for tool_id, status in statuses.items():
        spec = TOOL_CATALOG.get(tool_id)
        stage = ENGINE_STAGES.get(tool_id)
        if not spec or not stage or (status or {}).get("status") != "unavailable" or shutil.which(spec["binary"]):
            continue
        trigger = f"the {profile.title()} profile includes {spec['purpose'].lower()}"
        row = create_tool_request(scan_id, tool_id, "profile", trigger)
        tool_status[stage["stage"]] = {
            "status": "needs_tool_approval",
            "detail": f"{spec['label']} is not installed. Waiting for your approval to install it. Triggered by: {trigger}.",
        }
        created.append(row["id"])
    return created


def _update_scan_after_tool(scan_id: int, stage_name: str, state: dict, summary_key: str | None = None,
                            summary_value: dict | None = None) -> None:
    """Record one stage's new state and recompute the scan's gaps and overall status."""
    with connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return
        try:
            tools = json.loads(scan["tool_status"] or "{}")
        except ValueError:
            tools = {}
        try:
            summary = json.loads(scan["summary"] or "{}")
        except ValueError:
            summary = {}
        tools[stage_name] = state
        if summary_key:
            summary[summary_key] = summary_value or {}
        gaps = assessment_gaps(tools)
        summary["assessment_gaps"] = gaps
        summary["finding_count"] = conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id=?", (scan_id,)).fetchone()[0]
        status = scan["status"]
        stage_label = scan["current_stage"]
        if status in FINISHED_SCAN_STATUSES:
            status = "completed_with_gaps" if gaps else "completed"
            stage_label = "Assessment complete with gaps" if gaps else "Assessment complete"
        conn.execute("UPDATE scans SET status=?,summary=?,tool_status=?,current_stage=? WHERE id=?",
                     (status, json.dumps(summary), json.dumps(tools), stage_label, scan_id))


def _set_request(request_id: int, **fields) -> None:
    columns = ", ".join(f"{name}=?" for name in fields)
    with connect() as conn:
        conn.execute(f"UPDATE tool_requests SET {columns} WHERE id=?", (*fields.values(), request_id))


def _wait_until_scan_settles(scan_id: int, limit_seconds: int = 1200) -> None:
    deadline = time.monotonic() + limit_seconds
    while time.monotonic() < deadline:
        with connect() as conn:
            row = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row or row["status"] != "running":
            return
        time.sleep(2)


def install_package(tool_id: str) -> tuple[bool, str]:
    """Install one allow-listed tool from the Kali repositories. Returns (ok, message)."""
    spec = TOOL_CATALOG[tool_id]
    manual = f"sudo apt update && sudo apt install {spec['package']}"
    if shutil.which(spec["binary"]):
        return True, f"{spec['label']} is already installed."
    apt = shutil.which("apt-get")
    pkexec = shutil.which("pkexec")
    sudo = shutil.which("sudo")
    if not apt:
        return False, f"Automatic installation needs apt-get. Install it yourself with: {manual}"
    if os.geteuid() == 0:
        prefix = []
    elif pkexec:
        prefix = [pkexec]
    elif sudo:
        prefix = [sudo, "-n"]  # non-interactive: fails fast instead of waiting for a password
    else:
        return False, f"No privilege helper (pkexec or sudo) was found. Install it yourself with: {manual}"
    try:
        result = subprocess.run([*prefix, apt, "install", "-y", "--no-install-recommends", spec["package"]],
                                capture_output=True, text=True, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        return False, f"The package installation timed out. Check the package manager, or run: {manual}"
    except OSError as exc:
        return False, f"Could not start the package manager ({exc}). Run: {manual}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "Package installation failed").strip()[-400:]
        return False, f"Installation failed: {detail}. You can also run: {manual}"
    if not shutil.which(spec["binary"]):
        return False, f"The package installed but {spec['binary']} was not found on PATH. Run: {manual}"
    return True, f"{spec['label']} was installed from the Kali repository."


def run_engine_stage(tool_id: str, target: str, profile: str, urls: list[str], platform_ids=None):
    """Run one engine stage on its own. Returns (findings, engine_status, stage_state)."""
    if tool_id == "nuclei":
        deep = profile in ("deep", "active")
        tags = platforms.nuclei_tags_for(sorted(platform_ids or []))
        findings, status = perform_nuclei_check(target, timeout_seconds=(150 if deep else 75) + (30 if tags else 0),
                                                targets=nuclei_target_urls(target, urls, 5 if deep else 6),
                                                max_templates=60 if deep else 30, platform_tags=tags,
                                                platform_max=(40 if deep else 20) if tags else 0)
        label = "finding(s)"
    elif tool_id == "nikto":
        findings, status = perform_nikto_check(target)
        label = "finding(s)"
    elif tool_id == "whatweb":
        findings, status = perform_whatweb_check(target)
        label = "technology signal(s)"
    elif tool_id == "testssl":
        if target.lower().startswith("https://"):
            findings, status = perform_testssl_check(target)
        else:
            findings, status = [], {"status": "skipped", "reason": "TLS assessment requires an HTTPS target"}
        label = "finding(s)"
    elif tool_id == "wpscan":
        findings, status = perform_wpscan_check(target, profile=profile)
        label = "finding(s)"
    elif tool_id == "droopescan":
        cms_ids = [pid for pid in (platform_ids or []) if pid in DROOPESCAN_CMS]
        if not cms_ids:
            findings, status = [], {"status": "skipped", "reason": "No Drupal, Joomla, SilverStripe or Moodle site was detected"}
        else:
            findings, status = perform_droopescan_check(target, cms_ids, profile=profile)
        label = "finding(s)"
    elif tool_id in ("sqlmap", "dalfox"):
        runner = perform_sqlmap_check if tool_id == "sqlmap" else perform_dalfox_check
        if profile != "active":
            findings, status = [], {"status": "skipped", "reason": f"{TOOL_CATALOG[tool_id]['label']} runs only in the Active profile"}
        else:
            findings, status = runner(target, urls)
        label = "finding(s)"
    elif tool_id == "ffuf":
        if profile not in ("deep", "active"):
            findings, status = [], {"status": "skipped", "reason": "Content discovery runs in the Deep and Active profiles"}
        else:
            extras = signals.platform_paths(platform_ids)
            findings, status = perform_ffuf_check(target, timeout_seconds=(90 if profile == "active" else 60) + (20 if extras else 0), extra_paths=extras)
        label = "finding(s)"
    elif tool_id == "chromium":
        findings, status = perform_browser_crawl(target, [target], profile=profile)
        label = "finding(s)"
    elif tool_id == "wapiti":
        if profile != "active":
            findings, status = [], {"status": "skipped", "reason": "Wapiti runs only in the Active profile"}
        else:
            findings, status = perform_wapiti_check(target)
        label = "finding(s)"
    else:
        raise ValueError("Unsupported tool")
    detail = f"{status.get('finding_count', len(findings))} {label}; {status.get('reason', 'check finished')}"
    return findings, status, {"status": status.get("status", "completed"), "detail": detail}


def apply_tool_decision(request_id: int, wait: bool = True) -> None:
    """Carry out an approved or declined request. Runs on a background thread."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM tool_requests WHERE id=?", (request_id,)).fetchone()
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (row["scan_id"],)).fetchone() if row else None
    if not row or not scan:
        return
    tool_id, scan_id = row["tool_id"], row["scan_id"]
    spec, stage = TOOL_CATALOG[tool_id], ENGINE_STAGES[tool_id]
    if wait:
        _wait_until_scan_settles(scan_id)
        with connect() as conn:  # the scan may have finished and changed while we waited
            scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row["status"] == "declined":
        message = (f"{spec['label']} was not installed: installation was not approved by the assessor. "
                   f"Triggered by: {_trigger_text(row)}. This area was not assessed.")
        _update_scan_after_tool(scan_id, stage["stage"], {"status": "skipped_install_not_permitted", "detail": message})
        _set_request(request_id, result_message=message)
        return
    try:
        _set_request(request_id, status="installing")
        _update_scan_after_tool(scan_id, stage["stage"], {"status": "installing", "detail": f"Installing {spec['label']} from the Kali repository…"})
        ok, message = install_package(tool_id)
        if not ok:
            _set_request(request_id, status="failed", result_message=message)
            _update_scan_after_tool(scan_id, stage["stage"], {"status": "install_failed", "detail": message})
            return
        _set_request(request_id, status="running", result_message=message)
        _update_scan_after_tool(scan_id, stage["stage"], {"status": "running", "detail": f"{spec['label']} installed; running its checks…"})
        try:
            summary = json.loads(scan["summary"] or "{}")
        except ValueError:
            summary = {}
        urls = (summary.get("endpoint_discovery") or {}).get("urls") or [scan["target"]]
        findings, engine_status, state = run_engine_stage(tool_id, scan["target"], scan["profile"], urls,
                                                          platform_ids=list((summary.get("platform_detection") or {}).keys()))
        with connect() as conn:
            known = {(r["severity"], r["title"], r["affected_url"]) for r in conn.execute(
                "SELECT severity,title,affected_url FROM findings WHERE scan_id=?", (scan_id,))}
            for item in findings:
                if (item[0], item[1], item[2]) not in known:
                    add_finding(conn, scan_id, scan["target"], *item)
        _update_scan_after_tool(scan_id, stage["stage"], state, stage["summary_key"], engine_status)
        _set_request(request_id, status="completed", result_message=f"{message} {state['detail']}")
    except Exception as exc:  # never leave a request stuck in 'installing'
        message = f"The tool stage failed: {str(exc)[:300]}"
        _set_request(request_id, status="failed", result_message=message)
        _update_scan_after_tool(scan_id, stage["stage"], {"status": "install_failed", "detail": message})


class ToolDecision(BaseModel):
    decision: str = Field(pattern="^(approve|decline)$")


@app.get("/api/tool-requests")
def list_tool_requests(status: str | None = None, scan_id: int | None = None):
    clauses, params = [], []
    if status:
        clauses.append("status=?"); params.append(status)
    if scan_id is not None:
        clauses.append("scan_id=?"); params.append(scan_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM tool_requests {where} ORDER BY id DESC LIMIT 200", params).fetchall()
        scans = {r["id"]: r["target"] for r in conn.execute("SELECT id,target FROM scans")}
    return [{**tool_request_view(row), "scan_target": scans.get(row["scan_id"], "")} for row in rows]


@app.post("/api/tool-requests/{request_id}/decision")
def decide_tool_request(request_id: int, request: ToolDecision, client: FastAPIRequest):
    # Package installs change the machine, so only the local operator may decide.
    if client.client.host not in LOCAL_CLIENTS:
        raise HTTPException(403, "Tool approvals are available only from the local machine.")
    with connect() as conn:
        row = conn.execute("SELECT * FROM tool_requests WHERE id=?", (request_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Tool request not found.")
    if row["status"] not in ("pending", "failed"):
        raise HTTPException(409, f"This request is already {row['status']}.")
    new_status = "approved" if request.decision == "approve" else "declined"
    _set_request(request_id, status=new_status, decided_at=now(), decided_by=f"local assessor ({client.client.host})")
    _spawn(apply_tool_decision, request_id)
    with connect() as conn:
        updated = conn.execute("SELECT * FROM tool_requests WHERE id=?", (request_id,)).fetchone()
    return tool_request_view(updated)
