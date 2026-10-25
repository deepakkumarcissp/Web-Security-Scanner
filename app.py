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
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler, HTTPSHandler

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


class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep|active)$")
    authorized: bool = False
    active_testing_approved: bool = False


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


def require_in_scope_asset(target: str) -> dict:
    """Require an exact hostname/port match to an explicitly In Scope inventory asset."""
    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise HTTPException(400, "Target URL has an invalid port.") from exc
    with connect() as conn:
        rows = conn.execute("SELECT * FROM assets WHERE scope_status='in_scope'").fetchall()
    for row in rows:
        registered = urlparse(row["target"])
        registered_host = (registered.hostname or "").lower().rstrip(".")
        try:
            registered_port = registered.port or (443 if registered.scheme.lower() == "https" else 80)
        except ValueError:
            continue
        if hostname == registered_host and port == registered_port:
            return dict(row)
    raise HTTPException(
        403,
        "Target is not approved for scanning. Register it in Asset Inventory and explicitly set its scope to In Scope first.",
    )


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


def same_origin_opener(origin_url: str):
    return build_opener(_SameOriginRedirectHandler(origin_url), HTTPSHandler(context=ssl.create_default_context()))


def discover_same_origin_pages(root_url: str, root_html: str, max_pages: int = 12, max_depth: int = 2) -> dict:
    """Bounded, low-rate, same-origin page discovery; never submits forms or executes JS."""
    root = root_url.rstrip("/") or root_url
    root_origin = urlparse(root)
    discovered = [root]
    depths = {root: 0}
    queue = [(url, 0) for url in extract_same_origin_links(root, root_html)]
    seen = {root}
    opener = same_origin_opener(root)
    while queue and len(discovered) < max_pages:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
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
        if depth < max_depth:
            queue.extend((link, depth + 1) for link in extract_same_origin_links(url, body) if link not in seen)
        time.sleep(0.2)
    return {"urls": discovered[:max_pages], "pages_visited": max(0, len(discovered) - 1),
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

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            pending = zap_get("/JSON/pscan/view/recordsToScan/", {}).get("recordsToScan", "0")
            if int(pending) <= 0:
                break
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError):
            failures.append("Could not confirm passive-scan queue status")
            break
        time.sleep(0.4)

    # Filter alerts to the exact scheme/host/port origin, not a broad host prefix.
    origin = f"{root.scheme}://{root.netloc}/"
    try:
        payload = zap_get("/JSON/core/view/alerts/", {"baseurl": origin, "start": "0", "count": "100"})
        alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    except Exception as exc:
        return [], {"status": "completed_with_warnings", "reason": "ZAP fetched approved URLs but could not retrieve alerts",
                    "urls_requested": len(safe_targets), "urls_scanned": len(scanned), "errors": [str(exc)[:200]]}

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
    return normalized, {"status": status, "urls_requested": len(safe_targets), "urls_scanned": len(scanned),
                       "finding_count": len(normalized), "errors": failures[:3],
                       "mode": "passive only; no spider or active scan; same-origin URLs only"}

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



def select_nuclei_templates(max_templates: int = 60) -> tuple[list[str], dict]:
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
        if re.search(r"(?im)^\s*method\s*:\s*['\"]?(POST|PUT|PATCH|DELETE|OPTIONS)\b", text):
            continue
        if re.search(r"(?m)^\s*(payloads|attack|raw)\s*:", text):
            continue
        id_match = re.search(r"(?m)^id\s*:\s*['\"]?([^\s'\"]+)", text)
        tags_match = re.search(r"(?m)^\s*tags\s*:\s*([^\n]+)", text)
        severity_match = re.search(r"(?m)^\s*severity\s*:\s*([^\s#]+)", text)
        request_match = re.search(r"(?m)^\s*max-request\s*:\s*(\d+)", text)
        if not id_match or not tags_match:
            continue
        tags = {tag.strip().lower() for tag in re.split(r"[,\s]+", tags_match.group(1).strip(" []\"'")) if tag.strip()}
        if not (tags & allowed_tags) or tags & excluded_tags:
            continue
        max_requests = int(request_match.group(1)) if request_match else 1
        if max_requests > 5:
            continue
        severity = (severity_match.group(1).strip("'\"").lower() if severity_match else "unknown")
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
    return [item[3] for item in selected], {
        "status": "ready" if selected else "unavailable",
        "template_root": str(root), "templates_considered": scanned,
        "templates_eligible": len(candidates), "templates_selected": len(selected),
        "max_templates": max_templates,
        "selected_tags": sorted(allowed_tags), "excluded_tags": sorted(excluded_tags),
        "selection_note": "Local HTTP templates only; excludes explicit high-risk tags, flow/headless/code templates, and templates declaring over five requests.",
    }


def perform_nuclei_check(target: str, timeout_seconds: int = 60, targets: list[str] | None = None,
                         max_templates: int = 30) -> tuple[list[tuple], dict]:
    """Run bounded Nuclei checks and retain valid partial results if the runtime limit is reached."""
    binary = shutil.which(TOOL_CATALOG["nuclei"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "Nuclei is not installed"}
    selected_templates, selection_status = select_nuclei_templates(max_templates=max(1, min(max_templates, 60)))
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
        # Nuclei's single-target mode is simpler and avoids list-mode overhead for Standard.
        # Keep list mode only when Deep/Active scan multiple approved same-origin URLs.
        target_args = ["-u", safe_targets[0]] if len(safe_targets) == 1 else ["-list", targets_path]
        command = [
            binary, *target_args,
            "-templates", templates_path,
            "-pt", "http",
            "-severity", "info,low,medium,high,critical,unknown",
            "-rl", "5", "-c", "3", "-timeout", "4", "-retries", "0",
            "-duc", "-disable-redirects", "-no-interactsh", "-silent",
            "-jsonl-export", jsonl_path,
        ]
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
                        "redirects_disabled": True, "interactsh_disabled": True}
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
                     "interactsh_disabled": True, "timeout_seconds": timeout_seconds}


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


def perform_scan(scan_id: int, target: str, profile: str) -> None:
    findings = []
    tool_status = {
        "Built-in HTTP & headers": {"status": "running", "detail": "Requesting the supplied URL and inspecting response headers"},
        "Endpoint discovery": {"status": "queued", "detail": "Waiting for the initial page response"},
        "Nuclei": {"status": "queued", "detail": "Waiting for built-in checks"},
        "Nikto": {"status": "queued", "detail": "Runs in Deep and Active profiles"},
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
                "Medium", "Cookie may lack Secure attribute", cookies[:220],
                "Set Secure on cookies that should only be sent over HTTPS.", "Medium",
            )
        if cookies and "httponly" not in cookies.lower():
            finding(
                "Low", "Cookie may lack HttpOnly attribute", cookies[:220],
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

        discovery_status = {"status": "skipped", "reason": "Endpoint discovery is enabled for Standard/Deep/Active scans only", "urls": [final_url]}
        if profile in ("standard", "deep", "active"):
            tool_status["Endpoint discovery"] = {"status": "running", "detail": "Discovering same-origin links without submitting forms"}
            update_scan_progress(scan_id, 27, "Discovering same-origin pages", tool_status)
            discovery_status = discover_same_origin_pages(final_url, body)
            discovered_urls = discovery_status.get("urls", [final_url])
            tool_status["Endpoint discovery"] = {"status": "completed", "detail": f"Mapped {len(discovered_urls)} same-origin URL(s); bounded passive discovery"}
            # Extend low-impact response-header checks to discovered pages. Each URL is
            # fetched with a short timeout; only same-origin results are accepted.
            root_parsed = urlparse(final_url)
            root_port = root_parsed.port or (443 if root_parsed.scheme == "https" else 80)
            for page_url in discovered_urls:
                if page_url == final_url:
                    continue
                try:
                    page_req = Request(page_url, headers={"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized passive checks)", "Accept": "text/html,*/*;q=0.5"})
                    with same_origin_opener(final_url).open(page_req, timeout=4) as page_response:
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
                        findings.append(("Medium", "Cookie may lack Secure attribute", page_url_final, page_cookies[:220], "Set Secure on cookies that should only be sent over HTTPS.", "Medium"))
                    if page_cookies and "httponly" not in page_cookies.lower():
                        findings.append(("Low", "Cookie may lack HttpOnly attribute", page_url_final, page_cookies[:220], "Set HttpOnly for session cookies that do not require JavaScript access.", "Medium"))
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
        nuclei_status = {"status": "not_run", "reason": "Nuclei checks are enabled for Standard/Deep/Active profiles only"}
        nikto_status = {"status": "not_run", "reason": "Nikto server checks are enabled for Deep/Active profiles only"}
        if profile in ("standard", "deep", "active"):
            nuclei_targets = discovery_status.get("urls", [target])
            nuclei_template_cap = 60 if profile in ("deep", "active") else 5
            # Standard is a quick baseline: run a small category-balanced template set on the
            # authorized root URL. Deep/Active expand to 60 templates across discovered endpoints.
            # This keeps the default profile bounded while preserving broader coverage on demand.
            if profile == "standard":
                nuclei_targets = [target]
            nuclei_timeout = 240 if profile in ("deep", "active") else 30
            tool_status["Nuclei"] = {"status": "running", "detail": f"Running up to {nuclei_template_cap} safe templates across {len(nuclei_targets[:12])} same-origin URL(s); 5 requests/second maximum"}
            update_scan_progress(scan_id, 35, "Running Nuclei safe checks", tool_status)
            nuclei_findings, nuclei_status = perform_nuclei_check(target, timeout_seconds=nuclei_timeout,
                                                                  targets=nuclei_targets, max_templates=nuclei_template_cap)
            findings.extend(nuclei_findings)
            nuclei_state = nuclei_status.get("status", "completed")
            nuclei_detail = f"{nuclei_status.get('finding_count', len(nuclei_findings))} finding(s) across {nuclei_status.get('target_count', len(nuclei_targets))} same-origin URL(s)"
            if nuclei_state == "partial_timeout":
                nuclei_detail += "; time limit reached, partial findings retained"
            elif nuclei_state == "timeout":
                nuclei_detail += "; time limit reached before a report was produced"
            elif nuclei_status.get("reason"):
                nuclei_detail += "; " + str(nuclei_status["reason"])
            tool_status["Nuclei"] = {"status": nuclei_state, "detail": nuclei_detail}
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

        update_scan_progress(scan_id, 97, "Combining and deduplicating findings", tool_status)
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
                "UPDATE scans SET status=?,finished_at=?,summary=?,progress=100,current_stage=?,tool_status=? WHERE id=?",
                (
                    "completed", now(),
                    json.dumps({
                        "http_status": status_code, "final_url": final_url,
                        "checks": "passive HTTP/header checks, bounded same-origin discovery, curated Nuclei checks, WhatWeb fingerprinting, optional TLS assessment, Deep/Active Nikto checks, optional ZAP passive alerts, and explicitly approved Active-profile Wapiti tests",
                        "tls_check": tls_status, "whatweb_check": whatweb_status,
                        "nuclei_check": nuclei_status, "nikto_check": nikto_status, "wapiti_check": wapiti_status, "zap_check": zap_status,
                        "endpoint_discovery": discovery_status,
                        "finding_count": len(findings),
                    }),
                    "Assessment complete", json.dumps(tool_status), scan_id,
                ),
            )
    except Exception as exc:
        with connect() as conn:
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=?,current_stage=?,tool_status=? WHERE id=?",
                ("failed", now(), json.dumps({"error": str(exc)}), "Assessment failed", json.dumps(tool_status), scan_id),
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


def start_scan(target: str, profile: str) -> int:
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
                        # Scheduled work must respect the same worker cap as manual requests.
                        if running_scan_count(conn) >= max_concurrent_scans():
                            continue
                        try:
                            require_in_scope_asset(schedule["target"])
                        except HTTPException:
                            # Scope may have changed since scheduling; fail closed and pause the schedule.
                            conn.execute("UPDATE schedules SET enabled=0 WHERE id=?", (schedule["id"],))
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
    # Simple one-URL workflow: explicit authorization is enough for a newly entered target.
    # If the target already exists in inventory, respect any review or out-of-scope decision.
    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    with connect() as conn:
        assets = conn.execute("SELECT * FROM assets").fetchall()
    for asset in assets:
        registered = urlparse(asset["target"])
        registered_host = (registered.hostname or "").lower().rstrip(".")
        try:
            registered_port = registered.port or (443 if registered.scheme.lower() == "https" else 80)
        except ValueError:
            continue
        if hostname == registered_host and port == registered_port and asset["scope_status"] != "in_scope":
            raise HTTPException(403, "This target is marked " + asset["scope_status"].replace("_", " ") + " in Asset Inventory. Review its scope before scanning.")
    with connect() as conn:
        active_scans = running_scan_count(conn)
    limit = max_concurrent_scans()
    if active_scans >= limit:
        raise HTTPException(429, f"Scanner capacity reached ({active_scans}/{limit} assessments running). Wait for a scan to finish before starting another.")
    scan_id = start_scan(target, request.profile)
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
        return {"scan": dict(scan), "findings": findings}


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
        if current["status"] != "completed":
            raise HTTPException(409, "Only completed scans can be compared")
        current_target = validate_target(current["target"])
        if baseline_id is None:
            baseline = conn.execute(
                """SELECT * FROM scans WHERE id<>? AND status='completed' AND profile=?
                ORDER BY COALESCE(finished_at,created_at) DESC,id DESC""",
                (scan_id, current["profile"]),
            ).fetchall()
            baseline = next((row for row in baseline if validate_target(row["target"]) == current_target), None)
        else:
            baseline = conn.execute("SELECT * FROM scans WHERE id=?", (baseline_id,)).fetchone()
            if not baseline:
                raise HTTPException(404, "Baseline scan not found")
            if baseline["status"] != "completed":
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
                            "For a meaningful comparison, use the same target and assessment profile after remediation."]}


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
    target = validate_target(request.target)
    require_in_scope_asset(target)
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
    "wapiti": {"label": "Wapiti", "binary": "wapiti", "package": "wapiti", "version_args": ["--version"], "purpose": "Explicitly approved active tests for web-application vulnerabilities"},
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
