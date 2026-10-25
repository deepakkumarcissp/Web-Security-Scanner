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
from concurrent.futures import ThreadPoolExecutor
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlencode, urljoin, urldefrag
from html.parser import HTMLParser
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler, HTTPSHandler

# Shared resolver pool caps concurrent OS resolver calls across requests.
DNS_RESOLVER_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dkcissp-dns")

from fastapi import FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field
import yaml

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DKCISSP_DB", ROOT / "data.sqlite3"))
app = FastAPI(
    title="DKCISSP External Attack Surface & Web Security Scanner",
    version="0.1.0",
    description="Local-first asset inventory, passive EASM discovery, and scoped web security assessment",
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
                tool_status TEXT NOT NULL DEFAULT '{}',
                heartbeat_at TEXT
            );
            CREATE TABLE IF NOT EXISTS install_jobs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                finished_at TEXT
            );
            CREATE TABLE IF NOT EXISTS scanner_activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                category TEXT NOT NULL DEFAULT 'scan',
                status TEXT NOT NULL DEFAULT 'info',
                stage TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
            CREATE INDEX IF NOT EXISTS idx_scanner_activity_scan_id ON scanner_activity(scan_id, id);
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
            CREATE TABLE IF NOT EXISTS organizations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                root_domain TEXT NOT NULL,
                owner_contact TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS organization_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                event_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(organization_id) REFERENCES organizations(id)
            );
            CREATE INDEX IF NOT EXISTS idx_organization_events_org ON organization_events(organization_id, id DESC);
            CREATE TABLE IF NOT EXISTS discovery_runs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_asset_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                candidate_count INTEGER NOT NULL DEFAULT 0,
                new_assets_added INTEGER NOT NULL DEFAULT 0,
                error_summary TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(root_asset_id) REFERENCES assets(id)
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_runs_root ON discovery_runs(root_asset_id, id DESC);
            CREATE TABLE IF NOT EXISTS asset_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            );
            CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(asset_id, id DESC);
            CREATE TABLE IF NOT EXISTS asset_snapshots(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                root_asset_id INTEGER NOT NULL,
                discovery_run_id INTEGER NOT NULL,
                asset_id INTEGER,
                target TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('new','present','missing_from_source')),
                observed_at TEXT NOT NULL,
                FOREIGN KEY(root_asset_id) REFERENCES assets(id),
                FOREIGN KEY(discovery_run_id) REFERENCES discovery_runs(id),
                FOREIGN KEY(asset_id) REFERENCES assets(id)
            );
            CREATE INDEX IF NOT EXISTS idx_asset_snapshots_run ON asset_snapshots(discovery_run_id, id);
            CREATE INDEX IF NOT EXISTS idx_asset_snapshots_root ON asset_snapshots(root_asset_id, id DESC);
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
        if "heartbeat_at" not in scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN heartbeat_at TEXT")
        conn.execute("UPDATE scans SET heartbeat_at=created_at WHERE heartbeat_at IS NULL")
        finding_columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        if "lifecycle_status" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'open'")
        if "lifecycle_notes" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_notes TEXT NOT NULL DEFAULT ''")
        if "lifecycle_updated_at" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN lifecycle_updated_at TEXT")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(assets)")}
        if "organization_id" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN organization_id INTEGER REFERENCES organizations(id)")
        for column, definition in {
            "resolution_status": "TEXT NOT NULL DEFAULT 'unknown'",
            "resolved_addresses_json": "TEXT NOT NULL DEFAULT '[]'",
            "resolution_checked_at": "TEXT",
            "resolution_error": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE assets ADD COLUMN {column} {definition}")
        if "approval_reference" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN approval_reference TEXT NOT NULL DEFAULT ''")
        if "reviewed_at" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN reviewed_at TEXT")
        if "review_decision" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN review_decision TEXT NOT NULL DEFAULT 'pending'")


init_db()


def record_asset_event(conn, asset_id: int, event_type: str, summary: str, details: dict | None = None) -> None:
    """Persist a small, append-only inventory event in the same DB transaction as its change."""
    conn.execute(
        "INSERT INTO asset_events(asset_id,event_type,event_at,summary,details_json) VALUES(?,?,?,?,?)",
        (asset_id, event_type, now(), summary[:500], json.dumps(details or {}, sort_keys=True)[:4000]),
    )


def recover_stale_scans(conn=None, stale_after_minutes: int = 30) -> int:
    """Fail scans with no worker heartbeat after a conservative timeout; keep all findings/history."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max(1, stale_after_minutes))).isoformat(timespec="seconds")
    owns_connection = conn is None
    if owns_connection:
        conn = connect()
    try:
        cursor = conn.execute(
            """UPDATE scans
               SET status='failed', finished_at=?, current_stage='Failed: worker heartbeat expired',
                   summary=?, heartbeat_at=?
               WHERE status='running' AND COALESCE(heartbeat_at, created_at) < ?""",
            (now(), json.dumps({"error": "Scan worker heartbeat expired; scan marked failed by stale-worker recovery. Existing findings and scan history were preserved."}), now(), cutoff),
        )
        recovered = cursor.rowcount
        if owns_connection:
            conn.commit()
        return recovered
    finally:
        if owns_connection:
            conn.close()


recover_stale_scans()


class ScanRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep|active)$")
    authorized: bool = False
    active_testing_approved: bool = False


class ScheduleRequest(ScanRequest):
    name: str = Field(default="Scheduled scan", min_length=1, max_length=100)
    frequency: str = Field(default="daily", pattern="^(daily|weekly)$")
    run_at: str | None = None


class OrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    root_domain: str = Field(min_length=3, max_length=253)
    owner_contact: str = Field(default="", max_length=254)
    notes: str = Field(default="", max_length=1000)
    authorized: bool = False


class AssetRequest(BaseModel):
    target: str = Field(min_length=8, max_length=2048)
    organization_id: int | None = Field(default=None, ge=1)
    authorized: bool = False
    scope_status: str = Field(default="needs_review", pattern="^(in_scope|out_of_scope|needs_review)$")
    notes: str = Field(default="", max_length=1000)


class AssetOrganizationUpdate(BaseModel):
    authorized: bool = False
    organization_id: int | None = Field(default=None, ge=1)
    notes: str = Field(default="", max_length=500)


class AssetScopeUpdate(BaseModel):
    authorized: bool = False
    scope_status: str = Field(pattern="^(in_scope|out_of_scope|needs_review)$")
    notes: str | None = Field(default=None, max_length=1000)
    approval_reference: str | None = Field(default=None, max_length=200)


class AssetDiscoveryRequest(BaseModel):
    authorized: bool = False
    max_results: int = Field(default=50, ge=1, le=100)
    source: str = Field(default="crt.sh", pattern="^(crt.sh|wayback)$")


class AssetResolveRequest(BaseModel):
    authorized: bool = False
    timeout_seconds: int = Field(default=2, ge=1, le=4)


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


def is_html_document(content_type: str) -> bool:
    """Return whether response headers apply to a browser document rather than an asset."""
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    return media_type in {"text/html", "application/xhtml+xml"}


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


def exposed_file_observation(url: str, status_code: int, headers: dict) -> dict | None:
    """Return a cautious metadata-only signal for risky file paths already in scope.

    This helper never enumerates filenames or reads file content. Example/documentation
    files such as .env.example are intentionally excluded to reduce noisy findings.
    """
    if status_code < 200 or status_code >= 300:
        return None
    parsed = urlparse(url)
    path = (parsed.path or "/").lower()
    basename = path.rsplit("/", 1)[-1]
    repository_metadata_paths = {".git/config", ".svn/entries", ".hg/store"}
    sensitive_basenames = {
        ".env", ".env.local", ".env.production", ".env.development",
        "id_rsa", "id_ed25519", "server.key", "private.key",
        "wp-config.php.bak", "config.php.bak", "configuration.php.bak",
        "database.sql", "db.sql", "dump.sql", "backup.sql",
        "backup.zip", "site.zip", "www.zip", "webroot.zip",
    }
    risky_suffixes = (".sql.gz", ".dump", ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tar.gz")
    # Match sensitive basenames at any in-scope path, plus repository metadata
    # paths. Do not flag example templates, public well-known files, generic
    # config names, or ordinary ZIP downloads just because of their extension.
    normalized_path = path.lstrip("/")
    exact_match = basename in sensitive_basenames or any(
        normalized_path == item or normalized_path.endswith("/" + item)
        for item in repository_metadata_paths
    )
    suffix_match = basename.endswith(risky_suffixes)
    if not exact_match and not suffix_match:
        return None
    content_type = str(headers.get("content-type", headers.get("Content-Type", "unknown")))[:120]
    content_length = str(headers.get("content-length", headers.get("Content-Length", "unknown")))[:24]
    return {
        "title": "Potentially exposed backup or configuration artifact",
        "severity": "Low",
        "confidence": "Low",
        "evidence": (
            f"An in-scope URL matching a sensitive-file naming pattern returned HTTP {status_code}; "
            f"path={parsed.path}; content-type={content_type}; content-length={content_length}. "
            "File contents were not included in this finding. Validate access controls and intended publication."
        ),
        "remediation": (
            "Confirm whether this artifact is intended to be public. Remove backups, private configuration, "
            "repository metadata, and database dumps from web roots; rotate exposed credentials if validated. "
            "This filename/status observation alone does not confirm that secrets are present."
        ),
    }


def risky_http_methods_observation(allow_header: str, status_code: int) -> dict | None:
    """Report potentially risky methods only when the server explicitly advertises them."""
    if status_code < 200 or status_code >= 500:
        return None
    allowed = {
        item.strip().upper()
        for item in (allow_header or "").split(",")
        if item.strip()
    }
    risky = sorted(allowed.intersection({"TRACE", "PUT", "DELETE", "CONNECT", "PROPFIND"}))
    if not risky:
        return None
    return {
        "title": "Potentially risky HTTP methods advertised",
        "severity": "Low",
        "confidence": "Medium",
        "evidence": f"HTTP response advertised methods: {', '.join(risky)}. An Allow header is an indication only; method reachability and application impact require authorized validation.",
        "remediation": "Disable methods that the application does not require. Confirm method handling at the web server, reverse proxy, and application layers; do not rely on the Allow header alone as proof of exploitability.",
    }


def default_server_page_observation(body: str, content_type: str) -> dict | None:
    """Identify well-known stock server welcome pages as low-confidence inventory signals."""
    if not is_html_document(content_type):
        return None
    sample = (body or "")[:500_000].casefold()
    signatures = (
        ("apache2 debian default page", "Apache2 Debian Default Page"),
        ("welcome to nginx!", "nginx welcome page"),
        ("test page for the apache http server", "Apache HTTP Server test page"),
        ("iis windows server", "IIS default server page"),
        ("internet information services", "IIS default server page"),
    )
    for marker, label in signatures:
        if marker in sample:
            return {
                "title": "Possible default web-server page",
                "severity": "Info",
                "confidence": "Low",
                "evidence": f"The HTML response contains a known stock-page marker ({label}). This may be intentional or customized; validate manually.",
                "remediation": "If this is a production service, replace or remove unused stock welcome/test pages and confirm the intended application is served. This marker alone is not proof of a vulnerability.",
            }
    return None


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


def deduplicate_findings(findings):
    """Remove exact duplicate observations without discarding distinct evidence."""
    deduped = []
    seen = set()
    for item in findings:
        if len(item) < 6:
            key = ("legacy", repr(item))
        else:
            severity, title, affected_url, evidence, remediation, confidence = item[:6]
            normalize = lambda value: " ".join(str(value or "").split()).casefold()
            key = tuple(normalize(value) for value in (severity, title, affected_url, evidence, remediation, confidence))
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


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
        # ZAP's accessUrl response embeds the fetched responseBody as a JSON string.
        # Bundled JavaScript can exceed 1 MB, so the old cap truncated valid JSON.
        # Keep a finite 5 MB limit and detect oversize responses explicitly.
        max_response_bytes = 5_000_000
        with urlopen(req, timeout=4) as response:
            raw = response.read(max_response_bytes + 1)
        if len(raw) > max_response_bytes:
            raise ValueError("ZAP API response exceeded the 5 MB safety limit")
        payload = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            raise ValueError("ZAP API returned an unexpected JSON response shape")
        return payload

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
        # ZAP uses a broad CORS alert name. Preserve its reported severity, but make
        # clear that a wildcard origin alone is not proof of exploitable data access.
        if "cross-domain misconfiguration" in title.casefold() and "access-control-allow-origin" in str(alert.get("evidence", "")).casefold():
            evidence = (evidence + " Validation note: a wildcard CORS origin alone does not prove exploitable exposure; verify whether sensitive responses are readable cross-origin and whether credentialed requests are accepted.")[:1800]
            remediation = (remediation.rstrip() + " Validate the policy on sensitive endpoints; allow only required trusted origins, and review credentialed CORS behavior. Do not treat a wildcard header by itself as proof of data exposure.")[:1800]
        confidence = str(alert.get("confidence", "Medium"))
        normalized.append((severity, "OWASP ZAP: " + title, alert_url[:2048], evidence, remediation, confidence))

    # Group exact same signals reported on multiple resources, but retain each URL
    # in evidence so grouping reduces noise without hiding the affected surface.
    grouped = {}
    for severity, title, alert_url, evidence, remediation, confidence in normalized:
        key = (severity, title, evidence, remediation, confidence)
        if key not in grouped:
            grouped[key] = {"urls": [], "finding": (severity, title, alert_url, evidence, remediation, confidence)}
        if alert_url not in grouped[key]["urls"]:
            grouped[key]["urls"].append(alert_url)

    aggregated = []
    for item in grouped.values():
        severity, title, first_url, evidence, remediation, confidence = item["finding"]
        urls = item["urls"]
        if len(urls) > 1:
            url_list = "\n".join("- " + url for url in urls)
            evidence = (evidence + f"\nAffected URLs ({len(urls)}):\n" + url_list)[:1800]
        aggregated.append((severity, title, first_url, evidence, remediation, confidence))

    status = "completed_with_warnings" if failures else "completed"
    return aggregated, {"status": status, "urls_requested": len(safe_targets), "urls_scanned": len(scanned),
                       "alert_count": len(normalized), "finding_count": len(aggregated), "errors": failures[:3],
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

    # Default profile is deliberately limited to low-impact configuration,
    # exposure, TLS/header, technology and discovery checks. CVE/exploit classes
    # are not enabled merely because a template happens to carry a safe tag too.
    allowed_tags = {"misconfig", "misconfiguration", "exposure", "headers", "ssl", "config", "tech", "discovery"}
    excluded_tags = {
        "dos", "fuzz", "bruteforce", "brute-force", "intrusive", "headless",
        "token-spray", "default-login", "default-credentials", "filefuzz", "takeover",
        "cve", "vuln", "vulnerability", "rce", "lfi", "rfi", "sqli", "sql-injection",
        "xss", "ssrf", "ssti", "xxe", "auth-bypass", "unauth",
        "exploit", "kev", "vkev", "edb", "oast", "interactsh", "network", "cloud",
    }
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    category_order = ["misconfig", "misconfiguration", "exposure", "ssl", "headers", "config", "tech", "discovery"]
    scanned = 0
    for path in root.rglob("*.yaml"):
        scanned += 1
        try:
            # Avoid parsing oversized/unrelated community templates. The quick
            # checks are only a prefilter; accepted templates are still parsed.
            if path.stat().st_size > 65536:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not re.search(r"(?m)^http\s*:", text):
            continue
        if re.search(r"(?m)^(flow|headless|javascript|code|tcp|network|file|websocket|ssl)\s*:", text):
            continue
        if re.search(r"(?i)(interactsh|\boast\b|\bunsafe\b)", text):
            continue
        if re.search(r"(?im)^\s*method\s*:\s*['\"]?(POST|PUT|PATCH|DELETE|OPTIONS)\b", text):
            continue
        if re.search(r"(?m)^\s*(payloads|attack|raw)\s*:", text):
            continue
        quick_tags = re.search(r"(?im)^\s*tags\s*:\s*([^\n]+)", text)
        if not quick_tags:
            continue
        pre_tags = {tag.strip().lower() for tag in re.split(r"[,\s]+", quick_tags.group(1).strip(" []\"'")) if tag.strip()}
        if not (pre_tags & allowed_tags) or pre_tags & excluded_tags:
            continue
        try:
            # safe_load reads template structure without constructing arbitrary Python objects.
            template = yaml.safe_load(text)
        except (yaml.YAMLError, RecursionError):
            continue
        if not isinstance(template, dict):
            continue
        info = template.get("info") if isinstance(template.get("info"), dict) else {}
        template_id = str(template.get("id") or "").strip()
        raw_tags = info.get("tags", [])
        if isinstance(raw_tags, str):
            tags = {tag.strip().lower() for tag in re.split(r"[,\s]+", raw_tags) if tag.strip()}
        elif isinstance(raw_tags, list):
            tags = {str(tag).strip().lower() for tag in raw_tags if str(tag).strip()}
        else:
            continue
        if not template_id or not tags:
            continue
        # Only ordinary HTTP templates are in the default profile. Reject all
        # alternate execution engines and request forms that are hard to bound.
        if not isinstance(template.get("http"), list) or not template["http"]:
            continue
        if any(key in template for key in ("flow", "headless", "javascript", "code", "tcp", "network", "file", "websocket", "ssl")):
            continue
        if re.search(r"(?i)(interactsh|\boast\b|\bunsafe\b)", text):
            continue
        # A state-changing method or raw/payload-driven request is out of scope
        # for the default profile, regardless of how benign its tags look.
        if re.search(r"(?im)^\s*method\s*:\s*['\"]?(POST|PUT|PATCH|DELETE|OPTIONS)\b", text):
            continue
        if re.search(r"(?m)^\s*(payloads|attack|raw)\s*:", text):
            continue
        if not (tags & allowed_tags) or tags & excluded_tags:
            continue

        metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
        declared_max = metadata.get("max-request", metadata.get("max-request-count", 0))
        try:
            declared_max = int(declared_max or 0)
        except (TypeError, ValueError):
            continue
        if declared_max > 5:
            continue

        # Estimate requests from the parsed HTTP blocks and path lists. Templates
        # with more than five possible path requests are excluded even if they omit
        # Nuclei's optional max-request metadata.
        request_estimate = 0
        request_shape_safe = True
        for request in template["http"]:
            if not isinstance(request, dict):
                request_shape_safe = False
                break
            paths = request.get("path", [])
            if isinstance(paths, str):
                path_count = 1
            elif isinstance(paths, list):
                path_count = len(paths)
            else:
                request_shape_safe = False
                break
            if path_count < 1:
                request_shape_safe = False
                break
            request_estimate += path_count
            if request_estimate > 5:
                break
        if not request_shape_safe or request_estimate > 5:
            continue

        severity = str(info.get("severity", "unknown")).strip().lower()
        primary_category = next((tag for tag in category_order if tag in tags), "other")
        candidates.append((primary_category, severity_rank.get(severity, 5), template_id, str(path), tags))

    # Balance allowed low-impact categories so one large family cannot crowd out
    # configuration, exposure, TLS/header, technology, and discovery checks. Within
    # each group, higher-severity templates are selected first with stable IDs.
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
        "selection_note": "Parsed YAML HTTP templates for low-impact configuration, exposure, TLS/header, technology, and discovery only; rejects exploit/CVE classes, mixed-risk tags, external callbacks, alternate execution engines, state-changing methods, payload fuzzing, and templates with over five estimated path requests.",
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
            "-duc", "-no-stdin", "-disable-redirects", "-no-interactsh", "-silent",
            "-jsonl-export", jsonl_path,
        ]
        timed_out = False
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout_seconds,
                check=False, stdin=subprocess.DEVNULL,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # Preserve bounded, useful diagnostics from the timed-out process. Python may
            # return these as bytes even though text=True was requested.
            timeout_stdout = exc.stdout or ""
            timeout_stderr = exc.stderr or ""
            if isinstance(timeout_stdout, bytes):
                timeout_stdout = timeout_stdout.decode("utf-8", "replace")
            if isinstance(timeout_stderr, bytes):
                timeout_stderr = timeout_stderr.decode("utf-8", "replace")
            result = SimpleNamespace(returncode=124, stdout=timeout_stdout, stderr=timeout_stderr)
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
                        "stdout_tail": str(getattr(result, "stdout", "") or "")[-1000:] if timed_out else "",
                        "stderr_tail": str(getattr(result, "stderr", "") or "")[-1000:] if timed_out else "",
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
                # Legacy Feature-Policy is not a vulnerability by itself. Avoid repetitive
                # low-value observations on static assets while retaining the root-response
                # signal used by the expected-detection regression baseline.
                if (
                    "deprecated feature-policy header" in title.casefold()
                    and "/assets/" in matched_at.casefold()
                ):
                    continue
                # Treat tool output as untrusted: only persist findings attached to the
                # exact approved origin, even if a tool record unexpectedly names another host.
                if not is_same_origin_url(matched_at, target):
                    continue
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
                # Confidence reflects the evidence actually emitted by Nuclei,
                # not the template's severity label. A named matcher plus extracted
                # response evidence is stronger than a bare template match.
                confidence = "High" if matcher and isinstance(extracted, list) and any(str(x).strip() for x in extracted) else "Medium"
                findings.append((severity, "Nuclei: " + title, matched_at, "; ".join(evidence_parts)[:1800], remediation, confidence))

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
                # Wapiti labels broad method-response behavior as an additional;
                # generic responses are noisy and do not prove dangerous methods are enabled.
                if group_name == "additionals" and str(category).strip().casefold() == "http methods":
                    detail_text = str(entry.get("info") or entry.get("message") or "")
                    if not re.search(r"\b(?:TRACE|PUT|DELETE|CONNECT|PROPFIND)\b.*\b(?:enabled|allowed|accepted|permitted)\b|\b(?:enabled|allowed|accepted|permitted)\b.*\b(?:TRACE|PUT|DELETE|CONNECT|PROPFIND)\b", detail_text, re.I):
                        continue
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


def discover_openapi_json_operations(target: str, max_specs: int = 4, max_operations: int = 3) -> list[dict]:
    """Discover a small set of same-origin OpenAPI JSON operations without following redirects."""
    from urllib.request import Request

    candidates = [
        urljoin(target.rstrip("/") + "/", "openapi.json"),
        urljoin(target.rstrip("/") + "/", "swagger.json"),
        urljoin(target.rstrip("/") + "/", "api-docs"),
        urljoin(target.rstrip("/") + "/", "swagger/v1/swagger.json"),
    ][:max_specs]
    operations: list[dict] = []
    seen_specs = set()
    for spec_url in candidates:
        if not is_same_origin_url(spec_url, target) or spec_url in seen_specs:
            continue
        seen_specs.add(spec_url)
        try:
            req = Request(spec_url, headers={"Accept": "application/json", "User-Agent": "DKCISSP-Scanner"})
            with same_origin_opener(target).open(req, timeout=3) as response:
                if response.geturl() != spec_url or not is_same_origin_url(response.geturl(), target):
                    continue
                raw = response.read(512 * 1024 + 1)
                if len(raw) > 512 * 1024:
                    continue
                spec = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, ValueError, HTTPError, URLError, TimeoutError):
            continue
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            continue
        base = spec.get("servers", [{}])[0].get("url", "") if isinstance(spec.get("servers", [{}]), list) and spec.get("servers") else ""
        api_base = urljoin(spec_url, base) if base else target.rstrip("/") + "/"
        if not is_same_origin_url(api_base, target):
            continue
        for path, path_item in spec["paths"].items():
            if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
                continue
            endpoint = urljoin(api_base.rstrip("/") + "/", path.lstrip("/"))
            if not is_same_origin_url(endpoint, target):
                continue
            for method in ("get", "post"):
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                parameters = []
                for param in operation.get("parameters", []):
                    if isinstance(param, dict) and param.get("in") == "query" and isinstance(param.get("name"), str):
                        parameters.append(param["name"])
                body_fields = []
                request_body = operation.get("requestBody", {})
                content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
                schema = content.get("application/json", {}).get("schema", {}) if isinstance(content, dict) else {}
                properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                if isinstance(properties, dict):
                    body_fields = [name for name, value in properties.items()
                                   if isinstance(name, str) and isinstance(value, dict)
                                   and value.get("type") in ("string", "integer", "number")]
                if method == "post" and body_fields:
                    operations.append({"url": endpoint, "method": "POST", "fields": body_fields[:5], "body": True})
                elif method == "get" and parameters:
                    operations.append({"url": endpoint, "method": "GET", "fields": parameters[:5], "body": False})
                if len(operations) >= max_operations:
                    return operations
    return operations


def perform_sqlmap_check(target: str, timeout_seconds: int = 60) -> tuple[list[tuple], dict]:
    """Run bounded SQLMap checks only against same-origin operations declared by a discovered OpenAPI schema."""
    binary = shutil.which(TOOL_CATALOG["sqlmap"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "sqlmap is not installed", "operations_tested": 0}
    operations = discover_openapi_json_operations(target, max_operations=2)
    if not operations:
        return [], {"status": "not_found", "reason": "No same-origin OpenAPI JSON/query operations were discovered", "operations_tested": 0}
    findings: list[tuple] = []
    tested = 0
    deadline = time.monotonic() + max(1, timeout_seconds)
    with tempfile.TemporaryDirectory(prefix="dkcissp-sqlmap-") as temp_dir:
        for index, operation in enumerate(operations):
            for field in operation["fields"][:2]:
                remaining = deadline - time.monotonic()
                if remaining <= 1:
                    break
                per_operation_timeout = max(2, min(15, int(remaining)))
                if operation["body"]:
                    payload = {name: ("dkcissp-test" if name == field else "invalid") for name in operation["fields"]}
                    data = json.dumps(payload, separators=(",", ":"))
                    command = [binary, "-u", operation["url"], "--method=POST", "--data=" + data,
                               "--headers=Content-Type: application/json", "-p", field]
                    parameter_label = "JSON " + field
                else:
                    command = [binary, "-u", operation["url"], "-p", field]
                    parameter_label = field
                report_dir = str(Path(temp_dir) / f"op-{index}-{field}")
                command.extend([
                    "--batch", "--level=1", "--risk=1", "--technique=BEU",
                    "--threads=1", "--timeout=4", "--retries=0", "--ignore-code=401,403",
                    "--flush-session", "--disable-coloring", "--output-dir=" + report_dir,
                ])
                tested += 1
                try:
                    result = subprocess.run(command, capture_output=True, text=True,
                                            timeout=per_operation_timeout, check=False,
                                            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
                    output = (result.stdout or "") + "\n" + (result.stderr or "")
                except subprocess.TimeoutExpired:
                    continue
                except OSError:
                    continue
                # Require SQLMap's explicit positive classification; 500 responses alone never qualify.
                normalized_output = output.lower()
                explicit_positive = (
                    "sqlmap identified the following injection point" in normalized_output
                    or "is vulnerable" in normalized_output
                )
                if not explicit_positive or "parameter:" not in normalized_output or "type:" not in normalized_output:
                    continue
                evidence = f"SQLMap reported an injectable {parameter_label} parameter on {operation['method']} {operation['url']}."
                findings.append(("High", "SQL Injection (SQLMap)", operation["url"],
                                 evidence[:1200], "Use parameterized queries or prepared statements; validate input and review the affected database access path.",
                                 "High"))
    return findings, {"status": "completed", "finding_count": len(findings),
                      "operations_discovered": len(operations), "parameters_tested": tested,
                      "timeout_seconds": timeout_seconds,
                      "reason": "SQLMap explicit-positive output only; HTTP errors and generic response differences are not counted as SQL injection",
                      "safety": "Active profile only; same-origin OpenAPI operations; GET/POST only; bounded schema/operation/parameter counts; low risk and single thread"}


def perform_wapiti_check(target: str, timeout_seconds: int = 90) -> tuple[list[tuple], dict]:
    """Run an explicitly approved, bounded active Wapiti assessment on the supplied URL scope."""
    binary = shutil.which(TOOL_CATALOG["wapiti"]["binary"])
    if not binary:
        return [], {"status": "unavailable", "reason": "Wapiti is not installed"}
    # Keep the default active module set focused on common, bounded web checks.
    # High-impact server-side execution, file access, LDAP, and XXE modules are excluded.
    modules = "backup,crlf,csrf,htaccess,methods,redirect,sql,ssl,xss"
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
            # Suppress generic protocol/markup/header labels that add noise rather
            # than identifying a useful application technology. Keep actual frameworks,
            # CMSs, runtimes, and versioned components as informational inventory signals.
            if not name or name.lower() in {
                "httpserver", "ip", "country", "title", "redirectlocation",
                "html5", "script", "uncommonheaders", "x-frame-options",
            }:
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
            evidence += "; classification: informational technology inventory signal, not a confirmed vulnerability"
            key = (name.lower(), tuple(version_values[:3]))
            if key in seen_plugins:
                continue
            seen_plugins.add(key)
            findings.append(("Info", "WhatWeb technology detected: " + name,
                             str(entry.get("target") or target)[:1000], evidence[:1800],
                             "Inventory signal only—not a vulnerability finding by itself. Confirm whether this component/version is expected, check vendor support and patch status, and minimize unnecessary version disclosure.",
                             "Low"))

    return findings, {"status": "completed" if result.returncode == 0 else "completed_with_warnings",
                      "return_code": result.returncode, "finding_count": len(findings)}

def record_activity(scan_id: int | None, stage: str, message: str, status: str = "info", category: str = "scan") -> None:
    """Persist a short, secret-free event for the live activity timeline."""
    safe_stage = str(stage)[:160]
    safe_message = str(message)[:500]
    with connect() as conn:
        conn.execute(
            "INSERT INTO scanner_activity(scan_id,category,status,stage,message,created_at) VALUES(?,?,?,?,?,?)",
            (scan_id, str(category)[:40], str(status)[:24], safe_stage, safe_message, now()),
        )


def update_scan_progress(scan_id: int, progress: int, stage: str, tools: dict | None = None) -> None:
    """Persist truthful scan-stage progress and record actual stage transitions."""
    with connect() as conn:
        previous = conn.execute("SELECT current_stage,status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if tools is None:
            conn.execute("UPDATE scans SET progress=?,current_stage=?,heartbeat_at=? WHERE id=?", (progress, stage, now(), scan_id))
        else:
            conn.execute("UPDATE scans SET progress=?,current_stage=?,tool_status=?,heartbeat_at=? WHERE id=?",
                         (progress, stage, json.dumps(tools), now(), scan_id))
        if previous and previous["current_stage"] != stage:
            conn.execute(
                "INSERT INTO scanner_activity(scan_id,category,status,stage,message,created_at) VALUES(?,?,?,?,?,?)",
                (scan_id, "scan", "running", str(stage)[:160], f"{int(progress)}% — {str(stage)[:300]}", now()),
            )


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
            # Keep the initial request inside the exact approved origin too. urllib's
            # default opener follows cross-origin redirects, which could otherwise send
            # the scanner to a different host or port before any scope checks run.
            with same_origin_opener(target).open(req, timeout=12) as response:
                status_code = response.status
                headers = {k.lower(): v for k, v in response.headers.items()}
                final_url = response.geturl()
                # Do not read potentially sensitive backup/configuration bodies into the
                # scanner process; filename/status/header metadata is enough for triage.
                if exposed_file_observation(final_url, status_code, headers):
                    body = ""
                else:
                    body = response.read(500_000).decode("utf-8", "replace")
        except HTTPError as exc:
            status_code = exc.code
            headers = {k.lower(): v for k, v in exc.headers.items()}
            final_url = exc.geturl()
            body = exc.read(200_000).decode("utf-8", "replace")
        except (URLError, TimeoutError, ssl.SSLError, socket.timeout) as exc:
            with connect() as conn:
                conn.execute(
                    "UPDATE scans SET status=?,finished_at=?,summary=?,heartbeat_at=? WHERE id=?",
                    ("failed", now(), json.dumps({"error": str(exc)}), now(), scan_id),
                )
            return

        tool_status["Built-in HTTP & headers"] = {"status": "completed", "detail": f"HTTP {status_code}; response headers and sampled HTML inspected"}
        update_scan_progress(scan_id, 20, "Checking HTTP response, headers and cookies", tool_status)

        def finding(severity, title, evidence, remediation, confidence="High"):
            findings.append((severity, title, final_url, evidence, remediation, confidence))

        exposure = exposed_file_observation(final_url, status_code, headers)
        if exposure:
            finding(exposure["severity"], exposure["title"], exposure["evidence"],
                    exposure["remediation"], exposure["confidence"])

        # Check the supplied root response as well as discovered pages; otherwise
        # a directory index at the initial URL can be missed because discovery skips it.
        if is_html_document(headers.get("content-type", "")) and re.search(
            r"<title>\s*Index of /", body, re.I
        ):
            finding(
                "Medium", "Directory listing appears enabled",
                "The supplied response title resembles a directory index. Validate manually before treating as confirmed.",
                "Disable directory listing or restrict access.", "Medium",
            )

        default_page = default_server_page_observation(body, headers.get("content-type", ""))
        if default_page:
            finding(default_page["severity"], default_page["title"], default_page["evidence"],
                    default_page["remediation"], default_page["confidence"])

        # OPTIONS is a low-impact capability probe. It does not submit data or
        # execute the advertised methods, and redirect handling stays same-origin.
        if profile in ("standard", "deep", "active"):
            options_status = None
            options_headers = {}
            try:
                options_req = Request(final_url, headers={"User-Agent": "DKCISSP-WebSecurityScanner/0.1 (+authorized passive checks)"}, method="OPTIONS")
                with same_origin_opener(target).open(options_req, timeout=4) as options_response:
                    options_status = options_response.status
                    options_headers = {k.lower(): v for k, v in options_response.headers.items()}
            except HTTPError as exc:
                options_status = exc.code
                options_headers = {k.lower(): v for k, v in exc.headers.items()}
            except (URLError, TimeoutError, OSError, ssl.SSLError, ValueError):
                pass
            if options_status is not None:
                method_signal = risky_http_methods_observation(options_headers.get("allow", ""), options_status)
                if method_signal:
                    finding(method_signal["severity"], method_signal["title"], method_signal["evidence"],
                            method_signal["remediation"], method_signal["confidence"])

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
        cors_origin = headers.get("access-control-allow-origin", "").strip()
        if cors_origin == "*":
            cors_credentials = headers.get("access-control-allow-credentials", "").strip().lower()
            cors_evidence = "Access-Control-Allow-Origin: *"
            if cors_credentials:
                cors_evidence += f"; Access-Control-Allow-Credentials: {cors_credentials}"
            cors_evidence += "; wildcard origin is an observation, not proof of sensitive cross-origin data exposure"
            finding(
                "Info", "Wildcard CORS origin configured", cors_evidence,
                "Validate whether this endpoint returns sensitive data. Restrict allowed origins where appropriate; a wildcard origin alone does not prove exploitable exposure.",
                "Medium",
            )
        if target.startswith("http://"):
            finding(
                "Info", "Target URL uses HTTP (HTTPS not verified)",
                "The supplied target URL uses HTTP. HTTPS availability was not tested, so this is a transport observation rather than proof that HTTPS is unavailable.",
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
                        # Check metadata for already-discovered same-origin files before
                        # filtering non-HTML assets. Never read or store their contents.
                        exposure = exposed_file_observation(page_response.geturl(), page_response.status, page_headers)
                        if exposure:
                            findings.append((exposure["severity"], exposure["title"], page_response.geturl(),
                                             exposure["evidence"], exposure["remediation"], exposure["confidence"]))
                        # Document security policies should be assessed on HTML/XHTML
                        # documents, not every linked JS, CSS, image, or favicon asset.
                        if not is_html_document(page_headers.get("content-type", "")):
                            continue
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
        zap_finding_count = zap_status.get("finding_count", len(zap_findings))
        zap_alert_count = zap_status.get("alert_count", zap_finding_count)
        tool_status["OWASP ZAP passive"] = {"status": zap_status.get("status", "error"), "detail": f"{zap_finding_count} finding(s) from {zap_alert_count} alert(s) across {zap_status.get('urls_scanned', 0)} URL(s); {zap_status.get('reason', zap_status.get('mode', 'integration status recorded'))}"}
        wapiti_status = {"status": "not_run", "reason": "Wapiti active testing is available only in the Active profile"}
        if profile == "active":
            tool_status["Wapiti active checks"] = {"status": "running", "detail": "Active tests approved; checking common injection, file, redirect, and configuration weaknesses with bounded scope and runtime"}
            update_scan_progress(scan_id, 91, "Running approved Wapiti active checks", tool_status)
            wapiti_findings, wapiti_status = perform_wapiti_check(target)
            findings.extend(wapiti_findings)
            tool_status["Wapiti active checks"] = {"status": wapiti_status.get("status", "error"), "detail": f"{wapiti_status.get('finding_count', len(wapiti_findings))} finding(s); {wapiti_status.get('reason', 'active check finished')}"}
        else:
            tool_status["Wapiti active checks"] = {"status": "skipped", "detail": "Requires the separate Active profile and explicit approval"}

        sqlmap_status = {"status": "not_run", "reason": "SQLMap API checks require the Active profile"}
        if profile == "active":
            tool_status["SQLMap API SQLi checks"] = {"status": "running", "detail": "Looking for same-origin OpenAPI JSON/query operations; bounded SQL injection checks only"}
            update_scan_progress(scan_id, 94, "Running bounded OpenAPI-aware SQL injection checks", tool_status)
            sqlmap_findings, sqlmap_status = perform_sqlmap_check(target, timeout_seconds=60)
            findings.extend(sqlmap_findings)
            tool_status["SQLMap API SQLi checks"] = {
                "status": sqlmap_status.get("status", "error"),
                "detail": f"{sqlmap_status.get('finding_count', len(sqlmap_findings))} confirmed finding(s); "
                          f"{sqlmap_status.get('parameters_tested', 0)} parameter(s) tested; "
                          f"{sqlmap_status.get('reason', 'check finished')}",
            }
        else:
            tool_status["SQLMap API SQLi checks"] = {"status": "skipped", "detail": "Requires the separate Active profile and explicit approval"}

        update_scan_progress(scan_id, 97, "Combining and deduplicating findings", tool_status)
        findings = deduplicate_findings(findings)

        with connect() as conn:
            for item in findings:
                add_finding(conn, scan_id, target, *item)
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=?,progress=100,current_stage=?,tool_status=?,heartbeat_at=? WHERE id=?",
                (
                    "completed", now(),
                    json.dumps({
                        "http_status": status_code, "final_url": final_url,
                        "checks": "passive HTTP/header checks, bounded same-origin discovery, curated Nuclei checks, WhatWeb fingerprinting, optional TLS assessment, Deep/Active Nikto checks, optional ZAP passive alerts, and explicitly approved Active-profile Wapiti and OpenAPI-aware SQLMap tests",
                        "tls_check": tls_status, "whatweb_check": whatweb_status,
                        "nuclei_check": nuclei_status, "nikto_check": nikto_status, "wapiti_check": wapiti_status, "sqlmap_check": sqlmap_status, "zap_check": zap_status,
                        "endpoint_discovery": discovery_status,
                        "finding_count": len(findings),
                    }),
                    "Assessment complete", json.dumps(tool_status), now(), scan_id,
                ),
            )
    except Exception as exc:
        with connect() as conn:
            conn.execute(
                "UPDATE scans SET status=?,finished_at=?,summary=?,current_stage=?,tool_status=?,heartbeat_at=? WHERE id=?",
                ("failed", now(), json.dumps({"error": str(exc)}), "Assessment failed", json.dumps(tool_status), now(), scan_id),
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
        recover_stale_scans(conn)
        active_scans = running_scan_count(conn)
        limit = max_concurrent_scans()
        if active_scans >= limit:
            raise HTTPException(429, f"Scanner capacity reached ({active_scans}/{limit} assessments running). Wait for a scan to finish before starting another.")
        cursor = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at,progress,current_stage,tool_status,heartbeat_at) VALUES(?,?,?,?,?,?,?,?)",
            (target, profile, "running", now(), 1, "Queued", json.dumps({}), now()),
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
                        # Recover abandoned workers before enforcing the shared capacity limit.
                        recover_stale_scans(conn)
                        conn.commit()
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
    return {"status": "ok", "product": "DKCISSP External Attack Surface & Web Security Scanner", "version": app.version}


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


def normalize_root_domain(raw: str) -> str:
    """Accept a DNS name only, never a URL, wildcard, IP literal, or suffix lookalike."""
    domain = raw.strip().lower().rstrip(".")
    if not valid_dns_name(domain) or "." not in domain or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
        raise HTTPException(400, "Root domain must be a valid fully qualified DNS name, not a URL or IP address.")
    return domain


@app.get("/api/organizations")
def list_organizations():
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            """SELECT o.*, COUNT(a.id) AS asset_count FROM organizations o
               LEFT JOIN assets a ON a.organization_id=o.id
               GROUP BY o.id ORDER BY o.name COLLATE NOCASE"""
        )]


@app.post("/api/organizations")
def create_organization(request: OrganizationRequest):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to register this organization/root domain.")
    name = request.name.strip()
    if not name:
        raise HTTPException(400, "Organization name cannot be blank.")
    root_domain = normalize_root_domain(request.root_domain)
    timestamp = now()
    with connect() as conn:
        existing = conn.execute("SELECT * FROM organizations WHERE root_domain=?", (root_domain,)).fetchone()
        if existing:
            before = {key: existing[key] for key in ("name", "owner_contact", "notes")}
            after = {"name": name, "owner_contact": request.owner_contact.strip(), "notes": request.notes.strip()}
            conn.execute("UPDATE organizations SET name=?,owner_contact=?,notes=?,updated_at=? WHERE id=?",
                         (name, after["owner_contact"], after["notes"], timestamp, existing["id"]))
            if before != after:
                conn.execute("""INSERT INTO organization_events(organization_id,event_at,event_type,summary,details_json)
                    VALUES(?,?,?,?,?)""", (existing["id"], timestamp, "organization_updated", "Organization details updated",
                    json.dumps({"before": before, "after": after}, sort_keys=True)))
            row = conn.execute("SELECT * FROM organizations WHERE id=?", (existing["id"],)).fetchone()
            return {**dict(row), "created": False}
        try:
            cursor = conn.execute(
                "INSERT INTO organizations(name,root_domain,owner_contact,notes,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (name, root_domain, request.owner_contact.strip(), request.notes.strip(), timestamp, timestamp),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "An organization with that name already exists; use its existing record or choose a unique name.") from exc
        conn.execute("INSERT INTO organization_events(organization_id,event_at,event_type,summary,details_json) VALUES(?,?,?,?,?)",
                     (cursor.lastrowid, timestamp, "organization_registered", "Organization/root domain registered",
                      json.dumps({"root_domain": root_domain, "owner_contact": request.owner_contact.strip()}, sort_keys=True)))
        row = conn.execute("SELECT * FROM organizations WHERE id=?", (cursor.lastrowid,)).fetchone()
        return {**dict(row), "created": True}


def build_posture_signals(asset):
    signals = []
    if asset.get("scope_status") == "needs_review":
        signals.append({"code": "scope_review_required", "label": "Scope review required"})
    if not asset.get("organization_id"):
        signals.append({"code": "owner_unassigned", "label": "Organization unassigned"})
    if asset.get("discovery_source") != "manual":
        signals.append({"code": "discovered_candidate", "label": "Discovered candidate"})
    resolution = asset.get("resolution_status") or "unknown"
    if resolution == "unknown":
        signals.append({"code": "dns_not_checked", "label": "DNS not checked"})
    elif resolution != "resolved":
        signals.append({"code": "dns_unresolved", "label": "DNS unresolved"})
    if asset.get("scope_status") == "needs_review":
        priority = "Review scope"
    elif not asset.get("organization_id"):
        priority = "Assign organization"
    elif resolution != "resolved":
        priority = "Resolve DNS"
    else:
        priority = "Inventory recorded"
    return signals, priority


@app.get("/api/assets")
def list_assets():
    with connect() as conn:
        rows = [dict(row) for row in conn.execute(
            """SELECT a.*, o.name AS organization_name, o.root_domain AS organization_root_domain
               FROM assets a LEFT JOIN organizations o ON o.id=a.organization_id
               ORDER BY a.last_seen DESC, a.id DESC"""
        )]
    for asset in rows:
        signals, priority = build_posture_signals(asset)
        asset["posture_signals"] = signals
        asset["posture_priority"] = priority
    return rows


@app.get("/api/easm/source-health")
def easm_source_health():
    with connect() as conn:
        sources = conn.execute(
            """SELECT source, COUNT(*) AS run_count,
                      SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS success_count,
                      SUM(CASE WHEN status!='success' THEN 1 ELSE 0 END) AS failure_count
               FROM discovery_runs GROUP BY source ORDER BY source"""
        ).fetchall()
        result = []
        for source_row in sources:
            source = dict(source_row)
            latest = conn.execute(
                """SELECT id, root_asset_id, started_at, finished_at, status,
                          candidate_count, new_assets_added, error_summary
                   FROM discovery_runs WHERE source=? ORDER BY id DESC LIMIT 1""",
                (source["source"],),
            ).fetchone()
            source["latest_run"] = dict(latest) if latest else None
            result.append(source)
        dns = conn.execute(
            """SELECT resolution_status, COUNT(*) AS asset_count
               FROM assets GROUP BY resolution_status ORDER BY resolution_status"""
        ).fetchall()
    return {"sources": result, "dns_inventory": [dict(row) for row in dns]}


@app.get("/api/organizations/{organization_id}/events")
def list_organization_events(organization_id: int):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM organizations WHERE id=?", (organization_id,)).fetchone():
            raise HTTPException(404, "Organization not found")
        return [dict(row) for row in conn.execute(
            "SELECT * FROM organization_events WHERE organization_id=? ORDER BY id DESC LIMIT 100", (organization_id,))]


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
        organization_id = request.organization_id
        if organization_id is not None:
            organization = conn.execute("SELECT * FROM organizations WHERE id=?", (organization_id,)).fetchone()
            if not organization:
                raise HTTPException(404, "Organization not found")
            root_domain = organization["root_domain"].lower().rstrip(".")
            if hostname != root_domain and not hostname.endswith("." + root_domain):
                raise HTTPException(400, "Asset hostname must match the organization's exact root domain or a true subdomain label boundary.")
        else:
            matches = conn.execute("SELECT id,root_domain FROM organizations").fetchall()
            eligible = [row for row in matches if hostname == row["root_domain"] or hostname.endswith("." + row["root_domain"])]
            if eligible:
                organization_id = max(eligible, key=lambda row: len(row["root_domain"]))["id"]
        existing = conn.execute("SELECT * FROM assets WHERE target=?", (normalized,)).fetchone()
        if existing:
            conn.execute("UPDATE assets SET last_seen=?, notes=?, organization_id=COALESCE(?, organization_id) WHERE id=?",
                         (timestamp, request.notes, organization_id, existing["id"]))
            row = conn.execute("SELECT * FROM assets WHERE id=?", (existing["id"],)).fetchone()
            return {**dict(row), "created": False}
        initial_decision = "approved" if request.scope_status == "in_scope" else ("rejected" if request.scope_status == "out_of_scope" else "pending")
        cursor = conn.execute(
            """INSERT INTO assets(target,asset_type,scope_status,discovery_source,first_seen,last_seen,notes,reviewed_at,review_decision,organization_id)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (normalized, asset_type, request.scope_status, "manual", timestamp, timestamp, request.notes,
             timestamp if initial_decision in {"approved", "rejected"} else None, initial_decision, organization_id),
        )
        row = conn.execute("SELECT * FROM assets WHERE id=?", (cursor.lastrowid,)).fetchone()
        record_asset_event(conn, cursor.lastrowid, "asset_registered", "Asset registered in inventory", {
            "scope_status": request.scope_status, "discovery_source": "manual", "organization_id": organization_id,
        })
        return {**dict(row), "created": True}


@app.patch("/api/assets/{asset_id}/organization")
def update_asset_organization(asset_id: int, request: AssetOrganizationUpdate):
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to change asset ownership association.")
    with connect() as conn:
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not asset:
            raise HTTPException(404, "Asset not found")
        org = None
        if request.organization_id is not None:
            org = conn.execute("SELECT * FROM organizations WHERE id=?", (request.organization_id,)).fetchone()
            if not org:
                raise HTTPException(404, "Organization not found")
            hostname = (urlparse(asset["target"]).hostname or "").lower().rstrip(".")
            root = org["root_domain"].lower().rstrip(".")
            if hostname != root and not hostname.endswith("." + root):
                raise HTTPException(400, "Asset hostname must match the organization's exact root domain or a true subdomain label boundary.")
        old_id = asset["organization_id"]
        if old_id == request.organization_id:
            return {"asset_id": asset_id, "organization_id": old_id, "changed": False}
        conn.execute("UPDATE assets SET organization_id=?,last_seen=? WHERE id=?", (request.organization_id, now(), asset_id))
        record_asset_event(conn, asset_id, "organization_reassigned", "Asset organization association changed", {
            "from_organization_id": old_id, "to_organization_id": request.organization_id,
            "reason": request.notes.strip(),
        })
        return {"asset_id": asset_id, "organization_id": request.organization_id, "changed": True}


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
        if existing["scope_status"] != request.scope_status or (request.scope_status == "in_scope" and existing["approval_reference"] != approval_reference):
            record_asset_event(conn, asset_id, "scope_changed", "Asset scope changed", {
                "from": existing["scope_status"], "to": request.scope_status,
                "approval_reference": approval_reference if decision == "approved" else "",
                "review_decision": decision,
            })
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


def query_wayback_hosts(root_domain: str, max_results: int) -> list[str]:
    """Read a bounded Wayback CDX index response; never fetch archived pages or target hosts."""
    endpoint = "https://web.archive.org/cdx/search/cdx?" + urlencode({
        "url": "*." + root_domain + "/*",
        "output": "json",
        "fl": "original",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(min(max_results * 20, 2000)),
    })
    req = Request(endpoint, headers={
        "Accept": "application/json",
        "User-Agent": "DKCISSP-WebSecurityScanner/0.1 (passive authorized inventory)",
    })
    with urlopen(req, timeout=12) as response:
        payload = response.read(1_000_001)
    if len(payload) > 1_000_000:
        raise HTTPException(502, "Wayback CDX response exceeded the 1 MB safety limit.")
    try:
        records = json.loads(payload.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(502, "Wayback CDX returned invalid JSON.")
    if not isinstance(records, list):
        raise HTTPException(502, "Wayback CDX returned an unexpected response.")
    candidates = set()
    suffix = "." + root_domain
    for record in records:
        if not isinstance(record, list):
            continue
        for raw_url in record:
            try:
                hostname = (urlparse(str(raw_url)).hostname or "").lower().rstrip(".")
            except ValueError:
                continue
            if (hostname == root_domain or hostname.endswith(suffix)) and valid_dns_name(hostname):
                if hostname != root_domain:
                    candidates.add(hostname)
    return sorted(candidates)[:max_results]


def run_wayback_discovery_adapter(root_domain: str, max_results: int) -> dict:
    """Normalize a bounded Wayback CDX query into the common discovery contract."""
    started = now()
    try:
        candidates = query_wayback_hosts(root_domain, max_results)
        return {"source": "wayback", "started_at": started, "finished_at": now(),
                "status": "completed", "candidates": candidates, "errors": [],
                "limit_metadata": {"max_results": max_results, "response_limit_bytes": 1_000_000,
                                   "cdx_record_limit": min(max_results * 20, 2000)}}
    except Exception as exc:
        return {"source": "wayback", "started_at": started, "finished_at": now(),
                "status": "failed", "candidates": [],
                "errors": [f"{type(exc).__name__}: {str(exc)[:300]}"],
                "limit_metadata": {"max_results": max_results, "response_limit_bytes": 1_000_000,
                                   "cdx_record_limit": min(max_results * 20, 2000)}}


def run_ct_discovery_adapter(root_domain: str, max_results: int) -> dict:
    """Normalize the CT source into a stable, auditable adapter result contract."""
    started = now()
    try:
        candidates = query_certificate_transparency(root_domain, max_results)
        return {"source": "crt.sh", "started_at": started, "finished_at": now(),
                "status": "completed", "candidates": candidates, "errors": [],
                "limit_metadata": {"max_results": max_results, "response_limit_bytes": 1_000_000}}
    except Exception as exc:
        return {"source": "crt.sh", "started_at": started, "finished_at": now(),
                "status": "failed", "candidates": [],
                "errors": [f"{type(exc).__name__}: {str(exc)[:300]}"],
                "limit_metadata": {"max_results": max_results, "response_limit_bytes": 1_000_000}}


def persist_discovery_run(root_asset_id: int, result: dict, candidate_count: int = 0,
                          new_assets_added: int = 0, error_summary: str = "") -> int:
    with connect() as conn:
        cur = conn.execute("""INSERT INTO discovery_runs
            (root_asset_id,source,started_at,finished_at,status,candidate_count,new_assets_added,error_summary,metadata_json)
            VALUES(?,?,?,?,?,?,?,?,?)""", (root_asset_id, result["source"], result["started_at"],
            result["finished_at"], result["status"], candidate_count, new_assets_added,
            error_summary[:500], json.dumps(result.get("limit_metadata", {}), sort_keys=True)))
        run_id = cur.lastrowid
        if result.get("status") == "completed":
            previous = conn.execute("""SELECT id FROM discovery_runs WHERE root_asset_id=? AND source=? AND status='completed' AND id<?
                ORDER BY id DESC LIMIT 1""", (root_asset_id, result["source"], run_id)).fetchone()
            previous_targets = set()
            if previous:
                previous_targets = {row["target"] for row in conn.execute(
                    "SELECT target FROM asset_snapshots WHERE discovery_run_id=? AND state IN ('new','present')", (previous["id"],))}
            current_targets = {"https://" + host for host in result.get("candidates", [])}
            for target in sorted(current_targets):
                asset = conn.execute("SELECT id FROM assets WHERE target=?", (target,)).fetchone()
                state = "present" if target in previous_targets else "new"
                conn.execute("INSERT INTO asset_snapshots(root_asset_id,discovery_run_id,asset_id,target,state,observed_at) VALUES(?,?,?,?,?,?)",
                    (root_asset_id, run_id, asset["id"] if asset else None, target, state, result["finished_at"]))
                if state == "new" and previous:
                    record_asset_event(conn, asset["id"], "discovery_new", "Asset newly observed in a successful discovery run", {"source": result["source"], "run_id": run_id})
            missing_targets = previous_targets - current_targets
            for target in sorted(missing_targets):
                old = conn.execute("SELECT asset_id FROM asset_snapshots WHERE discovery_run_id=? AND target=? AND asset_id IS NOT NULL LIMIT 1", (previous["id"], target)).fetchone()
                conn.execute("INSERT INTO asset_snapshots(root_asset_id,discovery_run_id,asset_id,target,state,observed_at) VALUES(?,?,?,?,?,?)",
                    (root_asset_id, run_id, old["asset_id"] if old else None, target, "missing_from_source", result["finished_at"]))
                if old and old["asset_id"]:
                    record_asset_event(conn, old["asset_id"], "discovery_missing", "Asset absent from latest successful discovery result; not confirmed removed", {"source": result["source"], "run_id": run_id})
        return run_id


@app.get("/api/assets/{asset_id}/discovery-runs")
def list_asset_discovery_runs(asset_id: int):
    with connect() as conn:
        if not conn.execute("SELECT id FROM assets WHERE id=?", (asset_id,)).fetchone():
            raise HTTPException(404, "Asset not found")
        return [dict(row) for row in conn.execute(
            "SELECT * FROM discovery_runs WHERE root_asset_id=? ORDER BY id DESC LIMIT 50", (asset_id,))]


@app.get("/api/assets/{asset_id}/snapshots")
def list_asset_snapshots(asset_id: int):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone():
            raise HTTPException(404, "Asset not found")
        return [dict(row) for row in conn.execute(
            "SELECT * FROM asset_snapshots WHERE asset_id=? ORDER BY id DESC LIMIT 100", (asset_id,))]


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
    result = (run_ct_discovery_adapter(root_domain, request.max_results)
              if request.source == "crt.sh"
              else run_wayback_discovery_adapter(root_domain, request.max_results))
    if result["status"] != "completed":
        message = result["errors"][0] if result["errors"] else "Unknown source error"
        persist_discovery_run(asset_id, result, error_summary=message)
        raise HTTPException(502, "Passive discovery failed; source status was recorded in discovery history.")
    candidates = result["candidates"]
    timestamp = now()
    created = 0
    with connect() as conn:
        for hostname in candidates:
            target = "https://" + hostname
            exists = conn.execute("SELECT id FROM assets WHERE target=?", (target,)).fetchone()
            if exists:
                conn.execute("UPDATE assets SET last_seen=? WHERE id=?", (timestamp, exists["id"]))
                continue
            inserted = conn.execute(
                """INSERT INTO assets(target,asset_type,scope_status,discovery_source,first_seen,last_seen,notes,organization_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (target, "subdomain", "needs_review", result["source"], timestamp, timestamp,
                 "Passive " + result["source"] + " candidate; verify ownership and scope before scanning.", root["organization_id"]),
            )
            record_asset_event(conn, inserted.lastrowid, "passive_discovery", "Candidate discovered via " + result["source"], {
                "source": result["source"], "root_asset_id": asset_id, "scope_status": "needs_review",
            })
            created += 1
    run_id = persist_discovery_run(asset_id, result, candidate_count=len(candidates), new_assets_added=created)
    return {"root_asset_id": asset_id, "run_id": run_id, "source": result["source"],
            "source_status": result["status"], "started_at": result["started_at"],
            "finished_at": result["finished_at"], "candidates_found": len(candidates),
            "new_assets_added": created, "scope_status": "needs_review",
            "limit_metadata": result["limit_metadata"], "scans_started": 0,
            "message": "Candidates were added for review only; no hosts were contacted or scanned."}


@app.get("/api/assets/{asset_id}/events")
def list_asset_events(asset_id: int):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone():
            raise HTTPException(404, "Asset not found")
        return [dict(row) for row in conn.execute(
            "SELECT * FROM asset_events WHERE asset_id=? ORDER BY id DESC LIMIT 100", (asset_id,)
        )]


@app.post("/api/assets/{asset_id}/resolve")
def resolve_asset_dns(asset_id: int, request: AssetResolveRequest):
    """Explicit, bounded DNS inventory action. Does not probe HTTP/TLS or launch scans."""
    if not request.authorized:
        raise HTTPException(400, "Confirm you are authorized to resolve this asset's DNS records.")
    with connect() as conn:
        asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not asset:
            raise HTTPException(404, "Asset not found")
        org = conn.execute("SELECT root_domain FROM organizations WHERE id=?", (asset["organization_id"],)).fetchone() if asset["organization_id"] else None
    parsed = urlparse(asset["target"])
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not valid_dns_name(hostname) or "." not in hostname or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
        raise HTTPException(400, "DNS resolution requires a fully qualified DNS hostname, not an IP or local name.")
    if asset["discovery_source"] != "manual" and (not org or not (hostname == org["root_domain"] or hostname.endswith("." + org["root_domain"]))):
        raise HTTPException(403, "Discovered candidates must be linked to a registered organization root before DNS resolution.")
    checked = now()
    status, addresses, error = "no_records", [], ""
    future = DNS_RESOLVER_POOL.submit(socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM)
    try:
        records = future.result(timeout=request.timeout_seconds)
        addresses = sorted({str(record[4][0]) for record in records if record and len(record) > 4 and record[4]})
        status = "resolved" if addresses else "no_records"
    except Exception as exc:
        future.cancel()
        if isinstance(exc, TimeoutError):
            status, error = "timeout", f"DNS lookup exceeded {request.timeout_seconds}s"
        elif isinstance(exc, socket.gaierror):
            status, error = "no_records", str(exc)[:300]
        else:
            status, error = "error", f"{type(exc).__name__}: {str(exc)[:250]}"
    with connect() as conn:
        conn.execute("UPDATE assets SET resolution_status=?,resolved_addresses_json=?,resolution_checked_at=?,resolution_error=?,last_seen=? WHERE id=?",
                     (status, json.dumps(addresses), checked, error, checked, asset_id))
        record_asset_event(conn, asset_id, "dns_resolution", "DNS inventory lookup completed", {
            "status": status, "address_count": len(addresses), "error": error,
        })
    return {"asset_id": asset_id, "hostname": hostname, "resolution_status": status,
            "addresses": addresses, "checked_at": checked, "error": error,
            "http_probes_started": 0, "tls_checks_started": 0, "scans_started": 0}


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
    # start_scan performs the authoritative, atomic capacity check and stale-worker recovery.
    scan_id = start_scan(target, request.profile)
    return {
        "id": scan_id, "status": "running", "profile": request.profile,
        "message": "Assessment started with the selected profile. Standard adds bounded discovery and safe Nuclei checks; Deep adds bounded Nikto checks; Active additionally runs explicitly approved Wapiti payload tests. Optional ZAP passive alerts require a healthy local API.",
    }


@app.get("/api/scans")
def list_scans():
    with connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM scans ORDER BY id DESC")]


@app.get("/api/scans/{scan_id}/activity")
def get_scan_activity(scan_id: int, after_id: int = 0, limit: int = 100):
    """Return persisted timeline events for a single scan, newest events last."""
    limit = max(1, min(int(limit), 200))
    with connect() as conn:
        if not conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone():
            raise HTTPException(404, "Scan not found.")
        rows = conn.execute(
            "SELECT id,category,status,stage,message,created_at FROM scanner_activity WHERE scan_id=? AND id>? ORDER BY id ASC LIMIT ?",
            (scan_id, max(0, int(after_id)), limit),
        ).fetchall()
    return {"events": [dict(row) for row in rows]}


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
    significant = value.lstrip(" \\t\\r\n")
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
    # Existing scanner integrations. A registered tool is not necessarily run in every profile.
    "curl": {"label": "curl", "binary": "curl", "package": "curl", "version_args": ["--version"], "purpose": "HTTP connectivity and endpoint diagnostics", "capabilities": ["http_diagnostics"], "risk": "passive", "integration": "integrated", "installable": True},
    "zaproxy": {"label": "OWASP ZAP", "binary": "zaproxy", "package": "zaproxy", "version_args": ["-version"], "purpose": "Web application security rules and passive alerts", "capabilities": ["web_app", "passive_checks", "api_security"], "risk": "passive_by_default", "integration": "integrated", "installable": True},
    "whatweb": {"label": "WhatWeb", "binary": "whatweb", "package": "whatweb", "version_args": ["--version"], "purpose": "Technology fingerprinting", "capabilities": ["technology_fingerprinting", "cms_detection"], "risk": "passive", "integration": "integrated", "installable": True},
    "testssl": {"label": "testssl.sh", "binary": "testssl.sh", "package": "testssl.sh", "version_args": ["--version"], "purpose": "TLS and HTTPS configuration assessment", "capabilities": ["tls", "https_configuration"], "risk": "low_impact", "integration": "integrated", "installable": True},
    "nuclei": {"label": "Nuclei", "binary": "nuclei", "package": "nuclei", "version_args": ["-version"], "purpose": "Template-based checks for known exposures and misconfigurations", "capabilities": ["known_vulnerabilities", "misconfiguration", "exposure_detection"], "risk": "curated_templates_only", "integration": "integrated", "installable": True},
    "nikto": {"label": "Nikto", "binary": "nikto", "package": "nikto", "version_args": ["-Version"], "purpose": "Web-server files and misconfiguration checks", "capabilities": ["web_server", "exposed_files", "misconfiguration"], "risk": "low_to_moderate_request_volume", "integration": "integrated_deep_profile", "installable": True},
    "wapiti": {"label": "Wapiti", "binary": "wapiti", "package": "wapiti", "version_args": ["--version"], "purpose": "Active web-application vulnerability tests", "capabilities": ["web_app_active", "injection_testing"], "risk": "active_requires_approval", "integration": "explicit_active_profile", "installable": True},
    # Expanded Kali inventory. These are capability candidates, not a claim that the scan runner invokes them yet.
    "nmap": {"label": "Nmap", "binary": "nmap", "package": "nmap", "version_args": ["--version"], "purpose": "Network/service discovery for explicitly scoped hosts", "capabilities": ["service_discovery", "network_exposure"], "risk": "network_scope_required", "integration": "inventory_only", "installable": True},
    "httpx": {"label": "ProjectDiscovery httpx", "binary": "httpx", "package": None, "version_args": ["-version"], "purpose": "HTTP service probing and metadata enrichment", "capabilities": ["http_probing", "technology_enrichment"], "risk": "low_impact_scoped_probe", "integration": "inventory_only", "installable": False, "install_note": "Package name conflicts with other software; install only through a verified ProjectDiscovery-specific method."},
    "katana": {"label": "Katana", "binary": "katana", "package": "katana", "version_args": ["-version"], "purpose": "Endpoint discovery and crawling", "capabilities": ["endpoint_discovery"], "risk": "crawl_scope_and_rate_limits_required", "integration": "inventory_only", "installable": True},
    "ffuf": {"label": "FFUF", "binary": "ffuf", "package": "ffuf", "version_args": ["-V"], "purpose": "Content discovery and fuzzing", "capabilities": ["content_discovery", "fuzzing"], "risk": "active_high_request_volume", "integration": "inventory_only", "installable": True},
    "dirsearch": {"label": "Dirsearch", "binary": "dirsearch", "package": "dirsearch", "version_args": ["--version"], "purpose": "Web path and content discovery", "capabilities": ["content_discovery", "exposed_files"], "risk": "active_high_request_volume", "integration": "inventory_only", "installable": True},
    "gobuster": {"label": "Gobuster", "binary": "gobuster", "package": "gobuster", "version_args": ["version"], "purpose": "Directory and DNS discovery", "capabilities": ["content_discovery", "dns_discovery"], "risk": "active_scope_and_rate_limits_required", "integration": "inventory_only", "installable": True},
    "feroxbuster": {"label": "Feroxbuster", "binary": "feroxbuster", "package": "feroxbuster", "version_args": ["--version"], "purpose": "Recursive content discovery", "capabilities": ["content_discovery", "exposed_files"], "risk": "active_high_request_volume", "integration": "inventory_only", "installable": True},
    "sqlmap": {"label": "sqlmap", "binary": "sqlmap", "package": "sqlmap", "version_args": ["--version"], "purpose": "Specialized SQL injection testing against same-origin OpenAPI operations", "capabilities": ["sql_injection", "api_security"], "risk": "intrusive_requires_explicit_approval", "integration": "explicit_active_profile", "installable": True},
    "wpscan": {"label": "WPScan", "binary": "wpscan", "package": "wpscan", "version_args": ["--version"], "purpose": "WordPress detection and vulnerability checks", "capabilities": ["wordpress", "cms_vulnerabilities", "plugin_theme_inventory"], "risk": "scoped_checks_api_token_may_be_needed", "integration": "inventory_only", "installable": True},
    "dalfox": {"label": "Dalfox", "binary": "dalfox", "package": "dalfox", "version_args": ["version"], "purpose": "Specialized XSS detection and verification", "capabilities": ["xss_testing", "parameter_testing"], "risk": "active_payloads_requires_explicit_approval", "integration": "manual_only", "installable": True},
    "arjun": {"label": "Arjun", "binary": "arjun", "package": "arjun", "version_args": ["--version"], "purpose": "HTTP parameter discovery for web and API endpoints", "capabilities": ["api_parameter_discovery", "endpoint_discovery"], "risk": "active_parameter_probing_requires_scope_limits", "integration": "inventory_only", "installable": True},
    "commix": {"label": "Commix", "binary": "commix", "package": "commix", "version_args": ["--version"], "purpose": "Specialized command-injection testing", "capabilities": ["command_injection"], "risk": "intrusive_requires_explicit_approval", "integration": "manual_only", "installable": True},
    "joomscan": {"label": "JoomScan", "binary": "joomscan", "package": "joomscan", "version_args": ["--version"], "purpose": "Joomla CMS vulnerability and exposure checks", "capabilities": ["joomla", "cms_vulnerabilities"], "risk": "scoped_checks_required", "integration": "inventory_only", "installable": True},
    "wafw00f": {"label": "WAFW00F", "binary": "wafw00f", "package": "wafw00f", "version_args": ["--version"], "purpose": "Heuristic web application firewall detection", "capabilities": ["waf_detection", "technology_fingerprinting"], "risk": "low_impact_heuristic", "integration": "inventory_only", "installable": True},
    "gitleaks": {"label": "Gitleaks", "binary": "gitleaks", "package": "gitleaks", "version_args": ["version"], "purpose": "Secret scanning for explicitly supplied local repositories", "capabilities": ["secret_scanning", "repository_security"], "risk": "local_files_only_no_remote_repo_clone_by_default", "integration": "inventory_only", "installable": True},
    "sslscan": {"label": "sslscan", "binary": "sslscan", "package": "sslscan", "version_args": ["--version"], "purpose": "TLS protocol and certificate configuration checks", "capabilities": ["tls", "certificate_checks"], "risk": "low_impact", "integration": "inventory_only", "installable": True},
    "amass": {"label": "OWASP Amass", "binary": "amass", "package": "amass", "version_args": ["-version"], "purpose": "Asset and subdomain discovery", "capabilities": ["asset_discovery", "dns_discovery"], "risk": "recon_scope_required", "integration": "inventory_only", "installable": True},
    "subfinder": {"label": "Subfinder", "binary": "subfinder", "package": "subfinder", "version_args": ["-version"], "purpose": "Passive subdomain discovery", "capabilities": ["asset_discovery", "passive_recon"], "risk": "passive_but_scope_review_required", "integration": "inventory_only", "installable": True},
    "dnsx": {"label": "DNSx", "binary": "dnsx", "package": "dnsx", "version_args": ["-version"], "purpose": "DNS resolution and record checks", "capabilities": ["dns_discovery", "asset_validation"], "risk": "low_impact_scoped_dns", "integration": "inventory_only", "installable": True},
}

TOOL_CAPABILITY_DESCRIPTIONS = {
    "http_diagnostics": "HTTP connectivity and response diagnostics",
    "web_app": "Web application security checks",
    "passive_checks": "Passive checks that do not submit attack payloads",
    "api_security": "API and web application security signals",
    "technology_fingerprinting": "Identify frameworks, servers and libraries",
    "cms_detection": "Identify content management systems",
    "tls": "TLS and HTTPS configuration",
    "https_configuration": "HTTPS response and transport configuration",
    "known_vulnerabilities": "Template-based checks for known vulnerability patterns",
    "misconfiguration": "Security misconfiguration checks",
    "exposure_detection": "Detect exposed services, files and panels",
    "web_server": "Web-server security checks",
    "exposed_files": "Check for potentially exposed files and paths",
    "web_app_active": "Active web-application testing",
    "injection_testing": "Injection testing; requires approved profile",
    "service_discovery": "Discover services on explicitly authorized hosts",
    "network_exposure": "Network service exposure signals",
    "http_probing": "HTTP service metadata and status checks",
    "technology_enrichment": "Enrich detected web technology information",
    "endpoint_discovery": "Discover same-origin application endpoints",
    "content_discovery": "Discover web paths and content",
    "fuzzing": "Payload/path fuzzing; not a default action",
    "dns_discovery": "DNS and subdomain discovery",
    "sql_injection": "Specialized SQL injection assessment; explicit approval required",
    "wordpress": "WordPress-specific checks",
    "cms_vulnerabilities": "CMS, plugin and theme vulnerability checks",
    "plugin_theme_inventory": "Inventory CMS plugins and themes",
    "xss_testing": "Cross-site scripting tests; explicit approval required",
    "parameter_testing": "Parameter discovery and validation",
    "api_parameter_discovery": "Discover potential HTTP/API parameters",
    "command_injection": "Command-injection tests; intrusive and approval-gated",
    "joomla": "Joomla CMS-specific checks",
    "waf_detection": "Heuristic WAF presence detection, not proof of protection",
    "secret_scanning": "Detect likely secrets in explicitly supplied local files",
    "repository_security": "Static repository security checks",
    "certificate_checks": "Certificate and TLS checks",
    "asset_discovery": "Asset discovery requiring scope review",
    "passive_recon": "Passive reconnaissance signals",
    "asset_validation": "Validate discovered DNS assets",
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
    # Version commands are independent; run a bounded number concurrently so a
    # slow or noisy tool cannot serialize the entire inventory page load.
    candidates = [(key, spec, shutil.which(spec["binary"])) for key, spec in TOOL_CATALOG.items()]
    installed = [(key, spec, path) for key, spec, path in candidates if path]
    versions = {}
    if installed:
        with ThreadPoolExecutor(max_workers=min(8, len(installed)), thread_name_prefix="tool-version") as pool:
            futures = {key: pool.submit(_tool_version, spec) for key, spec, _ in installed}
            for key, future in futures.items():
                try:
                    versions[key] = future.result(timeout=5)
                except Exception:
                    versions[key] = None
    tools = []
    for key, spec, path in candidates:
        version = versions.get(key) if path else None
        tools.append({
            "id": key, "name": spec["label"], "purpose": spec["purpose"],
            "installed": bool(path), "status": "ready" if path and version else ("installed_check_failed" if path else "missing"),
            "path": path, "version": version,
            "install_method": "Kali/Debian package manager" if spec.get("installable") and spec.get("package") else "verified method required",
            "package": spec.get("package"),
            "installable": bool(spec.get("installable") and spec.get("package")),
            "install_note": spec.get("install_note", ""),
            "capabilities": spec.get("capabilities", []),
            "risk": spec.get("risk", "review_required"),
            "integration": spec.get("integration", "inventory_only"),
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
    tools = scanner_tools_status()
    capability_map = {}
    for item in tools:
        for capability in item.get("capabilities", []):
            capability_map.setdefault(capability, []).append({
                "tool_id": item["id"], "name": item["name"],
                "installed": item["installed"], "integration": item["integration"],
                "risk": item["risk"],
            })
    return {
        "tools": tools,
        "install_supported": bool(shutil.which("pkexec") and shutil.which("apt-get")),
        "capabilities": TOOL_CAPABILITY_DESCRIPTIONS,
        "capability_map": capability_map,
        "inventory_count": len(tools),
        "installed_count": sum(1 for item in tools if item["installed"]),
        "note": "Capability inventory covers curated web-security and supporting tools. Inventory-only tools are not automatically executed by scan profiles. Package installs use a fixed allow-list and require explicit local approval.",
    }


def update_install_job(job_id: int, status: str, stage: str, message: str, finished: bool = False) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE install_jobs SET status=?,stage=?,message=?,updated_at=?,finished_at=? WHERE id=?",
            (status, stage[:160], message[:800], now(), now() if finished else None, job_id),
        )


def run_install_job(job_id: int, tool_id: str) -> None:
    spec = TOOL_CATALOG[tool_id]
    try:
        update_install_job(job_id, "running", "Checking prerequisites", "Checking package manager and executable status.")
        if shutil.which(spec["binary"]):
            update_install_job(job_id, "completed", "Already installed", f"{spec['label']} is already installed and executable.", True)
            return
        pkexec, apt = shutil.which("pkexec"), shutil.which("apt-get")
        if not pkexec or not apt:
            update_install_job(job_id, "failed", "Manual installation required",
                               f"Automatic installation is unavailable. On Kali, run: sudo apt update && sudo apt install {spec['package']}", True)
            return
        update_install_job(job_id, "running", "Waiting for administrator approval",
                           "The package manager will request local administrator authentication if needed.")
        result = subprocess.run(
            [pkexec, apt, "install", "-y", "--no-install-recommends", spec["package"]],
            capture_output=True, text=True, timeout=240, check=False,
        )
        if result.returncode != 0:
            # Do not send raw package output to the UI; it can contain environment details.
            detail = (result.stderr or result.stdout or "Package installation failed").strip().splitlines()[-1:]
            message = (detail[0][:500] if detail else "Package installation failed")
            update_install_job(job_id, "failed", "Installation failed", message, True)
            return
        update_install_job(job_id, "running", "Verifying installation", "Installation command completed; checking the executable and version.")
        statuses = scanner_tools_status()
        installed = next((item for item in statuses if item["id"] == tool_id), None)
        ok = bool(installed and installed.get("installed"))
        update_install_job(job_id, "completed" if ok else "failed", "Installation verified" if ok else "Verification failed",
                           f"{spec['label']} {'is installed and verified.' if ok else 'could not be verified after installation.'}", True)
    except subprocess.TimeoutExpired:
        update_install_job(job_id, "failed", "Timed out", "Package installation exceeded 240 seconds. Check the package manager before retrying.", True)
    except Exception:
        update_install_job(job_id, "failed", "Installation error", "Installation could not be completed. Check the local package manager logs.", True)


@app.post("/api/tools/install/{tool_id}")
def install_tool(tool_id: str, request: ToolInstallRequest, client: FastAPIRequest):
    if tool_id not in TOOL_CATALOG:
        raise HTTPException(404, "Tool is not in the approved installer allow-list.")
    if not request.approved:
        raise HTTPException(400, "Explicit installation approval is required.")
    if client.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(403, "Tool installation is available only from the local machine.")
    spec = TOOL_CATALOG[tool_id]
    if not spec.get("installable") or not spec.get("package"):
        raise HTTPException(400, spec.get("install_note") or "No verified package installation method is configured for this tool.")
    with connect() as conn:
        active = conn.execute("SELECT id FROM install_jobs WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()
        if active:
            raise HTTPException(409, "Another tool installation is already running. Wait for it to finish before starting another.")
        cursor = conn.execute(
            "INSERT INTO install_jobs(tool_id,tool_name,status,stage,message,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (tool_id, spec['label'], 'running', 'Queued', 'Installation job queued; preparing package manager.', now(), now()),
        )
        job_id = cursor.lastrowid
    threading.Thread(target=run_install_job, args=(job_id, tool_id), daemon=True).start()
    return {"job_id": job_id, "tool_id": tool_id, "status": "running", "stage": "Queued", "message": "Installation job started."}


@app.get("/api/tools/install-jobs/{job_id}")
def get_install_job(job_id: int):
    with connect() as conn:
        row = conn.execute("SELECT * FROM install_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Installation job not found.")
    return dict(row)
