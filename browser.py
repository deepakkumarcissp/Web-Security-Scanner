"""Browser-based crawler for JavaScript single-page apps.

A headless Chromium (the Kali `chromium` package, installed only with the assessor's approval) loads the pages so the app's own
JavaScript runs, and the scanner reads what the browser ends up with: links that exist only in the rendered page, forms built in
the browser, and the API calls the app makes. Nothing else is installed: the browser is driven over its local DevTools socket by
the small client below (standard library only).

Safety rules, enforced on every request the browser makes (not just the ones the scanner asks for):
  * only GET requests leave the browser; any other method is blocked and reported as "not sent";
  * same-origin URLs that look like logout/delete/pay/reset (auth.is_unsafe_url) are blocked;
  * other hosts are reachable only for GET downloads of scripts, styles, fonts, images and media, and never receive credentials;
  * the scanner never clicks, types or submits anything, dialogs are dismissed, downloads and pop-ups are refused;
  * a login session is passed in memory over the local socket (cookies and headers) and never written to disk or a command line.
"""
from __future__ import annotations

import base64
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import ProxyHandler, Request, build_opener

import auth
import signals

STATIC_TYPES = {"Script", "Stylesheet", "Font", "Image", "Media"}
SKIP_EXTENSIONS = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|eot|pdf|zip|gz|tar|mp[34]|avi|mov|exe|dmg|iso)(\?|$)", re.I)
JWT_SHAPE = re.compile(r"^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*$")


class BrowserError(Exception):
    pass


def find_browser() -> str | None:
    configured = os.environ.get("DKCISSP_BROWSER", "").strip()
    if configured and os.path.isfile(configured) and os.access(configured, os.X_OK):
        return configured
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        found = shutil.which(name)
        if found:
            return found
    return None


# ---- a minimal WebSocket client (RFC 6455), enough for the local DevTools protocol -----------------------------------
class WebSocket:
    def __init__(self, host: str, port: int, path: str, timeout: float = 10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise BrowserError("The browser closed the DevTools connection during the handshake.")
            data += chunk
        head, _, self.buffer = data.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise BrowserError("The browser refused the DevTools connection.")

    def send(self, text: str) -> None:
        payload = text.encode()
        size = len(payload)
        header = bytearray([0x81])
        if size < 126:
            header.append(0x80 | size)
        elif size < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", size)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", size)
        mask = os.urandom(4)
        masked = (int.from_bytes(payload, "big") ^ int.from_bytes((mask * (size // 4 + 1))[:size], "big")).to_bytes(size, "big") if size else b""
        self.sock.sendall(bytes(header) + mask + masked)

    def _take(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self.sock.settimeout(10)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise BrowserError("The browser closed the DevTools connection.")
            self.buffer += chunk
        out, self.buffer = self.buffer[:count], self.buffer[count:]
        return out

    def receive(self, timeout: float) -> str | None:
        """One complete text message, or None if nothing arrives within `timeout` seconds."""
        message = b""
        while True:
            if not self.buffer:
                ready, _, _ = select.select([self.sock], [], [], timeout if not message else 10)
                if not ready:
                    return None
            first, second = self._take(2)
            opcode, final, length = first & 0x0F, bool(first & 0x80), second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._take(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._take(8))[0]
            payload = self._take(length) if length else b""
            if opcode == 8:
                raise BrowserError("The browser closed the DevTools connection.")
            if opcode == 9:  # ping: answer with a masked pong
                mask = os.urandom(4)
                if len(payload) < 126:
                    self.sock.sendall(bytes([0x8A, 0x80 | len(payload)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))
                continue
            if opcode in (0, 1, 2):
                message += payload
                if final:
                    return message.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Chromium:
    """A throwaway headless browser with its own empty profile. Always stopped and deleted afterwards."""

    def __init__(self, binary: str):
        self.binary, self.proc, self.dir, self.port = binary, None, "", 0

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="dkcissp-browser-")
        args = [self.binary, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                "--disable-background-networking", "--disable-sync", "--disable-dev-shm-usage", "--block-new-web-contents", "--mute-audio",
                "--disable-component-update", "--remote-debugging-port=0", f"--user-data-dir={self.dir}", "about:blank"]
        if os.geteuid() == 0 or os.environ.get("DKCISSP_BROWSER_NO_SANDBOX") == "1":
            args.insert(1, "--no-sandbox")   # Chromium cannot use its sandbox as root (or where the OS forbids it): opt-in via DKCISSP_BROWSER_NO_SANDBOX=1
        try:
            self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, cwd=self.dir)
        except OSError as exc:
            self.cleanup()
            raise BrowserError(f"The browser could not be started ({exc.__class__.__name__}).") from exc
        port_file = os.path.join(self.dir, "DevToolsActivePort")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.cleanup()
                raise BrowserError("The browser exited right after starting.")
            try:
                with open(port_file) as handle:
                    self.port = int(handle.readline().strip())
                break
            except (OSError, ValueError):
                time.sleep(0.1)
        if not self.port:
            self.cleanup()
            raise BrowserError("The browser did not open its DevTools port in time.")
        return self

    def new_page(self) -> "Page":
        opener = build_opener(ProxyHandler({}))          # the DevTools port is local: never through a proxy
        request = Request(f"http://127.0.0.1:{self.port}/json/new?about:blank", method="PUT")
        try:
            with opener.open(request, timeout=10) as response:
                info = json.loads(response.read().decode())
        except Exception as exc:
            raise BrowserError(f"The browser would not open a page ({exc.__class__.__name__}).") from exc
        path = urlparse(info["webSocketDebuggerUrl"]).path
        return Page(WebSocket("127.0.0.1", self.port, path))

    def cleanup(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    pass
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)

    def __exit__(self, *exc):
        self.cleanup()


EXTRACT = r"""(() => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href } catch (e) { return null } };
  const links = new Set();
  document.querySelectorAll('a[href]').forEach(a => { const h = abs(a.getAttribute('href')); if (h) links.add(h) });
  document.querySelectorAll('[routerlink],[ng-reflect-router-link],[data-href]').forEach(e => {
    const v = e.getAttribute('routerlink') || e.getAttribute('ng-reflect-router-link') || e.getAttribute('data-href') || '';
    if (v.startsWith('/') || v.startsWith('#/')) { const h = abs(v); if (h) links.add(h) } });
  const jwt = /^eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*$/, tokens = [];
  for (const [kind, store] of [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]]) {
    try { for (let i = 0; i < store.length; i++) { const k = store.key(i), v = (store.getItem(k) || '').trim();
      if (jwt.test(v) || (/(token|jwt|secret|api[_-]?key)/i.test(k) && v.length >= 16)) tokens.push([kind, k.slice(0, 60), jwt.test(v)]) } } catch (e) {}
  }
  return JSON.stringify({url: location.href, title: document.title.slice(0, 200), html: document.documentElement.outerHTML.slice(0, 600000),
    links: [...links].slice(0, 400), scripts: [...document.scripts].map(s => s.src).filter(Boolean).slice(0, 100), tokens: tokens.slice(0, 20)});
})()"""


class Page:
    """One browser tab, driven over its DevTools socket. Every network request it makes passes through `decide`."""

    def __init__(self, ws: WebSocket):
        self.ws, self.next_id = ws, 0
        self.origin = ""
        self.extra_headers: dict[str, str] = {}
        self.inflight: set = set()
        self.loaded = False
        self.responses: dict = {}
        self.api_calls: dict = {}
        self.blocked_writes: list = []
        self.blocked_unsafe: list = []
        self.blocked_cross: set = set()
        self.third_party: set = set()
        self.mixed: list = []

    # ---- protocol plumbing
    def _send(self, method: str, params: dict | None = None) -> int:
        self.next_id += 1
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params or {}}))
        return self.next_id

    def call(self, method: str, params: dict | None = None, timeout: float = 15) -> dict:
        wanted = self._send(method, params)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise BrowserError(f"The browser did not answer {method} in time.")
            raw = self.ws.receive(left)
            if raw is None:
                continue
            message = json.loads(raw)
            if message.get("id") == wanted:
                if "error" in message:
                    raise BrowserError(f"{method} failed: {str(message['error'].get('message', ''))[:120]}")
                return message.get("result", {})
            self._event(message)

    def pump(self, seconds: float, until=None) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if until and until():
                return
            raw = self.ws.receive(min(0.2, max(0.01, end - time.monotonic())))
            if raw is not None:
                self._event(json.loads(raw))

    # ---- the safety gate
    def decide(self, url: str, method: str, resource_type: str) -> tuple[bool, dict]:
        """(allow, extra_headers). Called for every request the page makes, including redirects and scripts' own fetches."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, {}
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        if auth.same_origin(url, self.origin):
            if method != "GET":
                if len(self.blocked_writes) < 50:
                    self.blocked_writes.append((method, parsed.path or "/"))
                return False, {}
            if auth.is_unsafe_url(url):
                if len(self.blocked_unsafe) < 50:
                    self.blocked_unsafe.append(parsed.path or "/")
                return False, {}
            return True, dict(self.extra_headers)
        if urlparse(self.origin).scheme == "https" and parsed.scheme == "http":
            if len(self.mixed) < 20:
                self.mixed.append(f"{parsed.hostname}{parsed.path or '/'}"[:160])
            return False, {}
        if method == "GET" and resource_type in STATIC_TYPES:
            self.third_party.add(f"{parsed.hostname}{':' + str(parsed.port) if parsed.port else ''}")
            return True, {}
        self.blocked_cross.add(parsed.hostname or "?")
        return False, {}

    def _event(self, message: dict) -> None:
        method, params = message.get("method"), message.get("params", {})
        if method == "Fetch.requestPaused":
            request = params.get("request", {})
            allow, extra = self.decide(request.get("url", ""), request.get("method", "GET"), params.get("resourceType", ""))
            if allow:
                body = {"requestId": params["requestId"]}
                if extra:
                    merged = {k: v for k, v in (request.get("headers") or {}).items() if k.lower() not in {e.lower() for e in extra}}
                    merged.update(extra)
                    body["headers"] = [{"name": k, "value": str(v)} for k, v in merged.items()]
                self._send("Fetch.continueRequest", body)
            else:
                self._send("Fetch.failRequest", {"requestId": params["requestId"], "errorReason": "BlockedByClient"})
        elif method == "Network.requestWillBeSent":
            self.inflight.add(params.get("requestId"))
            if params.get("type") in ("XHR", "Fetch") and params.get("request", {}).get("method") == "GET":
                url = params["request"]["url"]
                if auth.same_origin(url, self.origin) and len(self.api_calls) < 60:
                    self.api_calls.setdefault(url, {"url": url, "status": None, "mime": ""})
        elif method in ("Network.loadingFinished", "Network.loadingFailed"):
            self.inflight.discard(params.get("requestId"))
        elif method == "Network.responseReceived":
            response = params.get("response", {})
            entry = self.api_calls.get(response.get("url", ""))
            if entry is not None:
                entry["status"], entry["mime"] = response.get("status"), str(response.get("mimeType", ""))[:60]
        elif method == "Page.loadEventFired":
            self.loaded = True
        elif method == "Page.javascriptDialogOpening":     # nothing is ever answered "yes" except leaving a page
            self._send("Page.handleJavaScriptDialog", {"accept": params.get("type") == "beforeunload"})

    # ---- using the page
    def prepare(self, origin: str, session=None) -> None:
        self.origin = origin
        self.call("Page.enable")
        self.call("Network.enable")
        self.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
        try:
            self.call("Page.setDownloadBehavior", {"behavior": "deny"})
        except BrowserError:
            pass
        if session is not None:
            self.extra_headers = dict(session.headers)
            for cookie in session.jar:
                self.call("Network.setCookie", {"name": cookie.name, "value": cookie.value, "url": origin, "path": cookie.path or "/",
                                                "secure": bool(cookie.secure), "httpOnly": cookie.has_nonstandard_attr("HttpOnly")})

    def visit(self, url: str, load_timeout: float = 12, settle: float = 0.8, max_wait: float = 5) -> dict | None:
        self.loaded = False
        self.inflight.clear()
        result = self.call("Page.navigate", {"url": url})
        if result.get("errorText"):
            return None
        if result.get("loaderId"):                 # a hash-only change stays in the same document: there is no load to wait for
            self.pump(load_timeout, until=lambda: self.loaded)
        quiet_since, end = None, time.monotonic() + max_wait
        while time.monotonic() < end:
            self.pump(0.2)
            if self.inflight:
                quiet_since = None
            else:
                quiet_since = quiet_since or time.monotonic()
                if time.monotonic() - quiet_since >= settle:
                    break
        value = self.call("Runtime.evaluate", {"expression": EXTRACT, "returnByValue": True}).get("result", {}).get("value")
        try:
            return json.loads(value) if value else None
        except ValueError:
            return None

    def close(self) -> None:
        self.ws.close()


def _normalise(url: str) -> str:
    base, fragment = urldefrag(url)
    return base + ("#" + fragment if fragment.startswith(("/", "!/")) else "")        # hash routes are separate pages; other fragments are not


def crawl(origin_url: str, start_urls: list, session=None, max_pages: int = 12, max_depth: int = 2, budget_seconds: float = 60,
          binary: str | None = None) -> tuple[list, dict]:
    """Render pages in a headless browser. Returns (findings, status); status carries what the scanner learned.

    status["urls"], ["forms"], ["scripts"], ["api_urls"] feed the later stages. Nothing is clicked, typed or submitted.
    """
    binary = binary or find_browser()
    if not binary:
        return [], {"status": "unavailable", "reason": "Chromium is not installed"}
    findings, started = [], time.monotonic()
    visited, queue = [], deque((_normalise(u), 0) for u in start_urls)
    seen = {u for u, _ in queue}
    forms, scripts, tokens_seen, errors = [], [], [], 0
    hash_routes = {urldefrag(u)[1] for u in seen if urldefrag(u)[1].startswith(('/', '!/'))}
    try:
        with Chromium(binary) as browser:
            page = browser.new_page()
            try:
                page.prepare(origin_url, session)
                while queue and len(visited) < max_pages and time.monotonic() - started < budget_seconds:
                    url, depth = queue.popleft()
                    if not auth.same_origin(url, origin_url) or auth.is_unsafe_url(url) or SKIP_EXTENSIONS.search(urlparse(url).path):
                        continue
                    try:
                        info = page.visit(url)
                    except BrowserError:
                        errors += 1
                        if errors >= 3:
                            raise
                        continue
                    if not info:
                        continue
                    final = _normalise(info.get("url") or url)
                    if not auth.same_origin(final, origin_url):
                        continue
                    if final not in visited:
                        visited.append(final)
                    forms.extend(signals.parse_forms(info.get("html", ""), final))
                    scripts.extend(s for s in info.get("scripts", []) if isinstance(s, str))
                    for kind, key, is_jwt in info.get("tokens", []):
                        tokens_seen.append((final, kind, key, bool(is_jwt)))
                    if depth < max_depth:
                        for link in info.get("links", []):
                            link = _normalise(link)
                            route = urldefrag(link)[1]
                            if route.startswith(("/", "!/")):          # the same hash route linked from every page is one page
                                if route in hash_routes:
                                    continue
                                hash_routes.add(route)
                            if link not in seen and auth.same_origin(link, origin_url) and not auth.is_unsafe_url(link):
                                seen.add(link)
                                queue.append((link, depth + 1))
            finally:
                page.close()
    except BrowserError as exc:
        return findings, {"status": "error", "reason": str(exc)[:200], "pages_visited": len(visited)}

    reported = set()
    for final, kind, key, is_jwt in tokens_seen:
        if (kind, key, is_jwt) in reported:
            continue
        reported.add((kind, key, is_jwt))
        findings.append(("Low" if is_jwt else "Info", "Access token stored in browser storage (readable by any script on the page)", final,
                         f"{kind} key '{key}' holds " + ("a JWT-shaped value" if is_jwt else "a secret-looking value") + ". The value is not recorded.",
                         "Prefer short-lived tokens in HttpOnly cookies; a cross-site-scripting flaw would expose anything in browser storage.", "Medium"))
    if page.mixed:
        findings.append(("Medium", "Mixed content: the page requests insecure (HTTP) resources", origin_url,
                         "The browser blocked: " + ", ".join(page.mixed[:5]), "Serve every resource over HTTPS.", "High"))
    if page.third_party:
        findings.append(("Info", "Page loads scripts, styles, fonts or images from other hosts", origin_url,
                         "Hosts: " + ", ".join(sorted(page.third_party)[:8]) + ". They were fetched without credentials and not tested.",
                         "Review third-party content; use Subresource Integrity or self-host critical scripts.", "High"))
    api_calls = [c for c in page.api_calls.values()]
    status = {"status": "completed", "pages_visited": len(visited), "urls": visited, "forms": forms[:40], "scripts": list(dict.fromkeys(scripts))[:60],
              "api_urls": [c["url"] for c in api_calls if c.get("status") and c["status"] < 500][:30], "api_calls": len(api_calls),
              "blocked_writes": [f"{m} {p}" for m, p in dict.fromkeys(page.blocked_writes)], "blocked_unsafe": list(dict.fromkeys(page.blocked_unsafe)),
              "blocked_other_hosts": sorted(page.blocked_cross)[:10], "third_party_hosts": sorted(page.third_party)[:10],
              "authenticated": session is not None, "finding_count": len(findings),
              "reason": f"rendered {len(visited)} page(s) in a headless browser; {len(api_calls)} API call(s) seen"
                        + (f"; {len(set(page.blocked_writes))} write request(s) blocked, never sent" if page.blocked_writes else "")}
    return findings, status
