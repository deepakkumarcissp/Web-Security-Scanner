"""Signals: read forms, scripts, API descriptions and GraphQL answers, and turn them into findings and facts.

Pure functions only (no network, no subprocesses), so every rule here is easy to test. The scanner fetches the
pages; this module decides what they mean. It supports the planner: a login form, an upload form, a
single-page app, an API that wants authentication or a GraphQL endpoint each change what should be tested,
and what honestly could not be.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

CSRF_NAME = re.compile(r"csrf|xsrf|_token\b|^token$|authenticity_token|csrfmiddlewaretoken|requestverificationtoken|anti-?forgery|"
                       r"form_?key|_wpnonce|nonce|formtoken", re.I)
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
STATIC_EXT = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|mp4|webm|pdf|txt|html?|xml)(\?|$)", re.I)


def _origin(url: str) -> tuple:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.scheme, (parsed.hostname or "").lower().rstrip("."), port)


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self._form = [], None
        self.scripts, self.csrf_meta = [], False

    def handle_starttag(self, tag, attrs):
        values = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(),
                          "enctype": values.get("enctype", "").lower(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            kind = values.get("type", "text" if tag == "input" else tag).lower()
            self._form["inputs"].append((values.get("name", "")[:80], kind))
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"].strip())
        elif tag == "link" and values.get("href") and ("modulepreload" in values.get("rel", "") or values.get("as") == "script"):
            self.scripts.append(values["href"].strip())
        elif tag == "meta" and re.search(r"csrf|xsrf", values.get("name", ""), re.I):
            self.csrf_meta = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_forms(html: str, page_url: str) -> list[dict]:
    """Forms on a page, described for security review. Nothing is ever submitted."""
    parser = _FormParser()
    try:
        parser.feed((html or "")[:500_000])
    except Exception:
        return []
    forms = []
    for raw in parser.forms[:20]:
        action = urldefrag(urljoin(page_url, raw["action"] or ""))[0]
        inputs = raw["inputs"]
        passwords = sum(1 for _, kind in inputs if kind == "password")
        has_token = any(CSRF_NAME.search(name) for name, kind in inputs if name) or parser.csrf_meta
        forms.append({
            "page": page_url[:2048], "action": action[:2048], "method": "post" if raw["method"] == "post" else "get",
            "inputs": [{"name": n, "type": k} for n, k in inputs][:40],
            "has_password": passwords > 0, "kind": "register" if passwords >= 2 else "login" if passwords == 1 else "other",
            "has_file": any(kind == "file" for _, kind in inputs) or "multipart" in raw["enctype"],
            "has_csrf_token": bool(has_token),
            "cross_origin": _origin(action) != _origin(page_url) if urlparse(action).scheme in ("http", "https") else False,
        })
    return forms


def script_urls(html: str, page_url: str) -> list[str]:
    """Same-origin script URLs referenced by a page, absolute, de-duplicated."""
    parser = _FormParser()
    try:
        parser.feed((html or "")[:500_000])
    except Exception:
        return []
    found = []
    for src in parser.scripts:
        absolute = urldefrag(urljoin(page_url, src))[0]
        if urlparse(absolute).scheme in ("http", "https") and _origin(absolute) == _origin(page_url) and absolute not in found:
            found.append(absolute)
    return found[:30]


def form_findings(forms: list[dict], target: str) -> list[tuple]:
    """Security findings from form structure alone. Verified facts only; heuristics are labelled as such."""
    findings, seen = [], set()
    loopback = (urlparse(target).hostname or "").lower() in LOOPBACK

    def add(severity, title, url, evidence, fix, confidence):
        key = (title, url)
        if key not in seen:
            seen.add(key)
            findings.append((severity, title, url[:2048], evidence[:1800], fix, confidence))

    for form in forms:
        action, page = form["action"], form["page"]
        https = urlparse(action).scheme == "https"
        if form["has_password"] and not https:
            add("Low" if loopback else "High", "Login form sends the password over unencrypted HTTP", page,
                f"The {form['kind']} form on {page} submits to {action}, which is not HTTPS. Anyone on the network path can read the credentials."
                + (" (The host is local, so this is rated Low.)" if loopback else ""),
                "Serve the page and the form action over HTTPS only, redirect HTTP to HTTPS and send HSTS.", "High")
        if form["has_password"] and form["method"] == "get":
            add("Medium", "Password form submits with GET, so credentials appear in the URL", page,
                f"The form on {page} uses method GET with a password field; the password ends up in URLs, logs and browser history.",
                "Use method POST for any form that carries credentials.", "High")
        if form["has_password"] and form["cross_origin"]:
            add("High", "Credentials are posted to a different origin", page,
                f"The {form['kind']} form on {page} submits to {action}, which is another site.",
                "Post credentials only to your own origin unless a trusted single-sign-on provider is intended.", "High")
        if form["kind"] == "login" and form["method"] == "post" and not form["has_csrf_token"]:
            add("Low", "Login form has no visible anti-CSRF token (heuristic)", page,
                f"No hidden input or meta tag with a CSRF-style name was found on the login form at {page}. Frameworks can protect forms in other ways (SameSite cookies, custom headers), so verify manually.",
                "Add per-session anti-CSRF tokens to state-changing forms, or confirm another CSRF defence is in place.", "Low")
        if form["has_file"]:
            add("Info", "File upload form found", page,
                f"The form on {page} accepts file uploads (submits to {action}). Upload restrictions were not tested by the scanner.",
                "Validate type, size and content on the server, store uploads outside the web root, and never execute uploaded files.", "High")
        if form["cross_origin"] and not form["has_password"]:
            add("Info", "Form posts to a different origin", page, f"A form on {page} submits to {action}.",
                "Confirm the third party is trusted and that no sensitive data is sent.", "Medium")
    return findings


def form_facts(forms: list[dict]) -> dict:
    return {"forms": len(forms), "login_form": any(f["kind"] == "login" for f in forms),
            "register_form": any(f["kind"] == "register" for f in forms), "upload_form": any(f["has_file"] for f in forms)}


_PATH_CHARS = r"A-Za-z0-9_\-.~:@!$&*+,;=%{}\[\]?/"
_ENDPOINT = re.compile(r"""["'`](/(?:api|rest|graphql|gql|v[0-9]{1,2}|services?|backend|ajax|json|odata|trpc|rpc)(?:[/?][""" + _PATH_CHARS + r"""]*)?)["'`]""")


def extract_js_endpoints(js_text: str, limit: int = 60) -> list[str]:
    """API-looking paths that a JavaScript file mentions as string literals (static analysis only; the code is not run)."""
    found = []
    for match in _ENDPOINT.finditer((js_text or "")[:1_500_000]):
        path = match.group(1)
        path = re.sub(r"\$\{[^}]*\}", "1", path)                      # template literal  /api/users/${id}
        path = re.sub(r"\{[A-Za-z0-9_]+\}", "1", path)                 # OpenAPI-style      /api/users/{id}
        path = re.sub(r"/:[A-Za-z0-9_]+", "/1", path)                  # express-style      /api/users/:id
        path = path.rstrip("&,;?") if path.endswith(("&", ",", ";")) else path
        if (not path.startswith("/") or STATIC_EXT.search(path.split("?")[0]) or len(path) > 200 or "//" in path[1:]
                or any(ch in path for ch in "{}[]$`'\"<>\\ ")):
            continue
        if path not in found:
            found.append(path)
        if len(found) >= limit:
            break
    return found


def openapi_summary(text: str, base_url: str) -> dict | None:
    """Summarise an OpenAPI / Swagger JSON document, or None if the text is not one."""
    try:
        spec = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")) or not isinstance(spec.get("paths"), dict):
        return None
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    paths = spec["paths"]
    sample, testable = [], []
    for path, operations in list(paths.items())[:300]:
        if not isinstance(operations, dict) or not isinstance(path, str):
            continue
        if len(sample) < 25:
            sample.append(path[:120])
        get = operations.get("get")
        if isinstance(get, dict) and len(testable) < 10:
            names = [p.get("name") for p in (get.get("parameters") or operations.get("parameters") or [])
                     if isinstance(p, dict) and p.get("in") == "query" and re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,64}", str(p.get("name") or ""))]
            if names:
                concrete = re.sub(r"\{[^}]*\}", "1", path)
                testable.append(urljoin(base_url, concrete + "?" + "&".join(f"{n}=1" for n in names[:4])))
    return {"title": str(info.get("title") or "")[:100], "version": str(info.get("version") or "")[:40],
            "path_count": len(paths), "sample_paths": sample, "testable_urls": testable}


def classify_graphql(text: str) -> dict:
    """Is this response a GraphQL endpoint answering, and does it allow introspection?"""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"graphql": False, "introspection": False}
    if not isinstance(data, dict):
        return {"graphql": False, "introspection": False}
    graphql = isinstance(data.get("data"), dict) or (isinstance(data.get("errors"), list) and any(
        isinstance(e, dict) and re.search(r"graphql|query|syntax|field|validation", str(e.get("message", "")), re.I) for e in data["errors"]))
    introspection = isinstance(data.get("data"), dict) and isinstance(data["data"].get("__schema"), dict)
    return {"graphql": bool(graphql or introspection), "introspection": bool(introspection)}


def looks_like_spa(html: str, platform_ids, link_count: int) -> bool:
    """A single-page app builds most of its pages in the browser, so a link crawler sees very little of it."""
    from platforms import SPA_PLATFORMS
    if set(platform_ids or []) & SPA_PLATFORMS:
        return True
    text = html or ""
    scripts = len(re.findall(r"<script[^>]+src=", text, re.I))
    visible = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", text, flags=re.S | re.I)
    return scripts >= 3 and link_count <= 3 and len(visible.split()) < 40


# Paths worth requesting once a framework or product is recognised. Used on top of ffuf's general list.
PLATFORM_PATHS = {
    "springboot": ["actuator", "actuator/env", "actuator/health", "actuator/heapdump", "actuator/mappings", "actuator/beans",
                   "actuator/configprops", "actuator/loggers", "actuator/httptrace", "jolokia", "h2-console", "v3/api-docs", "swagger-ui/index.html"],
    "laravel": ["telescope", "horizon", "_ignition/health-check", "_debugbar", "storage/logs/laravel.log", ".env", "artisan", "nova", "api/documentation"],
    "django": ["admin/", "static/admin/", "__debug__/", "api/schema/", "silk/", "api/docs/"],
    "rails": ["rails/info/routes", "rails/info/properties", "rails/mailers", "sidekiq", "letter_opener", "admin", "api/v1"],
    "aspnet": ["trace.axd", "elmah.axd", "web.config", "Glimpse.axd", "swagger/index.html", "hangfire", "_framework/blazor.boot.json"],
    "flask": ["console", "api/docs", "swagger.json", "openapi.json"],
    "express": ["package.json", ".env", "api-docs", "node_modules/", "api/v1"],
    "nextjs": ["_next/static/", "api/", "_next/data/", ".next/", "next.config.js"],
    "tomcat": ["manager/html", "host-manager/html", "examples/", "docs/", "manager/status"],
    "jenkins": ["script", "asynchPeople/", "computer/", "credentials/", "manage", "pluginManager/", "cli", "view/all/"],
    "wordpress": ["wp-json/wp/v2/users", "wp-admin/install.php", "wp-content/debug.log", "xmlrpc.php", "wp-cron.php", "wp-config.php.bak"],
    "drupal": ["user/login", "admin/config", "core/CHANGELOG.txt", "CHANGELOG.txt", "update.php", "install.php"],
    "joomla": ["administrator/", "configuration.php.bak", "administrator/manifests/files/joomla.xml", "README.txt", "web.config.txt"],
    "gitlab": ["users/sign_in", "explore", "api/v4/projects", "api/v4/version", "help"],
    "grafana": ["login", "api/health", "api/snapshots", "api/datasources", "api/frontend/settings"],
    "phpmyadmin": ["setup/", "index.php", "phpmyadmin/setup/", "doc/html/index.html"],
    "confluence": ["login.action", "rest/api/space", "setup/setupstart.action", "rest/api/content"],
    "jira": ["secure/Dashboard.jspa", "rest/api/2/serverInfo", "rest/api/2/project", "secure/ContactAdministrators!default.jspa"],
    "magento": ["admin", "downloader/", "var/log/", "app/etc/env.php", "rest/V1/store/storeViews"],
    "moodle": ["login/index.php", "admin/", "lib/upgrade.txt", "mod/", "config.php.bak"],
}


def platform_paths(platform_ids, limit: int = 120) -> list[str]:
    """Extra paths for the recognised platforms, de-duplicated and bounded."""
    paths = []
    for platform_id in platform_ids or []:
        for path in PLATFORM_PATHS.get(platform_id, []):
            if path not in paths:
                paths.append(path)
    return paths[:limit]
