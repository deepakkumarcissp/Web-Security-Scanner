"""Credentialed (authenticated) scanning: log in once, keep the session, and browse safely as that user.

Design rules, because credentials are the most sensitive thing the scanner ever handles:

  * Credentials exist only in memory for the length of one scan. They are never written to the database,
    never logged, never placed on a command line, and never copied into a finding or a report.
  * The scanner logs in once. It never guesses or retries passwords, so it cannot lock an account out.
    (A later session loss may trigger at most two fresh logins with the same credentials.)
  * Login only ever goes to the origin being scanned. Credentials are never sent to another site.
  * Browsing as the user is read-only: GET requests only, and links that look like logout, delete, checkout,
    payment, reset and similar actions are never requested.
  * Multi-factor prompts, CAPTCHAs and single-sign-on redirects are detected and reported as unsupported,
    not worked around.

This module holds the login flows and the session. app.py decides when to use them.
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import re
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request

import signals

KINDS = ("form", "json", "bearer", "cookie", "header", "basic")
COMMON_LOGIN_PATHS = ("login", "signin", "sign-in", "users/sign_in", "account/login", "user/login", "wp-login.php", "admin", "auth/login")
UNSAFE_URL = re.compile(
    r"(log[-_]?out|sign[-_]?out|sign[-_]?off|delete|remove|destroy|erase|purge|wipe|cancel|unsubscribe|deactivate|"
    r"disable|close[-_]?account|revoke|terminate|reset|checkout|payment|purchase|transfer|withdraw|confirm|approve|"
    r"(?:^|[/?&=_-])(?:pay|buy|send|drop|kill|ban)(?:$|[/?&=_-]))", re.I)
MFA_FIELD = re.compile(r"otp|mfa|totp|2fa|two[-_]?factor|verification[-_]?code|captcha|recaptcha|hcaptcha", re.I)
SESSION_COOKIE = re.compile(r"sess|sid\b|^sid|token|auth|jwt|login|remember|^connect\.sid$", re.I)
NOT_SESSION = re.compile(r"csrf|xsrf|consent|theme|lang|locale|tracking|_ga|cookieconsent", re.I)
FAILURE_TEXT = re.compile(r"invalid (?:user|login|credential|password|email)|incorrect (?:user|password|login|email)|wrong (?:user|password)|"
                          r"login failed|authentication failed|bad credentials|unable to log ?in|not recognized", re.I)


class AuthError(Exception):
    """A login problem the assessor can act on. The message never contains a secret."""


@dataclass
class AuthSettings:
    kind: str
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = ""
    password_field: str = ""
    token: str = ""
    cookie: str = ""
    header_name: str = ""
    header_value: str = ""
    verify_url: str = ""
    success_text: str = ""
    logged_out_text: str = ""
    identity_text: str = ""     # text that appears in this user's own pages (access-control tests); not a secret

    def __repr__(self) -> str:  # never show a secret, even by accident in a traceback
        return f"AuthSettings(kind={self.kind!r}, login_url={self.login_url!r}, username={self.username!r}, secrets=hidden)"


def is_unsafe_url(url: str) -> bool:
    """True for links that look like they would change state or end the session (never requested while authenticated)."""
    parsed = urlparse(str(url))
    return bool(UNSAFE_URL.search(parsed.path + ("?" + parsed.query if parsed.query else "")))


def _origin(url: str) -> tuple:
    parsed = urlparse(url)
    return (parsed.scheme, (parsed.hostname or "").lower().rstrip("."), parsed.port or (443 if parsed.scheme == "https" else 80))


def same_origin(a: str, b: str) -> bool:
    return _origin(a) == _origin(b)


def decode_jwt(token: str):
    """(header, payload) of a JWT, or None. Only the unsigned metadata is read; nothing is verified or stored."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        decoded = [json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode("utf-8", "replace")) for p in parts[:2]]
    except (ValueError, UnicodeDecodeError):
        return None
    return (decoded[0], decoded[1]) if all(isinstance(d, dict) for d in decoded) else None


def jwt_findings(token: str, where: str) -> list[tuple]:
    """Weaknesses visible in a JWT's own header and claims. The token value itself never appears in a finding."""
    decoded = decode_jwt(token)
    if not decoded:
        return []
    header, payload = decoded
    findings = []
    algorithm = str(header.get("alg", "")).lower()
    if algorithm in ("none", ""):
        findings.append(("High", "Session token is an unsigned JWT (alg none)", where,
                         "The token's header declares no signature algorithm, so anyone could forge one.",
                         "Reject unsigned tokens and require a strong signing algorithm (for example RS256 or ES256).", "High"))
    elif algorithm == "hs256":
        findings.append(("Info", "Session token is a JWT signed with HS256", where,
                         "A shared-secret signature is only as strong as the secret; confirm it is long and random.",
                         "Use a long random signing key, or an asymmetric algorithm, and rotate keys.", "Medium"))
    expiry = payload.get("exp")
    if expiry is None:
        findings.append(("Low", "Session token has no expiry claim", where,
                         "The JWT carries no 'exp' claim, so a stolen token stays valid until the server revokes it.",
                         "Issue short-lived tokens with an expiry and a refresh mechanism.", "High"))
    elif isinstance(expiry, (int, float)) and isinstance(payload.get("iat"), (int, float)) and expiry - payload["iat"] > 30 * 86400:
        findings.append(("Low", "Session token lifetime is very long", where,
                         f"The JWT is valid for about {int((expiry - payload['iat']) / 86400)} days.",
                         "Shorten token lifetimes and use refresh tokens.", "Medium"))
    return findings


class AuthSession:
    """One authenticated browsing session on one origin."""

    def __init__(self, origin_url: str, settings: AuthSettings, opener_factory):
        self.origin = origin_url
        self.settings = settings
        self.jar = http.cookiejar.CookieJar()
        self.opener = opener_factory(self.jar)
        self.headers: dict[str, str] = {}
        self.status = "not_started"          # not_started | logged_in | failed
        self.reason = ""
        self.verified_by = ""
        self.landing_url = origin_url
        self.findings: list[tuple] = []
        self.requests = 0
        self.logins = 0
        self.token_value = ""                # kept only so tools can use it; never serialised
        self.unsupported = ""                # mfa | captcha | sso

    # ---- plumbing -------------------------------------------------------------------------------------------
    def describe(self) -> dict:
        """Non-secret facts about the session, safe to store in a report."""
        s = self.settings
        return {"type": s.kind, "username": s.username if s.kind in ("form", "json", "basic") else "",
                "login_url": s.login_url, "status": self.status, "reason": self.reason, "verified_by": self.verified_by,
                "landing_url": self.landing_url, "requests": self.requests, "unsupported": self.unsupported}

    def _apply_default_headers(self):
        self.opener.addheaders = [("User-Agent", "DKCISSP-WebSecurityScanner/0.1 (+authorized authenticated assessment)"),
                                  ("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"), *self.headers.items()]

    def request(self, url: str, data: dict | bytes | None = None, json_body: dict | None = None, headers: dict | None = None,
                timeout: int = 8, limit: int = 400_000) -> tuple[int, str, str, str]:
        """One request within the session. Returns (status, content_type, body, final_url). Raises AuthError on a bad target."""
        if not same_origin(url, self.origin):
            raise AuthError("The session is only ever used on the scanned origin.")
        self._apply_default_headers()
        body, extra = None, dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode()
            extra["Content-Type"] = "application/json"
        elif data is not None:
            body = urlencode(data).encode() if isinstance(data, dict) else data
            extra.setdefault("Content-Type", "application/x-www-form-urlencoded")
        self.requests += 1
        try:
            with self.opener.open(Request(url, data=body, headers=extra), timeout=timeout) as response:
                return response.status, str(response.headers.get("Content-Type", "")), response.read(limit).decode("utf-8", "replace"), response.geturl()
        except HTTPError as exc:
            try:
                text = exc.read(limit).decode("utf-8", "replace")
            except Exception:
                text = ""
            return exc.code, str(exc.headers.get("Content-Type", "")) if exc.headers else "", text, exc.geturl()
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise AuthError(f"Could not reach {urlparse(url).path or '/'}: {str(exc)[:120]}") from exc
        finally:
            time.sleep(0.15)

    def cookie_string(self, url: str | None = None) -> str:
        """The Cookie header value urllib would send to this URL (a secret; for passing to tools through files only)."""
        probe = Request(url or self.origin)
        self.jar.add_cookie_header(probe)
        return probe.get_header("Cookie") or ""

    def tool_headers(self, url: str | None = None) -> list[tuple[str, str]]:
        """Every header that identifies this session, for tools. These are secrets: write them to a private file."""
        headers = list(self.headers.items())
        cookie = self.cookie_string(url)
        if cookie and not any(k.lower() == "cookie" for k, _ in headers):
            headers.append(("Cookie", cookie))
        return headers

    def cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.jar}

    # ---- credentials for external tools: always through private files, never on a command line ------------------
    @property
    def cookie_only(self) -> bool:
        """True when the session is made of cookies alone (some tools can only read cookies from a file)."""
        return all(name.lower() == "cookie" for name, _ in self.tool_headers())

    def headers_file_text(self, url: str | None = None) -> str:
        """One 'Name: value' per line, the format Nuclei reads with -H FILE."""
        return "".join(f"{name}: {value}\n" for name, value in self.tool_headers(url))

    def raw_request(self, url: str, method: str = "GET") -> str:
        """A raw HTTP request carrying the session, for tools that read one from a file (ffuf -request, sqlmap -r, dalfox)."""
        parsed = urlparse(url)
        target = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        default_port = 443 if parsed.scheme == "https" else 80
        host = parsed.hostname + (f":{parsed.port}" if parsed.port and parsed.port != default_port else "")
        lines = [f"{method} {target} HTTP/1.1", f"Host: {host}", "User-Agent: DKCISSP-WebSecurityScanner/0.1 (+authorized authenticated assessment)",
                 "Accept: */*", *[f"{name}: {value}" for name, value in self.tool_headers(url)]]
        return "\r\n".join(lines) + "\r\n\r\n"

    def secret_values(self) -> list[str]:
        """Every secret this session holds, so the scanner can scrub them from anything it stores. Never stored itself."""
        s = self.settings
        values = [s.password, s.token, s.cookie, s.header_value, self.token_value, *(c.value for c in self.jar), *self.headers.values()]
        values += [part.split("=", 1)[1] for part in s.cookie.split(";") if "=" in part]
        return [v for v in values if v and len(v) >= 6]

    # ---- recognising a logged-out page -----------------------------------------------------------------------
    @staticmethod
    def is_login_form(form: dict) -> bool:
        """A real login form has a password field and something to type a user name into. A change-password form does not."""
        return form["has_password"] and form["kind"] == "login" and any(
            i["type"] in ("text", "email", "tel") or re.search(r"user|login|email", i["name"] or "", re.I) for i in form["inputs"] if i["type"] != "password")

    def has_login_form(self, body: str, url: str) -> bool:
        return any(self.is_login_form(f) for f in signals.parse_forms(body, url))

    def looks_logged_out(self, status: int, body: str, final_url: str, asked_url: str) -> bool:
        s = self.settings
        if status in (401, 403):
            return True
        if s.logged_out_text and s.logged_out_text.lower() in body.lower():
            return True
        if self.has_login_form(body, final_url):
            return True
        path = urlparse(final_url).path.lower()
        return bool(re.search(r"/(log[-_]?in|sign[-_]?in|auth)(/|$|\.)", path) and path != urlparse(asked_url).path.lower())

    def still_logged_in(self) -> bool:
        """A single cheap check that the session still works (used before and after a crawl)."""
        probe = self.settings.verify_url or self.landing_url or self.origin
        try:
            status, _, body, final = self.request(probe)
        except AuthError:
            return False
        return not self.looks_logged_out(status, body, final, probe)

    # ---- login flows ------------------------------------------------------------------------------------------
    def login(self) -> bool:
        """Log in once. Sets status/reason and records login-time findings. Never raises with a secret in the message."""
        self.logins += 1
        s = self.settings
        try:
            if s.kind == "form":
                self._login_form()
            elif s.kind == "json":
                self._login_json()
            elif s.kind == "bearer":
                self.headers["Authorization"] = "Bearer " + s.token.strip()
                self.token_value = s.token.strip()
                self._verify_static("a bearer token")
            elif s.kind == "basic":
                raw = base64.b64encode(f"{s.username}:{s.password}".encode()).decode()
                self.headers["Authorization"] = "Basic " + raw
                self._verify_static("HTTP Basic credentials")
            elif s.kind == "cookie":
                self.headers["Cookie"] = s.cookie.strip()
                self._verify_static("the session cookie")
            elif s.kind == "header":
                self.headers[s.header_name.strip()] = s.header_value.strip()
                self._verify_static("the API-key header")
            else:
                raise AuthError("Unknown login type.")
        except AuthError as exc:
            self.status, self.reason = "failed", str(exc)
            return False
        self.status = "logged_in"
        self._apply_default_headers()      # crawlers and tools that use self.opener now send the session
        if self.token_value:
            self.findings.extend(jwt_findings(self.token_value, self.origin))
        return True

    def _verify_static(self, what: str):
        """For credentials supplied ready-made: confirm the site accepts them."""
        probe = self.settings.verify_url or self.origin
        if not same_origin(probe, self.origin):
            raise AuthError("The verification URL must be on the scanned origin.")
        status, _, body, final = self.request(probe)
        if self.looks_logged_out(status, body, final, probe):
            raise AuthError(f"The site did not accept {what} (the page still looks logged out, HTTP {status}).")
        self.landing_url = final
        self.verified_by = f"{probe} answered without a login prompt (HTTP {status})"

    def _find_login_form(self):
        s = self.settings
        candidates = [s.login_url] if s.login_url else [urljoin(self.origin.rstrip("/") + "/", p) for p in ("",) + COMMON_LOGIN_PATHS]
        for url in candidates[:8]:
            try:
                status, _, body, final = self.request(url)
            except AuthError:
                continue
            if status >= 400 and s.login_url:
                raise AuthError(f"The login page returned HTTP {status}.")
            for form in signals.parse_forms(body, final):
                if self.is_login_form(form):
                    return form, final, body
        raise AuthError("No login form with a password field was found. Give the login page address under 'Login page'.")

    def _login_form(self):
        s = self.settings
        form, page_url, page_html = self._find_login_form()
        if not same_origin(form["action"], self.origin):
            raise AuthError("The login form submits to a different site (single sign-on). Credentials are never sent off the scanned origin.")
        names = [i["name"] for i in form["inputs"] if i["name"]]
        if any(MFA_FIELD.search(n) for n in names) or re.search(r"g-recaptcha|h-captcha|data-sitekey", page_html, re.I):
            self.unsupported = "captcha" if re.search(r"captcha", " ".join(names) + page_html, re.I) else "mfa"
            raise AuthError("The login page asks for a CAPTCHA or a second factor, which the scanner cannot supply. Use a session cookie or token instead.")
        pw_field = s.password_field or next(i["name"] for i in form["inputs"] if i["type"] == "password")
        user_field = s.username_field or next((i["name"] for i in form["inputs"] if i["name"] and i["type"] in ("text", "email", "tel") and i["name"] != pw_field), "")
        if not user_field:
            user_field = next((i["name"] for i in form["inputs"] if re.search(r"user|login|email|name", i["name"] or "", re.I)), "")
        if not user_field:
            raise AuthError("The login form has no recognisable username field. Name it under 'Username field'.")
        data = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"] and i["type"] in ("hidden",)}
        submit = next((i for i in form["inputs"] if i["type"] == "submit" and i["name"]), None)
        if submit:
            data[submit["name"]] = submit.get("value", "")
        data[user_field], data[pw_field] = s.username, s.password
        before = self.cookies()
        status, ctype, body, final = self.request(form["action"], data=data, headers={"Referer": page_url})
        self._finish_form_login(status, body, final, before, page_url, form)

    def _login_json(self):
        s = self.settings
        if not s.login_url:
            raise AuthError("A JSON login needs the login endpoint address under 'Login page'.")
        if not same_origin(s.login_url, self.origin):
            raise AuthError("Credentials are never sent off the scanned origin.")
        before = self.cookies()
        status, ctype, body, final = self.request(s.login_url, json_body={s.username_field or "username": s.username, s.password_field or "password": s.password})
        if status >= 400:
            raise AuthError(f"The login endpoint answered HTTP {status}; the credentials were not accepted.")
        token = self._token_from_json(body)
        if token:
            self.token_value = token
            self.headers["Authorization"] = "Bearer " + token
        elif not self.cookies():
            raise AuthError("The login answered successfully but returned no token and set no cookie.")
        self._verify_static("the login result")
        self._login_checks(before, s.login_url)

    @staticmethod
    def _token_from_json(text: str) -> str:
        try:
            data = json.loads(text)
        except ValueError:
            return ""
        def search(node, depth=0):
            if depth > 3 or not isinstance(node, dict):
                return ""
            for key in ("access_token", "token", "jwt", "id_token", "accessToken", "authToken"):
                if isinstance(node.get(key), str) and len(node[key]) > 8:
                    return node[key]
            for value in node.values():
                found = search(value, depth + 1)
                if found:
                    return found
            return ""
        return search(data)

    def _finish_form_login(self, status: int, body: str, final: str, before: dict, login_page: str, form: dict):
        s = self.settings
        action_path = urlparse(form["action"]).path
        # The login failed if the same login form is shown again, an error message is shown, or the server refused us.
        if status in (301, 302, 303, 307, 308):
            raise AuthError("The login redirected to another site (single sign-on). The scanner never sends credentials off the scanned origin.")
        same_form_again = any(self.is_login_form(f) and urlparse(f["action"]).path == action_path for f in signals.parse_forms(body, final))
        if status in (401, 403) or same_form_again or (FAILURE_TEXT.search(body) and self.has_login_form(body, final)):
            hint = " The page reports an error." if FAILURE_TEXT.search(body) else ""
            raise AuthError(f"The login was not accepted: the site still shows the login form (HTTP {status}).{hint}")
        if s.success_text and s.success_text.lower() not in body.lower():
            raise AuthError("The login finished, but the expected text was not found on the page afterwards.")
        if not self.cookies() and not self.headers:
            raise AuthError("The login finished but the site set no session cookie.")
        self.landing_url = final
        self.verified_by = f"after login {urlparse(final).path or '/'} shows no login form"
        if not self.still_logged_in():
            raise AuthError("The login appeared to work, but the next request was logged out again.")
        self._login_checks(before, login_page)

    def _login_checks(self, before: dict, where: str):
        """Security findings about the login itself (all observed, none guessed)."""
        after_cookies = [c for c in self.jar if SESSION_COOKIE.search(c.name) and not NOT_SESSION.search(c.name)]
        https = urlparse(self.origin).scheme == "https"
        loopback = (urlparse(self.origin).hostname or "").lower() in signals.LOOPBACK
        if not https and not loopback:
            self.findings.append(("High", "Credentials were sent over unencrypted HTTP", where,
                                  "The login had to be submitted over plain HTTP, so the username and password crossed the network readable.",
                                  "Serve the login over HTTPS only and redirect all HTTP traffic.", "High"))
        for cookie in after_cookies:
            attrs = {k.lower() for k in getattr(cookie, "_rest", {})}
            flags = []
            if "httponly" not in attrs:
                flags.append("HttpOnly")
            if https and not cookie.secure:
                flags.append("Secure")
            if "samesite" not in attrs:
                flags.append("SameSite")
            if flags:
                severity = "Medium" if ("HttpOnly" in flags or "Secure" in flags) else "Low"
                self.findings.append((severity, f"Session cookie '{cookie.name}' is missing: {', '.join(flags)}", where,
                                      f"The cookie '{cookie.name}' set at login lacks {', '.join(flags)}. (Its value is not recorded.)",
                                      "Set HttpOnly, Secure (on HTTPS) and SameSite=Lax or Strict on session cookies.", "High"))
            if cookie.name in before and before[cookie.name] == cookie.value:
                self.findings.append(("Medium", f"Session ID '{cookie.name}' was not renewed at login (session fixation risk)", where,
                                      f"The cookie '{cookie.name}' kept the same value before and after logging in, so a session ID planted beforehand stays valid.",
                                      "Issue a new session identifier at login and invalidate the old one.", "High"))
