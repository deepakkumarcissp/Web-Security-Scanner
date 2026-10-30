"""A small test website with logins, used by the self-test and the test suite. It is deliberately imperfect.

It listens on 127.0.0.1 only. It models what an authenticated scan meets: a login form with a CSRF token,
a JSON login that returns a token, a second user (so other people's data can be requested), an admin area,
a change-password form, and links the scanner must never follow (/logout, /delete-account). Every request is
recorded in `site.log` so a test can prove what was and was not requested.
"""
from __future__ import annotations

import base64
import html
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERS = {"alice": {"password": "alicepw", "id": 1, "role": "user"},
         "bob": {"password": "bobpw", "id": 2, "role": "user"},
         "admin": {"password": "adminpw", "id": 3, "role": "admin"}}


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


class Site:
    def __init__(self, rotate_session=True, cookie_flags="HttpOnly; SameSite=Lax", require_mfa=False, jwt_alg="HS256", jwt_exp=True, admin_open=False):
        self.rotate_session, self.cookie_flags, self.require_mfa = rotate_session, cookie_flags, require_mfa
        self.jwt_alg, self.jwt_exp, self.admin_open = jwt_alg, jwt_exp, admin_open
        self.sessions, self.tokens, self.csrf, self.log = {}, {}, set(), []
        self.fixed_sid = "fixed-session-id-0001"
        self.login_posts = 0
        self.lock = threading.Lock()

    def make_token(self, username: str) -> str:
        now = int(time.time())
        payload = {"sub": username, "iat": now}
        if self.jwt_exp:
            payload["exp"] = now + 3600
        token = f"{_b64({'alg': self.jwt_alg, 'typ': 'JWT'})}.{_b64(payload)}.sig"
        self.tokens[token] = username
        return token


def make_handler(site: Site):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        # --- helpers
        def cookies(self) -> dict:
            jar = SimpleCookie(self.headers.get("Cookie", ""))
            return {k: v.value for k, v in jar.items()}

        def user(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and auth[7:] in site.tokens:
                return site.tokens[auth[7:]]
            if auth.startswith("Basic "):
                try:
                    name, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                    if USERS.get(name, {}).get("password") == pw:
                        return name
                except Exception:
                    pass
            if self.headers.get("X-Api-Key") == "key-for-alice":
                return "alice"
            return site.sessions.get(self.cookies().get("sid", ""))

        def reply(self, code, body, ctype="text/html", extra=None):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            for key, value in (extra or []):
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        def redirect(self, location, extra=None):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            for key, value in (extra or []):
                self.send_header(key, value)
            self.end_headers()

        def record(self, method):
            site.log.append({"method": method, "path": self.path, "user": self.user(), "cookie": bool(self.headers.get("Cookie")),
                             "auth": bool(self.headers.get("Authorization"))})

        def login_page(self, error=""):
            token = secrets.token_hex(8)
            site.csrf.add(token)
            mfa = '<input name="otp_code" placeholder="6-digit code">' if site.require_mfa else ""
            pre = [("Set-Cookie", f"pre={site.fixed_sid if not site.rotate_session else secrets.token_hex(6)}; Path=/")]
            if not site.rotate_session:
                pre = [("Set-Cookie", f"sid={site.fixed_sid}; Path=/; {site.cookie_flags}")]
            self.reply(200, f"<html><body><h1>Sign in</h1>{'<p>' + html.escape(error) + '</p>' if error else ''}"
                            f'<form action="/login" method="post"><input type="hidden" name="csrf_token" value="{token}">'
                            f'<input name="username"><input type="password" name="password">{mfa}<input type="submit" name="go" value="Sign in"></form></body></html>', extra=pre)

        # --- routes
        def do_GET(self):
            self.record("GET")
            path, _, query = self.path.partition("?")
            user = self.user()
            if path in ("/", "/about"):
                self.reply(200, '<html><body><a href="/login">Sign in</a> <a href="/about">about</a><script src="/app.js"></script></body></html>')
            elif path == "/login":
                self.login_page()
            elif path == "/app.js":
                self.reply(200, 'fetch("/api/me");fetch("/api/items?limit=1");', "application/javascript")
            elif path == "/api/items":
                self.reply(200, '{"items": [1, 2]}', "application/json")
            elif path == "/dashboard":
                if not user:
                    return self.redirect("/login")
                self.reply(200, f"<html><body><h1>Welcome {html.escape(user)}</h1><a href='/account/{USERS[user]['id']}'>my account</a> "
                                "<a href='/account/1'>acct 1</a> <a href='/account/2'>acct 2</a> <a href='/orders'>orders</a> <a href='/settings'>settings</a> "
                                "<a href='/admin'>admin</a> <a href='/logout'>Log out</a> <a href='/delete-account'>Delete my account</a> "
                                "<a href='/dashboard?action=remove-card'>remove card</a> "
                                f"<a href='/notes/{USERS[user]['id']}'>my notes</a> <a href='/profile/{USERS[user]['id']}'>my profile</a> "
                                "<a href='/invoices/9'>invoice</a>" + ("<a href='/admin/users'>users</a>" if USERS[user]["role"] == "admin" else "") + "</body></html>")
            elif path.startswith("/account/"):
                if not user:
                    return self.redirect("/login")
                try:
                    owner = next(n for n, u in USERS.items() if u["id"] == int(path.rsplit("/", 1)[1]))
                except (ValueError, StopIteration):
                    return self.reply(404, "no such account")
                self.reply(200, f"<html><body><h1>Account {path.rsplit('/', 1)[1]}</h1><p>Owner: {owner}</p><p>Balance: 1000</p></body></html>")
            elif path.startswith(("/notes/", "/profile/")):
                # /notes has no ownership check (an IDOR); /profile does.
                if not user:
                    return self.redirect("/login")
                try:
                    owner = next(n for n, u in USERS.items() if u["id"] == int(path.rsplit("/", 1)[1]))
                except (ValueError, StopIteration):
                    return self.reply(404, "no such user")
                if path.startswith("/profile/") and owner != user:
                    return self.reply(403, "forbidden")
                self.reply(200, f"<html><body><h1>{path.split('/')[1].title()} of {owner}</h1><p>Private details for {owner}.</p></body></html>")
            elif path == "/invoices/9":
                self.reply(200, "<html><body><h1>Invoice 9</h1><p>Amount due: 120.00</p></body></html>")   # no login check: reachable by anyone
            elif path == "/admin/users":
                if not user:
                    return self.redirect("/login")
                if USERS[user]["role"] != "admin" and not site.admin_open:
                    return self.reply(403, "forbidden")
                self.reply(200, "<html><body><h1>All users</h1><p>alice, bob, admin</p></body></html>")
            elif path == "/orders":
                if not user:
                    return self.redirect("/login")
                self.reply(200, "<html><body><h1>Orders</h1><a href='/orders/7'>order 7</a></body></html>")
            elif path == "/orders/7":
                self.reply(200, "<html><body>order 7 detail</body></html>") if user else self.redirect("/login")
            elif path == "/settings":
                if not user:
                    return self.redirect("/login")
                self.reply(200, '<html><body><h1>Settings</h1><form action="/settings/password" method="post"><input type="password" name="new_password"></form></body></html>')
            elif path == "/admin":
                if not user:
                    return self.redirect("/login")
                if USERS[user]["role"] != "admin":
                    return self.reply(403, "forbidden")
                self.reply(200, "<html><body><h1>Admin console</h1></body></html>")
            elif path in ("/logout", "/delete-account"):
                site.sessions.pop(self.cookies().get("sid", ""), None)   # a real app would end the session or delete data here
                self.reply(200, f"<html><body>{path} done</body></html>")
            elif path == "/api/me":
                if not user:
                    return self.reply(401, '{"error": "login required"}', "application/json")
                self.reply(200, json.dumps({"user": user, "role": USERS[user]["role"]}), "application/json")
            elif path == "/api/private/report":
                if not user:
                    return self.reply(401, '{"error": "login required"}', "application/json")
                self.reply(200, '{"report": "confidential"}', "application/json")
            else:
                self.reply(404, "not found", "text/plain")

        def do_POST(self):
            self.record("POST")
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length).decode() if length else ""
            path = self.path.partition("?")[0]
            if path == "/login":
                form = {k: v[0] for k, v in parse_qs(raw).items()}
                with site.lock:
                    site.login_posts += 1
                if form.get("csrf_token") not in site.csrf:
                    return self.login_page("Session expired, try again.")
                name = form.get("username", "")
                if USERS.get(name, {}).get("password") != form.get("password") or (site.require_mfa and not form.get("otp_code")):
                    return self.login_page("Invalid username or password.")
                sid = site.fixed_sid if not site.rotate_session else secrets.token_hex(12)
                site.sessions[sid] = name
                self.redirect("/dashboard", [("Set-Cookie", f"sid={sid}; Path=/; {site.cookie_flags}")])
            elif path == "/api/login":
                try:
                    data = json.loads(raw)
                except ValueError:
                    return self.reply(400, '{"error": "bad json"}', "application/json")
                name = data.get("username", "")
                if USERS.get(name, {}).get("password") != data.get("password"):
                    return self.reply(401, '{"error": "bad credentials"}', "application/json")
                self.reply(200, json.dumps({"authentication": {"token": site.make_token(name)}}), "application/json")
            else:
                self.reply(404, "not found", "text/plain")

    return Handler


def start_site(**config):
    """Start the test site on a free 127.0.0.1 port. Returns (server, base_url, site)."""
    site = Site(**config)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(site))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}", site


if __name__ == "__main__":
    srv, base, _ = start_site()
    print("Test site running at", base, "(Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
