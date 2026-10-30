#!/usr/bin/env python3
"""End-to-end self-test for a running DKCISSP Web Security Scanner.

It talks to the scanner only over its HTTP API, so it works against any installation, on any machine.
It starts a small test website on 127.0.0.1 (a login form over HTTP, an API named in its JavaScript,
an OpenAPI file and a GraphQL endpoint), runs a real Standard scan against it, and checks the results.

Nothing is installed and no package is ever approved. A missing optional tool is reported as a WARNING,
not a failure, because it depends on the machine. Exit code: 0 = all required checks passed, 1 = a check failed.

    python3 scripts/selftest.py --scanner http://127.0.0.1:1005
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import testsite  # noqa: E402  (a small site with logins, shared with the test suite)

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"


class TestSite(BaseHTTPRequestHandler):
    """A tiny, deliberately imperfect website for the scanner to assess."""

    def log_message(self, *args):
        pass

    def reply(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/":
            self.reply(200, "<html><head><title>DKCISSP test site</title></head><body>"
                            '<a href="/about">about</a><script src="/app.js"></script>'
                            '<form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>'
                            "</body></html>", "text/html")
        elif path == "/about":
            self.reply(200, "<html><body>about this test site</body></html>", "text/html")
        elif path == "/app.js":
            self.reply(200, 'fetch("/api/items?limit=1");fetch("/api/private/report");', "application/javascript")
        elif path == "/api/items":
            self.reply(200, '{"items": [1, 2, 3]}')
        elif path == "/api/private/report":
            self.reply(401, '{"error": "login required"}')
        elif path == "/swagger.json":
            self.reply(200, json.dumps({"openapi": "3.0.0", "info": {"title": "Test API", "version": "1"},
                                        "paths": {"/api/items": {"get": {"parameters": [{"name": "limit", "in": "query"}]}}}}))
        elif path == "/graphql":
            self.reply(200, '{"data": {"__schema": {"queryType": {"name": "Query"}}}}' if "__schema" in self.path
                       else '{"data": {"__typename": "Query"}}')
        else:
            self.reply(404, "not found", "text/plain")


class Report:
    def __init__(self):
        self.rows = []

    def add(self, status, name, detail=""):
        self.rows.append({"status": status, "check": name, "detail": detail})
        print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""), flush=True)

    def failed(self):
        return [r for r in self.rows if r["status"] == FAIL]


def call(base, path, method="GET", body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    request = Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, response.headers.get("Content-Type", ""), raw
    except HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def get_json(base, path, **kw):
    status, _, raw = call(base, path, **kw)
    return status, (json.loads(raw) if raw else None)


def run(args) -> int:
    base = args.scanner.rstrip("/")
    report = Report()
    started = time.time()
    print(f"DKCISSP self-test against {base}", flush=True)

    # 1. Service and dashboard
    try:
        status, health = get_json(base, "/api/health")
        ok = status == 200 and isinstance(health, dict) and health.get("status") == "ok"
        report.add(PASS if ok else FAIL, "scanner answers /api/health", f"version {health.get('version')}" if ok else f"HTTP {status}")
    except (URLError, OSError, ValueError) as exc:
        report.add(FAIL, "scanner answers /api/health", f"could not connect: {exc}")
        return finish(report, args, started)
    status, ctype, raw = call(base, "/")
    page = raw.decode("utf-8", "replace")
    report.add(PASS if status == 200 and "DKCISSP" in page else FAIL, "dashboard loads and shows the DKCISSP brand", f"HTTP {status}")
    external = sorted(set(re.findall(r"""(?:src|href)=["'](https?://[^"']+)""", page)))
    report.add(PASS if not external else FAIL, "dashboard loads nothing from outside (works offline)", ", ".join(external[:3]))
    for needle in ("Assess Website", "Approvals", "Scan History", "Findings"):
        report.add(PASS if needle in page else FAIL, f"dashboard has '{needle}'")

    # 2. Tool readiness (informational: depends on the machine)
    status, tools = get_json(base, "/api/tools")
    if status == 200 and isinstance(tools, dict):
        listing = tools.get("tools", [])
        ready = [t["name"] for t in listing if t.get("status") == "ready"]
        missing = [t["name"] for t in listing if t.get("status") == "missing"]
        report.add(PASS, "tool readiness is reported", f"{len(ready)} ready, {len(missing)} not installed")
        if missing:
            report.add(WARN, "some scanning tools are not installed (normal on a fresh machine)", ", ".join(missing[:8]))
    else:
        report.add(FAIL, "tool readiness is reported", f"HTTP {status}")

    # 3. A real scan against the built-in test site
    server = ThreadingHTTPServer(("127.0.0.1", 0), TestSite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, created = get_json(base, "/api/scans", method="POST",
                                   body={"target": target, "profile": "standard", "authorized": True})
        if status != 200 or not isinstance(created, dict) or "id" not in created:
            report.add(FAIL, "a Standard scan starts", f"HTTP {status}: {created}")
            return finish(report, args, started)
        scan_id = created["id"]
        report.add(PASS, "a Standard scan starts", f"scan #{scan_id} against the local test site")
        status, rejected = get_json(base, "/api/scans", method="POST", body={"target": target, "profile": "standard", "authorized": False})
        report.add(PASS if status == 400 else FAIL, "a scan without the authorization confirmation is refused", f"HTTP {status}")

        deadline = time.time() + args.scan_timeout
        detail = None
        while time.time() < deadline:
            status, detail = get_json(base, f"/api/scans/{scan_id}")
            if status == 200 and detail["scan"]["status"] != "running":
                break
            time.sleep(3)
        scan = detail["scan"] if detail else {}
        finished = scan.get("status") in ("completed", "completed_with_gaps")
        report.add(PASS if finished else FAIL, "the scan finishes", f"status {scan.get('status')} after ~{int(time.time() - (deadline - args.scan_timeout))}s")
        if not finished:
            return finish(report, args, started)

        tools_state = json.loads(scan.get("tool_status") or "{}")
        summary = json.loads(scan.get("summary") or "{}")
        findings = detail.get("findings", [])
        titles = [f["title"] for f in findings]

        report.add(PASS if tools_state.get("Built-in HTTP & headers", {}).get("status") == "completed" else FAIL, "built-in HTTP and header checks completed")
        report.add(PASS if tools_state.get("Forms & APIs (built-in)", {}).get("status") == "completed" else FAIL, "forms and API analysis completed",
                   tools_state.get("Forms & APIs (built-in)", {}).get("detail", "")[:120])
        report.add(PASS if any("header" in t.lower() or "missing" in t.lower() for t in titles) else FAIL, "security-header findings are reported")
        expectations = [("Login form sends the password over unencrypted HTTP", "an HTTP login form is flagged"),
                        ("API documentation is publicly accessible", "an exposed OpenAPI file is found"),
                        ("GraphQL introspection is enabled", "GraphQL introspection is detected"),
                        ("API endpoints referenced in JavaScript", "API endpoints are read from the site's JavaScript")]
        for prefix, label in expectations:
            report.add(PASS if any(t.startswith(prefix) for t in titles) else FAIL, label)

        # Truthfulness: the status must agree with the gaps it lists.
        gaps = summary.get("assessment_gaps", [])
        consistent = (scan["status"] == "completed_with_gaps") == bool(gaps)
        report.add(PASS if consistent else FAIL, "scan status agrees with its listed gaps (never 'completed' with gaps)",
                   f"{len(gaps)} gap(s): " + ", ".join(g["tool"] for g in gaps[:6]))
        report.add(PASS if "coverage" in summary else FAIL, "the report says what could not be tested (coverage notes)",
                   f"{len(summary.get('coverage', {}).get('not_covered', []))} note(s)")
        notes = {n.get("rule") for n in summary.get("coverage", {}).get("not_covered", [])}
        report.add(PASS if "login_testing" in notes else FAIL, "a login form is reported as a coverage note (credentialed scanning not available)")

        # 4. Tool approval flow: decline only, nothing is ever installed
        status, requests = get_json(base, f"/api/tool-requests?scan_id={scan_id}")
        pending = [r for r in (requests or []) if r["status"] == "pending"]
        if pending:
            target_request = pending[0]
            status, decided = get_json(base, f"/api/tool-requests/{target_request['id']}/decision", method="POST", body={"decision": "decline"})
            report.add(PASS if status == 200 and decided.get("status") == "declined" else FAIL, "declining a tool approval works", f"{target_request['tool_name']}: HTTP {status}")
            time.sleep(2)
            status, after = get_json(base, f"/api/scans/{scan_id}")
            # The stage that belonged to the request we declined (its detail starts with the tool's name).
            stage = next((k for k, v in tools_state.items() if v.get("status") == "needs_tool_approval"
                          and v.get("detail", "").startswith(target_request["tool_name"])), "")
            state = json.loads(after["scan"]["tool_status"]).get(stage, {})
            report.add(PASS if state.get("status") == "skipped_install_not_permitted" and "not approved by the assessor" in state.get("detail", "") else FAIL,
                       "a declined tool is recorded as 'not assessed', with the reason", state.get("detail", "")[:90])
            status, _ = get_json(base, f"/api/tool-requests/{target_request['id']}/decision", method="POST", body={"decision": "approve"})
            report.add(PASS if status == 409 else FAIL, "a decided request cannot be decided again", f"HTTP {status}")
        else:
            report.add(INFO, "no tool approval was needed on this machine", "all tools the profile uses are already installed")

        # 5. Exports and comparison
        status, ctype, raw = call(base, "/api/export/findings.csv")
        report.add(PASS if status == 200 and b"severity" in raw.lower() else FAIL, "CSV export works", f"HTTP {status}, {len(raw)} bytes")
        status, ctype, raw = call(base, "/api/export/findings.html")
        report.add(PASS if status == 200 and b"<html" in raw.lower() else FAIL, "HTML report export works", f"HTTP {status}")
        status, comparison = get_json(base, f"/api/scans/{scan_id}/comparison")
        report.add(PASS if status == 200 else FAIL, "retest comparison endpoint works", f"HTTP {status}")
        status, dash = get_json(base, "/api/dashboard")
        report.add(PASS if status == 200 and dash.get("total_scans", 0) >= 1 else FAIL, "dashboard totals include the scan")

        # 6. Authenticated scan against a site with a login (credentials are fake and belong to the test site)
        login_server, login_target, login_site = testsite.start_site()
        try:
            auth = {"kind": "form", "login_url": login_target + "/login", "username": "alice", "password": "alicepw"}
            status, refused = get_json(base, "/api/scans", method="POST", body={"target": login_target, "profile": "standard", "authorized": True, "auth": auth})
            report.add(PASS if status == 400 else FAIL, "a login without the separate 'act as this user' approval is refused", f"HTTP {status}")
            status, created = get_json(base, "/api/scans", method="POST", body={"target": login_target, "profile": "standard", "authorized": True,
                                                                               "auth": auth, "authenticated_testing_approved": True})
            report.add(PASS if status == 200 and "id" in created else FAIL, "an authenticated scan starts", f"HTTP {status}")
            if status == 200 and "id" in created:
                auth_id = created["id"]
                deadline = time.time() + args.scan_timeout
                while time.time() < deadline:
                    status, adetail = get_json(base, f"/api/scans/{auth_id}")
                    if status == 200 and adetail["scan"]["status"] != "running":
                        break
                    time.sleep(3)
                ascan = adetail["scan"]
                report.add(PASS if ascan.get("status") in ("completed", "completed_with_gaps") else FAIL, "the authenticated scan finishes", f"status {ascan.get('status')}")
                asummary = json.loads(ascan.get("summary") or "{}")
                report.add(PASS if asummary.get("authentication", {}).get("status") == "logged_in" else FAIL, "the login worked and the report says so",
                           str(asummary.get("authentication", {}).get("status")))
                requested = {entry["path"].split("?")[0] for entry in login_site.log}
                report.add(PASS if {"/dashboard", "/orders", "/settings"} <= requested else FAIL, "pages behind the login were visited")
                report.add(PASS if not requested & {"/logout", "/delete-account"} and not any("action=remove" in e["path"] for e in login_site.log) else FAIL,
                           "the scanner never requested logout, delete or other state-changing links")
                report.add(PASS if login_site.login_posts == 1 else FAIL, "the password was tried exactly once", f"{login_site.login_posts} login submission(s)")
                blob = json.dumps(adetail) + json.dumps(get_json(base, "/api/scans")[1]) + call(base, "/api/export/findings.csv")[2].decode("utf-8", "replace")
                leaked = [secret for secret in ("alicepw", *[v for site_sid in login_site.sessions for v in (site_sid,)]) if secret in blob]
                report.add(PASS if not leaked else FAIL, "neither the password nor the session id appears in stored results or exports")
                status, _ = get_json(base, "/api/schedules", method="POST", body={"target": login_target, "authorized": True, "auth": auth, "name": "x"})
                report.add(PASS if status == 400 else FAIL, "scheduling a scan with credentials is refused (credentials are never stored)", f"HTTP {status}")
            # 7. Access control: two users compared. /notes/<id> has no ownership check (a planted flaw); /profile/<id> does.
            second = {"kind": "form", "login_url": login_target + "/login", "username": "bob", "password": "bobpw"}
            status, created = get_json(base, "/api/scans", method="POST", body={"target": login_target, "profile": "standard", "authorized": True, "auth": auth, "auth_second": second,
                                                                               "second_account_role": "peer", "authenticated_testing_approved": True})
            report.add(PASS if status == 200 and "id" in created else FAIL, "a two-account scan starts", f"HTTP {status}")
            if status == 200 and "id" in created:
                deadline = time.time() + args.scan_timeout
                while time.time() < deadline:
                    status, bdetail = get_json(base, f"/api/scans/{created['id']}")
                    if status == 200 and bdetail["scan"]["status"] != "running":
                        break
                    time.sleep(3)
                bfind = bdetail.get("findings", [])
                idor = [f["affected_url"] for f in bfind if f["title"].startswith("Another user's page is readable")]
                report.add(PASS if any("/notes/" in u for u in idor) else FAIL, "a page one user can open that belongs to another user is found (planted flaw)")
                report.add(PASS if not any("/profile/" in u for u in idor) else FAIL, "a page that correctly refuses other users is not reported")
                report.add(PASS if any(f["title"].startswith("Page from the logged-in area is reachable without logging in") and "/invoices/" in f["affected_url"] for f in bfind) else FAIL,
                           "a logged-in page that a visitor can open is found (planted flaw)")
                report.add(PASS if login_site.login_posts == 3 else FAIL, "each account's password was tried once per scan", f"{login_site.login_posts} login submission(s) in total")
                report.add(PASS if not {e["path"].split("?")[0] for e in login_site.log} & {"/logout", "/delete-account"} else FAIL, "no logout or delete link was ever requested, even with two accounts")
                report.add(PASS if "bobpw" not in json.dumps(bdetail) else FAIL, "the second account's password does not appear in stored results")
        finally:
            login_server.shutdown()
    finally:
        server.shutdown()
    return finish(report, args, started)


def finish(report: Report, args, started: float) -> int:
    failed = report.failed()
    counts = {s: sum(1 for r in report.rows if r["status"] == s) for s in (PASS, FAIL, WARN, INFO)}
    verdict = "PASS" if not failed else "FAIL"
    print(f"\nRESULT: {verdict}  ({counts[PASS]} passed, {counts[FAIL]} failed, {counts[WARN]} warnings) in {int(time.time() - started)}s", flush=True)
    if failed:
        print("Failed checks:")
        for row in failed:
            print(f"  - {row['check']}: {row['detail']}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            json.dump({"verdict": verdict, "scanner": args.scanner, "when": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "counts": counts, "checks": report.rows}, handle, indent=2)
        print(f"Report written to {args.report}")
    return 0 if not failed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scanner", default="http://127.0.0.1:1005", help="base URL of the running scanner")
    parser.add_argument("--scan-timeout", type=int, default=420, help="seconds to wait for the test scan (default 420)")
    parser.add_argument("--report", help="write a JSON report to this file")
    sys.exit(run(parser.parse_args()))
