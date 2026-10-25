import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="dkcissp-default-page-test-")
os.environ["DKCISSP_DB"] = str(Path(_TEST_DB_DIR.name) / "test.sqlite3")
sys.path.insert(0, str(ROOT))
import app


def test_known_stock_server_pages_are_low_confidence_inventory_signals():
    examples = [
        ("<html><title>Apache2 Debian Default Page</title></html>", "text/html"),
        ("<html><h1>Welcome to nginx!</h1></html>", "text/html; charset=utf-8"),
        ("<html>Test Page for the Apache HTTP Server</html>", "application/xhtml+xml"),
        ("<html>Internet Information Services</html>", "text/html"),
    ]
    for body, content_type in examples:
        signal = app.default_server_page_observation(body, content_type)
        assert signal is not None
        assert signal["title"] == "Possible default web-server page"
        assert signal["severity"] == "Info"
        assert signal["confidence"] == "Low"
        assert "validate manually" in signal["evidence"]
        assert "not proof of a vulnerability" in signal["remediation"]


def test_custom_pages_and_non_html_assets_are_not_flagged():
    assert app.default_server_page_observation(
        "<html><title>Customer Portal</title><body>Welcome</body></html>", "text/html"
    ) is None
    assert app.default_server_page_observation(
        "Welcome to nginx!", "text/plain"
    ) is None
    assert app.default_server_page_observation(
        "<html><title>Apache2 Debian Default Page</title></html>", "application/json"
    ) is None


def test_stock_page_matching_is_case_insensitive_and_bounded():
    assert app.default_server_page_observation(
        "<HTML><TITLE>WELCOME TO NGINX!</TITLE></HTML>", "text/html"
    ) is not None
    assert app.default_server_page_observation(
        "x" * 500_001 + "<title>Welcome to nginx!</title>", "text/html"
    ) is None


def test_standard_scan_records_stock_page_as_informational_signal(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><head><title>Welcome to nginx!</title></head><body>stock page</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=()")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/"
    empty_status = {"status": "skipped", "reason": "controlled test", "finding_count": 0}
    monkeypatch.setattr(app, "perform_nuclei_check", lambda *_args, **_kwargs: ([], empty_status))
    monkeypatch.setattr(app, "perform_nikto_check", lambda *_args, **_kwargs: ([], empty_status))
    monkeypatch.setattr(app, "perform_whatweb_check", lambda *_args, **_kwargs: ([], empty_status))
    monkeypatch.setattr(app, "perform_testssl_check", lambda *_args, **_kwargs: ([], empty_status))
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *_args, **_kwargs: ([], {
        "status": "skipped", "reason": "controlled test", "finding_count": 0,
        "alert_count": 0, "urls_scanned": 0,
    }))
    try:
        with app.connect() as conn:
            scan_id = conn.execute(
                "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                (target, "standard", "running", app.now()),
            ).lastrowid
        app.perform_scan(scan_id, target, "standard")
        with app.connect() as conn:
            scan = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
            rows = conn.execute(
                "SELECT title,severity,confidence,evidence,remediation FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        assert scan["status"] == "completed"
        signal = next(row for row in rows if row["title"] == "Possible default web-server page")
        assert signal["severity"] == "Info"
        assert signal["confidence"] == "Low"
        assert "nginx welcome page" in signal["evidence"]
        assert "not proof of a vulnerability" in signal["remediation"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
