import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="dkcissp-methods-test-")
os.environ["DKCISSP_DB"] = str(Path(_TEST_DB_DIR.name) / "test.sqlite3")
sys.path.insert(0, str(ROOT))
import app


def test_advertised_risky_methods_are_low_severity_observations():
    signal = app.risky_http_methods_observation("GET, HEAD, OPTIONS, TRACE, PUT, DELETE", 200)
    assert signal is not None
    assert signal["title"] == "Potentially risky HTTP methods advertised"
    assert signal["severity"] == "Low"
    assert signal["confidence"] == "Medium"
    assert "DELETE, PUT, TRACE" in signal["evidence"]
    assert "proof of exploitability" in signal["remediation"]


def test_safe_method_list_and_missing_allow_header_do_not_create_findings():
    assert app.risky_http_methods_observation("GET, HEAD, OPTIONS, POST", 200) is None
    assert app.risky_http_methods_observation("", 200) is None
    assert app.risky_http_methods_observation("TRACE, PUT", 500) is None


def test_method_header_parsing_is_case_insensitive_and_deduplicated():
    signal = app.risky_http_methods_observation("get, trace, TRACE, propfind", 405)
    assert signal is not None
    assert signal["evidence"].count("TRACE") == 1
    assert "PROPFIND" in signal["evidence"]


def test_standard_scan_uses_scoped_options_probe_and_records_advertised_method(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><title>Controlled application</title><body>fixture</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=()")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
            self.end_headers()

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
                "SELECT title,severity,confidence,evidence FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        assert scan["status"] == "completed"
        signal = next(row for row in rows if row["title"] == "Potentially risky HTTP methods advertised")
        assert signal["severity"] == "Low"
        assert signal["confidence"] == "Medium"
        assert "TRACE" in signal["evidence"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
