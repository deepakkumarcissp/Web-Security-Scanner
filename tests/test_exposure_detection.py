import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="dkcissp-exposure-test-")
os.environ["DKCISSP_DB"] = str(Path(_TEST_DB_DIR.name) / "test.sqlite3")
sys.path.insert(0, str(ROOT))
import app


def test_sensitive_file_path_requires_successful_response_and_uses_metadata_only():
    headers = {"content-type": "application/octet-stream", "content-length": "37"}
    signal = app.exposed_file_observation(
        "http://127.0.0.1:12345/backup.zip", 200, headers
    )
    assert signal is not None
    assert signal["title"] == "Potentially exposed backup or configuration artifact"
    assert signal["severity"] == "Low"
    assert signal["confidence"] == "Low"
    assert "path=/backup.zip" in signal["evidence"]
    assert "content-type=application/octet-stream" in signal["evidence"]
    assert "File contents were not included" in signal["evidence"]
    assert "does not confirm that secrets are present" in signal["remediation"]

    assert app.exposed_file_observation(
        "http://127.0.0.1:12345/backup.zip", 404, headers
    ) is None


def test_example_templates_and_ordinary_downloads_are_not_flagged():
    headers = {"content-type": "text/plain", "content-length": "20"}
    benign_urls = [
        "http://127.0.0.1:12345/.env.example",
        "http://127.0.0.1:12345/downloads/product.zip",
        "http://127.0.0.1:12345/robots.txt",
        "http://127.0.0.1:12345/.well-known/security.txt",
    ]
    for url in benign_urls:
        assert app.exposed_file_observation(url, 200, headers) is None


def test_repository_metadata_and_private_key_names_are_cautious_observations():
    headers = {"content-type": "text/plain", "content-length": "100"}
    for path in ("/.git/config", "/app/.git/config", "/id_rsa", "/app/.env.production", "/db.sql"):
        signal = app.exposed_file_observation(
            f"http://127.0.0.1:12345{path}", 200, headers
        )
        assert signal is not None, path
        assert signal["severity"] == "Low"
        assert signal["confidence"] == "Low"
        assert "File contents were not included" in signal["evidence"]


def test_standard_scan_detects_linked_backup_metadata_without_reading_body(monkeypatch):
    marker = b"LINKED_FIXTURE_BODY_MUST_NOT_BE_REPORTED"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = b'<html><body><a href="/downloads/backup.zip">download</a></body></html>'
                content_type = "text/html; charset=utf-8"
            elif self.path == "/downloads/backup.zip":
                body = marker
                content_type = "application/zip"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}/"

    monkeypatch.setattr(app, "perform_nuclei_check", lambda *_args, **_kwargs: ([], {"status": "skipped", "reason": "controlled test", "finding_count": 0, "target_count": 0}))
    monkeypatch.setattr(app, "perform_whatweb_check", lambda *_args, **_kwargs: ([], {"status": "skipped", "reason": "controlled test", "finding_count": 0}))
    monkeypatch.setattr(app, "perform_testssl_check", lambda *_args, **_kwargs: ([], {"status": "skipped", "reason": "controlled test", "finding_count": 0}))
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *_args, **_kwargs: ([], {"status": "skipped", "reason": "controlled test", "finding_count": 0, "alert_count": 0, "urls_scanned": 0}))

    try:
        with app.connect() as conn:
            scan_id = conn.execute(
                "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                (target, "standard", "running", app.now()),
            ).lastrowid
        app.perform_scan(scan_id, target, "standard")
        with app.connect() as conn:
            scan = conn.execute("SELECT status,summary FROM scans WHERE id=?", (scan_id,)).fetchone()
            rows = conn.execute(
                "SELECT title,affected_url,evidence,severity,confidence FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        assert scan["status"] == "completed"
        exposure = next(row for row in rows if row["title"] == "Potentially exposed backup or configuration artifact")
        assert exposure["affected_url"].endswith("/downloads/backup.zip")
        assert exposure["severity"] == "Low"
        assert exposure["confidence"] == "Low"
        assert "File contents were not included" in exposure["evidence"]
        assert marker.decode() not in str(rows)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
