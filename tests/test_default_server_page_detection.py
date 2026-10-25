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
