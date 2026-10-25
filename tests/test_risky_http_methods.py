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
