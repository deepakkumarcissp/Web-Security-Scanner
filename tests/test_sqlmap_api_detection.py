import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import json

_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="dkcissp-sqlmap-api-test-")
os.environ["DKCISSP_DB"] = str(Path(_TEST_DB_DIR.name) / "test.sqlite3")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


class FakeOpener:
    def __init__(self, responder):
        self.responder = responder

    def open(self, request, timeout=3):
        return self.responder(request, timeout)


class FakeResponse:
    def __init__(self, payload, url):
        self.payload = json.dumps(payload).encode()
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, limit=-1):
        return self.payload[:limit]


def test_openapi_discovery_extracts_same_origin_json_post_fields():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://127.0.0.1:1003"}],
        "paths": {
            "/rest/user/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string"},
                                        "password": {"type": "string"},
                                        "ignored": {"type": "object"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }

    def fake_urlopen(request, timeout=3):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url == "http://127.0.0.1:1003/openapi.json":
            return FakeResponse(spec, url)
        raise OSError("not found")

    with patch.object(app, "same_origin_opener", return_value=FakeOpener(fake_urlopen)):
        operations = app.discover_openapi_json_operations("http://127.0.0.1:1003/")
    assert operations == [{
        "url": "http://127.0.0.1:1003/rest/user/login",
        "method": "POST",
        "fields": ["email", "password"],
        "body": True,
    }]


def test_openapi_discovery_rejects_external_server_base():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://evil.invalid"}],
        "paths": {"/login": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {"email": {"type": "string"}}}
        }}}}}},
    }

    def fake_urlopen(request, timeout=3):
        url = request.full_url
        if url == "http://127.0.0.1:1003/openapi.json":
            return FakeResponse(spec, url)
        raise OSError("not found")

    with patch.object(app, "same_origin_opener", return_value=FakeOpener(fake_urlopen)):
        assert app.discover_openapi_json_operations("http://127.0.0.1:1003/") == []


def test_sqlmap_requires_explicit_injection_point_evidence():
    with patch.object(app.shutil, "which", return_value="/usr/bin/sqlmap"), \
         patch.object(app, "discover_openapi_json_operations", return_value=[{
             "url": "http://127.0.0.1:1003/rest/user/login",
             "method": "POST", "fields": ["email"], "body": True,
         }]), \
         patch.object(app.subprocess, "run", return_value=type("Result", (), {
             "stdout": "Parameter: JSON email (POST)\\n Type: boolean-based blind\\n Title: test",
             "stderr": "", "returncode": 0,
         })()):
        findings, status = app.perform_sqlmap_check("http://127.0.0.1:1003/", timeout_seconds=10)
    assert findings == []
    assert status["parameters_tested"] == 1


def test_sqlmap_normalizes_only_explicit_positive_report():
    output = ("sqlmap identified the following injection point(s) with a total of 10 HTTP(s) requests:\\n"
              "Parameter: JSON email (POST)\\n Type: boolean-based blind\\n Title: AND boolean-based blind")
    with patch.object(app.shutil, "which", return_value="/usr/bin/sqlmap"), \
         patch.object(app, "discover_openapi_json_operations", return_value=[{
             "url": "http://127.0.0.1:1003/rest/user/login",
             "method": "POST", "fields": ["email"], "body": True,
         }]), \
         patch.object(app.subprocess, "run", return_value=type("Result", (), {
             "stdout": output, "stderr": "", "returncode": 0,
         })()):
        findings, status = app.perform_sqlmap_check("http://127.0.0.1:1003/", timeout_seconds=10)
    assert len(findings) == 1
    assert findings[0][1] == "SQL Injection (SQLMap)"
    assert findings[0][0] == "High"
    assert status["finding_count"] == 1
