from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

client = TestClient(app.app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_requires_authorization():
    response = client.post(
        "/api/scans",
        json={"target": "http://127.0.0.1:1003", "profile": "quick", "authorized": False},
    )
    assert response.status_code == 400
    assert "authorized" in response.json()["detail"].lower()


def test_scan_rejects_invalid_scheme():
    response = client.post(
        "/api/scans",
        json={"target": "ftp://example.com", "profile": "quick", "authorized": True},
    )
    assert response.status_code == 400


def test_schedule_requires_authorization():
    response = client.post(
        "/api/schedules",
        json={
            "name": "test",
            "target": "http://127.0.0.1:1003",
            "profile": "quick",
            "frequency": "daily",
            "authorized": False,
        },
    )
    assert response.status_code == 400


def test_schedule_accepts_future_time_and_can_be_deleted():
    run_at = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    response = client.post(
        "/api/schedules",
        json={
            "name": "test schedule",
            "target": "http://127.0.0.1:1003",
            "profile": "quick",
            "frequency": "daily",
            "run_at": run_at,
            "authorized": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["frequency"] == "daily"
    assert payload["enabled"] is True
    assert client.delete(f"/api/schedules/{payload['id']}").status_code == 200


def test_csv_export_has_expected_fields():
    response = client.get("/api/export/findings.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "severity" in response.text
    assert "remediation" in response.text


def test_csv_cell_neutralizes_spreadsheet_formulas():
    assert app.safe_csv_cell("=1+1") == "'=1+1"
    assert app.safe_csv_cell("  @SUM(A1:A2)") == "'  @SUM(A1:A2)"
    assert app.safe_csv_cell("-2") == "'-2"
    assert app.safe_csv_cell("ordinary finding text") == "ordinary finding text"
    assert app.safe_csv_cell(123) == 123


def test_testssl_skips_http_targets():
    findings, status = app.perform_testssl_check("http://example.test")
    assert findings == []
    assert status["status"] == "skipped"


def test_testssl_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda _binary: None)
    findings, status = app.perform_testssl_check("https://example.test")
    assert findings == []
    assert status["status"] == "unavailable"


def test_testssl_parses_findings_with_bounded_subprocess(monkeypatch):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/testssl.sh")

    def fake_run(command, **kwargs):
        assert command[0] == "/usr/bin/testssl.sh"
        assert "--jsonfile-pretty" in command
        assert kwargs["timeout"] == 75
        report_path = command[command.index("--jsonfile-pretty") + 1]
        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump([
                {"id": "TLS 1.0", "severity": "HIGH", "finding": "offered"},
                {"id": "TLS 1.3", "severity": "OK", "finding": "offered"},
            ], report_file)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_testssl_check("https://example.test")
    assert status["status"] == "completed"
    assert status["finding_count"] == 1
    assert findings[0][0] == "High"
    assert findings[0][1] == "testssl.sh: TLS 1.0"


def test_dashboard_renders_with_schedule_and_report_navigation():
    response = client.get("/")
    assert response.status_code == 200
    assert "Web Security Scanner" in response.text
    assert "Schedules" in response.text
    assert "Download findings.csv" in response.text



def test_tool_status_reports_allowlisted_integrations():
    response = client.get("/api/tools")
    assert response.status_code == 200
    payload = response.json()
    assert {tool["id"] for tool in payload["tools"]} == {
        "curl", "zaproxy", "whatweb", "testssl"
    }
    assert all("status" in tool and "installed" in tool for tool in payload["tools"])


def test_tool_install_requires_approval_and_allowlisted_id():
    denied = client.post("/api/tools/install/zaproxy", json={"approved": False})
    assert denied.status_code == 400
    unknown = client.post("/api/tools/install/not-allowlisted", json={"approved": True})
    assert unknown.status_code == 404


def test_tool_setup_page_is_separate_from_risk_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert 'data-page="toolsetup"' in response.text
    assert 'id="toolCards"' in response.text
    assert "v0.1 MVP" not in response.text


def test_asset_inventory_requires_explicit_authorization():
    response = client.post("/api/assets", json={
        "target": "https://Example.com", "authorized": False,
    })
    assert response.status_code == 400
    assert "authorized" in response.json()["detail"].lower()


def test_asset_inventory_normalizes_and_deduplicates_target():
    from uuid import uuid4
    hostname = f"inventory-{uuid4().hex}.example"
    first = client.post("/api/assets", json={
        "target": f"HTTPS://{hostname.upper()}:443/", "authorized": True,
        "scope_status": "in_scope", "notes": "approved root",
    })
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["target"] == f"https://{hostname}"
    assert first_payload["scope_status"] == "in_scope"
    assert first_payload["created"] is True

    second = client.post("/api/assets", json={
        "target": f"https://{hostname}/", "authorized": True,
    })
    assert second.status_code == 200
    assert second.json()["id"] == first_payload["id"]
    assert second.json()["created"] is False
    assert len([asset for asset in client.get("/api/assets").json()
                if asset["target"] == f"https://{hostname}"]) == 1


def test_new_assets_default_to_needs_review_and_do_not_start_scan():
    before = len(client.get("/api/scans").json())
    response = client.post("/api/assets", json={
        "target": "https://review-me.example", "authorized": True,
    })
    assert response.status_code == 200
    assert response.json()["scope_status"] == "needs_review"
    assert len(client.get("/api/scans").json()) == before


def test_asset_scope_change_requires_authorization_and_valid_asset():
    asset = client.post("/api/assets", json={
        "target": "https://scope-change.example", "authorized": True,
    }).json()
    denied = client.patch(f"/api/assets/{asset['id']}/scope", json={
        "scope_status": "in_scope", "authorized": False,
    })
    assert denied.status_code == 400
    changed = client.patch(f"/api/assets/{asset['id']}/scope", json={
        "scope_status": "in_scope", "authorized": True,
    })
    assert changed.status_code == 200
    assert changed.json()["scope_status"] == "in_scope"
    missing = client.patch("/api/assets/999999/scope", json={
        "scope_status": "in_scope", "authorized": True,
    })
    assert missing.status_code == 404


def test_asset_inventory_ui_is_wired_to_scope_api():
    response = client.get("/")
    assert response.status_code == 200
    assert 'data-page="assets"' in response.text
    assert 'id="assetRows"' in response.text
    assert 'id="assetForm"' in response.text
    assert "loadAssets()" in response.text
    assert "New assets default to Needs Review" in response.text



def test_passive_discovery_requires_authorization_and_in_scope_root(monkeypatch):
    calls = []
    monkeypatch.setattr(app, "query_certificate_transparency", lambda root, limit: calls.append((root, limit)) or [])
    asset = client.post("/api/assets", json={"target": "https://discover-auth.example", "authorized": True}).json()
    denied = client.post(f"/api/assets/{asset['id']}/discover", json={"authorized": False})
    assert denied.status_code == 400
    not_in_scope = client.post(f"/api/assets/{asset['id']}/discover", json={"authorized": True})
    assert not_in_scope.status_code == 400
    assert calls == []


def test_passive_discovery_candidates_stay_needs_review_and_never_start_scans(monkeypatch):
    from uuid import uuid4
    root_domain = f"discovery-{uuid4().hex}.example"
    root = client.post("/api/assets", json={
        "target": f"https://{root_domain}", "authorized": True, "scope_status": "in_scope",
    }).json()
    before = len(client.get("/api/scans").json())
    monkeypatch.setattr(app, "query_certificate_transparency", lambda domain, limit: [
        f"api.{domain}", f"login.{domain}", "evil-example.test", f"api.{domain}",
    ][:limit])
    response = client.post(f"/api/assets/{root['id']}/discover", json={"authorized": True, "max_results": 20})
    assert response.status_code == 200
    payload = response.json()
    assert payload["new_assets_added"] == 2
    assert payload["scans_started"] == 0
    rows = client.get("/api/assets").json()
    discovered = [a for a in rows if a["discovery_source"] == "crt.sh" and root_domain in a["target"]]
    assert len(discovered) == 2
    assert all(a["scope_status"] == "needs_review" for a in discovered)
    assert all(a["asset_type"] == "subdomain" for a in discovered)
    assert len(client.get("/api/scans").json()) == before


def test_certificate_transparency_parser_only_keeps_valid_subdomains(monkeypatch):
    import json
    from io import BytesIO
    records = [
        {"name_value": "api.parser-example.test\nlogin.parser-example.test\n*.wild.parser-example.test"},
        {"name_value": "parser-example.test\nevil-parser-example.test\nhttps://bad.parser-example.test"},
    ]
    class FakeResponse(BytesIO):
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    captured = {}
    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse(json.dumps(records).encode())
    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    names = app.query_certificate_transparency("parser-example.test", 10)
    assert names == ["api.parser-example.test", "login.parser-example.test", "wild.parser-example.test"]
    assert "crt.sh" in captured["url"] and captured["timeout"] == 12


def test_passive_discovery_ui_warns_about_external_lookup_and_review_only():
    response = client.get("/")
    assert response.status_code == 200
    assert "Passive Discovery" in response.text
    assert "contacts crt.sh, not the target" in response.text
    assert "discoverSubdomains" in response.text
