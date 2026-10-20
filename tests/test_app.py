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
    from uuid import uuid4
    target = f"https://schedule-{uuid4().hex}.example"
    registered = client.post("/api/assets", json={
        "target": target, "authorized": True, "scope_status": "in_scope",
    })
    assert registered.status_code == 200
    run_at = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    response = client.post(
        "/api/schedules",
        json={
            "name": "test schedule",
            "target": target,
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


def test_finding_lifecycle_update_and_not_found():
    from uuid import uuid4
    with app.connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
            (f"http://lifecycle-{uuid4().hex}.example", "quick", "completed", app.now()),
        )
        scan_id = cur.lastrowid
        cur = conn.execute(
            """INSERT INTO findings
            (scan_id,target,severity,title,affected_url,evidence,remediation,confidence,discovered_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (scan_id, f"http://lifecycle-{uuid4().hex}.example", "Low", "Test finding", "http://example.test", "evidence", "fix", "Medium", app.now()),
        )
        finding_id = cur.lastrowid
    response = client.patch(f"/api/findings/{finding_id}/lifecycle", json={"status":"retest_required", "notes":"Fix deployed; retest needed"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["lifecycle_status"] == "retest_required"
    assert payload["lifecycle_notes"] == "Fix deployed; retest needed"
    assert payload["lifecycle_updated_at"]
    invalid = client.patch(f"/api/findings/{finding_id}/lifecycle", json={"status":"invented", "notes":""})
    assert invalid.status_code == 422
    missing = client.patch("/api/findings/999999999/lifecycle", json={"status":"open", "notes":""})
    assert missing.status_code == 404


def test_csv_export_has_expected_fields():
    response = client.get("/api/export/findings.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "severity" in response.text
    assert "remediation" in response.text
    assert "lifecycle_status" in response.text


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



def test_nuclei_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda _binary: None)
    findings, status = app.perform_nuclei_check("https://example.test")
    assert findings == []
    assert status["status"] == "unavailable"


def test_nuclei_parses_jsonl_with_safe_bounded_command(monkeypatch):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/nuclei")

    def fake_run(command, **kwargs):
        assert command[0] == "/usr/bin/nuclei"
        assert command[command.index("-id") + 1] == "http-missing-security-headers,cookies-without-secure,cookies-without-httponly"
        assert command[command.index("-pt") + 1] == "http"
        assert command[command.index("-rl") + 1] == "3"
        assert command[command.index("-c") + 1] == "1"
        assert "-disable-redirects" in command
        assert "-no-interactsh" in command
        assert "-jsonl-export" in command
        assert kwargs["timeout"] == 30
        report_path = command[command.index("-jsonl-export") + 1]
        records = [
            {"template-id": "tls-test", "matched-at": "https://example.test/", "info": {"name": "Weak TLS setting", "severity": "high", "remediation": "Enable secure TLS."}},
            {"template-id": "tls-test", "matched-at": "https://example.test/", "info": {"name": "Weak TLS setting", "severity": "high", "remediation": "Enable secure TLS."}},
            {"template-id": "info-test", "matched-at": "https://example.test/", "info": {"name": "Banner info", "severity": "info"}},
        ]
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write("not json\n")
            for record in records:
                report_file.write(json.dumps(record) + "\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_nuclei_check("https://example.test")
    assert status["status"] == "completed"
    assert status["finding_count"] == 2
    assert status["malformed_records"] == 1
    assert findings[0][0] == "High"
    assert findings[0][1] == "Nuclei: Weak TLS setting"
    assert "template-id" not in findings[0][3]
    assert all("curl-command" not in str(item) for item in findings)


def test_nuclei_timeout_is_reported(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    monkeypatch.setattr(app.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("nuclei", 30)))
    findings, status = app.perform_nuclei_check("https://example.test")
    assert findings == []
    assert status == {"status": "timeout", "timeout_seconds": 30}


def test_whatweb_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda _binary: None)
    findings, status = app.perform_whatweb_check("https://example.test")
    assert findings == []
    assert status["status"] == "unavailable"


def test_whatweb_parses_technology_findings_with_bounded_subprocess(monkeypatch):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/whatweb")

    def fake_run(command, **kwargs):
        assert command[0] == "/usr/bin/whatweb"
        assert "--aggression=1" in command
        assert "--follow-redirect=never" in command
        assert "--log-json=" in next(arg for arg in command if arg.startswith("--log-json="))
        assert kwargs["timeout"] == 30
        report_path = next(arg.split("=", 1)[1] for arg in command if arg.startswith("--log-json="))
        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump([{"target": "https://example.test", "plugins": {
                "WordPress": {"version": ["6.5"]},
                "PHP": {"version": ["8.2"]},
                "HTTPServer": {"string": ["nginx"]},
            }}], report_file)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_whatweb_check("https://example.test")
    assert status["status"] == "completed"
    assert status["finding_count"] == 2
    assert {finding[1] for finding in findings} == {
        "WhatWeb technology detected: WordPress", "WhatWeb technology detected: PHP"
    }
    assert all(finding[0] == "Info" and finding[5] == "Low" for finding in findings)


def test_whatweb_timeout_is_reported(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/whatweb")
    monkeypatch.setattr(app.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("whatweb", 30)))
    findings, status = app.perform_whatweb_check("https://example.test")
    assert findings == []
    assert status == {"status": "timeout", "timeout_seconds": 30}

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
        "curl", "zaproxy", "whatweb", "testssl", "nuclei"
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
        f"api.{domain}", f"login.{domain}", f"api.{domain}",
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



def test_scan_and_schedule_require_explicit_in_scope_inventory_asset(monkeypatch):
    from uuid import uuid4
    target = f"https://scope-gate-{uuid4().hex}.example"
    unregistered_scan = client.post("/api/scans", json={"target": target, "profile": "quick", "authorized": True})
    assert unregistered_scan.status_code == 403
    unregistered_schedule = client.post("/api/schedules", json={
        "name": "blocked", "target": target, "profile": "quick", "frequency": "daily", "authorized": True,
    })
    assert unregistered_schedule.status_code == 403
    asset = client.post("/api/assets", json={"target": target, "authorized": True}).json()
    needs_review = client.post("/api/scans", json={"target": target, "profile": "quick", "authorized": True})
    assert needs_review.status_code == 403
    client.patch(f"/api/assets/{asset['id']}/scope", json={"scope_status": "out_of_scope", "authorized": True})
    out_of_scope = client.post("/api/scans", json={"target": target, "profile": "quick", "authorized": True})
    assert out_of_scope.status_code == 403
    client.patch(f"/api/assets/{asset['id']}/scope", json={"scope_status": "in_scope", "authorized": True})
    monkeypatch.setattr(app, "start_scan", lambda target, profile: 12345)
    approved = client.post("/api/scans", json={"target": target, "profile": "quick", "authorized": True})
    assert approved.status_code == 200 and approved.json()["id"] == 12345


def test_discovered_candidate_cannot_be_scanned_until_human_approves_it(monkeypatch):
    from uuid import uuid4
    root_domain = f"approval-{uuid4().hex}.example"
    root = client.post("/api/assets", json={"target": f"https://{root_domain}", "authorized": True, "scope_status": "in_scope"}).json()
    monkeypatch.setattr(app, "query_certificate_transparency", lambda domain, limit: [f"api.{domain}"])
    found = client.post(f"/api/assets/{root['id']}/discover", json={"authorized": True}).json()
    candidate = next(a for a in client.get("/api/assets").json() if a["target"] == f"https://api.{root_domain}")
    blocked = client.post("/api/scans", json={"target": candidate["target"], "profile": "quick", "authorized": True})
    assert blocked.status_code == 403
    assert found["scans_started"] == 0
    missing_reference = client.patch(f"/api/assets/{candidate['id']}/scope", json={"scope_status": "in_scope", "authorized": True})
    assert missing_reference.status_code == 400
    assert "reference" in missing_reference.json()["detail"].lower()
    approved = client.patch(f"/api/assets/{candidate['id']}/scope", json={
        "scope_status": "in_scope", "authorized": True, "approval_reference": "CHG-12345",
    })
    assert approved.status_code == 200
    assert approved.json()["approval_reference"] == "CHG-12345"
    assert approved.json()["review_decision"] == "approved"
    assert approved.json()["reviewed_at"]
    monkeypatch.setattr(app, "start_scan", lambda target, profile: 23456)
    allowed = client.post("/api/scans", json={"target": candidate["target"], "profile": "quick", "authorized": True})
    assert allowed.status_code == 200


def test_discovered_candidate_can_be_rejected_with_audit_state(monkeypatch):
    from uuid import uuid4
    root_domain = f"reject-{uuid4().hex}.example"
    root = client.post("/api/assets", json={"target": f"https://{root_domain}", "authorized": True, "scope_status": "in_scope"}).json()
    monkeypatch.setattr(app, "query_certificate_transparency", lambda domain, limit: [f"api.{domain}"])
    client.post(f"/api/assets/{root['id']}/discover", json={"authorized": True})
    candidate = next(a for a in client.get("/api/assets").json() if a["target"] == f"https://api.{root_domain}")
    rejected = client.patch(f"/api/assets/{candidate['id']}/scope", json={
        "scope_status": "out_of_scope", "authorized": True, "notes": "Not owned by our organization",
    })
    assert rejected.status_code == 200
    assert rejected.json()["scope_status"] == "out_of_scope"
    assert rejected.json()["review_decision"] == "rejected"
    assert rejected.json()["reviewed_at"]
    assert rejected.json()["notes"] == "Not owned by our organization"
    blocked = client.post("/api/scans", json={"target": candidate["target"], "profile": "quick", "authorized": True})
    assert blocked.status_code == 403



def test_zap_diagnostics_reports_expected_version_without_exposing_api_key(monkeypatch):
    import io
    from urllib.request import Request
    captured = {}
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url if isinstance(request, Request) else str(request)
        return Response(b'{"version":"2.15.0"}')
    monkeypatch.setenv("DKCISSP_ZAP_API_URL", "http://127.0.0.1:8090")
    monkeypatch.setenv("DKCISSP_ZAP_API_KEY", "secret-test-key")
    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    result = app.diagnose_zap_api()
    assert result["status"] == "ready"
    assert result["version"] == "2.15.0"
    assert result["endpoint"] == "http://127.0.0.1:8090"
    assert "secret-test-key" not in str(result)
    assert "secret-test-key" in captured["url"]


def test_zap_diagnostics_distinguishes_unrelated_service(monkeypatch):
    import io
    class Response(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
    monkeypatch.delenv("DKCISSP_ZAP_API_KEY", raising=False)
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    monkeypatch.setenv("DKCISSP_ZAP_API_URL", "http://127.0.0.1:8091")
    monkeypatch.setattr(app, "urlopen", lambda *args, **kwargs: Response(b'{"service":"not-zap"}'))
    result = app.diagnose_zap_api()
    assert result["status"] == "api_mismatch"
    assert "another service" in result["message"]


def test_zap_diagnostics_handles_auth_failure_without_secret_leak(monkeypatch):
    from urllib.error import HTTPError
    monkeypatch.setenv("DKCISSP_ZAP_API_URL", "http://127.0.0.1:8092")
    monkeypatch.setenv("DKCISSP_ZAP_API_KEY", "top-secret")
    def denied(*args, **kwargs):
        raise HTTPError("http://127.0.0.1:8092", 403, "Forbidden", {}, None)
    monkeypatch.setattr(app, "urlopen", denied)
    result = app.diagnose_zap_api()
    assert result["status"] == "auth_failed"
    assert "top-secret" not in str(result)


def test_zap_diagnostics_rejects_invalid_endpoint(monkeypatch):
    monkeypatch.setenv("DKCISSP_ZAP_API_URL", "http://user:password@127.0.0.1:8080")
    result = app.diagnose_zap_api()
    assert result["status"] == "configuration_error"
