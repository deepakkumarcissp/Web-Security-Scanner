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


def _create_completed_scan(target, profile, findings):
    from uuid import uuid4
    with app.connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at,finished_at) VALUES(?,?,?,?,?)",
            (target, profile, "completed", app.now(), app.now()),
        )
        scan_id = cur.lastrowid
        for severity, title, url in findings:
            conn.execute(
                """INSERT INTO findings
                (scan_id,target,severity,title,affected_url,evidence,remediation,confidence,discovered_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (scan_id, target, severity, title, url, "controlled test evidence", "controlled test remediation", "Medium", app.now()),
            )
    return scan_id


def test_scan_comparison_reports_new_resolved_persistent_and_risk_change():
    target = "https://compare-fixture.example/"
    baseline_id = _create_completed_scan(target, "standard", [
        ("High", "Missing security header", target, ),
        ("Medium", "Old exposed endpoint", target + "old"),
        ("Low", "Cookie attribute note", target + "login?source=old"),
    ])
    current_id = _create_completed_scan(target, "standard", [
        ("Medium", "Missing security header", target + "?cache=2"),
        ("High", "New unsafe endpoint", target + "new"),
        ("Low", "Cookie attribute note", target + "login?source=new"),
    ])
    response = client.get(f"/api/scans/{current_id}/comparison")
    assert response.status_code == 200
    data = response.json()
    assert data["baseline"]["scan_id"] == baseline_id
    assert data["summary"]["new"] == 1
    assert data["summary"]["resolved"] == 1
    assert data["summary"]["persistent"] == 2
    assert data["summary"]["severity_decreased"] == 1
    assert data["summary"]["risk_points_before"] == 13
    assert data["summary"]["risk_points_after"] == 13
    assert data["summary"]["risk_reduction_percent"] == 0
    assert data["limitations"]


def test_scan_comparison_requires_same_target_and_completed_scans():
    first = _create_completed_scan("https://compare-one.example/", "quick", [])
    second = _create_completed_scan("https://compare-two.example/", "quick", [])
    response = client.get(f"/api/scans/{second}/comparison?baseline_id={first}")
    assert response.status_code == 400
    with app.connect() as conn:
        cur = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                           ("https://compare-pending.example/", "quick", "running", app.now()))
        pending_id = cur.lastrowid
    assert client.get(f"/api/scans/{pending_id}/comparison").status_code == 409
    with app.connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (pending_id,))


def test_scan_comparison_without_baseline_returns_clear_message():
    scan_id = _create_completed_scan("https://compare-no-baseline.example/", "deep", [])
    response = client.get(f"/api/scans/{scan_id}/comparison")
    assert response.status_code == 200
    assert response.json()["baseline"] is None
    assert "No earlier completed scan" in response.json()["message"]
    assert response.json()["summary"]["risk_reduction_percent"] is None


def test_csv_export_has_expected_fields():
    response = client.get("/api/export/findings.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "severity" in response.text
    assert "remediation" in response.text
    assert "lifecycle_status" in response.text


def test_html_findings_report_has_download_headers_and_summary():
    response = client.get("/api/export/findings.html")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'filename="dkcissp-findings-report.html"' in response.headers["content-disposition"]
    assert "Website Security Findings Report" in response.text
    assert "Total findings" in response.text
    assert "Print / Save as PDF" in response.text
    assert "Content-Security-Policy" in response.headers


def test_html_findings_report_escapes_untrusted_finding_content():
    from uuid import uuid4
    marker = f"report-{uuid4().hex}"
    with app.connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
            (f"http://{marker}.example", "quick", "completed", app.now()),
        )
        scan_id = cur.lastrowid
        conn.execute(
            """INSERT INTO findings
            (scan_id,target,severity,title,affected_url,evidence,remediation,confidence,discovered_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (scan_id, f"http://{marker}.example", "High", '<script>alert("x")</script>',
             f"http://{marker}.example/?q=<svg>", '<img src=x onerror=alert(1)>',
             'Use <strong>parameterized</strong> output', "High", app.now()),
        )
    response = client.get("/api/export/findings.html")
    assert response.status_code == 200
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in response.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
    assert '<script>alert("x")</script>' not in response.text
    assert "<img src=x onerror=alert(1)>" not in response.text


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
    monkeypatch.setattr(app, "select_nuclei_templates", lambda max_templates=30: (["/tmp/safe-template.yaml"], {"status": "ready", "templates_selected": 1, "max_templates": max_templates}))

    def fake_run(command, **kwargs):
        assert command[0] == "/usr/bin/nuclei"
        assert command[command.index("-templates") + 1].endswith("selected-templates.txt")
        assert command[command.index("-list") + 1].endswith("targets.txt")
        with open(command[command.index("-list") + 1], encoding="utf-8") as targets_file:
            assert targets_file.read().splitlines() == ["https://example.test", "https://example.test/admin"]
        assert command[command.index("-pt") + 1] == "http"
        assert command[command.index("-rl") + 1] == "5"
        assert command[command.index("-c") + 1] == "3"
        assert command[command.index("-timeout") + 1] == "4"
        assert "-disable-redirects" in command
        assert "-no-interactsh" in command
        assert "-jsonl-export" in command
        assert kwargs["timeout"] == 60
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
    findings, status = app.perform_nuclei_check("https://example.test", targets=[
        "https://example.test", "https://example.test/admin", "https://evil.example/",
        "http://example.test/insecure",
    ])
    assert status["status"] == "completed"
    assert status["target_count"] == 2
    assert status["finding_count"] == 2
    assert status["malformed_records"] == 1
    assert status["template_selection"]["status"] == "ready"
    assert status["rate_limit_per_second"] == 5
    assert status["interactsh_disabled"] is True
    assert findings[0][0] == "High"
    assert findings[0][1] == "Nuclei: Weak TLS setting"
    assert "template-id" not in findings[0][3]
    assert all("curl-command" not in str(item) for item in findings)


def test_nuclei_timeout_is_reported(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    monkeypatch.setattr(app, "select_nuclei_templates", lambda max_templates=30: (["/tmp/safe-template.yaml"], {"status": "ready", "templates_selected": 1, "max_templates": max_templates}))
    monkeypatch.setattr(app.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("nuclei", 60)))
    findings, status = app.perform_nuclei_check("https://example.test")
    assert findings == []
    assert findings == []
    assert status["status"] == "timeout"
    assert status["timeout_seconds"] == 60
    assert status["target_count"] == 1
    assert status["interactsh_disabled"] is True


def test_nuclei_success_without_jsonl_is_zero_findings_not_error(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    monkeypatch.setattr(app, "select_nuclei_templates", lambda max_templates=30: (["/tmp/safe-template.yaml"], {"status": "ready", "templates_selected": 1, "max_templates": max_templates}))
    monkeypatch.setattr(app.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    findings, status = app.perform_nuclei_check("https://example.test")
    assert findings == []
    assert status["status"] == "completed"
    assert status["finding_count"] == 0
    assert "no matches" in status["reason"]


def test_nuclei_timeout_retains_valid_partial_jsonl_findings(monkeypatch):
    import json
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/nuclei")
    monkeypatch.setattr(app, "select_nuclei_templates", lambda max_templates=30: (["/tmp/safe-template.yaml"], {"status": "ready", "templates_selected": 1, "max_templates": max_templates}))
    def fake_run(command, **kwargs):
        report_path = command[command.index("-jsonl-export") + 1]
        record = {"template-id": "partial-check", "matched-at": "https://example.test/health", "info": {"name": "Partial evidence", "severity": "medium"}}
        Path(report_path).write_text(json.dumps(record) + "\n", encoding="utf-8")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_nuclei_check("https://example.test", timeout_seconds=60)
    assert status["status"] == "partial_timeout"
    assert status["partial_results_retained"] is True
    assert status["finding_count"] == 1
    assert findings[0][1] == "Nuclei: Partial evidence"


def test_nuclei_template_selector_excludes_high_risk_and_non_http_templates(tmp_path, monkeypatch):
    import app
    root = tmp_path / "http"
    root.mkdir()
    (root / "safe.yaml").write_text("id: safe-config\ninfo:\n  name: Safe config\n  severity: medium\n  metadata:\n    max-request: 2\n  tags: misconfig,headers\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n")
    (root / "intrusive.yaml").write_text("id: risky-probe\ninfo:\n  name: Risky probe\n  severity: high\n  tags: cve,intrusive\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n")
    (root / "too-many-requests.yaml").write_text("id: noisy-probe\ninfo:\n  name: Noisy probe\n  severity: high\n  metadata:\n    max-request: 10\n  tags: cve\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n")
    (root / "headless.yaml").write_text("id: browser-check\ninfo:\n  name: Browser check\n  severity: low\n  tags: tech\nheadless:\n  - steps: []\n")
    (root / "nested-payloads.yaml").write_text("id: payload-probe\ninfo:\n  name: Payload probe\n  severity: medium\n  tags: cve\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n    payloads:\n      name: [admin, test]\n")
    (root / "nested-attack.yaml").write_text("id: attack-probe\ninfo:\n  name: Attack probe\n  severity: medium\n  tags: cve\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n    attack: batteringram\n")
    monkeypatch.setenv("DKCISSP_NUCLEI_TEMPLATES", str(root))
    selected, status = app.select_nuclei_templates(max_templates=10)
    assert selected == [str(root / "safe.yaml")]
    assert status["templates_selected"] == 1
    assert "intrusive" in status["excluded_tags"]


def test_nuclei_template_selection_balances_categories_before_filling_cap(tmp_path, monkeypatch):
    root = tmp_path / "http"
    root.mkdir()
    # CVE-tagged templates are intentionally excluded by the safe default selector.
    categories = ["misconfig", "exposure", "ssl", "tech", "discovery"]
    for category in categories:
        for index in range(3):
            (root / f"{category}-{index}.yaml").write_text(
                f"id: {category}-{index}\ninfo:\n  name: {category} check\n  severity: high\n  metadata:\n    max-request: 1\n  tags: {category}\nhttp:\n  - method: GET\n    path: [\"{{{{BaseURL}}}}/\"]\n"
            )
    monkeypatch.setenv("DKCISSP_NUCLEI_TEMPLATES", str(root))
    selected, status = app.select_nuclei_templates(max_templates=5)
    selected_ids = {Path(path).stem.split("-")[0] for path in selected}
    assert selected_ids == set(categories)
    assert status["templates_eligible"] == 15
    assert status["templates_selected"] == 5


def test_wapiti_parser_normalizes_findings_and_filters_out_of_scope_urls():
    report = {
        "classifications": {"SQL Injection": {"sol": "Use parameterized queries."}},
        "vulnerabilities": {"SQL Injection": [
            {"level": 3, "path": "/search?q=x", "info": "SQL error detected", "method": "GET", "parameter": "q", "module": "sql", "http_request": "SECRET REQUEST", "curl_command": "SECRET CURL"},
            {"level": 4, "path": "https://evil.example/", "info": "out of scope", "method": "GET"},
        ]},
        "additionals": {"HTTP Methods": [{"level": 0, "path": "/", "info": "Unexpected method response", "module": "methods"}]},
    }
    findings = app.parse_wapiti_report(report, "https://app.example.test/")
    assert len(findings) == 2
    sql = next(item for item in findings if "SQL Injection" in item[1])
    assert sql[0] == "High"
    assert sql[2] == "https://app.example.test/search?q=x"
    assert "Use parameterized queries" in sql[4]
    assert "SECRET" not in str(findings)
    additional = next(item for item in findings if "HTTP Methods" in item[1])
    assert additional[0] == "Info"


def test_wapiti_runs_bounded_active_modules_and_parses_json(monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace
    monkeypatch.setattr(app.shutil, "which", lambda _binary: "/usr/bin/wapiti")
    def fake_run(command, **kwargs):
        assert command[command.index("--scope") + 1] == "folder"
        modules = command[command.index("-m") + 1].split(",")
        assert "sql" in modules and "xss" in modules and "exec" in modules
        assert not ({"ssrf", "upload", "permanentxss", "timesql"} & set(modules))
        assert command[command.index("--max-scan-time") + 1] == "75"
        assert command[command.index("--tasks") + 1] == "1"
        assert "--no-bugreport" in command
        assert kwargs["timeout"] == 90
        report_path = command[command.index("-o") + 1]
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump({"classifications": {"SQL Injection": {"sol": "Use prepared statements."}},
                       "vulnerabilities": {"SQL Injection": [{"level": 2, "path": "/search", "info": "Test evidence", "method": "GET", "parameter": "q", "module": "sql"}]},
                       "additionals": {}, "infos": {"crawled_pages_nbr": 2}}, handle)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_wapiti_check("https://app.example.test/")
    assert status["status"] == "completed"
    assert status["finding_count"] == 1
    assert status["crawled_pages"] == 2
    assert findings[0][0] == "Medium"


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
    assert "Assessment depth" in response.text
    assert "Active — test application vulnerabilities" in response.text
    assert "I explicitly approve active payload testing" in response.text
    assert "DKCISSP Local Lab Target" in response.text
    assert "http://127.0.0.1:1003" in response.text
    assert "http://127.0.0.1:1006" in response.text
    assert "http://127.0.0.1:1007/WebGoat" in response.text



def test_tool_status_reports_allowlisted_integrations():
    response = client.get("/api/tools")
    assert response.status_code == 200
    payload = response.json()
    tool_ids = {tool["id"] for tool in payload["tools"]}
    # The registry can grow; assert required integrations without rejecting additions.
    assert {
        "curl", "zaproxy", "whatweb", "testssl", "nuclei", "nikto", "wapiti"
    } <= tool_ids
    assert all("status" in tool and "installed" in tool for tool in payload["tools"])


def test_zap_api_readiness_overrides_unhelpful_launcher_version(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/zaproxy" if binary == "zaproxy" else None)
    monkeypatch.setattr(app, "_tool_version", lambda tool: None)
    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {
        "status": "ready", "message": "OWASP ZAP API responded successfully.",
        "endpoint": "http://127.0.0.1:8090", "version": "2.17.0",
    })
    tools = app.scanner_tools_status()
    zap = next(tool for tool in tools if tool["id"] == "zaproxy")
    assert zap["status"] == "ready"
    assert zap["version"] == "OWASP ZAP API 2.17.0"
    assert zap["service_status"] == "ready"


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


def test_assessment_and_schedule_need_no_asset_registration(monkeypatch):
    from uuid import uuid4
    target = f"https://simple-flow-{uuid4().hex}.example"
    started = []
    monkeypatch.setattr(app, "start_scan", lambda target, profile: started.append((target, profile)) or 12345)
    allowed = client.post("/api/scans", json={"target": target, "profile": "deep", "authorized": True})
    assert allowed.status_code == 200 and allowed.json()["id"] == 12345
    assert allowed.json()["status"] == "running"
    assert allowed.json()["profile"] == "deep"
    assert started == [(target, "deep")]
    schedule = client.post("/api/schedules", json={
        "name": "no registration needed", "target": target, "profile": "quick", "frequency": "daily", "authorized": True,
    })
    assert schedule.status_code == 200
    client.delete(f"/api/schedules/{schedule.json()['id']}")
    # The authorization confirmation is still required for scans and schedules.
    assert client.post("/api/scans", json={"target": target, "authorized": False}).status_code == 400
    assert client.post("/api/schedules", json={
        "name": "x", "target": target, "profile": "quick", "frequency": "daily", "authorized": False,
    }).status_code == 400


def test_assessment_page_does_not_mention_asset_registration():
    page = client.get("/").text
    assert "Asset Inventory" not in page
    assert "marked In Scope" not in page
    assert 'id="authorized"' in page


def test_active_scan_requires_separate_approval_and_reaches_worker(monkeypatch):
    from uuid import uuid4
    target = f"https://active-{uuid4().hex}.example"
    started = []
    monkeypatch.setattr(app, "start_scan", lambda target, profile: started.append((target, profile)) or 98765)
    denied = client.post("/api/scans", json={"target": target, "profile": "active", "authorized": True})
    assert denied.status_code == 400
    assert "active-testing approval" in denied.json()["detail"].lower()
    allowed = client.post("/api/scans", json={
        "target": target, "profile": "active", "authorized": True, "active_testing_approved": True,
    })
    assert allowed.status_code == 200
    assert allowed.json()["profile"] == "active"
    assert started == [(target, "active")]


def test_active_scan_cannot_be_scheduled():
    from uuid import uuid4
    response = client.post("/api/schedules", json={
        "name": "active scan", "target": f"https://active-schedule-{uuid4().hex}.example",
        "profile": "active", "frequency": "daily", "authorized": True,
        "active_testing_approved": True,
    })
    assert response.status_code == 400
    assert "cannot be scheduled" in response.json()["detail"].lower()


def test_scan_progress_fields_are_available_to_the_dashboard(monkeypatch):
    from uuid import uuid4
    target = f"https://progress-{uuid4().hex}.example"
    monkeypatch.setattr(app, "start_scan", lambda target, profile: 45678)
    response = client.post("/api/scans", json={"target": target, "authorized": True})
    assert response.status_code == 200
    # The full progress fields are populated by the worker and exposed on scan detail.
    with app.connect() as conn:
        conn.execute("INSERT INTO scans(target,profile,status,created_at,progress,current_stage,tool_status) VALUES(?,?,?,?,?,?,?)",
                     (target, "standard", "running", app.now(), 35, "Running Nuclei safe checks", '{"Nuclei":{"status":"running"}}'))
        scan_id = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
    detail = client.get(f"/api/scans/{scan_id}").json()["scan"]
    assert detail["progress"] == 35
    assert detail["current_stage"] == "Running Nuclei safe checks"
    assert '"Nuclei"' in detail["tool_status"]
    with app.connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def test_discovered_candidate_approval_reference_is_recorded(monkeypatch):
    from uuid import uuid4
    root_domain = f"approval-{uuid4().hex}.example"
    root = client.post("/api/assets", json={"target": f"https://{root_domain}", "authorized": True, "scope_status": "in_scope"}).json()
    monkeypatch.setattr(app, "query_certificate_transparency", lambda domain, limit: [f"api.{domain}"])
    found = client.post(f"/api/assets/{root['id']}/discover", json={"authorized": True}).json()
    candidate = next(a for a in client.get("/api/assets").json() if a["target"] == f"https://api.{root_domain}")
    monkeypatch.setattr(app, "start_scan", lambda target, profile: 34567)
    # Discovery never starts scans itself, and scanning a candidate needs no registration or approval.
    assert found["scans_started"] == 0
    assert client.post("/api/scans", json={"target": candidate["target"], "profile": "quick", "authorized": True}).status_code == 200
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


def test_discovered_candidate_rejection_is_recorded_and_does_not_block_scans(monkeypatch):
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
    monkeypatch.setattr(app, "start_scan", lambda target, profile: 45678)
    assert client.post("/api/scans", json={"target": candidate["target"], "profile": "quick", "authorized": True}).status_code == 200



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


def test_endpoint_discovery_extracts_only_same_origin_http_urls():
    base = "https://app.example.test/home"
    html = '''<html><a href="/account">Account</a><a href="https://app.example.test/search?q=x#top">Search</a>
      <a href="https://evil.example/steal">external</a><a href="//other.example.test/path">other host</a>
      <a href="javascript:alert(1)">script</a><form action="/login"><input></form>
      <script src="/assets/app.js"></script><a href="mailto:help@example.test">mail</a></html>'''
    urls = app.extract_same_origin_links(base, html)
    assert "https://app.example.test/account" in urls
    assert "https://app.example.test/search?q=x" in urls
    assert "https://app.example.test/login" in urls
    assert "https://app.example.test/assets/app.js" in urls
    assert all("evil.example" not in url and "other.example.test" not in url for url in urls)
    assert all("javascript:" not in url and "mailto:" not in url and "#top" not in url for url in urls)


def test_endpoint_discovery_does_not_cross_port_or_scheme():
    html = '<a href="http://app.example.test/plain">http</a><a href="https://app.example.test:8443/admin">port</a>'
    assert app.extract_same_origin_links("https://app.example.test/", html) == []


def test_nikto_json_report_is_normalized_conservatively():
    report = {"host": "example.test", "findings": [
        {"method": "GET", "url": "/admin/", "msg": "Directory indexing found.", "OSVDB": "1234"},
        {"method": "GET", "url": "/admin/", "msg": "Directory indexing found.", "OSVDB": "1234"},
        {"method": "GET", "url": "/", "msg": "Server banner disclosure"},
        {"method": "GET", "url": "/empty", "msg": ""},
    ]}
    findings = app.parse_nikto_report(report, "https://example.test/")
    assert len(findings) == 2
    directory = next(item for item in findings if "Directory indexing" in item[1])
    assert directory[0] == "Low"
    assert directory[2] == "https://example.test/admin/"
    assert "1234" in directory[3]
    banner = next(item for item in findings if "banner disclosure" in item[1])
    assert banner[0] == "Info"


def test_nikto_report_parser_handles_unknown_and_malformed_shapes():
    assert app.parse_nikto_report({"host": "example.test", "findings": "not-a-list"}, "https://example.test") == []
    assert app.parse_nikto_report(None, "https://example.test") == []


def test_zap_passive_scans_only_same_origin_urls_and_reports_status(monkeypatch):
    import json
    from types import SimpleNamespace
    seen = []
    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "ready", "endpoint": "http://127.0.0.1:8090"})
    monkeypatch.setattr(app, "zap_api_settings", lambda: ("http://127.0.0.1:8090", "test-key"))
    class FakeResponse:
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, _size): return json.dumps(self.payload).encode()
    def fake_urlopen(request, timeout=4):
        from urllib.parse import urlparse, parse_qs
        url = request.full_url
        seen.append(url)
        path = urlparse(url).path
        if path.endswith("/accessUrl/"): return FakeResponse({"Result": "OK"})
        if path.endswith("/recordsToScan/"): return FakeResponse({"recordsToScan": "0"})
        if path.endswith("/alerts/"):
            return FakeResponse({"alerts": [
                {"risk": "Medium", "alert": "CSP header missing", "url": "http://app.example.test/about", "description": "No CSP", "solution": "Set CSP"},
                {"risk": "High", "alert": "Out of scope", "url": "https://evil.example.test/", "description": "ignore", "solution": "ignore"},
            ]})
        raise AssertionError(url)
    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    findings, status = app.perform_zap_passive_check("http://app.example.test/", targets=[
        "http://app.example.test/", "http://app.example.test/about", "https://evil.example.test/",
    ])
    assert status["status"] == "completed"
    assert status["urls_scanned"] == 2
    assert len(findings) == 1
    assert findings[0][1] == "OWASP ZAP: CSP header missing"
    assert all("evil.example.test" not in url for url in seen)


def test_zap_passive_unavailable_status_is_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "api_unreachable", "message": "ZAP unavailable"})
    findings, status = app.perform_zap_passive_check("https://example.test")
    assert findings == []
    assert status["status"] == "api_unreachable"
    assert status["reason"] == "ZAP unavailable"


def test_same_origin_redirect_handler_allows_only_exact_origin():
    from urllib.request import Request

    handler = app._SameOriginRedirectHandler("https://app.example.test/start")
    request = Request("https://app.example.test/start")
    headers = {}

    same_host = handler.redirect_request(request, None, 302, "Found", headers, "https://app.example.test/next")
    same_host_explicit_default_port = handler.redirect_request(request, None, 302, "Found", headers, "https://app.example.test:443/next")
    assert same_host is not None
    assert same_host_explicit_default_port is not None

    assert handler.redirect_request(request, None, 302, "Found", headers, "https://evil.example.test/next") is None
    assert handler.redirect_request(request, None, 302, "Found", headers, "http://app.example.test/next") is None
    assert handler.redirect_request(request, None, 302, "Found", headers, "https://app.example.test:8443/next") is None
    assert handler.redirect_request(request, None, 302, "Found", headers, "//evil.example.test/next") is None


def test_same_origin_redirect_handler_normalizes_trailing_dot_hostname():
    from urllib.request import Request

    handler = app._SameOriginRedirectHandler("https://app.example.test/")
    request = Request("https://app.example.test/")
    allowed = handler.redirect_request(request, None, 301, "Moved", {}, "https://app.example.test./next")
    assert allowed is not None


def test_scan_rejects_malformed_or_out_of_range_target_ports():
    for target in (
        "http://example.test:not-a-port/",
        "http://example.test:0/",
        "https://example.test:65536/",
    ):
        response = client.post("/api/scans", json={
            "target": target, "profile": "quick", "authorized": True,
        })
        assert response.status_code == 400, target


def test_scan_rejects_url_with_embedded_credentials():
    response = client.post("/api/scans", json={
        "target": "https://user:password@example.test/", "profile": "quick", "authorized": True,
    })
    assert response.status_code == 400


def test_same_origin_redirect_handler_rejects_malformed_and_credential_urls():
    from urllib.request import Request

    handler = app._SameOriginRedirectHandler("https://app.example.test/")
    request = Request("https://app.example.test/")
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://app.example.test:notaport/") is None
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://user:secret@app.example.test/next") is None


def test_nikto_parser_filters_out_of_scope_absolute_urls_and_ports():
    report = {"findings": [
        {"url": "/admin/", "msg": "Directory indexing found"},
        {"url": "https://evil.example.test/steal", "msg": "Out-of-scope URL"},
        {"url": "http://app.example.test/plain", "msg": "Different scheme"},
        {"url": "https://app.example.test:8443/admin", "msg": "Different port"},
        {"url": "https://user:secret@app.example.test/secret", "msg": "Embedded credentials"},
        {"url": "https://app.example.test:notaport/path", "msg": "Malformed port"},
    ]}
    findings = app.parse_nikto_report(report, "https://app.example.test/")
    assert len(findings) == 1
    assert findings[0][2] == "https://app.example.test/admin/"


def test_shared_same_origin_validator_fails_closed():
    assert app.is_same_origin_url("https://app.example.test/a", "https://app.example.test/")
    assert app.is_same_origin_url("https://app.example.test./a", "https://app.example.test/")
    for candidate in (
        "http://app.example.test/a", "https://evil.example.test/a",
        "https://app.example.test:8443/a", "https://user:secret@app.example.test/a",
        "https://app.example.test:notaport/a", "javascript:alert(1)",
    ):
        assert not app.is_same_origin_url(candidate, "https://app.example.test/"), candidate


def test_scan_creation_rejects_when_concurrency_limit_is_reached(monkeypatch):
    from uuid import uuid4
    target = f"https://capacity-{uuid4().hex}.example"
    started = []
    monkeypatch.setenv("DKCISSP_MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setattr(app, "start_scan", lambda target, profile: started.append((target, profile)) or 777)
    with app.connect() as conn:
        cursor = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
            (f"https://already-running-{uuid4().hex}.example", "standard", "running", app.now()),
        )
        running_id = cursor.lastrowid
    try:
        response = client.post("/api/scans", json={"target": target, "profile": "quick", "authorized": True})
        assert response.status_code == 429
        assert "capacity reached" in response.json()["detail"].lower()
        assert started == []
    finally:
        with app.connect() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (running_id,))


def test_concurrency_limit_is_bounded_and_has_safe_fallback(monkeypatch):
    monkeypatch.setenv("DKCISSP_MAX_CONCURRENT_SCANS", "not-a-number")
    assert app.max_concurrent_scans() == 2
    monkeypatch.setenv("DKCISSP_MAX_CONCURRENT_SCANS", "1000")
    assert app.max_concurrent_scans() == 8
    monkeypatch.setenv("DKCISSP_MAX_CONCURRENT_SCANS", "0")
    assert app.max_concurrent_scans() == 1


def test_start_scan_enforces_capacity_atomically(monkeypatch):
    import pytest
    from uuid import uuid4
    monkeypatch.setenv("DKCISSP_MAX_CONCURRENT_SCANS", "1")
    with app.connect() as conn:
        cursor = conn.execute(
            "INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
            (f"https://worker-running-{uuid4().hex}.example", "quick", "running", app.now()),
        )
        running_id = cursor.lastrowid
    try:
        with pytest.raises(app.HTTPException) as exc_info:
            app.start_scan(f"https://worker-new-{uuid4().hex}.example", "quick")
        assert exc_info.value.status_code == 429
    finally:
        with app.connect() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (running_id,))


def _fake_zap(monkeypatch, queue_values, alerts=None):
    """Patch ZAP's HTTP API; queue_values is a list of recordsToScan values, or an Exception, consumed per poll."""
    import json
    from urllib.parse import urlparse
    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "ready", "endpoint": "http://127.0.0.1:8090"})
    monkeypatch.setattr(app, "zap_api_settings", lambda: ("http://127.0.0.1:8090", "test-key"))
    monkeypatch.setattr(app.time, "sleep", lambda _s: None)
    polls = {"n": 0}
    class FakeResponse:
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, _size): return json.dumps(self.payload).encode()
    def fake_urlopen(request, timeout=4):
        path = urlparse(request.full_url).path
        if path.endswith("/accessUrl/"): return FakeResponse({"Result": "OK"})
        if path.endswith("/recordsToScan/"):
            value = queue_values[min(polls["n"], len(queue_values) - 1)]
            polls["n"] += 1
            if isinstance(value, Exception): raise value
            return FakeResponse({"recordsToScan": str(value)})
        if path.endswith("/alerts/"): return FakeResponse({"alerts": alerts or []})
        raise AssertionError(path)
    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    return polls


def test_zap_passive_waits_for_two_consecutive_empty_polls(monkeypatch):
    polls = _fake_zap(monkeypatch, [5, 0, 3, 0, 0])
    findings, status = app.perform_zap_passive_check("http://app.example.test/")
    assert status["status"] == "completed"
    assert status["passive_queue_status"] == "drained"
    assert status["passive_timeout_seconds"] == 30.0
    assert polls["n"] == 5  # a single empty reading (poll 2) was not accepted as drained


def test_zap_passive_timeout_is_reported_as_warning(monkeypatch):
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS", "1")
    _fake_zap(monkeypatch, [7])
    ticks = iter(range(0, 1000, 2))
    monkeypatch.setattr(app.time, "monotonic", lambda: next(ticks))
    _, status = app.perform_zap_passive_check("http://app.example.test/")
    assert status["status"] == "completed_with_warnings"
    assert status["passive_queue_status"] == "timeout"
    assert status["passive_timeout_seconds"] == 1.0
    assert "did not drain" in status["reason"]


def test_zap_passive_queue_error_is_reported_as_warning(monkeypatch):
    _fake_zap(monkeypatch, [OSError("connection reset")])
    _, status = app.perform_zap_passive_check("http://app.example.test/")
    assert status["status"] == "completed_with_warnings"
    assert status["passive_queue_status"] == "error"
    assert "Could not confirm" in status["reason"]
    assert "active" not in status["reason"].lower()
    assert "no spider or active scan" in status["mode"]


def test_zap_passive_queue_settings_are_bounded(monkeypatch):
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS", "9999")
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_POLL_SECONDS", "0")
    assert app.zap_passive_queue_settings() == (180.0, 0.1)
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS", "0")
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_POLL_SECONDS", "50")
    assert app.zap_passive_queue_settings() == (1.0, 2.0)
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS", "junk")
    monkeypatch.setenv("DKCISSP_ZAP_PASSIVE_POLL_SECONDS", "nan")
    assert app.zap_passive_queue_settings() == (30.0, 0.5)


def test_assessment_gaps_flag_unfinished_stages_but_not_deliberate_skips():
    gaps = app.assessment_gaps({
        "Built-in HTTP & headers": {"status": "completed", "detail": "ok"},
        "Nikto": {"status": "skipped", "detail": "Deep only"},
        "Nuclei": {"status": "unavailable", "detail": "Nuclei is not installed"},
        "OWASP ZAP passive": {"status": "completed_with_warnings", "detail": "queue timeout"},
        "WhatWeb": {"status": "running", "detail": "stuck"},
    })
    assert [g["tool"] for g in gaps] == ["Nuclei", "OWASP ZAP passive", "WhatWeb"]
    assert app.assessment_gaps({"A": {"status": "completed"}, "B": {"status": "skipped"}}) == []


def test_scan_with_unavailable_tool_is_completed_with_gaps(monkeypatch):
    import json
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *a, **k: ([], {"status": "api_unreachable", "reason": "ZAP down"}))
    for name in ("perform_nuclei_check", "perform_whatweb_check", "perform_nikto_check", "perform_testssl_check"):
        monkeypatch.setattr(app, name, lambda *a, **k: ([], {"status": "completed"}))
    monkeypatch.setattr(app, "urlopen", lambda *a, **k: _FakeHTTP())
    with app.connect() as conn:
        scan_id = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                               ("http://gap-test.example/", "quick", "running", app.now())).lastrowid
    app.perform_scan(scan_id, "http://gap-test.example/", "quick")
    with app.connect() as conn:
        row = dict(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
    summary = json.loads(row["summary"])
    assert row["status"] == "completed_with_gaps"
    assert [g["tool"] for g in summary["assessment_gaps"]] == ["OWASP ZAP passive"]
    assert client.get(f"/api/scans/{scan_id}/comparison").status_code == 200


class _FakeHTTP:
    status = 200
    headers = {"Content-Type": "text/html"}
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def geturl(self): return "http://gap-test.example/"
    def read(self, _n=-1): return b"<html><title>t</title></html>"


# ---- tool approval flow -------------------------------------------------------------------------

def _scan_with_missing_nuclei(monkeypatch, target="http://approval-test.example/"):
    """Run a Standard scan in which Nuclei is not installed; everything else is stubbed and clean."""
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *a, **k: ([], {"status": "completed"}))
    for name in ("perform_whatweb_check", "perform_nikto_check", "perform_testssl_check"):
        monkeypatch.setattr(app, name, lambda *a, **k: ([], {"status": "completed"}))
    monkeypatch.setattr(app, "perform_nuclei_check", lambda *a, **k: ([], {"status": "unavailable", "reason": "Nuclei is not installed"}))
    monkeypatch.setattr(app.shutil, "which", lambda binary: None if binary == "nuclei" else "/usr/bin/" + str(binary))
    fake_page = _FakeHTTP()
    fake_page.geturl = lambda: target
    monkeypatch.setattr(app, "urlopen", lambda *a, **k: fake_page)
    monkeypatch.setattr(app, "discover_same_origin_pages", lambda url, body: {"status": "completed", "urls": [url, url + "about"]})
    with app.connect() as conn:
        scan_id = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                               (target, "standard", "running", app.now())).lastrowid
    app.perform_scan(scan_id, target, "standard")
    return scan_id


def _scan_row(scan_id):
    import json
    with app.connect() as conn:
        row = dict(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())
    return row, json.loads(row["tool_status"]), json.loads(row["summary"])


def test_missing_tool_creates_request_and_scan_finishes_with_gap(monkeypatch):
    scan_id = _scan_with_missing_nuclei(monkeypatch)
    row, tools, summary = _scan_row(scan_id)
    assert row["status"] == "completed_with_gaps"
    assert tools["Nuclei"]["status"] == "needs_tool_approval"
    assert "Triggered by" in tools["Nuclei"]["detail"]
    assert [g["tool"] for g in summary["assessment_gaps"]] == ["Nuclei"]
    requests = client.get(f"/api/tool-requests?scan_id={scan_id}").json()
    assert len(requests) == 1 and requests[0]["tool_id"] == "nuclei" and requests[0]["status"] == "pending"
    assert requests[0]["package"] == "nuclei" and requests[0]["scan_target"] == "http://approval-test.example/"
    assert client.get(f"/api/scans/{scan_id}").json()["tool_requests"][0]["id"] == requests[0]["id"]


def test_tool_request_is_unique_per_scan_and_allow_listed():
    with app.connect() as conn:
        scan_id = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                               ("http://unique.example/", "standard", "completed", app.now())).lastrowid
    first = app.create_tool_request(scan_id, "nuclei", "profile", "reason")
    second = app.create_tool_request(scan_id, "nuclei", "profile", "other reason")
    assert first["id"] == second["id"]
    import pytest
    with pytest.raises(ValueError):
        app.create_tool_request(scan_id, "rm-rf", "profile", "x")
    with pytest.raises(ValueError):
        app.create_tool_request(scan_id, "zaproxy", "profile", "x")  # ZAP needs a configured service, not just a package


def test_declined_install_is_reported_as_not_permitted(monkeypatch):
    scan_id = _scan_with_missing_nuclei(monkeypatch, "http://decline-test.example/")
    monkeypatch.setattr(app, "_spawn", lambda function, *args: function(*args))
    installs = []
    monkeypatch.setattr(app, "install_package", lambda tool_id: installs.append(tool_id) or (True, "x"))
    request = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    response = client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "decline"})
    assert response.status_code == 200 and response.json()["status"] == "declined"
    assert installs == []  # declining never installs anything
    row, tools, summary = _scan_row(scan_id)
    assert tools["Nuclei"]["status"] == "skipped_install_not_permitted"
    assert "not approved by the assessor" in tools["Nuclei"]["detail"]
    assert "Triggered by: the Standard profile" in tools["Nuclei"]["detail"]
    assert "not assessed" in tools["Nuclei"]["detail"]
    assert row["status"] == "completed_with_gaps"
    assert summary["assessment_gaps"][0]["status"] == "skipped_install_not_permitted"
    assert client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"}).status_code == 409


def test_approved_install_runs_the_stage_and_closes_the_gap(monkeypatch):
    scan_id = _scan_with_missing_nuclei(monkeypatch, "http://approve-test.example/")
    monkeypatch.setattr(app, "_spawn", lambda function, *args: function(*args))
    monkeypatch.setattr(app, "install_package", lambda tool_id: (True, "Nuclei was installed from the Kali repository."))
    seen = {}
    def fake_nuclei(target, timeout_seconds=60, targets=None, max_templates=30):
        seen.update(targets=targets, templates=max_templates)
        return [("Medium", "Exposed admin panel", target + "admin", "evidence", "fix", "High")], {"status": "completed", "finding_count": 1}
    monkeypatch.setattr(app, "perform_nuclei_check", fake_nuclei)
    request = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    before = len(client.get(f"/api/scans/{scan_id}").json()["findings"])
    response = client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"})
    assert response.status_code == 200
    row, tools, summary = _scan_row(scan_id)
    assert seen["targets"] == ["http://approve-test.example/", "http://approve-test.example/about"]  # reuses discovery
    assert seen["templates"] == 30
    assert tools["Nuclei"]["status"] == "completed"
    assert row["status"] == "completed"  # no gaps left
    assert summary["assessment_gaps"] == [] and summary["finding_count"] == before + 1
    assert summary["nuclei_check"]["status"] == "completed"
    stored = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    assert stored["status"] == "completed" and stored["decided_by"].startswith("local assessor")
    assert any(f["title"] == "Exposed admin panel" for f in client.get(f"/api/scans/{scan_id}").json()["findings"])


def test_failed_install_keeps_the_gap_and_can_be_retried(monkeypatch):
    scan_id = _scan_with_missing_nuclei(monkeypatch, "http://fail-test.example/")
    monkeypatch.setattr(app, "_spawn", lambda function, *args: function(*args))
    monkeypatch.setattr(app, "install_package", lambda tool_id: (False, "Installation failed: no network. You can also run: sudo apt install nuclei"))
    request = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"})
    row, tools, _ = _scan_row(scan_id)
    assert tools["Nuclei"]["status"] == "install_failed" and "sudo apt install nuclei" in tools["Nuclei"]["detail"]
    assert row["status"] == "completed_with_gaps"
    assert client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]["status"] == "failed"
    monkeypatch.setattr(app, "install_package", lambda tool_id: (True, "ok"))
    monkeypatch.setattr(app, "perform_nuclei_check", lambda *a, **k: ([], {"status": "completed", "finding_count": 0}))
    assert client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"}).status_code == 200
    assert _scan_row(scan_id)[0]["status"] == "completed"


def test_tool_decisions_are_local_only_and_validated(monkeypatch):
    scan_id = _scan_with_missing_nuclei(monkeypatch, "http://local-only.example/")
    request = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    assert client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "maybe"}).status_code == 422
    assert client.post("/api/tool-requests/999999/decision", json={"decision": "approve"}).status_code == 404
    remote = TestClient(app.app, client=("203.0.113.9", 50000))
    assert remote.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"}).status_code == 403
    assert client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]["status"] == "pending"


def test_install_package_uses_only_the_allow_listed_package(monkeypatch):
    calls = []
    present = {"installed": False}
    monkeypatch.setattr(app.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(app.shutil, "which", lambda b: ("/usr/bin/" + b) if (b != "nuclei" or present["installed"]) else None)
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        present["installed"] = True
        return SimpleNamespaceResult()
    class SimpleNamespaceResult: returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    ok, message = app.install_package("nuclei")
    assert ok and calls == [["/usr/bin/pkexec", "/usr/bin/apt-get", "install", "-y", "--no-install-recommends", "nuclei"]]
    import pytest
    with pytest.raises(KeyError):
        app.install_package("not-a-tool")


def test_dashboard_exposes_the_approval_page():
    page = client.get("/").text
    assert 'data-page="approvals"' in page and 'id="approvals"' in page
    assert "loadApprovals" in page and "decideTool" in page


# ---- planner and content discovery ----------------------------------------------------------------

def test_planner_applies_rules_by_profile_technology_and_parameters():
    import planner
    standard = planner.Facts(profile="standard")
    deep = planner.Facts(profile="deep")
    active = planner.Facts(profile="active", has_parameters=True, technologies={"wordpress"})
    assert [r.id for r in planner.RULES if planner.rule_applies(r, standard)] == []
    assert [r.id for r in planner.RULES if planner.rule_applies(r, deep)] == ["content_discovery"]
    assert {r.id for r in planner.RULES if planner.rule_applies(r, active)} == {"content_discovery", "wordpress", "sql_injection", "xss"}
    # Technology-specific rules need the technology; injection rules need parameters.
    assert "wordpress" not in {r.id for r in planner.RULES if planner.rule_applies(r, planner.Facts(profile="deep"))}
    assert "sql_injection" not in {r.id for r in planner.RULES if planner.rule_applies(r, planner.Facts(profile="active"))}


def test_planner_reports_unavailable_engines_as_coverage_notes_not_silence():
    import planner
    facts = planner.Facts(profile="deep", technologies={"wordpress"}, url_count=5)
    plan = planner.plan_coverage(facts, available_tools={"ffuf"})
    assert [p["tool"] for p in plan["planned"]] == ["ffuf"]
    assert [n["tool"] for n in plan["not_covered"]] == ["wpscan"]
    assert "not available in this version" in plan["not_covered"][0]["message"]
    assert "WordPress was detected" in plan["not_covered"][0]["message"]
    nothing_available = planner.plan_coverage(facts, available_tools=set())
    assert {n["tool"] for n in nothing_available["not_covered"]} == {"ffuf", "wpscan"}
    assert plan["facts"]["technologies"] == ["wordpress"]


def test_planner_detects_technologies_from_markup_headers_and_fingerprints():
    import planner
    assert planner.detect_technologies({}, '<link href="/wp-content/themes/x/style.css">') == {"wordpress"}
    assert planner.detect_technologies({"x-generator": "Drupal 10"}, "") == {"drupal"}
    assert planner.detect_technologies({}, "<meta name=\"generator\" content=\"Joomla! 4\">") == {"joomla"}
    assert planner.detect_technologies({}, "<html>plain</html>", ["WhatWeb technology detected: WordPress"]) == {"wordpress"}
    assert planner.detect_technologies({}, "<html>plain</html>") == set()
    assert planner.has_query_parameters(["http://a.example/", "http://a.example/p?id=1"]) is True
    assert planner.has_query_parameters(["http://a.example/", "http://a.example/p"]) is False


def test_ffuf_report_parser_ranks_findings_and_keeps_only_the_approved_origin():
    report = {"results": [
        {"url": "http://t.example/.git/HEAD", "status": 200, "length": 23},
        {"url": "http://t.example/backup", "status": 200, "length": 900},
        {"url": "http://t.example/about", "status": 200, "length": 500},
        {"url": "http://t.example/admin", "status": 403, "length": 10},
        {"url": "http://t.example/old", "status": 404, "length": 10},
        {"url": "http://evil.example/admin", "status": 200, "length": 10},
        {"url": "http://t.example:8080/other", "status": 200, "length": 10},
        {"url": "http://t.example/about", "status": 200, "length": 500},
        {"url": "http://t.example/x", "status": "bad"},
        "junk",
    ]}
    findings, urls = app.parse_ffuf_report(report, "http://t.example/")
    assert [f[0] for f in findings] == ["High", "Medium", "Info", "Info"]
    assert findings[0][1].startswith("Sensitive file or directory appears exposed: /.git/HEAD")
    assert findings[0][5] == "Medium" and "Verify manually" in findings[0][4]
    assert "Protected path exists: /admin (HTTP 403)" in findings[3][1]
    assert urls == ["http://t.example/.git/HEAD", "http://t.example/backup", "http://t.example/about"]
    redirects = {"results": [
        {"url": "http://t.example/admin", "status": 301, "length": 0, "redirectlocation": "http://t.example/admin/"},
        {"url": "http://t.example/docs", "status": 301, "length": 0, "redirectlocation": "/docs/"},
        {"url": "http://t.example/account", "status": 302, "length": 0, "redirectlocation": "/login"},
    ]}
    found, urls = app.parse_ffuf_report(redirects, "http://t.example/")
    assert [(f[0], f[1].split(":")[0]) for f in found] == [("Medium", "Potentially sensitive path is reachable"),
                                                         ("Info", "Hidden or unlinked content found"),
                                                         ("Info", "Path exists and redirects elsewhere")]
    assert urls == []  # directory redirects are not 200 pages, so they are not fed to later stages
    assert app.parse_ffuf_report({"results": "nope"}, "http://t.example/") == ([], [])
    assert app.parse_ffuf_report(None, "http://t.example/") == ([], [])


def test_ffuf_runs_with_bounded_arguments_and_reads_only_its_json_report(monkeypatch):
    import json
    seen = {}
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/ffuf")
    def fake_run(command, **kwargs):
        seen["command"] = command
        out = command[command.index("-o") + 1]
        with open(out, "w") as handle:
            json.dump({"results": [{"url": "http://t.example/admin", "status": 200, "length": 5}]}, handle)
        return SimpleNamespaceResult()
    class SimpleNamespaceResult: returncode = 0; stdout = "console text that must be ignored"; stderr = ""
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_ffuf_check("http://t.example/", timeout_seconds=60)
    command = seen["command"]
    assert command[command.index("-u") + 1] == "http://t.example/FUZZ"
    assert command[command.index("-rate") + 1] == "10" and command[command.index("-t") + 1] == "4"
    assert "-recursion" not in command and "-r" not in command  # no recursion, no redirect following
    assert command[command.index("-w") + 1].endswith("wordlists/common-paths.txt")
    assert status["status"] == "completed" and status["found_urls"] == ["http://t.example/admin"]
    assert findings and findings[0][1].startswith("Potentially sensitive path is reachable: /admin")


def test_ffuf_missing_or_failing_is_reported_truthfully(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda binary: None)
    assert app.perform_ffuf_check("http://t.example/") == ([], {"status": "unavailable", "reason": "ffuf is not installed"})
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/ffuf")
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("ffuf", 60)))
    assert app.perform_ffuf_check("http://t.example/")[1]["status"] == "timeout"
    class Done: returncode = 0; stdout = ""; stderr = ""
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: Done())
    status = app.perform_ffuf_check("http://t.example/")[1]
    assert status["status"] == "error" and "no findings were inferred" in status["reason"]


def test_builtin_wordlist_is_present_and_bounded():
    lines = [l for l in (app.ROOT / "wordlists" / "common-paths.txt").read_text().splitlines() if l and not l.startswith("#")]
    assert 100 <= len(lines) <= 400 and len(lines) == len(set(lines))
    assert ".git/HEAD" in lines and "admin" in lines and not any(" " in l or l.startswith("/") for l in lines)


def _deep_scan(monkeypatch, ffuf_result, target="http://deep-test.example/", body="<html></html>"):
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *a, **k: ([], {"status": "completed"}))
    for name in ("perform_whatweb_check", "perform_nikto_check", "perform_testssl_check", "perform_nuclei_check"):
        monkeypatch.setattr(app, name, lambda *a, **k: ([], {"status": "completed"}))
    seen = {}
    def fake_nuclei(target, timeout_seconds=60, targets=None, max_templates=30):
        seen["urls"] = targets
        return [], {"status": "completed"}
    monkeypatch.setattr(app, "perform_nuclei_check", fake_nuclei)
    monkeypatch.setattr(app, "perform_ffuf_check", lambda *a, **k: ffuf_result)
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/" + str(binary))
    page = _FakeHTTP()
    page.geturl = lambda: target
    page.read = lambda _n=-1: body.encode()
    monkeypatch.setattr(app, "urlopen", lambda *a, **k: page)
    monkeypatch.setattr(app, "discover_same_origin_pages", lambda url, html: {"status": "completed", "urls": [url]})
    with app.connect() as conn:
        scan_id = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)",
                               (target, "deep", "running", app.now())).lastrowid
    app.perform_scan(scan_id, target, "deep")
    return scan_id, seen


def test_deep_scan_runs_content_discovery_and_feeds_found_pages_to_later_stages(monkeypatch):
    import json
    finding = ("Medium", "Potentially sensitive path is reachable: /backup", "http://deep-test.example/backup", "e", "f", "Medium")
    scan_id, seen = _deep_scan(monkeypatch, ([finding], {"status": "completed", "finding_count": 1,
                                                         "found_urls": ["http://deep-test.example/backup"]}))
    row, tools, summary = _scan_row(scan_id)
    assert tools["Content discovery (ffuf)"]["status"] == "completed"
    assert seen["urls"] == ["http://deep-test.example/", "http://deep-test.example/backup"]
    assert "found_urls" not in summary["ffuf_check"]
    assert any(f["title"].startswith("Potentially sensitive path") for f in client.get(f"/api/scans/{scan_id}").json()["findings"])
    assert summary["coverage"]["planned"][0]["tool"] == "ffuf" and summary["coverage"]["not_covered"] == []


def test_standard_scan_skips_content_discovery_and_notes_uncovered_technology(monkeypatch):
    import json
    scan_id, _ = _deep_scan(monkeypatch, ([], {"status": "completed"}), "http://wp-test.example/",
                            '<link href="/wp-content/themes/a/style.css">')
    row, tools, summary = _scan_row(scan_id)
    assert summary["coverage"]["facts"]["technologies"] == ["wordpress"]
    assert [n["tool"] for n in summary["coverage"]["not_covered"]] == ["wpscan"]
    assert "not available in this version" in summary["coverage"]["not_covered"][0]["message"]
    assert row["status"] == "completed"  # a coverage note is information, not a failed stage


def test_missing_ffuf_asks_for_approval_then_runs_and_merges(monkeypatch):
    scan_id, _ = _deep_scan(monkeypatch, ([], {"status": "unavailable", "reason": "ffuf is not installed"}), "http://ffuf-missing.example/")
    monkeypatch.setattr(app.shutil, "which", lambda binary: None if binary == "ffuf" else "/usr/bin/" + str(binary))
    # The scan above ran with every binary present; re-create the missing-tool situation explicitly.
    tool_status = {}
    created = app.request_missing_tools(scan_id, "deep", tool_status, {"ffuf": {"status": "unavailable"}})
    assert len(created) == 1 and tool_status["Content discovery (ffuf)"]["status"] == "needs_tool_approval"
    request = client.get(f"/api/tool-requests?scan_id={scan_id}").json()[0]
    assert request["tool_id"] == "ffuf" and request["package"] == "ffuf"
    monkeypatch.setattr(app, "_spawn", lambda function, *args: function(*args))
    monkeypatch.setattr(app, "install_package", lambda tool_id: (True, "ffuf was installed from the Kali repository."))
    monkeypatch.setattr(app, "perform_ffuf_check", lambda target, timeout_seconds=60: (
        [("Info", "Hidden or unlinked content found: /docs", target + "docs", "e", "f", "Low")], {"status": "completed", "finding_count": 1}))
    client.post(f"/api/tool-requests/{request['id']}/decision", json={"decision": "approve"})
    _, tools, summary = _scan_row(scan_id)
    assert tools["Content discovery (ffuf)"]["status"] == "completed"
    assert summary["ffuf_check"]["status"] == "completed"


# ---- sqlmap and dalfox (Active profile) -------------------------------------------------------------

REAL_SQLMAP_LOG = """sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 2518=2518

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: id=1 UNION ALL SELECT CHAR(113,118,98,120,113)-- xpCw
---
back-end DBMS: SQLite
"""
REAL_DALFOX_LINES = (
    '{"type":"R","inject_type":"inHTML-URL","poc_type":"plain","method":"GET","data":"http://t.example/search?q=test%22%3E","param":"q","payload":"\\"><svg>","evidence":"1 line: reflected","cwe":"CWE-79","severity":"Medium"}\n'
    '{"type":"V","inject_type":"inHTML-URL","poc_type":"plain","method":"GET","data":"http://t.example/search?q=test%22%3E%3CSvG","param":"q","payload":"\\"><SvG/onload=alert(1)>","evidence":"1 line: dy>Results for: test","cwe":"CWE-79","severity":"High"}\n'
)


def test_select_test_urls_keeps_only_safe_same_origin_parameterised_shapes():
    urls = ["http://t.example/", "http://t.example/item?id=1", "http://t.example/item?id=2", "http://t.example/s?q=a&p=1",
            "http://t.example/s?p=9&q=b", "http://evil.example/x?a=1", "http://t.example:8080/x?a=1", "https://t.example/x?a=1",
            "http://t.example/bad path?a=1", "-oBad?x=1", "http://t.example/ctl\x01?a=1", "http://t.example/a?x=1",
            "http://t.example/b?x=1", "http://t.example/c?x=1"]
    chosen = app.select_test_urls("http://t.example/", urls)
    assert chosen == ["http://t.example/item?id=1", "http://t.example/s?q=a&p=1", "http://t.example/a?x=1", "http://t.example/b?x=1"]
    assert len(app.select_test_urls("http://t.example/", urls, limit=2)) == 2
    assert app.select_test_urls("http://t.example/", ["http://t.example/"]) == []


def test_query_parameter_names_are_sanitised():
    assert app.query_parameter_names("http://a/p?id=1&id=2&-x=1&q=2&ok[]=3&bad name=4&=5") == ["id", "q", "ok[]"]


def test_sqlmap_log_parser_reads_the_structured_block():
    findings = app.parse_sqlmap_log(REAL_SQLMAP_LOG, "http://t.example/item?id=1")
    assert len(findings) == 1
    severity, title, url, evidence, remediation, confidence = findings[0]
    assert severity == "High" and confidence == "High" and "parameter 'id' (GET)" in title
    assert "boolean-based blind" in evidence and "UNION query" in evidence and "SQLite" in evidence
    assert "parameterized queries" in remediation
    assert app.parse_sqlmap_log("Parameter: id (GET)\n---\n", "http://t/") == []
    assert app.parse_sqlmap_log("nothing here", "http://t/") == []


def test_sqlmap_skips_without_parameters_even_if_not_installed_and_asks_when_needed(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda binary: None)
    assert app.perform_sqlmap_check("http://t.example/", ["http://t.example/"])[1]["status"] == "skipped"
    assert app.perform_sqlmap_check("http://t.example/", ["http://t.example/p?id=1"])[1] == {"status": "unavailable", "reason": "sqlmap is not installed"}


def test_sqlmap_runs_detection_only_with_bounded_arguments(monkeypatch):
    seen = []
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/sqlmap")
    class Done: returncode = 0; stdout = ""; stderr = ""
    def fake_run(command, **kwargs):
        seen.append((command, kwargs))
        out = [a for a in command if a.startswith("--output-dir=")][0].split("=", 1)[1]
        (app.Path(out) / "t.example").mkdir(parents=True)
        (app.Path(out) / "t.example" / "log").write_text(REAL_SQLMAP_LOG)
        return Done()
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_sqlmap_check("http://t.example/", ["http://t.example/item?id=1"])
    command = seen[0][0]
    assert command[:3] == ["/usr/bin/sqlmap", "-u", "http://t.example/item?id=1"]
    for required in ("--batch", "--level=1", "--risk=1", "--technique=BEU", "--threads=1", "--ignore-redirects", "--flush-session"):
        assert required in command
    forbidden = ("--dump", "--dump-all", "--os-shell", "--os-cmd", "--sql-shell", "--passwords", "--file-read", "--file-write", "--forms", "--crawl", "--level=5", "--risk=3")
    assert not any(a.startswith(f) for a in command for f in forbidden)
    assert "S" not in command[command.index("--technique=BEU")].split("=")[1]  # no stacked queries
    assert status["status"] == "completed" and status["urls_tested"] == 1 and len(findings) == 1


def test_sqlmap_timeout_keeps_partial_findings_and_is_not_reported_clean(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/sqlmap")
    def fake_run(command, **kwargs):
        out = [a for a in command if a.startswith("--output-dir=")][0].split("=", 1)[1]
        (app.Path(out) / "t.example").mkdir(parents=True)
        (app.Path(out) / "t.example" / "log").write_text(REAL_SQLMAP_LOG)
        raise subprocess.TimeoutExpired("sqlmap", 30)
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_sqlmap_check("http://t.example/", ["http://t.example/item?id=1"])
    assert len(findings) == 1 and status["status"] == "partial_timeout"
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("sqlmap", 30)))
    assert app.perform_sqlmap_check("http://t.example/", ["http://t.example/item?id=1"])[1]["status"] == "timeout"


def test_dalfox_parser_maps_verified_and_reflected_and_stays_in_origin():
    findings = app.parse_dalfox_lines(REAL_DALFOX_LINES + '{"type":"V","param":"x","data":"http://evil.example/?x=1","payload":"p"}\nnot json\n[1]\n', "http://t.example/")
    assert [f[0] for f in findings] == ["Medium", "High"]
    assert findings[1][1] == "Cross-site scripting: parameter 'q' executes a verified payload" and findings[1][5] == "High"
    assert findings[0][1].startswith("Input reflected without encoding") and findings[0][5] == "Medium"
    assert all("evil.example" not in f[2] for f in findings)
    assert app.parse_dalfox_lines("", "http://t.example/") == []


def test_dalfox_runs_without_browser_mining_or_callbacks_and_with_known_parameters(monkeypatch):
    seen = []
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/dalfox")
    class Done: returncode = 0; stdout = ""; stderr = ""
    def fake_run(command, **kwargs):
        seen.append(command)
        app.Path(command[command.index("--output") + 1]).write_text(REAL_DALFOX_LINES)
        return Done()
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    findings, status = app.perform_dalfox_check("http://t.example/", ["http://t.example/search?q=test&page=2"])
    command = seen[0]
    assert command[:3] == ["/usr/bin/dalfox", "url", "http://t.example/search?q=test&page=2"]
    for required in ("--skip-headless", "--skip-mining-all", "--skip-bav", "--skip-discovery", "--no-spinner"):
        assert required in command
    assert [command[i + 1] for i, a in enumerate(command) if a == "-p"] == ["q", "page"]
    assert "-b" not in command and "--blind" not in command and "--remote-payloads" not in command
    assert command[command.index("--format") + 1] == "jsonl"
    assert status["status"] == "completed" and len(findings) == 2


def test_dalfox_timeout_is_an_incomplete_test(monkeypatch):
    import subprocess
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/dalfox")
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("dalfox", 60)))
    findings, status = app.perform_dalfox_check("http://t.example/", ["http://t.example/s?q=1"])
    assert findings == [] and status["status"] == "timeout" and "not fully tested" in status["reason"]
    monkeypatch.setattr(app.shutil, "which", lambda binary: None)
    assert app.perform_dalfox_check("http://t.example/", ["http://t.example/s?q=1"])[1]["status"] == "unavailable"
    assert app.perform_dalfox_check("http://t.example/", ["http://t.example/"])[1]["status"] == "skipped"


def _active_scan(monkeypatch, urls, profile="active", sqlmap_result=None, dalfox_result=None):
    monkeypatch.setattr(app, "perform_zap_passive_check", lambda *a, **k: ([], {"status": "completed"}))
    for name in ("perform_whatweb_check", "perform_nikto_check", "perform_testssl_check", "perform_nuclei_check", "perform_wapiti_check"):
        monkeypatch.setattr(app, name, lambda *a, **k: ([], {"status": "completed"}))
    monkeypatch.setattr(app, "perform_ffuf_check", lambda *a, **k: ([], {"status": "completed"}))
    calls = []
    def fake_sqlmap(target, test_urls, *a, **k):
        calls.append(("sqlmap", list(test_urls))); return sqlmap_result or ([], {"status": "completed", "finding_count": 0})
    def fake_dalfox(target, test_urls, *a, **k):
        calls.append(("dalfox", list(test_urls))); return dalfox_result or ([], {"status": "completed", "finding_count": 0})
    monkeypatch.setattr(app, "perform_sqlmap_check", fake_sqlmap)
    monkeypatch.setattr(app, "perform_dalfox_check", fake_dalfox)
    monkeypatch.setattr(app.shutil, "which", lambda binary: "/usr/bin/" + str(binary))
    target = "http://inj-" + profile + ".example/"
    page = _FakeHTTP(); page.geturl = lambda: target
    monkeypatch.setattr(app, "urlopen", lambda *a, **k: page)
    monkeypatch.setattr(app, "discover_same_origin_pages", lambda url, html: {"status": "completed", "urls": [url] + urls})
    with app.connect() as conn:
        scan_id = conn.execute("INSERT INTO scans(target,profile,status,created_at) VALUES(?,?,?,?)", (target, profile, "running", app.now())).lastrowid
    app.perform_scan(scan_id, target, profile)
    return scan_id, calls


def test_active_scan_runs_sqlmap_and_dalfox_and_merges_their_findings(monkeypatch):
    sql = ([("High", "SQL injection: parameter 'id' (GET) appears injectable", "http://inj-active.example/item?id=1", "e", "f", "High")], {"status": "completed", "finding_count": 1})
    xss = ([("High", "Cross-site scripting: parameter 'q' executes a verified payload", "http://inj-active.example/s?q=1", "e", "f", "High")], {"status": "completed", "finding_count": 1})
    scan_id, calls = _active_scan(monkeypatch, ["http://inj-active.example/item?id=1", "http://inj-active.example/s?q=1"], sqlmap_result=sql, dalfox_result=xss)
    row, tools, summary = _scan_row(scan_id)
    assert [c[0] for c in calls] == ["sqlmap", "dalfox"]
    assert tools["SQL injection (sqlmap)"]["status"] == "completed" and tools["XSS (dalfox)"]["status"] == "completed"
    assert summary["sqlmap_check"]["status"] == "completed" and summary["dalfox_check"]["status"] == "completed"
    titles = [f["title"] for f in client.get(f"/api/scans/{scan_id}").json()["findings"]]
    assert any(t.startswith("SQL injection") for t in titles) and any(t.startswith("Cross-site scripting") for t in titles)
    assert {p["tool"] for p in summary["coverage"]["planned"]} >= {"ffuf", "sqlmap", "dalfox"}
    assert summary["coverage"]["not_covered"] == []


def test_injection_tools_never_run_outside_the_active_profile(monkeypatch):
    scan_id, calls = _active_scan(monkeypatch, ["http://inj-deep.example/item?id=1"], profile="deep")
    row, tools, summary = _scan_row(scan_id)
    assert calls == []
    assert tools["SQL injection (sqlmap)"]["status"] == "skipped" and tools["XSS (dalfox)"]["status"] == "skipped"
    assert row["status"] == "completed"
    stage_findings, status, state = app.run_engine_stage("sqlmap", "http://t.example/", "standard", ["http://t.example/p?id=1"])
    assert status["status"] == "skipped" and stage_findings == []
    assert app.run_engine_stage("dalfox", "http://t.example/", "deep", ["http://t.example/p?id=1"])[1]["status"] == "skipped"


def test_missing_injection_tool_asks_for_approval_and_a_timeout_is_a_gap(monkeypatch):
    monkeypatch.setattr(app.shutil, "which", lambda binary: None)
    scan_id, _ = _active_scan(monkeypatch, ["http://inj-active.example/item?id=1"],
                              sqlmap_result=([], {"status": "unavailable", "reason": "sqlmap is not installed"}),
                              dalfox_result=([], {"status": "timeout", "reason": "time limit reached"}))
    monkeypatch.setattr(app.shutil, "which", lambda binary: None)  # _active_scan re-patched which to present
    row, tools, summary = _scan_row(scan_id)
    assert row["status"] == "completed_with_gaps"
    assert tools["XSS (dalfox)"]["status"] == "timeout"
    assert {g["tool"] for g in summary["assessment_gaps"]} >= {"XSS (dalfox)"}
    created = app.request_missing_tools(scan_id, "active", {}, {"sqlmap": {"status": "unavailable"}, "dalfox": {"status": "unavailable"}})
    assert len(created) == 2
    requests = {r["tool_id"]: r for r in client.get(f"/api/tool-requests?scan_id={scan_id}").json()}
    assert requests["sqlmap"]["package"] == "sqlmap" and requests["dalfox"]["package"] == "dalfox"
