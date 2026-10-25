from datetime import datetime, timedelta, timezone
import os
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

# Never let automated tests read or mutate the scanner's development/deployment database.
_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="dkcissp-test-")
os.environ["DKCISSP_DB"] = str(Path(_TEST_DB_DIR.name) / "test.sqlite3")

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
        assert "-no-stdin" in command
        assert kwargs["stdin"] is app.subprocess.DEVNULL
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
    categories = ["cve", "misconfig", "exposure", "ssl", "tech"]
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
                "HTML5": {"string": ["HTML5"]},
                "Script": {"string": ["script"]},
                "UncommonHeaders": {"string": ["Feature-Policy"]},
                "X-Frame-Options": {"string": ["SAMEORIGIN"]},
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
    assert not any(title.endswith(("HTML5", "Script", "UncommonHeaders", "X-Frame-Options"))
                   for _severity, title, *_rest in findings)


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



def test_tool_status_reports_allowlisted_integrations():
    response = client.get("/api/tools")
    assert response.status_code == 200
    payload = response.json()
    assert {tool["id"] for tool in payload["tools"]} == {
        "curl", "zaproxy", "whatweb", "testssl", "nuclei", "nikto", "wapiti"
    }
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



def test_one_off_assessment_needs_no_inventory_but_respects_reviewed_scope(monkeypatch):
    from uuid import uuid4
    target = f"https://simple-flow-{uuid4().hex}.example"
    started = []
    monkeypatch.setattr(app, "start_scan", lambda target, profile: started.append((target, profile)) or 12345)
    allowed = client.post("/api/scans", json={"target": target, "profile": "deep", "authorized": True})
    assert allowed.status_code == 200 and allowed.json()["id"] == 12345
    assert allowed.json()["status"] == "running"
    assert allowed.json()["profile"] == "deep"
    assert started == [(target, "deep")]
    unregistered_schedule = client.post("/api/schedules", json={
        "name": "blocked", "target": target, "profile": "quick", "frequency": "daily", "authorized": True,
    })
    assert unregistered_schedule.status_code == 403
    reviewed_target = f"https://needs-review-{uuid4().hex}.example"
    asset = client.post("/api/assets", json={"target": reviewed_target, "authorized": True}).json()
    needs_review = client.post("/api/scans", json={"target": reviewed_target, "authorized": True})
    assert needs_review.status_code == 403
    client.patch(f"/api/assets/{asset['id']}/scope", json={"scope_status": "out_of_scope", "authorized": True})
    out_of_scope = client.post("/api/scans", json={"target": reviewed_target, "authorized": True})
    assert out_of_scope.status_code == 403


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


def test_is_html_document_only_accepts_html_document_media_types():
    assert app.is_html_document("text/html; charset=utf-8") is True
    assert app.is_html_document("application/xhtml+xml") is True
    assert app.is_html_document("text/css") is False
    assert app.is_html_document("application/javascript") is False
    assert app.is_html_document("image/x-icon") is False
    assert app.is_html_document("") is False


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


def test_zap_passive_handles_large_valid_access_url_response(monkeypatch):
    import json
    from urllib.parse import urlparse

    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "ready", "endpoint": "http://127.0.0.1:8090"})
    monkeypatch.setattr(app, "zap_api_settings", lambda: ("http://127.0.0.1:8090", "test-key"))

    class FakeResponse:
        def __init__(self, body):
            self.body = body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size):
            return self.body[:size]

    def fake_urlopen(request, timeout=4):
        path = urlparse(request.full_url).path
        if path.endswith("/accessUrl/"):
            # Real ZAP accessUrl wraps the fetched body in JSON; large JS bundles
            # can make the API response exceed the previous 1 MB read cap.
            body = json.dumps({"accessUrl": [{"responseBody": "x" * 1_100_000}]}).encode()
            return FakeResponse(body)
        if path.endswith("/recordsToScan/"):
            return FakeResponse(b'{"recordsToScan":"0"}')
        if path.endswith("/alerts/"):
            return FakeResponse(b'{"alerts":[]}')
        raise AssertionError(request.full_url)

    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    findings, status = app.perform_zap_passive_check(
        "http://app.example.test/",
        targets=["http://app.example.test/", "http://app.example.test/vendor.js"],
    )
    assert findings == []
    assert status["status"] == "completed"
    assert status["urls_scanned"] == 2


def test_zap_passive_rejects_oversized_api_response(monkeypatch):
    import json
    from urllib.parse import urlparse

    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "ready", "endpoint": "http://127.0.0.1:8090"})
    monkeypatch.setattr(app, "zap_api_settings", lambda: ("http://127.0.0.1:8090", "test-key"))

    class FakeResponse:
        def __init__(self, body):
            self.body = body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, size):
            return self.body[:size]

    def fake_urlopen(request, timeout=4):
        path = urlparse(request.full_url).path
        if path.endswith("/accessUrl/"):
            body = json.dumps({"accessUrl": [{"responseBody": "x" * 5_100_000}]}).encode()
            return FakeResponse(body)
        raise AssertionError(request.full_url)

    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    findings, status = app.perform_zap_passive_check(
        "http://app.example.test/",
        targets=["http://app.example.test/"],
    )
    assert findings == []
    assert status["status"] == "error"
    assert "5 MB safety limit" in status["errors"][0]




def test_zap_passive_groups_duplicate_signals_and_preserves_affected_urls(monkeypatch):
    import json
    from urllib.parse import urlparse

    monkeypatch.setattr(app, "diagnose_zap_api", lambda: {"status": "ready", "endpoint": "http://127.0.0.1:8090"})
    monkeypatch.setattr(app, "zap_api_settings", lambda: ("http://127.0.0.1:8090", "test-key"))

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, _size):
            return json.dumps(self.payload).encode()

    def fake_urlopen(request, timeout=4):
        path = urlparse(request.full_url).path
        if path.endswith("/accessUrl/"):
            return FakeResponse({"accessUrl": [{"Result": "OK"}]})
        if path.endswith("/recordsToScan/"):
            return FakeResponse({"recordsToScan": "0"})
        if path.endswith("/alerts/"):
            return FakeResponse({"alerts": [
                {"risk": "Medium", "alert": "Cross-Domain Misconfiguration",
                 "url": "http://app.example.test/runtime.js", "description": "CORS wildcard",
                 "evidence": "Access-Control-Allow-Origin: *", "solution": "Review CORS", "confidence": "Medium"},
                {"risk": "Medium", "alert": "Cross-Domain Misconfiguration",
                 "url": "http://app.example.test/vendor.js", "description": "CORS wildcard",
                 "evidence": "Access-Control-Allow-Origin: *", "solution": "Review CORS", "confidence": "Medium"},
                {"risk": "Low", "alert": "Timestamp Disclosure - Unix",
                 "url": "http://app.example.test/main.js", "description": "Timestamp disclosed",
                 "evidence": "1734944650", "solution": "Review timestamp", "confidence": "Low"},
            ]})
        raise AssertionError(request.full_url)

    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    findings, status = app.perform_zap_passive_check(
        "http://app.example.test/",
        targets=["http://app.example.test/", "http://app.example.test/runtime.js", "http://app.example.test/vendor.js"],
    )
    assert status["status"] == "completed"
    assert status["alert_count"] == 3
    assert status["finding_count"] == 2
    cors = next(f for f in findings if "Cross-Domain Misconfiguration" in f[1])
    assert "runtime.js" in cors[3]
    assert "vendor.js" in cors[3]
    assert "Affected URLs (2)" in cors[3]
    assert any("Timestamp Disclosure" in f[1] for f in findings)


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
