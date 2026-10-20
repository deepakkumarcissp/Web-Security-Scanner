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
