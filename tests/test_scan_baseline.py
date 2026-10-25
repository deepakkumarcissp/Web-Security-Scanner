import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_scan_baseline.py"
SPEC = importlib.util.spec_from_file_location("evaluate_scan_baseline", SCRIPT)
evaluator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(evaluator)
BASELINE = __import__("json").loads((ROOT / "tests/fixtures/juice_shop_expected_signals.json").read_text())


def finding(title, url="http://127.0.0.1:1003", finding_id=None, severity="Info", confidence="High"):
    return {"id": finding_id, "title": title, "affected_url": url, "severity": severity, "confidence": confidence}


def test_expected_signals_all_match_and_unmatched_findings_are_triage_only():
    report = {"scan_status": "completed", "profile": "standard", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption", finding_id=1, severity="High"),
        finding("Content-Security-Policy header missing", finding_id=2, severity="Medium"),
        finding("Referrer-Policy header missing", finding_id=3, severity="Low"),
        finding("Permissions-Policy header missing", finding_id=4, severity="Info"),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection", finding_id=5, severity="Info", confidence="Medium"),
        finding("WhatWeb technology detected: JQuery", finding_id=6),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "PASS"
    assert result["expected_signal_coverage_percent"] == 100.0
    assert result["false_positive_status"] == "NOT_ASSESSED"
    assert [f["id"] for f in result["unmatched_findings_requiring_triage"]] == [6]


def test_missing_expected_signal_fails_regression_baseline():
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption", severity="High"),
        finding("Content-Security-Policy header missing", severity="Medium"),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "FAIL"
    assert result["expected_signal_coverage_percent"] == 40.0
    assert "missing-referrer-policy" in result["missing_expected_signals"]


def test_duplicate_same_title_and_url_is_reported_but_not_misclassified():
    title = "Content-Security-Policy header missing"
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [finding(title, finding_id=11), finding("  content-security-policy HEADER missing  ", finding_id=12)]}
    result = evaluator.evaluate_report(report, {"expected_signals": [{"id": "csp", "title_contains": title}]})
    assert result["duplicate_finding_count"] == 1
    assert len(result["duplicate_groups"]) == 1
    assert result["false_positive_status"] == "NOT_ASSESSED"


def test_expected_signal_must_match_the_configured_url_scope():
    baseline = {"expected_signals": [{
        "id": "csp-root",
        "title_contains": "Content-Security-Policy header missing",
        "affected_url_contains": "127.0.0.1:1003",
    }]}
    report = {
        "scan_status": "completed",
        "tool_status": {"Nuclei": {"status": "completed"}},
        "findings": [finding("Content-Security-Policy header missing", url="http://127.0.0.1:9999")],
    }
    result = evaluator.evaluate_report(report, baseline)
    assert result["result"] == "FAIL"
    assert result["missing_expected_signals"] == ["csp-root"]
    assert result["unmatched_findings_requiring_triage"][0]["affected_url"] == "http://127.0.0.1:9999"


def test_expected_signal_can_also_require_a_severity_match():
    baseline = {"expected_signals": [{
        "id": "csp-medium",
        "title_contains": "Content-Security-Policy header missing",
        "severity": "Medium",
    }]}
    report = {
        "scan_status": "completed",
        "tool_status": {"Nuclei": {"status": "completed"}},
        "findings": [finding("Content-Security-Policy header missing", severity="Info")],
    }
    result = evaluator.evaluate_report(report, baseline)
    assert result["result"] == "FAIL"
    assert result["missing_expected_signals"] == ["csp-medium"]




def test_expected_signal_must_match_configured_confidence():
    baseline = {"expected_signals": [{
        "id": "csp-high-confidence",
        "title_contains": "Content-Security-Policy header missing",
        "severity": "Medium",
        "confidence": "High",
    }]}
    report = {
        "scan_status": "completed",
        "tool_status": {"Nuclei": {"status": "completed"}},
        "findings": [finding(
            "Content-Security-Policy header missing",
            severity="Medium",
            confidence="Low",
        )],
    }
    result = evaluator.evaluate_report(report, baseline)
    assert result["result"] == "FAIL"
    assert result["missing_expected_signals"] == ["csp-high-confidence"]
    assert result["expected_signal_results"][0]["match_constraints"]["confidence"] == "High"


def test_empty_baseline_fails_instead_of_claiming_zero_percent_coverage():
    result = evaluator.evaluate_report({"findings": [], "scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}}, {"expected_signals": []})
    assert result["result"] == "FAIL"
    assert result["expected_signal_coverage_percent"] is None


def test_tool_timeout_fails_overall_evaluation_even_when_expected_signals_match():
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "timeout"}}, "findings": [
        finding("Target uses HTTP without transport encryption", severity="High"),
        finding("Content-Security-Policy header missing", severity="Medium"),
        finding("Referrer-Policy header missing", severity="Low"),
        finding("Permissions-Policy header missing", severity="Info"),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection", severity="Info", confidence="Medium"),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["expected_signal_coverage_percent"] == 100.0
    assert result["result"] == "FAIL"
    assert result["failed_required_tools"] == ["Nuclei"]


def test_missing_tool_status_fails_overall_evaluation():
    report = {"scan_status": "completed", "findings": [
        finding("Target uses HTTP without transport encryption"),
        finding("Content-Security-Policy header missing"),
        finding("Referrer-Policy header missing"),
        finding("Permissions-Policy header missing"),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "FAIL"
    assert result["required_tool_results"] == [{"tool": "Nuclei", "status": "missing", "result": "FAIL"}]


def test_severity_and_confidence_drift_each_break_expected_signal_match():
    for field, value in (("severity", "Critical"), ("confidence", "Low")):
        report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
            finding("Target uses HTTP without transport encryption", severity="High"),
            finding("Content-Security-Policy header missing", severity="Medium"),
            finding("Referrer-Policy header missing", severity="Low"),
            finding("Permissions-Policy header missing", severity="Info"),
            finding("Nuclei: Deprecated Feature-Policy Header - Detection", severity="Info", confidence="Medium"),
        ]}
        report["findings"][0][field] = value
        result = evaluator.evaluate_report(report, BASELINE)
        assert result["result"] == "FAIL"
        assert "transport-http" in result["missing_expected_signals"]


def test_incomplete_scan_fails_even_when_expected_signals_match():
    report = {"scan_status": "running", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption", severity="High"),
        finding("Content-Security-Policy header missing", severity="Medium"),
        finding("Referrer-Policy header missing", severity="Low"),
        finding("Permissions-Policy header missing", severity="Info"),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection", severity="Info", confidence="Medium"),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "FAIL"
    assert result["scan_completed"] is False


def test_duplicate_group_and_unmatched_finding_are_triage_only():
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption", finding_id=1, severity="High"),
        finding("Target uses HTTP without transport encryption", finding_id=2, severity="High"),
        finding("Content-Security-Policy header missing", severity="Medium"),
        finding("Referrer-Policy header missing", severity="Low"),
        finding("Permissions-Policy header missing", severity="Info"),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection", severity="Info", confidence="Medium"),
        finding("Synthetic unmatched finding", finding_id=100, severity="Low"),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "PASS"
    assert result["duplicate_finding_count"] == 1
    assert result["duplicate_groups"][0]["finding_ids"] == [1, 2]
    assert any(item["id"] == 100 for item in result["unmatched_findings_requiring_triage"])
    assert result["false_positive_status"] == "NOT_ASSESSED"


def test_empty_expected_signal_list_fails_without_claiming_coverage():
    result = evaluator.evaluate_report(
        {"scan_status": "completed", "tool_status": {}, "findings": []},
        {"expected_signals": [], "required_tools": []},
    )
    assert result["result"] == "FAIL"
    assert result["expected_signal_checks"] == 0
    assert result["expected_signal_coverage_percent"] is None


def test_controlled_http_fixture_baseline_reports_header_and_transport_signals():
    controlled = __import__("json").loads(
        (ROOT / "tests/fixtures/controlled_http_expected_signals.json").read_text()
    )
    report = {
        "scan_status": "completed",
        "profile": "quick",
        "tool_status": {"Built-in HTTP & headers": {"status": "completed"}},
        "findings": [
            finding("Target uses HTTP without transport encryption", "http://127.0.0.1:34567/", 1, "High", "High"),
            finding("Content-Security-Policy header missing", "http://127.0.0.1:34567/missing-headers", 2, "Medium", "High"),
            finding("Referrer-Policy header missing", "http://127.0.0.1:34567/missing-headers", 3, "Low", "High"),
            finding("X-Content-Type-Options missing or weak", "http://127.0.0.1:34567/missing-headers", 4, "Low", "High"),
            finding("Permissions-Policy header missing", "http://127.0.0.1:34567/missing-headers", 5, "Info", "High"),
            finding("Wildcard CORS origin configured", "http://127.0.0.1:34567/cors-wildcard", 6, "Info", "Medium"),
            finding("Potentially exposed backup or configuration artifact", "http://127.0.0.1:34567/backup.zip", 7, "Low", "Low"),
            finding("Unmatched observation retained for review", "http://127.0.0.1:34567/", 8, "Info", "Medium"),
        ],
    }
    result = evaluator.evaluate_report(report, controlled)
    assert result["result"] == "PASS"
    assert result["expected_signals_matched"] == 7
    assert result["expected_signal_coverage_percent"] == 100.0
    assert result["false_positive_status"] == "NOT_ASSESSED"
    assert [item["id"] for item in result["unmatched_findings_requiring_triage"]] == [8]
