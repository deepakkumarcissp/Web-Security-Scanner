import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "evaluate_scan_baseline.py"
SPEC = importlib.util.spec_from_file_location("evaluate_scan_baseline", SCRIPT)
evaluator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(evaluator)
BASELINE = __import__("json").loads((ROOT / "tests/fixtures/juice_shop_expected_signals.json").read_text())


def finding(title, url="http://127.0.0.1:1003", finding_id=None, severity="Info"):
    return {"id": finding_id, "title": title, "affected_url": url, "severity": severity}


def test_expected_signals_all_match_and_unmatched_findings_are_triage_only():
    report = {"scan_status": "completed", "profile": "standard", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption", finding_id=1, severity="High"),
        finding("Content-Security-Policy header missing", finding_id=2),
        finding("Referrer-Policy header missing", finding_id=3),
        finding("Permissions-Policy header missing", finding_id=4),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection", finding_id=5),
        finding("WhatWeb technology detected: JQuery", finding_id=6),
    ]}
    result = evaluator.evaluate_report(report, BASELINE)
    assert result["result"] == "PASS"
    assert result["expected_signal_coverage_percent"] == 100.0
    assert result["false_positive_status"] == "NOT_ASSESSED"
    assert [f["id"] for f in result["unmatched_findings_requiring_triage"]] == [6]


def test_missing_expected_signal_fails_regression_baseline():
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}, "findings": [
        finding("Target uses HTTP without transport encryption"),
        finding("Content-Security-Policy header missing"),
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


def test_empty_baseline_fails_instead_of_claiming_zero_percent_coverage():
    result = evaluator.evaluate_report({"findings": [], "scan_status": "completed", "tool_status": {"Nuclei": {"status": "completed"}}}, {"expected_signals": []})
    assert result["result"] == "FAIL"
    assert result["expected_signal_coverage_percent"] is None


def test_tool_timeout_fails_overall_evaluation_even_when_expected_signals_match():
    report = {"scan_status": "completed", "tool_status": {"Nuclei": {"status": "timeout"}}, "findings": [
        finding("Target uses HTTP without transport encryption"),
        finding("Content-Security-Policy header missing"),
        finding("Referrer-Policy header missing"),
        finding("Permissions-Policy header missing"),
        finding("Nuclei: Deprecated Feature-Policy Header - Detection"),
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
