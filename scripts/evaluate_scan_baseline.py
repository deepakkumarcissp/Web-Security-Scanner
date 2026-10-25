#!/usr/bin/env python3
"""Evaluate a scanner JSON report against explicit expected-signal checks.

This evaluator measures regression signals and report hygiene. It does not determine
whether unmatched findings are false positives, and it does not claim overall detection
coverage for vulnerabilities outside the declared baseline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def normalize(value: Any) -> str:
    """Normalize a string for stable title/URL comparisons."""
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def evaluate_report(report: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    checks = baseline.get("expected_signals", [])
    if not isinstance(checks, list):
        checks = []
    tool_status = report.get("tool_status", {})
    if not isinstance(tool_status, dict):
        tool_status = {}
    required_tools = baseline.get("required_tools", ["Nuclei"])
    if not isinstance(required_tools, list):
        required_tools = ["Nuclei"]
    tool_results = []
    for tool_name in required_tools:
        entry = tool_status.get(str(tool_name), {})
        status = entry.get("status", "missing") if isinstance(entry, dict) else "invalid_status"
        tool_results.append({"tool": str(tool_name), "status": status,
                             "result": "PASS" if status == "completed" else "FAIL"})

    expected_results = []
    matched_indexes: set[int] = set()
    for check in checks:
        check_id = str(check.get("id", "unnamed-check"))
        needle = normalize(check.get("title_contains", ""))
        url_needle = normalize(check.get("affected_url_contains", ""))
        expected_severity = normalize(check.get("severity", ""))
        expected_confidence = normalize(check.get("confidence", ""))
        matching = [
            i for i, finding in enumerate(findings)
            if isinstance(finding, dict)
            and needle
            and needle in normalize(finding.get("title"))
            and (not url_needle or url_needle in normalize(finding.get("affected_url") or finding.get("target")))
            and (not expected_severity or expected_severity == normalize(finding.get("severity")))
            and (not expected_confidence or expected_confidence == normalize(finding.get("confidence")))
        ]
        matched_indexes.update(matching)
        expected_results.append({
            "id": check_id,
            "description": check.get("description", ""),
            "status": "PASS" if matching else "MISS",
            "matching_finding_count": len(matching),
            "finding_titles": [findings[i].get("title", "") for i in matching],
            "match_constraints": {
                "title_contains": check.get("title_contains", ""),
                "affected_url_contains": check.get("affected_url_contains"),
                "severity": check.get("severity"),
                "confidence": check.get("confidence"),
            },
        })

    duplicate_groups: dict[tuple[str, str], list[int]] = {}
    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        key = (normalize(finding.get("title")), normalize(finding.get("affected_url") or finding.get("target")))
        if key[0]:
            duplicate_groups.setdefault(key, []).append(i)
    duplicates = []
    for (title, url), indexes in duplicate_groups.items():
        if len(indexes) > 1:
            duplicates.append({
                "title": findings[indexes[0]].get("title", title),
                "affected_url": findings[indexes[0]].get("affected_url") or findings[indexes[0]].get("target", url),
                "count": len(indexes),
                "finding_ids": [findings[i].get("id") for i in indexes],
            })

    unmatched = [
        {"id": f.get("id"), "title": f.get("title", ""), "severity": f.get("severity", "Unknown"),
         "affected_url": f.get("affected_url") or f.get("target", "")}
        for i, f in enumerate(findings)
        if isinstance(f, dict) and i not in matched_indexes
    ]
    passed_checks = sum(item["status"] == "PASS" for item in expected_results)
    missing = [item["id"] for item in expected_results if item["status"] == "MISS"]
    # Duplicate groups and unmatched findings are reported for review, not automatically
    # classified as false positives or used as hard failures.
    scan_status = report.get("scan_status", report.get("status", "unknown"))
    scan_completed = scan_status == "completed"
    failed_tools = [item["tool"] for item in tool_results if item["result"] != "PASS"]
    passed = bool(expected_results) and not missing and scan_completed and not failed_tools
    return {
        "evaluation": "dkcissp-expected-signal-regression-baseline",
        "result": "PASS" if passed else "FAIL",
        "scan_status": scan_status,
        "scan_completed": scan_completed,
        "required_tool_results": tool_results,
        "failed_required_tools": failed_tools,
        "profile": report.get("profile", "unknown"),
        "finding_count": len(findings),
        "expected_signal_checks": len(expected_results),
        "expected_signals_matched": passed_checks,
        "expected_signal_coverage_percent": round(100 * passed_checks / len(expected_results), 2) if expected_results else None,
        "missing_expected_signals": missing,
        "expected_signal_results": expected_results,
        "duplicate_groups": duplicates,
        "duplicate_finding_count": sum(item["count"] - 1 for item in duplicates),
        "unmatched_findings_requiring_triage": unmatched,
        "false_positive_status": "NOT_ASSESSED",
        "coverage_boundary": baseline.get(
            "coverage_boundary",
            "This percentage covers only the explicit expected signals in this baseline; it is not overall vulnerability detection coverage.",
        ),
        "triage_boundary": "Unmatched findings require human review; they are not automatically false positives. Duplicate matching uses normalized title and affected URL.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="Scanner JSON report to evaluate")
    parser.add_argument("--baseline", default="tests/fixtures/juice_shop_expected_signals.json", help="Expected-signal baseline JSON")
    parser.add_argument("--output", help="Optional path to write the evaluation JSON")
    args = parser.parse_args()
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        result = evaluate_report(report, baseline)
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0 if result["result"] == "PASS" else 1
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        print(json.dumps({"result": "ERROR", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
