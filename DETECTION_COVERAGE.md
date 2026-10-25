# Detection Coverage Matrix

This document is the human-readable companion to `tests/fixtures/detection_coverage_matrix.json`. Update both the matrix and its tests whenever a detector is added, changed, or reclassified.

## Status definitions

- **validated** — a named controlled regression or expected-signal test exercises the specific behavior described. This is not a claim of comprehensive coverage.
- **implemented** — integration or detector code exists and has tests, and at least one narrow controlled signal has been observed; category-wide coverage remains incomplete.
- **unverified** — there is not yet a dedicated repeatable expected-positive benchmark for the category.
- **planned** — the capability or benchmark has not been delivered as a verified feature.

## Current priorities

| Priority | Category | Current status | Next proof point |
|---|---|---|---|
| P0 | Detection baseline integrity | In progress | Keep each expected signal tied to a deterministic fixture and report coverage boundaries clearly. |
| P0 | Scope enforcement | Validated | Add a scope regression test for every new external tool adapter. |
| P1 | Web-server misconfiguration | Implemented | Root directory-listing, stock-page signatures, and bounded OPTIONS/Allow method observations have helper and scan-level regression coverage. The broader category remains incomplete pending further controlled server-configuration cases. |
| P1 | SQL injection | Validated (narrow JSON/SQLite case) | Expand expected-positive coverage across schema variants and database/query patterns; Juice Shop schema discovery remains unresolved. |
| P1 | Cross-site scripting | Implemented (narrow reflected case) | Repeat adapter testing and add separate controlled contexts; stored XSS and DOM-based XSS are not established. |
| P1 | API security | Planned | Local API fixture with explicit role, authentication, and authorization expectations. |
| P2 | Authenticated assessment | Planned | Credential-safe login/session design with explicit scope and secret redaction. |
| P2 | Network/infrastructure assessment | Planned | Separate authorization model and controlled host/service lab. |

## Benchmark rules

1. Run against deterministic local fixtures first.
2. Record scanner version, profile, enabled tools, tool versions, template-set identity where applicable, and fixture version.
3. Match findings by stable expected-signal identifiers and documented evidence, not just the total number of findings.
4. Record missed expected signals, duplicate detections, severity/confidence drift, runtime, and tool failures.
5. Keep unmatched findings in human triage; do not automatically label them false positives.
6. Report per-category results. Do not combine unrelated categories into a single headline coverage percentage.
7. Do not claim a vulnerability class is comprehensively supported because one example was detected.
8. Run external scans only with explicit authorization and bounded approved scope.

## SQLi/XSS benchmark result (2026-10-25)

Direct Wapiti 3.2.10 against the loopback fixture crawled 5 pages and reported one reflected-XSS finding on `GET /search`, parameter `q`; SQL injection findings were zero. The SQL module emitted an HTTP 500 anomaly for `/product`, parameter `id`, which is not counted as SQLi evidence.

The DKCISSP Wapiti adapter was then run against the same loopback fixture. It completed with return code 0, crawled 5 pages, and normalized one finding: `Wapiti: Reflected Cross Site Scripting` on `/search`, parameter `q`. No SQLi finding was normalized. This confirms the narrow reflected-XSS path through the adapter, not broad XSS coverage.

A separate bounded direct Wapiti 3.2.10 SQL-only run against local Juice Shop at `http://127.0.0.1:1003/` used a fresh session and crawled 18 pages. It reported zero SQL Injection and zero Blind SQL Injection findings, with zero SQL-related anomalies. A new loopback-only oracle at `scripts/benchmark_juice_shop_sqli.py` now reproduces a known expected-positive login API behavior: an invalid-login control returns HTTP 401, while a boolean-based injection test returns HTTP 200 with an authentication response. This validates the benchmark oracle, not scanner detection. A targeted Wapiti OpenAPI JSON run and a bounded sqlmap 1.10.8 JSON run against Juice Shop both failed to report confirmed SQLi. That specific Juice Shop detector benchmark remains unresolved; the later database-backed SQLite fixture provides a separate narrow positive result documented in the updated result section below.

Raw reports remain local-only:
- `/tmp/dkcissp-wapiti-benchmark.json`
- `/tmp/dkcissp-wapiti-juice-shop-sqli-fresh.json`

Reproduction parameters and interpretation are documented in `LOCAL_DETECTION_BENCHMARK.md`.

## Important distinction: parser tests versus detection benchmarks

`tests/test_wapiti_vulnerability_signals.py` verifies how sample Wapiti SQL injection and XSS report records are normalized, deduplicated, scoped, and assigned severity/evidence. It does **not** prove that Wapiti discovers those vulnerabilities on a live target. Direct scanner runs and DKCISSP adapter runs are separate evidence and should be recorded separately.

## Existing benchmark suites

- `tests/fixtures/controlled_http_expected_signals.json`: seven declared deterministic loopback HTTP/header/CORS/backup metadata regression signals.
- `tests/fixtures/juice_shop_expected_signals.json`: five declared Juice Shop lab signals, including a Nuclei header signal.

These are regression baselines, not comprehensive vulnerability coverage estimates. Review the [Public Release Verification Checklist](RELEASE_CHECKLIST.md) before publishing a release.


## Updated SQLi expected-positive result (2026-10-25)

The dedicated loopback-only SQLite-backed JSON API fixture is now tested end-to-end through the integrated DKCISSP OpenAPI-aware SQLMap adapter. Run `python3 scripts/run_sqlmap_api_benchmark.py` from the repository root. The latest run passed the control-vs-test oracle, discovered one same-origin POST operation, tested two JSON fields, and produced two High SQL injection findings from explicit SQLMap injection-point evidence. The runner isolates the scanner database and stops its fixture process after completion. SQLi is therefore **validated for this narrow JSON/SQLite case only**; broad SQLi coverage remains incomplete. Juice Shop's common Swagger paths did not expose a machine-readable schema, and other database dialects, schema variants, time-based SQLi, and authenticated flows are not covered by this result.
