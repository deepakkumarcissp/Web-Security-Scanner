# Detection Coverage Matrix

This document is the human-readable companion to `tests/fixtures/detection_coverage_matrix.json`. Update both the matrix and its tests whenever a detector is added, changed, or reclassified.

## Status definitions

- **validated** — a named controlled regression or expected-signal test exercises the specific behavior described. This is not a claim of comprehensive coverage.
- **implemented** — integration or detector code exists and has tests, but a category-wide controlled benchmark is incomplete.
- **unverified** — there is not yet a dedicated repeatable expected-signal benchmark for the category.
- **planned** — the capability or benchmark has not been delivered as a verified feature.

## Current priorities

| Priority | Category | Current status | Next proof point |
|---|---|---|---|
| P0 | Detection baseline integrity | In progress | Keep each expected signal tied to a deterministic fixture and report coverage boundaries clearly. |
| P0 | Scope enforcement | Validated | Add a scope regression test for every new external tool adapter. |
| P1 | Web-server misconfiguration | In progress | Root directory-listing, stock-page signatures, and bounded OPTIONS/Allow method observations have helper and scan-level regression coverage. The broader category remains incomplete pending further controlled server-configuration cases. |
| P1 | SQL injection | Unverified | Local deliberately vulnerable fixture with expected detection and miss cases. |
| P1 | Cross-site scripting | Unverified | Separate reflected/stored cases and evidence-quality checks; a single reflected case is not broad coverage. |
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

## Existing benchmark suites

- `tests/fixtures/controlled_http_expected_signals.json`: seven declared deterministic loopback HTTP/header/CORS/backup metadata regression signals.
- `tests/fixtures/juice_shop_expected_signals.json`: five declared Juice Shop lab signals, including a Nuclei header signal.

These are regression baselines, not comprehensive vulnerability coverage estimates. Review the [Public Release Verification Checklist](RELEASE_CHECKLIST.md) before publishing a release.
