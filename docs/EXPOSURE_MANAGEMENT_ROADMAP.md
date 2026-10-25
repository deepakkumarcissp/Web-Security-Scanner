# Exposure Management Foundation

## Purpose

Evolve DKCISSP Web Security Scanner from a target-by-target scanner into a local-first, authorization-led exposure management workspace. Use the DKCISSP AIAgent repository as an architectural reference for phased discovery and integrations, but keep this application lightweight and independently testable.

## Product principles

- **Explicit authorization and scope:** only assess assets the operator is authorized to test. Discovery must not silently expand scan scope.
- **Evidence before conclusions:** every finding records its source, observation, timestamp, and validation status. A tool's absence or failure is never reported as a clean result.
- **Local-first:** persist inventory and findings in the existing SQLite store; no mandatory SaaS service or external AI dependency.
- **Safe defaults:** passive collection and low-impact checks first. Active probing is opt-in, bounded by timeouts, and constrained to approved targets.
- **Human-controlled remediation:** recommend and track fixes; never make changes to a target system automatically.
- **Incremental integrations:** each scanner is an adapter with consistent input, output, health, and error behavior.

## Delivery phases

### Phase 1 — Asset inventory and scope
- Represent a user-approved root domain or web URL as an asset.
- Record discovery source, first-seen/last-seen timestamps, asset type, and scope status.
- Distinguish **in scope**, **out of scope**, and **needs review**. Newly discovered hosts do not become active-scan targets automatically.
- Normalize hostnames and URLs; reject unsupported schemes, credentials in URLs, malformed targets, and unsafe local/network destinations where applicable.
- Add tests for authorization, normalization, scope boundaries, and duplicate assets.

### Phase 2 — Normalized findings and lifecycle
- Standardize: title, severity, confidence, asset, source adapter, evidence, remediation, first seen, last seen, status, and verification result.
- Deduplicate repeat observations without losing source evidence.
- Track states such as Open, In Progress, Fixed—Pending Verification, Verified, and Accepted Risk.
- Keep scan execution status separate from security posture: failed/unavailable/skipped checks must not count as clean.

### Phase 3 — Controlled discovery and adapters
- Add bounded DNS and certificate-transparency based discovery for an explicitly approved root domain.
- Require review before discovered assets enter active scan scope.
- Use adapter contracts for WhatWeb, testssl.sh, and OWASP ZAP; report installed/unavailable, started/completed/warning/timeout/error/skipped statuses consistently.
- Bound subprocess timeouts and output size; invoke commands with argument arrays and no shell.
- Add mocked tests first, followed by controlled live validation against a test target owned by the operator.

### Phase 4 — Exposure dashboard and change tracking
- Show assets by type and scope, new/changed assets, critical/high findings, stale findings, and remediation progress.
- Provide asset detail with discovery history and linked findings.
- Keep export safe against spreadsheet formula injection.
- Make empty states and tool failures explicit; do not use fabricated sample data as live findings.

### Phase 5 — Reporting and future integrations
- Add an executive summary and technical evidence report.
- Design optional integrations as separate adapters (for example, cloud inventory or code exposure) only after credentials, permissions, data handling, and test strategy are documented.
- AI may summarize evidence, but it must not invent findings or make authorization decisions.

## Acceptance criteria for each implementation PR

1. The change is on a feature branch and submitted as a pull request against `main`.
2. Existing tests and new focused tests pass in a clean checkout.
3. Security-sensitive inputs and subprocess behavior are covered by tests.
4. The PR states what was tested and what remains unverified.
5. After review/merge, verify the merged commit and tests on `main`; never infer success from a feature branch alone.

## Immediate next implementation

Start with Phase 1's minimal asset inventory model and API, reusing the existing FastAPI and SQLite patterns. Keep it additive, include migration-safe initialization, and avoid adding broad reconnaissance commands until scope handling is tested.
