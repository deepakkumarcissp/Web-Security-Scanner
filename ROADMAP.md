# DKCISSP Web Security Scanner — Engineering Roadmap

**Goal:** turn the current local-first MVP into a reliable, repeatable, evidence-led scanner without overstating coverage.

## Working rules

- Work through phases in order; do not stop for approval between ordinary engineering steps.
- Keep tests deterministic and local. Use loopback fixtures or mocked tool output; never scan external targets during development.
- Do not enable Active scanning by default, submit forms, use exploit payloads, enable OAST/callbacks, or widen target scope.
- Do not restart/deploy the live service or merge a pull request as part of routine implementation.
- Every finding must preserve source evidence, approved-origin validation, tool status, and clear confidence/severity semantics.
- A passing smoke test means the workflow ran; only explicit expected-signal assertions count as detection validation.

## Phase 1 — Regression safety and finding integrity
**Status: In progress**

- [x] Filter Nuclei output to the exact approved origin before persistence.
- [x] Test TLS finding severity normalization and non-zero tool exits.
- [x] Test exposed-file normalization and cross-origin filtering.
- [x] Test ZAP duplicate grouping while preserving affected URLs.
- [x] Test CORS evidence preservation and exact-origin filtering.
- [x] Add controlled response-header fixtures for present/missing headers and malformed URL handling.
- [x] Block cross-origin redirects on the initial request and test with two loopback servers on different ports.
- [ ] Ensure test state is isolated and repeatable across full-suite runs.

**Exit gate:** tests pass, compilation succeeds, no whitespace errors, no test touches public targets.

## Phase 2 — Controlled local integration lab
**Status: Planned**

- [x] Build a deterministic loopback HTTP fixture with known security headers and verify real scanner response parsing in the Quick profile.
- [x] Extend the fixture with a cross-origin redirect attempt; the second loopback server receives no request.
- [ ] Extend the fixture with controlled CORS responses and a small set of exposed test files.
- [ ] Generate/use a test-only certificate; never disable TLS verification in production scanner code to make tests pass.
- [ ] Validate scanner response parsing and TLS adapter invocation against loopback only.
- [ ] Produce a machine-readable report with expected signals, observed signals, tool statuses, and scope checks.

**Exit gate:** every expected fixture signal is asserted; a completed scan cannot pass solely because the API returned HTTP 200.

## Phase 3 — Detection quality and evidence
**Status: Planned**

- [ ] Expand the expected-signal baseline to distinct header, CORS, TLS, and exposure cases.
- [ ] Add tests for confidence/severity drift, duplicate suppression, URL canonicalization, and malformed tool JSON.
- [ ] Keep unmatched findings for human triage; never auto-label them false positives.
- [ ] Document false-negative boundaries and known unsupported coverage.

**Exit gate:** repeatable benchmark output distinguishes expected-signal coverage from overall detection rate.

## Phase 4 — Engine reliability and observability
**Status: Planned**

- [ ] Record tool start/end, duration, exit code, timeout, and partial-output state in the activity timeline.
- [ ] Verify cancellation, timeout handling, and partial findings are consistent across adapters.
- [ ] Bound subprocess output, response sizes, URL counts, concurrency, and temporary-file cleanup.
- [ ] Add tests for unavailable tools, tool crashes, malformed output, and interrupted scans.

**Exit gate:** every integration reports an honest terminal status and cannot silently convert a failure into success.

## Phase 5 — User workflow and reporting
**Status: Planned**

- [ ] Verify scan progress, activity feed, finding evidence, CSV and HTML exports.
- [ ] Verify lifecycle updates and same-target/profile retest comparisons.
- [ ] Add report metadata: scanner version, profile, timestamps, tools run, skipped checks, and validation limits.
- [ ] Ensure dashboard language distinguishes findings, observations, and confirmed vulnerabilities.

**Exit gate:** exported reports match stored results and clearly state which checks ran.

## Phase 6 — Fresh-clone and release readiness
**Status: Planned**

- [ ] Test installation and startup from a clean checkout.
- [ ] Test health check, documented port, missing-dependency path, and recovery instructions.
- [ ] Verify the default branch, CI checks, README claims, and release checklist agree.
- [ ] Review dependency versions and local-service exposure defaults.
- [ ] Publish a release note listing evidence, limitations, and remaining gaps.

**Exit gate:** clean-clone instructions work as written and all public capability claims are backed by tests.

## Current execution checkpoint

- Latest regression implementation before current working changes: `b281bee` — controlled local HTTP fixture.
- This batch adds initial-request redirect scope enforcement and tests for present/missing security headers, pending commit.
- Local Juice Shop Standard scan: **scan 31 PASS**, completed in 14.1 seconds; 7 same-origin URLs mapped, Nuclei completed, WhatWeb completed, and ZAP passive completed. Active Wapiti was correctly skipped.
- Expected-signal evaluator: **PASS, 5/5 expected signals matched**, zero duplicate groups, three unmatched findings retained for human triage. This is 100% coverage of the five declared fixture signals only, not overall vulnerability detection coverage.
- Full regression suite before the latest scope-hardening change: **98 passed**, 2 dependency deprecation warnings.
- Latest local regression suite after blocking cross-origin redirects on the initial request: **99 passed**, 2 dependency deprecation warnings; focused loopback/redirect tests: **4 passed**.

The roadmap is intentionally evidence-gated. Do not claim broad detection coverage, production readiness, or a release-ready default branch until the relevant exit gates have been demonstrated.
