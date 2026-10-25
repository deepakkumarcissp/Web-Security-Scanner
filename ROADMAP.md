# DKCISSP Web Security Scanner — Engineering Roadmap

**Goal:** build DKCISSP as an asset-centric External Attack Surface Management (EASM) workbench, with the existing web scanner as its evidence-led assessment engine. Advance in small, tested steps without overstating coverage.

## Working rules

- Work through phases in order; do not stop for approval between ordinary engineering steps.
- Keep tests deterministic and local. Use loopback fixtures or mocked tool output; never scan external targets during development.
- Do not enable Active scanning by default, submit forms, use exploit payloads, enable OAST/callbacks, or widen target scope.
- Do not restart/deploy the live service or merge a pull request as part of routine implementation.
- Every finding must preserve source evidence, approved-origin validation, tool status, and clear confidence/severity semantics.
- A passing smoke test means the workflow ran; only explicit expected-signal assertions count as detection validation.


## EASM foundation — product direction

**Baseline reference:** the AIAgent repository's `asm/asm_orchestrator.py` and `assessments/domain_recon.py`. Adapt the staged discovery → resolve → fingerprint → scope gate → assessment → reporting model; do not copy implementation wholesale or inherit automatic assessment defaults. See `EASM_FOUNDATION.md` for the review, gaps, guardrails, and delivery sequence.

- [x] Review AIAgent ASM orchestration and broader domain-recon capability model.
- [x] Document capability gaps, implementation stages, and security requirements for DKCISSP EASM.
- [x] Expose the existing asset inventory as **Attack Surface (Beta)** while describing only capabilities that exist today.
- [x] Add organization/root-domain records and exact-boundary asset association without losing URL/port scope boundaries (API/data layer; dashboard management UI remains to be added).
- [ ] Add a discovery adapter contract and persist per-source status, provenance, timestamps, limits, and errors.
- [ ] Add bounded DNS resolution as a distinct inventory stage, not implicit permission to probe/scan.
- [ ] Add approved-only, low-impact HTTP/TLS fingerprinting and asset-change snapshots.

**Non-negotiable gate:** passive discovery results remain `Needs Review`; no candidate is automatically scanned. Approval is auditable and tied to exact scope.

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
- [x] Add a machine-readable controlled-HTTP expected-signal baseline and evaluator regression test; report includes expected/observed signal results, tool status, and scope checks are independently asserted.

**Exit gate:** every expected fixture signal is asserted; a completed scan cannot pass solely because the API returned HTTP 200.

## Phase 3 — Detection quality and evidence
**Status: Planned**

- [x] Add a dedicated controlled-HTTP expected-signal baseline for HTTP transport and missing-header cases.
- [ ] Expand expected-signal baselines to distinct CORS, TLS, and exposed-file cases.
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
- Commit `0fffdcd` blocks cross-origin redirects on the initial request; tests verify a second loopback port is never contacted.
- Commit `cdbb2cc` adds a controlled-HTTP expected-signal baseline and evaluator regression test; full suite: **100 passed**, 2 dependency deprecation warnings.
- Commit `8127966` documents the AIAgent EASM reference architecture and exposes the existing inventory page as **Attack Surface (Beta)**.
- Current batch adds an organization/root-domain registry API, backward-compatible SQLite migration, exact-boundary asset association, and inherited organization linkage for CT candidates. Focused tests: **10 passed**; full suite: **103 passed**; Python/JavaScript syntax and diff checks passed.
- Local Juice Shop Standard scan: **scan 31 PASS**, completed in 14.1 seconds; 7 same-origin URLs mapped, Nuclei completed, WhatWeb completed, and ZAP passive completed. Active Wapiti was correctly skipped.
- Expected-signal evaluator: **PASS, 5/5 expected signals matched**, zero duplicate groups, three unmatched findings retained for human triage. This is 100% coverage of the five declared fixture signals only, not overall vulnerability detection coverage.
- Full regression suite before the latest scope-hardening change: **98 passed**, 2 dependency deprecation warnings.
- Latest local regression suite after blocking cross-origin redirects on the initial request: **99 passed**, 2 dependency deprecation warnings; focused loopback/redirect tests: **4 passed**.

The roadmap is intentionally evidence-gated. Do not claim broad detection coverage, production readiness, or a release-ready default branch until the relevant exit gates have been demonstrated.


## EASM implementation checkpoint — adapter history and DNS inventory

- [x] Add normalized CT adapter contract and persistent successful/failed discovery run history.
- [x] Add bounded, explicitly invoked DNS resolution with per-asset status and deduplicated addresses; no HTTP/TLS probes or scan launch.
- [x] Add regression tests for adapter success/failure persistence, authorization, DNS scope linkage, and no-scan behavior.
- [ ] Add dashboard controls for organization registration, discovery history, and DNS resolution status.
- [ ] Add additional passive discovery sources only behind the same bounded adapter contract.
