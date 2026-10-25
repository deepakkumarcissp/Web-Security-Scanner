# DKCISSP External Attack Surface & Web Security Scanner

**DKCISSP — Where Security Becomes Simple.**  
*Security Is Better Together.*

A community-first, local-first security workbench with an emerging External Attack Surface Management (EASM) foundation and a modular web security assessment engine. It is being built for Kali Linux first. The current EASM beta manages explicitly registered roots, performs opt-in passive certificate-transparency discovery, and places discovered hostname candidates into a human-review queue before any scan.

> **Project principle:** show what actually ran, show the evidence, explain the risk, and make remediation and retesting measurable. Never report a tool as working just because it is listed in the UI.

## At a glance

- **Platform:** Kali Linux / Debian-based Linux
- **Interface:** browser dashboard, bound to localhost by default
- **Backend:** Python + FastAPI
- **Storage:** SQLite
- **Reports:** CSV findings export with spreadsheet-formula injection mitigation
- **Current scan behavior:** Quick uses built-in passive HTTP/response-header checks; Standard adds bounded same-origin discovery, curated Nuclei checks, WhatWeb, HTTPS/TLS assessment, and optional ZAP passive alerts; Deep adds time-bounded Nikto checks; Active adds bounded Wapiti payload testing only after a separate approval confirmation. Active scans cannot be scheduled. A controlled vulnerable local fixture produced a reflected-XSS detection through Wapiti; broader benchmark coverage remains pending.
- **Scope:** only scan systems you own or have explicit authorization to assess

## What is this project?

DKCISSP combines an EASM asset-inventory foundation with a practical workbench for authorized web security assessments. Instead of making users jump between discovery sources, tool output, scan logs, and spreadsheets, the project is evolving toward one workflow for asset provenance, scope approval, assessment evidence, remediation guidance, scan history, and exports.

The dashboard is risk-focused. Tool installation and integration health live on a separate **Scanner Setup** page so the main dashboard remains about the security posture and findings.

### Who is it for?

- Security engineers and penetration testers conducting authorized assessments
- Blue-team and application-security practitioners who need actionable findings
- Learners using intentionally vulnerable local labs
- Teams that want a lightweight, understandable starting point before adopting a larger platform

## How it works

```text
Authorized root asset (explicitly registered)
      |
      v
Opt-in passive certificate-transparency discovery
      |
      v
Hostname candidate inventory (Needs Review; no scan starts)
      |
      v
Human scope review + approval/change reference
      |
      v
Approved asset → web assessment engine
      |
      +--> findings, evidence, remediation, retest/reporting

Assessment engine (for an approved target)
      |
      v
Create scan / choose profile
      |
      v
Built-in passive HTTP and response-header checks
      |
      +---- if local OWASP ZAP API is available ----+
      |       bounded same-origin fetches + passive alerts       |
      +----------------------------------------------+
      |
      v
Bounded same-origin page discovery (Standard/Deep/Active only)
      |
      v
Passive header/cookie checks on discovered URLs
      |
      v
Optional Nuclei / WhatWeb / testssl.sh / ZAP passive adapters
      |
      v
Normalize findings, evidence, confidence, remediation
      |
      v
SQLite persistence
      |
      +--> Risk dashboard and scan history
      +--> Finding details and remediation guidance
      +--> CSV export
      +--> Scheduled scans (while the app process is running)
```

Standard/Deep scans now discover up to 12 same-origin URLs, with a maximum link depth of two and a short per-request timeout. Discovery extracts links, resource URLs, and form actions but never submits forms or executes JavaScript; query strings are retained, and cross-origin links/redirects are rejected. Passive header/cookie checks are repeated on discovered URLs. This is a bounded link crawler, not a JavaScript renderer or authenticated crawler, so it will miss client-side routes and pages requiring login. The ZAP adapter checks API readiness, fetches only the validated same-origin URLs already discovered by the scanner, reports the actual integration outcome, and does **not** launch a spider or active scan. The optional WhatWeb adapter runs for Standard/Deep/Active scans, uses aggression level 1, disables redirect following to prevent scope expansion, writes a temporary JSON report, and has a 30-second timeout. The optional `testssl.sh` adapter runs only for authorized HTTPS scans using Standard, Deep, or Active profiles, writes a temporary JSON report, and has a 75-second timeout. The Nuclei adapter runs for Standard/Deep/Active profiles using a curated local HTTP template set. Standard selects up to 30 templates; Deep and Active select up to 60, balanced across exposure, misconfiguration, TLS/header, technology, and CVE categories after filtering explicit high-risk tags, non-HTTP flows, state-changing methods, raw/payload-driven requests, and templates declaring over five requests. It scans up to 12 validated same-origin URLs, uses a 5 requests/second cap, concurrency 3, 4-second per-request timeout, no retries, redirects disabled, and OAST/Interactsh disabled. Standard is capped at 75 seconds and Deep at 150 seconds. Valid JSONL findings collected before a timeout are retained and the partial-timeout status is explicit. If a binary is missing or a tool errors/times out, the scan summary records that status and built-in checks continue. The application must not imply that an external tool ran when it did not.

## Current capabilities

- **EASM foundation (beta):** organization/root-domain registry API, explicit root-asset registration, passive certificate-transparency hostname discovery, source/provenance tracking, and a human-reviewed scope gate; discovered candidates do not trigger scans. Organization/root records and asset association are currently API/data-layer capabilities, not yet a dedicated management screen. DNS/ASN resolution, historical discovery, web fingerprinting, and exposure trends are not yet implemented in this scanner.
- Risk-focused dashboard with summary cards, findings, and scan history
- Built-in low-impact HTTP and response-header checks
- Bounded same-origin endpoint discovery for Standard/Deep scans, followed by passive header/cookie checks across discovered URLs
- Metadata-only observations for potentially exposed backup/configuration/repository paths when those URLs are supplied or discovered in scope; no arbitrary filename brute force, file contents are not recorded, and observations remain Low severity/Low confidence until validated
- Optional OWASP ZAP passive-alert retrieval from a local API
- Scanner Setup page with real executable/version checks for supported tools
- Allow-listed tool installation workflow with explicit user confirmation
- Target authorization confirmation before scan and schedule creation; malformed ports and credential-bearing URLs are rejected
- Bounded concurrent scan workers (default 2; `DKCISSP_MAX_CONCURRENT_SCANS` may be set from 1 to 8); manual and scheduled scans respect the same cap
- Adapter finding URLs are filtered against the approved target origin for Nikto and Wapiti, with regression tests for scheme/host/port and malformed URL cases
- Finding normalization with severity, affected URL, evidence, confidence, and remediation
- SQLite-backed scan and finding history
- Finding lifecycle tracking: open, accepted, remediated, false positive, and retest required, with notes and update timestamps
- Retest comparison API and Scan History action: new, persistent, and no-longer-detected findings, severity shifts, and heuristic risk-point delta
- Daily and weekly recurring schedules
- CSV findings export
- Printable HTML findings report with severity summary and a browser Print / Save as PDF option
- JSON API for dashboard and scan workflows
- Tests for core application behavior and tool-installation guards

## Scanner integrations and readiness

The Scanner Setup page checks tools independently of scan results. Availability can vary by host and PATH configuration.

| Tool | Intended role | Current integration status |
|---|---|---|
| Built-in passive checks | HTTP response and security-header checks | Used by scan execution |
| OWASP ZAP | Passive web alerts | Optional adapter implemented; setup diagnostics distinguish missing API, wrong service/port, authentication failure, and ready state |
| `curl` | HTTP connectivity diagnostics | Detected/version checked by setup page |
| WhatWeb | Technology fingerprinting | Invoked for Standard/Deep scans when installed; stealthy aggression level 1, no redirect following, bounded timeout, JSON findings normalization |
| `testssl.sh` | TLS configuration assessment | Invoked for Standard/Deep HTTPS scans when installed; 75-second timeout and JSON report parsing; controlled local HTTPS execution validated |
| Nuclei | Known exposure/misconfiguration template checks | Invoked for Standard/Deep/Active scans across up to 12 validated same-origin URLs; 30 templates Standard / 60 Deep or Active; 5 requests/second, concurrency 3, redirects and OAST disabled; 75/150-second cap; JSONL partial findings retained on timeout |
| Nikto | Web-server exposure and misconfiguration checks | Invoked for Deep/Active only; bounded runtime, 0.1-second request delay, selected low-risk test groups, conservative severity |
| Wapiti | Active web-application vulnerability testing | Invoked only for Active after separate approval; depth 2, one task, polite mode, 75-second scan budget, 8-second per-module attack budget; excludes SSRF, file upload, stored XSS, brute force, time-based SQL, and high-risk exploit/takeover modules; excludes common logout/delete/checkout paths |


**Important distinction:** Wapiti's full selected-module adapter was exercised against a controlled local app with a deliberately reflected-XSS parameter and reported the reflected-XSS finding. That validates invocation, scope, and report normalization for this fixture; broader vulnerability coverage, false-positive rates, and the full multi-tool Active pipeline still require benchmark testing. testssl.sh completed against a temporary local HTTPS target; that validates invocation and report parsing, not every TLS scenario. A controlled multi-page Standard scan previously reached Nuclei's 60-second cap and discarded partial output. The engine now retains valid partial JSONL findings, uses a smaller Standard template cap, and gives Deep a longer bounded budget; this updated behavior must be revalidated against the same controlled lab before claiming broad vulnerability coverage. Quick scans do not invoke Nuclei, WhatWeb, or testssl.sh. WhatWeb runs only for Standard/Deep profiles at low aggression and records detected technologies as informational findings, not as confirmed vulnerabilities.

### Tool installation safety

The setup workflow uses a fixed list of package names, requires explicit confirmation, and restricts installation requests to local callers. Depending on the machine configuration, installation may request administrator authentication. Review package-manager prompts before approving changes.

Never expose the local dashboard or its tool-installation endpoint to untrusted networks. Do not add arbitrary command execution or accept user-supplied shell commands as an installation mechanism.

## Quick start on Kali Linux

### Requirements

- Kali Linux or a compatible Debian-based Linux system
- Python 3.11 or newer
- Permission to create a local virtual environment and install Python dependencies
- Optional: OWASP ZAP, installed and running locally, for ZAP passive-alert retrieval

### Start the application

From the repository directory:

```bash
bash ./run.sh
```

Then open:

**http://127.0.0.1:1005**

The launcher creates/uses a Python virtual environment, installs project dependencies, and starts the web service on loopback port 1005. Invoke it with `bash ./run.sh`; the script is not required to have its executable bit set in a downloaded ZIP or fresh clone.

### Manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 1005
```

Keep the terminal and application process running while using the dashboard and while scheduled scans are due.

## First-run workflow

1. Start the application on Kali Linux.
2. Open the local dashboard at `http://127.0.0.1:1005`.
3. Visit **Scanner Setup** and run the tool-status check.
4. Install optional dependencies only when needed and only after reviewing the confirmation prompt.
5. Use a target you own or are explicitly authorized to test. For initial validation, prefer a local training application such as OWASP Juice Shop.
6. Create a scan and review its findings, evidence, and remediation guidance.
7. Export findings as CSV when you need to share or analyze results.
8. Keep scan scope, permissions, and the intended test intensity documented.

## Scheduling

The Schedules page supports daily and weekly recurrence and an optional first-run date/time. Browser-selected time is sent as an ISO timestamp and stored in UTC.

**The application process must remain running for scheduled scans to execute.** The current MVP does not yet guarantee execution across reboots or provide a production-grade background worker/service. Do not treat the scheduler as a durable enterprise job service yet.

## Retest comparison and risk trend

After a completed scan, open **Scan History → Compare**. The scanner compares it with the latest earlier completed scan for the same normalized target and profile, then summarizes new findings, findings that persisted, findings not detected in the later scan, severity changes, and a simple risk-point delta. The endpoint `GET /api/scans/{scan_id}/comparison` also accepts an optional `baseline_id` query parameter for an explicit same-target baseline.

Risk points are a transparent prioritization heuristic (Critical 10, High 8, Medium 4, Low 1, Informational 0), not CVSS, a probability estimate, or a formal business-risk measure. Matching uses normalized finding title and URL path; query strings are ignored. Renamed detections can be misclassified, and an issue absent from a retest is **not proof** that it was fixed. Compare the same profile after remediation and validate important results manually. If no prior scan exists, the API explains that a second scan is needed.

## Reports and exports

Use **Reports & Export** to download either a spreadsheet-friendly CSV or a printable HTML findings report. Open the HTML report and select **Print / Save as PDF** to create a PDF copy. The HTML report escapes untrusted finding content and includes severity counts, evidence, remediation, confidence, and lifecycle details.

For CSV, use **Reports & Export → Download findings.csv**, or run:

```bash
curl -OJ http://127.0.0.1:1005/api/export/findings.csv
```

The export includes scan ID, target, severity, finding title, affected URL, evidence, remediation, confidence, and discovery timestamp.

## API overview

The current API includes the following main routes:

- `GET /api/health` — application health
- `GET /api/dashboard` — dashboard summary
- `GET /api/tools` — scanner executable/version and integration status
- `POST /api/tools/install/{tool_id}` — explicitly approved install for allow-listed tools
- `POST /api/scans` — create a scan
- `GET /api/scans` and `GET /api/scans/{id}` — scan history/details
- `GET /api/findings` — findings, including lifecycle status and notes
- `PATCH /api/findings/{finding_id}/lifecycle` — update a finding lifecycle status and notes
- `GET /api/export/findings.csv` — CSV export
- `GET /api/export/findings.html` — printable HTML findings report
- `GET /api/schedules` and `POST /api/schedules` — list/create schedules
- `PATCH /api/schedules/{id}` — pause/resume a schedule
- `DELETE /api/schedules/{id}` — delete a schedule

API behavior can evolve as the MVP develops; consult the route definitions and tests when integrating clients.

## Repeatable local OWASP Juice Shop validation

The loopback-only smoke test starts a **Standard** assessment against an already-running local Juice Shop instance, waits for completion, and writes a timestamped JSON evidence report. It never starts containers, changes firewall rules, targets public hosts, or runs the Active profile. Keep the lab bound to loopback (for example, `127.0.0.1:1003:3000`).

Prerequisites: Docker with Juice Shop running on loopback, and the DKCISSP scanner running locally (default `http://127.0.0.1:1005`). Then run:

```bash
python3 scripts/validate_juice_shop.py
```

For a different loopback port or a longer timeout:

```bash
python3 scripts/validate_juice_shop.py --target http://127.0.0.1:1003 --scanner http://127.0.0.1:1005 --timeout 900
```

Reports are written to `validation-reports/` (ignored by Git because scan output can contain target-specific evidence). A PASS means the API workflow completed; it does **not** mean every known Juice Shop issue was detected. The report includes the tool execution statuses and findings so detector benchmarks can be added without confusing scan completion with detection quality. The script rejects non-loopback scanner and target URLs. Do not change it to run Active scans automatically.

### Evaluate expected-signal regression coverage

Evaluate an existing report against the explicit baseline in `tests/fixtures/juice_shop_expected_signals.json` (five observed transport/header signals):

```bash
python3 scripts/evaluate_scan_baseline.py \
  --report validation-reports/<scan-report>.json \
  --output validation-reports/<scan-report>-evaluation.json
```

The evaluator fails if an expected signal is missing, the scan is incomplete, or the required Nuclei tool did not complete. It reports duplicate findings by normalized title and affected URL, and lists unmatched findings for human triage. Unmatched findings are **not** automatically labeled false positives. The Juice Shop baseline covers only its five explicitly declared signals; the separate controlled loopback HTTP baseline covers seven explicit regression signals. Neither is an overall vulnerability detection rate. Regression tests in `tests/test_scan_baseline.py` cover expected-signal matching, severity/confidence drift, incomplete scans, required-tool failures, duplicate reporting, and unmatched-finding triage. Re-check the baseline if Juice Shop configuration or response headers change.

## Run tests

```bash
python -m pip install pytest httpx
pytest -q
```

The GitHub Actions workflow runs Python compilation and the automated test suite on Ubuntu/Python 3.11. CSV exports neutralize untrusted cell values that spreadsheet applications could interpret as formulas. CI does not prove a clean Kali install, browser-based end-to-end behavior, or live external scanner integrations. Before merging or announcing a release, follow the [Public-Release Verification Checklist](RELEASE_CHECKLIST.md). A running end-to-end OWASP ZAP scan still needs to be verified against an actual local ZAP service. Configure the API endpoint with `DKCISSP_ZAP_API_URL` (defaults to `http://127.0.0.1:8080`) and optionally set `DKCISSP_ZAP_API_KEY`; the key is never included in diagnostic response fields. On the Kali development machine, a dedicated ZAP daemon is configured on loopback port `8090`, with its API key stored in a user-only config file. Port `8080` is another service and is not modified. The daemon is configured for passive-alert retrieval only by this scanner; no ZAP spider or active scan is launched. A listening port alone is not proof that ZAP is running.

## Safety model

- Only test targets you own or are explicitly authorized to assess.
- Prefer local training labs while developing and validating scanner integrations.
- Keep the service bound to loopback unless a deliberate, separately secured deployment design is implemented.
- External scanning tools must use fixed adapters, explicit scope, timeouts, and safe defaults.
- Active scanning must require both target authorization and a separate active-testing confirmation. Active scans can submit test payloads and may affect application state; use staging or a specifically approved test target. Active scans cannot be scheduled. The Active profile excludes SSRF, upload, stored-XSS, brute-force, time-based SQL, and selected high-risk exploit modules by default.
- Never silently install packages, execute arbitrary shell commands, or report unverified tool status as healthy.
- Findings are signals for investigation, not proof by themselves; validate context and business impact before remediation.

## Repository layout

```text
Web-Security-Scanner/
├── app.py                 # FastAPI application and scan workflows
├── static/
│   └── index.html         # Dashboard and Scanner Setup UI
├── tests/
│   └── test_app.py        # Application and API tests
├── requirements.txt       # Python dependencies
├── run.sh                 # Local startup helper
├── README.md              # Project overview, use, safety, and roadmap
└── .github/
    └── workflows/         # CI and repository automation (as configured)
```

## Project roadmap

The roadmap is staged so each integration is independently testable and the UI stays honest about what is operational.

### Phase 1 — Reliable local foundation

- [x] Risk-focused dashboard and persistent scan/finding records
- [x] CSV findings export
- [x] Daily/weekly scan scheduling MVP
- [x] Dedicated Scanner Setup page
- [x] Allow-listed tool status/version checks
- [x] Explicit-confirmation package installation flow
- [x] Optional OWASP ZAP passive-alert adapter
- [x] Verify ZAP adapter against a running local ZAP service and a controlled local HTTP fixture
- [x] Improve ZAP service setup guidance and actionable diagnostics

### Phase 2 — Safe, modular scanner integrations

- [ ] Add a dedicated HTTP/header integration with repeatable evidence
- [x] Integrate WhatWeb as an optional technology-discovery module
- [x] Integrate `testssl.sh` as an optional TLS assessment module
- [x] Validate `testssl.sh` invocation and JSON report parsing against a controlled local TLS target
- [ ] Make each integration report installed, version, execution, timeout, and error status distinctly
- [x] Add mocked integration-level tests for testssl.sh and WhatWeb outputs
- [ ] Validate WhatWeb end-to-end against a controlled local target
- [x] Add constrained Nuclei adapter with JSONL parsing and bounded execution
- [x] Validate bounded Nuclei invocation/report parsing against a controlled local HTTP target; broader template coverage still requires benchmark testing
- [ ] Connect scan profiles to clearly documented, real module sets

### Phase 3 — Scan operations and reporting

- [ ] Live scan progress and useful per-module status
- [ ] Safe cancellation and consistent timeout handling
- [ ] Stronger scheduler execution and restart/reboot behavior
- [x] HTML report alongside CSV
- [x] Finding lifecycle: open, accepted, remediated, false positive, and retest required, with notes and timestamps
- [x] Retest comparisons and heuristic risk-point change (not a formal risk or CVSS score)
- [ ] Better scan logs and exportable diagnostic bundles

### Phase 4 — Validation lab and security hardening

- [ ] Repeatable end-to-end validation against a local OWASP Juice Shop lab
- [ ] Validate target scope and redirect behavior for every adapter
- [x] Add a bounded concurrent-scan cap and robust target URL validation for scan creation
- [ ] Review authentication and deployment hardening before any non-local use
- [ ] Document threat model, permissions, data retention, and known limitations

### Phase 5 — Community and extensibility

- [ ] Documented scanner adapter interface for contributors
- [ ] Contribution guide, issue templates, and security reporting process
- [ ] Versioned releases and CI checks for supported Linux environments
- [ ] Community-reviewed detection and remediation guidance
- [ ] Plugin/module documentation without arbitrary command execution

Roadmap items are goals, not claims of completed functionality. Completion should be reflected in code, tests, documentation, and observed tool behavior.

## Contributing

Contributions should keep the project safe, transparent, and easy to validate. For new integrations, include the tool's supported version detection, fixed invocation arguments, timeout/error handling, normalized findings, tests, documentation, and an explanation of scan scope. Do not include secrets, real customer targets, or sensitive scan results in issues or commits.

## License

See the repository's `LICENSE` file for the applicable project license.
