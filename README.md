# DKCISSP Web Security Scanner

**DKCISSP — Where Security Becomes Simple.**  
*Security Is Better Together.*

A community-first, local-first web application security scanner designed to help security practitioners understand web exposure, prioritize findings, and track remediation from one dashboard. It is being built for Kali Linux first, with a clear path from safe passive checks toward carefully scoped, modular scanner integrations.

> **Project principle:** show what actually ran, show the evidence, explain the risk, and make remediation and retesting measurable. Never report a tool as working just because it is listed in the UI.

## At a glance

- **Platform:** Kali Linux / Debian-based Linux
- **Interface:** browser dashboard, bound to localhost by default
- **Backend:** Python + FastAPI
- **Storage:** SQLite
- **Reports:** CSV findings export
- **Current scan behavior:** built-in passive HTTP/response-header checks, with an optional OWASP ZAP passive-alert adapter when a local ZAP API is running
- **Scope:** only scan systems you own or have explicit authorization to assess

## What is this project?

The DKCISSP Web Security Scanner is intended to be a practical workbench for authorized web security assessments. Instead of making users jump between tool output, scan logs, and spreadsheets, the project brings target scans, findings, evidence, confidence, remediation guidance, scan history, schedules, and exports into a consistent workflow.

The dashboard is risk-focused. Tool installation and integration health live on a separate **Scanner Setup** page so the main dashboard remains about the security posture and findings.

### Who is it for?

- Security engineers and penetration testers conducting authorized assessments
- Blue-team and application-security practitioners who need actionable findings
- Learners using intentionally vulnerable local labs
- Teams that want a lightweight, understandable starting point before adopting a larger platform

## How it works

```text
Authorized target
      |
      v
Create scan / choose profile
      |
      v
Built-in passive HTTP and response-header checks
      |
      +---- if local OWASP ZAP API is available ----+
      |       exact-URL fetch + passive alerts       |
      +----------------------------------------------+
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

The current ZAP adapter does **not** launch a spider or active scan. If ZAP is missing or unavailable, built-in passive checks should still complete. The application must not imply that an external tool ran when it did not.

## Current capabilities

- Risk-focused dashboard with summary cards, findings, and scan history
- Built-in low-impact HTTP and response-header checks
- Optional OWASP ZAP passive-alert retrieval from a local API
- Scanner Setup page with real executable/version checks for supported tools
- Allow-listed tool installation workflow with explicit user confirmation
- Target authorization confirmation before scan and schedule creation
- Finding normalization with severity, affected URL, evidence, confidence, and remediation
- SQLite-backed scan and finding history
- Daily and weekly recurring schedules
- CSV findings export
- JSON API for dashboard and scan workflows
- Tests for core application behavior and tool-installation guards

## Scanner integrations and readiness

The Scanner Setup page checks tools independently of scan results. Availability can vary by host and PATH configuration.

| Tool | Intended role | Current integration status |
|---|---|---|
| Built-in passive checks | HTTP response and security-header checks | Used by scan execution |
| OWASP ZAP | Passive web alerts | Optional adapter implemented; requires a working local ZAP API |
| `curl` | HTTP connectivity diagnostics | Detected/version checked by setup page |
| WhatWeb | Technology fingerprinting | Detected/version checked; not yet invoked by scan profiles |
| `testssl.sh` | TLS configuration assessment | Detected/version checked; not yet invoked by scan profiles |

**Important distinction:** detecting an installed executable is not the same as integrating it into scan execution. The roadmap tracks the remaining adapters and validation separately. Quick, Standard, and Deep profiles must not be described as performing deeper external scans until those behaviors are implemented, tested, and documented.

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

**http://127.0.0.1:1004**

The launcher creates/uses a Python virtual environment, installs project dependencies, and starts the web service on loopback port 1004. Invoke it with `bash ./run.sh`; the script is not required to have its executable bit set in a downloaded ZIP or fresh clone.

### Manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 1004
```

Keep the terminal and application process running while using the dashboard and while scheduled scans are due.

## First-run workflow

1. Start the application on Kali Linux.
2. Open the local dashboard at `http://127.0.0.1:1004`.
3. Visit **Scanner Setup** and run the tool-status check.
4. Install optional dependencies only when needed and only after reviewing the confirmation prompt.
5. Use a target you own or are explicitly authorized to test. For initial validation, prefer a local training application such as OWASP Juice Shop.
6. Create a scan and review its findings, evidence, and remediation guidance.
7. Export findings as CSV when you need to share or analyze results.
8. Keep scan scope, permissions, and the intended test intensity documented.

## Scheduling

The Schedules page supports daily and weekly recurrence and an optional first-run date/time. Browser-selected time is sent as an ISO timestamp and stored in UTC.

**The application process must remain running for scheduled scans to execute.** The current MVP does not yet guarantee execution across reboots or provide a production-grade background worker/service. Do not treat the scheduler as a durable enterprise job service yet.

## CSV reporting

Use **Reports & Export → Download findings.csv**, or run:

```bash
curl -OJ http://127.0.0.1:1004/api/export/findings.csv
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
- `GET /api/findings` — findings
- `GET /api/export/findings.csv` — CSV export
- `GET /api/schedules` and `POST /api/schedules` — list/create schedules
- `PATCH /api/schedules/{id}` — pause/resume a schedule
- `DELETE /api/schedules/{id}` — delete a schedule

API behavior can evolve as the MVP develops; consult the route definitions and tests when integrating clients.

## Run tests

```bash
python -m pip install pytest httpx
pytest -q
```

The feature branch has been checked with Python compilation and the automated test suite. The GitHub Actions workflow runs those same Python checks on Ubuntu/Python 3.11; it does not prove a clean Kali install, browser-based end-to-end behavior, or live external scanner integrations. Before merging or announcing a release, follow the [Public-Release Verification Checklist](RELEASE_CHECKLIST.md). A running end-to-end OWASP ZAP scan still needs to be verified against an actual local ZAP service.

## Safety model

- Only test targets you own or are explicitly authorized to assess.
- Prefer local training labs while developing and validating scanner integrations.
- Keep the service bound to loopback unless a deliberate, separately secured deployment design is implemented.
- External scanning tools must use fixed adapters, explicit scope, timeouts, and safe defaults.
- Active scanning, crawling, and intrusive checks must be separate, explicit capabilities—not hidden side effects of a profile name.
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
- [ ] Verify ZAP adapter against a running local ZAP service
- [ ] Improve ZAP service setup guidance and actionable diagnostics

### Phase 2 — Safe, modular scanner integrations

- [ ] Add a dedicated HTTP/header integration with repeatable evidence
- [ ] Integrate WhatWeb as an optional technology-discovery module
- [ ] Integrate `testssl.sh` as an optional TLS assessment module
- [ ] Make each integration report installed, version, execution, timeout, and error status distinctly
- [ ] Add integration-level tests using mocked tool outputs and local test targets
- [ ] Connect scan profiles to clearly documented, real module sets

### Phase 3 — Scan operations and reporting

- [ ] Live scan progress and useful per-module status
- [ ] Safe cancellation and consistent timeout handling
- [ ] Stronger scheduler execution and restart/reboot behavior
- [ ] HTML report alongside CSV
- [ ] Finding lifecycle: accepted, remediated, false positive, and retest required
- [ ] Retest comparisons and measurable risk reduction
- [ ] Better scan logs and exportable diagnostic bundles

### Phase 4 — Validation lab and security hardening

- [ ] Repeatable end-to-end validation against a local OWASP Juice Shop lab
- [ ] Validate target scope and redirect behavior for every adapter
- [ ] Add rate limits and robust input validation for scan creation
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
