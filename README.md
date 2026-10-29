# DKCISSP Web Security Scanner

**DKCISSP — Where Security Becomes Simple.**  
*Security Is Better Together.*

A free, community-built vulnerability scanner that runs on your own Kali Linux machine. It brings the best open-source web-security tools behind one dashboard, decides which of them a target needs, asks before it installs anything, and tells you plainly what was and was not checked.

> **Project principle:** show what actually ran, show the evidence, explain the risk, and never call an assessment complete when a check did not finish. A tool is never reported as working just because it is listed in the UI.

**Status:** the **web-application engine** is working and tested. Network scanning, credentialed scanning and compliance checks are on the [roadmap](#roadmap) and are not built yet. Findings are signals for investigation, not proof. Only scan systems you own or are explicitly authorized to assess.

## Contents

[Install in one command](#install-in-one-command) ·
[Your first scan](#your-first-scan) ·
[How it works](#how-it-works) ·
[Assessment profiles](#assessment-profiles) ·
[Engines](#engines) ·
[Scan results and status](#scan-results-and-status) ·
[Tool approvals](#tool-approvals) ·
[Planner and coverage notes](#planner-and-coverage-notes) ·
[Configuration](#configuration) ·
[Local practice lab](#local-practice-lab) ·
[Scheduling, comparison, reports](#scheduling-retest-comparison-and-reports) ·
[API](#api-overview) ·
[Safety model](#safety-model) ·
[Testing](#testing) ·
[Repository layout](#repository-layout) ·
[Roadmap](#roadmap) ·
[Known limitations](#known-limitations)

## Install in one command

On Kali Linux (or any Debian-based system with internet access), open a terminal and run:

```bash
curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/install.sh | bash
```

That single command:

1. checks for `git`, `curl` and `python3` (3.9+ with `venv`) and installs only the missing ones with `apt` (you may be asked for your password);
2. downloads the scanner from this GitHub repository into `~/DKCISSP-Web-Security-Scanner`;
3. installs its Python packages in a private virtual environment (nothing is installed system-wide);
4. creates a `dkcissp-scanner` command;
5. starts the scanner and opens the dashboard at **http://127.0.0.1:1005** (press `Ctrl+C` in the terminal to stop it).

It does **not** install the scanning tools (Nuclei, Nikto, ZAP and so on). The scanner asks you, one tool at a time, on its [Approvals page](#tool-approvals) the first time a scan needs one.

**Prefer to read the script first?** Download it, look at it, then run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/install.sh
less install.sh
bash install.sh
```

**Installer options** (add them after `bash -s --` when piping, or directly when running the file):

| Option | Meaning |
|---|---|
| `--dir PATH` | install folder (default `~/DKCISSP-Web-Security-Scanner`) |
| `--port N` | port to run on (default `1005`) |
| `--branch NAME` | branch to install (default `main`) |
| `--no-start` | install only; do not start the scanner |
| `--no-browser` | do not open the dashboard automatically |

Example: `curl -fsSL …/install.sh | bash -s -- --port 1015 --no-browser`

**Daily use**

```bash
dkcissp-scanner          # start the scanner
dkcissp-scanner update   # update to the latest version (scan history is never touched)
```

If the command is not found right after installing, open a new terminal or run `export PATH="$HOME/.local/bin:$PATH"`. Running the installer again is safe: it updates an existing installation in place. If the install folder already exists and is not a scanner clone, the installer leaves it alone and tells you to choose another folder.

**Manual install** (if you prefer not to use the script):

```bash
git clone https://github.com/deepakkumarcissp/Web-Security-Scanner.git
cd Web-Security-Scanner
./run.sh
```

`run.sh` creates the virtual environment, installs the packages and starts the scanner on `127.0.0.1`. It refuses to start if the port is already in use and tells you how to pick another (`DKCISSP_PORT=1015 ./run.sh`). To update a manual install, run `./update.sh`.

**Uninstall:** delete the install folder and `~/.local/bin/dkcissp-scanner`. Your scan history is the file `data.sqlite3` inside the install folder; copy it first if you want to keep it.

## Your first scan

1. Open **http://127.0.0.1:1005** and choose **Assess Website** (or type a URL into **Quick assessment** in the left menu).
2. Enter the URL, pick an [assessment depth](#assessment-profiles), and tick the confirmation that you own the target or have permission to test it. No other registration is needed.
3. Watch the stage list: every tool shows its real state. When a tool is missing, the scan carries on and a card appears under **Approvals**. Approve the install to run that part, or skip it and the report records that the area was not assessed.
4. Open **Findings** for evidence and remediation advice, set a lifecycle status, and use **Reports & Export** to download a CSV or printable report.

New here? Practice on the intentionally vulnerable [local lab](#local-practice-lab), not on someone else's site.

## How it works

```text
                     ┌──────────────────────────────────────────────┐
  Browser dashboard  │  FastAPI application (app.py)  ·  SQLite     │
  127.0.0.1:1005 ───►│  scans, findings, schedules, tool requests   │
                     └───────────────┬──────────────────────────────┘
                                     │ starts a scan worker (2 at a time by default)
                                     ▼
   1. Built-in checks      HTTP, security headers, cookies, CSP, TLS use
   2. Discovery            same-origin crawl (≤12 URLs); Deep/Active add ffuf hidden-content discovery
   3. Specialist engines   Nuclei · WhatWeb · testssl.sh · Nikto · wpscan · Wapiti · sqlmap · dalfox
                           OWASP ZAP (passive alerts) when its API is running
   4. Planner (planner.py) which specialist checks apply to this target; honest "not covered" notes
   5. Normalise            severity · evidence · confidence · remediation, deduplicated
   6. Status               completed  or  completed_with_gaps  (listing every gap)
                                     │
        missing tool? ───────────────┘──► Approvals page ──► you approve ► install that one package
                                                                 │         ► run only that stage
                                                                 └ or skip ► report says "not assessed"
```

Everything runs on your machine. The dashboard is bound to `127.0.0.1`. The only traffic to a target is what the selected profile sends, and only to the origin you entered. No external fonts, scripts or telemetry are loaded by the dashboard.

## Assessment profiles

| Profile | What it adds | Notes |
|---|---|---|
| **Quick** | built-in HTTP, header and cookie checks | lowest impact; also asks ZAP for passive alerts if its API is running |
| **Standard** | same-origin discovery (up to 12 URLs), Nuclei (30 safe templates), WhatWeb, testssl.sh (HTTPS targets), wpscan *only if WordPress is detected* (passive) | recommended starting point |
| **Deep** | Nikto, ffuf hidden-content discovery, Nuclei (60 templates), wpscan with bounded active detection and user enumeration | more requests; use on targets you control |
| **Active** | Wapiti, sqlmap and dalfox payload testing | can submit payloads and change application state; needs a separate approval tick box; cannot be scheduled |

Use staging or a lab target for Active scans.

## Engines

All tools are run with fixed, bounded arguments from a built-in allow-list. Nothing from a scanned page is ever passed to a tool as a command, and URLs taken from crawled pages are validated before use.

| Engine | What it checks | Profiles | Limits and behaviour |
|---|---|---|---|
| Built-in checks | response headers, CSP, cookie flags, directory listing, redaction of cookie values in evidence | all | low-impact requests only |
| Discovery | links, resources and form targets on the same origin | Standard+ | ≤12 URLs, depth 2, forms never submitted, no JavaScript executed, redirects off-origin rejected |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | known exposures and misconfigurations from a curated local template set | Standard+ | 30 (Standard) or 60 templates, 5 requests/second, redirects and OAST off, partial results kept on timeout |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | technology fingerprinting | Standard+ | aggression level 1, no redirect following |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | TLS configuration | Standard+ (HTTPS) | 75-second cap, JSON report |
| [OWASP ZAP](https://www.zaproxy.org/) | passive alerts on the approved URLs | all, when its API is ready | passive only (no spider, no active scan); waits for ZAP's queue to drain; see [ZAP](#owasp-zap) |
| [wpscan](https://github.com/wpscanteam/wpscan) | WordPress core, plugins, themes, exposed files, user enumeration | Standard+ when WordPress is detected | Standard is passive; Deep adds bounded active detection and user enumeration; plugins and themes are detected passively (no slug brute-forcing); 2 threads; see [wpscan token](#wpscan-api-token) |
| [Nikto](https://github.com/sullo/nikto) | common web-server files and misconfigurations | Deep+ | bounded runtime and request delay, low-risk test groups only |
| [ffuf](https://github.com/ffuf/ffuf) | hidden files and directories (admin, backup, `.git`, `.env`, config) | Deep+ | built-in list of about 230 paths, 10 requests/second, 4 threads, no recursion, no redirects followed; response bodies are not inspected, so exposed-file findings say "verify manually" |
| [Wapiti](https://wapiti-scanner.github.io/) | injection, file and configuration weaknesses | Active | depth 2, polite mode, 75-second budget; excludes SSRF, upload, stored XSS, brute force, time-based SQL and takeover modules |
| [sqlmap](https://sqlmap.org/) | SQL injection | Active | up to 4 same-origin parameterised URLs; detection only: level 1, risk 1, boolean/error/union techniques (no stacked queries), no data extraction or shell options |
| [dalfox](https://github.com/hahwul/dalfox) | reflected cross-site scripting | Active | up to 3 URLs; known parameter names only; no headless browser, parameter mining, blind callbacks or BAV; stops at the first verified payload per URL |

Tested against the real tools: ffuf 2.1, sqlmap 1.8, dalfox and wpscan 4.2 on local fixtures (a vulnerable test app and a WordPress-style test site). That proves invocation, scope limits and result parsing. It is not a benchmark of detection rates or false positives across real-world applications.

## Scan results and status

A scan ends as one of:

| Scan status | Meaning |
|---|---|
| `completed` | every stage the profile selected finished cleanly |
| `completed_with_gaps` | findings were saved, but at least one stage did not fully run. The scan summary lists each gap under `assessment_gaps`. **Absence of findings does not cover a gap.** |
| `failed` | the scan could not start or stopped (for example the target was unreachable) |

Each stage reports its own state, shown in the dashboard:

| Stage state | Meaning | Counts as a gap? |
|---|---|---|
| `completed` | finished cleanly | no |
| `skipped` | the profile or target type deliberately excludes it (for example TLS on an HTTP site, or wpscan when WordPress was not detected) | no |
| `completed_with_warnings` | ran, but something limited it (for example a ZAP queue that did not drain, or wpscan without an API token) | **yes** |
| `partial_timeout`, `timeout` | time limit reached; findings so far are kept | **yes** |
| `unavailable`, `api_unreachable`, `error` | tool missing, service not running, or it failed | **yes** |
| `needs_tool_approval` | a tool is missing and waiting for your decision | **yes** |
| `skipped_install_not_permitted` | you declined the install | **yes** |
| `install_failed` | the install did not succeed | **yes** |

Every finding has a severity (High, Medium, Low, Info), affected URL, evidence, remediation advice and a confidence level, plus a lifecycle status you control (open, accepted, remediated, false positive, retest required) with notes.

## Tool approvals

The scanner never installs software on its own. If a tool a profile needs is missing, the scan keeps going, records a request that names what needed the tool, and finishes as `completed_with_gaps`. Open **Approvals** in the menu (a badge and a dashboard banner show how many are waiting):

- **Approve install** installs that one allow-listed package from the Kali repository with `apt-get` (through `pkexec`, or non-interactive `sudo -n` when you are not root), then runs only the missing stage and merges its findings into the same scan. If nothing else is missing, the scan becomes `completed`.
- **Skip** installs nothing. The report records: "*Tool* was not installed: installation was not approved by the assessor. Triggered by: *what needed it*. This area was not assessed."
- A failed install keeps the gap, shows the manual `sudo apt install …` command, and can be retried.

Every decision is stored with who and when (see **Decision history**). Decisions are accepted only from the local machine, and package names come only from the built-in list, never from scan output or user input. Tools that can be requested: Nuclei, Nikto, WhatWeb, testssl.sh, Wapiti, ffuf, wpscan, sqlmap, dalfox. OWASP ZAP is not offered for automatic install because it needs a configured API service, not just a package.

## Planner and coverage notes

`planner.py` holds the rules for which specialist checks apply to a target: the profile, technologies detected from headers, page markup and WhatWeb results, and whether URLs with query parameters were found. After each scan, `summary.coverage` lists what was planned and what applied but has **no engine in this version**. For example, if Joomla is detected, the dashboard shows a "Coverage note" that Joomla-specific checks are not available yet. Notes do not change the scan status, but they are never hidden.

Known rules without an engine yet: joomscan (Joomla) and droopescan (Drupal). Adding an engine means adding its rule in `planner.py`, its stage in `app.py`, tests, and documentation.

## Configuration

All settings are optional environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `DKCISSP_PORT` | `1005` | port used by `run.sh` / `dkcissp-scanner` |
| `DKCISSP_DB` | `data.sqlite3` in the install folder | where scan history is stored |
| `DKCISSP_MAX_CONCURRENT_SCANS` | `2` | simultaneous scans, 1 to 8 |
| `DKCISSP_NUCLEI_TEMPLATES` | auto-detected | path to the Nuclei template directory |
| `DKCISSP_ZAP_API_URL` | `http://127.0.0.1:8080` | OWASP ZAP API endpoint |
| `DKCISSP_ZAP_API_KEY` | none | ZAP API key (never returned by diagnostics) |
| `DKCISSP_ZAP_PASSIVE_TIMEOUT_SECONDS` | `30` (1 to 180) | how long to wait for ZAP's passive queue to drain |
| `DKCISSP_ZAP_PASSIVE_POLL_SECONDS` | `0.5` (0.1 to 2) | queue polling interval |
| `DKCISSP_WPSCAN_API_TOKEN` | none | WPScan API token for known-vulnerability data (see below) |

The installer also reads `DKCISSP_HOME`, `DKCISSP_BRANCH` and `DKCISSP_REPO_URL`.

### OWASP ZAP

ZAP is used for **passive alerts only**. The scanner fetches the approved same-origin URLs through a running ZAP, waits until ZAP's passive-scan queue has been observed empty twice in a row, then reads the alerts. If the queue does not drain in time, or its status cannot be read, the stage is `completed_with_warnings` with `passive_queue_status` set to `timeout` or `error`. No ZAP spider or active scan is started. Start ZAP with its API enabled (for example `zaproxy -daemon -port 8090 -config api.key=YOURKEY`) and point `DKCISSP_ZAP_API_URL` and `DKCISSP_ZAP_API_KEY` at it. A listening port alone is not proof that ZAP is running: the diagnostics distinguish a missing API, a wrong service on the port, an authentication failure and a ready state.

### wpscan API token

wpscan finds WordPress components, but its **known-vulnerability database needs an API token**. A free token (limited daily lookups) is available at <https://wpscan.com/register>. Set `DKCISSP_WPSCAN_API_TOKEN` (or `WPSCAN_API_TOKEN`) before starting the scanner. The token is passed to wpscan through its environment only, never on the command line, and it is never stored or logged. Without a token the scan still lists the core version, plugins, themes, exposed files and user enumeration, but the stage is `completed_with_warnings` with the reason "known-vulnerability data was not included", so you never mistake it for a full vulnerability check. wpscan downloads its own database on first use, which needs internet access to `data.wpscan.org`.

## Local practice lab

The scanner and the lab installer are separate repositories. The lab starts intentionally vulnerable targets; this project scans them.

```bash
git clone https://github.com/deepakkumarcissp/Kali-Web-Application-Security-Lab.git
cd Kali-Web-Application-Security-Lab
chmod +x install.sh lab.sh scenarios.sh
./install.sh
```

If you already cloned the lab, run `./lab.sh start` from its directory. Then, on **Assess Website**, choose a target from **DKCISSP Local Lab Target** (or type its URL), tick the authorization box and start with **Quick** or **Standard**:

| Training target | URL |
|---|---|
| OWASP Juice Shop | `http://127.0.0.1:1003` |
| DVWA | `http://127.0.0.1:1006` |
| OWASP WebGoat | `http://127.0.0.1:1007/WebGoat` |

These applications are intentionally vulnerable. Keep their ports bound to `127.0.0.1`, never expose them to a network, and never use production credentials or data. If your machine uses an HTTP proxy environment variable, make sure it does not intercept requests to local lab targets.

A repeatable smoke test is included: `python3 scripts/validate_juice_shop.py` runs a Standard assessment against a local Juice Shop and writes a JSON evidence report to `validation-reports/` (git-ignored). A PASS means the workflow completed; it does not mean every known issue was detected.

## Scheduling, retest comparison and reports

**Scheduling.** Daily or weekly recurring Quick, Standard or Deep scans, with an optional first-run time (stored in UTC). Active scans cannot be scheduled. The scanner process must be running for schedules to fire; there is no guarantee across reboots and it is not a durable job service yet. Schedules are managed through the API (`/api/schedules`); the Schedules page exists but is hidden from the menu in this version.

**Retest comparison.** After remediation, **Scan History → Compare** matches a scan against the latest earlier completed scan of the same target and profile: new findings, persistent findings, findings no longer detected, severity changes and a simple risk-point change (Critical 10, High 8, Medium 4, Low 1, Info 0, a prioritisation heuristic and not CVSS). Matching uses the normalized title and URL path. A finding that is absent later is not proof it was fixed, and if either scan had gaps the comparison says so.

**Reports.** **Reports & Export** offers a CSV (untrusted cell values are neutralised against spreadsheet-formula injection) and a printable HTML report (use the browser's Print / Save as PDF). Both include severity, evidence, remediation, confidence and lifecycle details. Or from the command line:

```bash
curl -OJ http://127.0.0.1:1005/api/export/findings.csv
```

## API overview

The dashboard uses a JSON API on the same port.

| Method and path | Purpose |
|---|---|
| `GET /api/health` | service health |
| `GET /api/dashboard` | totals and recent activity |
| `POST /api/scans` | start a scan (`target`, `profile`, `authorized`, `active_testing_approved`) |
| `GET /api/scans`, `GET /api/scans/{id}` | history; one scan with findings, stage status and tool requests |
| `GET /api/scans/{id}/comparison` | retest comparison |
| `GET /api/findings`, `PATCH /api/findings/{id}/lifecycle` | findings; update a lifecycle status and notes |
| `GET /api/tool-requests`, `POST /api/tool-requests/{id}/decision` | list approval requests; approve or decline (local machine only) |
| `GET /api/tools`, `POST /api/tools/install/{tool}` | tool readiness; install one allow-listed tool (local only, explicit approval) |
| `GET/POST /api/schedules`, `PATCH/DELETE /api/schedules/{id}` | recurring scans |
| `GET /api/export/findings.csv`, `GET /api/export/findings.html` | exports |

An older asset-inventory API (`/api/assets…`, including passive certificate-transparency subdomain discovery) is still present for later use. It has no screen and is not required to scan: any URL with the authorization confirmation can be scanned.

## Safety model

- Only test targets you own or are explicitly authorized to assess. Every scan and schedule requires an authorization confirmation.
- The service binds to loopback. Do not expose it, or its tool-install endpoints, to an untrusted network.
- Active testing needs a second, separate approval and cannot be scheduled. Its payload tools run detection-only settings; there is no data extraction, no shell access and no brute forcing.
- External tools run from fixed argument lists with timeouts and request limits, never through a shell, and only against the origin you entered. Findings from tools are filtered back to that origin.
- Software is never installed silently. Installs are limited to a built-in allow-list, need your approval each time, and are recorded.
- Secrets (the ZAP key and the wpscan token) are never printed, stored in scan data or placed on command lines.
- Tool status is verified (executable, version, service readiness), not assumed. A timeout or error is a gap, never a clean result.
- Findings are signals for investigation. Validate context and business impact before acting.

## Testing

```bash
python -m pip install pytest httpx
pytest -q
```

The suite (over 110 tests) uses a throwaway database, so it never touches your real `data.sqlite3`. GitHub Actions runs compilation and the suite on Ubuntu with Python 3.11. CI does not prove a clean Kali install, browser behaviour, or live tool integrations; before a release, follow the [Public-Release Verification Checklist](RELEASE_CHECKLIST.md).

## Repository layout

```text
app.py                 FastAPI application: scan engine, engine adapters, approval flow, API
planner.py             which specialist checks apply to a target; coverage notes
static/index.html      the dashboard (single page, no external assets)
wordlists/             built-in content-discovery list used by ffuf
scripts/               local validation scripts (Juice Shop smoke test)
tests/                 test suite and throwaway-database configuration
install.sh             one-command installer
run.sh / update.sh     start / update an existing install
requirements.txt       Python dependencies (FastAPI, uvicorn)
RELEASE_CHECKLIST.md   checks before publishing a release
KALI_WEB_SCANNER_TOOL_RESEARCH.md  notes on candidate tools
```

## Roadmap

The goal is a free, community-maintained alternative to commercial vulnerability scanners: web applications first, then your wider network.

| Stage | Status |
|---|---|
| Web-application engine: discovery, passive and active checks, approvals, honest status | **working** (this release) |
| More technology-specific engines (Joomla, Drupal) and wider wordlists | next |
| Smarter planning: choose tools from more signals (forms, APIs, frameworks) | next |
| Network engine: host discovery, ports, service and version detection | planned |
| CVE matching of detected services (NVD, CISA KEV, EPSS) with prioritisation | planned |
| Credentialed (authenticated) scanning | planned |
| Compliance and hardening checks, richer reports, multi-user and a service-grade scheduler | planned |

## Known limitations

- Web engine only. There is no network, host or credentialed scanning yet.
- Detection quality has been verified on local fixtures, not benchmarked against real-world applications; expect false negatives and false positives like any scanner.
- Discovery is a bounded link crawler: it does not run JavaScript, so client-side routes and pages behind a login are missed.
- ffuf uses a short built-in list on purpose; it finds common exposures, not every hidden path. wpscan's vulnerability data needs an API token.
- Active scans of several URLs can take several minutes (dalfox needs up to about 2.5 minutes per clean URL).
- Pages found by ffuf are not given the built-in header checks (Nuclei and ZAP still cover them).
- The Schedules and Scanner Setup pages are hidden from the menu in this version; the scheduler needs the app running.

## Contributing

Keep the project safe, transparent and easy to validate. A new integration should include the tool's version detection, fixed invocation arguments, timeout and error handling, normalized findings, tests (including what the tool does when missing or timed out), documentation and an explanation of its scope. Do not include secrets, real customer targets or sensitive scan results in issues or commits.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
