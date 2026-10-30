# DKCISSP Web Security Scanner

**DKCISSP — Where Security Becomes Simple.**  
*Security Is Better Together.*

A free, community-built vulnerability scanner that runs on your own Kali Linux machine. It brings the best open-source web-security tools behind one dashboard, decides which of them a target needs, asks before it installs anything, and tells you plainly what was and was not checked.

> **Project principle:** show what actually ran, show the evidence, explain the risk, and never call an assessment complete when a check did not finish. A tool is never reported as working just because it is listed in the UI.

**Status:** the **web-application engine** is working and tested. Authenticated (logged-in) scanning works for common logins. Network scanning and compliance checks are on the [roadmap](#roadmap) and are not built yet. Findings are signals for investigation, not proof. Only scan systems you own or are explicitly authorized to assess.

## Contents

[Install in one command](#install-in-one-command) ·
[Your first scan](#your-first-scan) ·
[Verify an install](#verify-an-install-automatically) ·
[How it works](#how-it-works) ·
[Assessment profiles](#assessment-profiles) ·
[Engines](#engines) ·
[Platform coverage](#platform-coverage) ·
[Scan results and status](#scan-results-and-status) ·
[Tool approvals](#tool-approvals) ·
[Planner and coverage notes](#planner-and-coverage-notes) ·
[Authenticated scanning](#authenticated-scanning) ·
[Browser crawling](#browser-crawling-single-page-apps) ·
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

## Verify an install automatically

One command checks that what GitHub serves right now installs and works on your machine, with no manual steps:

```bash
curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Web-Security-Scanner/main/verify.sh | bash
```

It downloads the latest scanner into a **throwaway folder**, installs it with the real installer, starts it on a spare port with its own empty database, runs a real Standard scan against a small built-in test website, and checks about 30 things: the dashboard, the API, the security-header, form, API and GraphQL findings, truthful scan status, the tool-approval flow (it only ever *declines*; nothing is installed), the exports and the retest comparison. It then stops everything, deletes the folder and prints **PASS** or **FAIL** (exit code 0 or 1) and writes a JSON report to `~/dkcissp-verify-reports/`. Your real installation and your `data.sqlite3` are never touched. A scanning tool that is not installed on your machine is shown as a warning, not a failure.

Options: `--branch NAME`, `--port N`, `--scan-timeout SECONDS`, `--report-dir DIR`, `--keep` (keep the throwaway install for inspection). Run it from a checkout (`./verify.sh`) to test the repository you have.

**It also runs on GitHub by itself.** The *Install check* workflow repeats this on every push and pull request, every day, and on demand, on Ubuntu, on a real **Kali Linux** container, and through the exact one-line command above. A red cross on the repository means a new user would hit a problem. Reports are attached to each run.

**Letting an assistant run it for you.** In Claude Desktop with the Desktop Commander connector (or Claude Code on your laptop), ask: *"Run the DKCISSP verify command and tell me the result"*. The command is self-contained, so the assistant only needs to run it and read the report.

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
   2. Discovery            same-origin crawl (≤12 URLs); collects forms and script URLs as it goes
   3. Platform detection   which of 60+ platforms the site runs (platforms.py)
   4. Deep/Active          ffuf hidden-content discovery, plus extra paths for the detected framework
   5. Forms & APIs         forms, API paths named in the site's scripts, API documentation, GraphQL (signals.py)
   6. Specialist engines   Nuclei (general + platform-targeted templates) · WhatWeb · testssl.sh · Nikto
                           wpscan (WordPress) · droopescan (Drupal, Joomla, SilverStripe, Moodle)
                           Wapiti · sqlmap · dalfox (Active) · OWASP ZAP passive alerts when its API is running
   7. Planner (planner.py) which checks applied, and honest "not covered" notes for what no engine here can do
   8. Normalise            severity · evidence · confidence · remediation, deduplicated
   9. Status               completed  or  completed_with_gaps  (listing every gap)
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
| **Standard** | same-origin discovery (up to 12 URLs), platform detection, forms and API analysis, Nuclei (30 general templates plus up to 20 for the detected platform), WhatWeb, testssl.sh (HTTPS targets), wpscan if WordPress is detected (passive), droopescan if Drupal, Joomla, SilverStripe or Moodle is detected | recommended starting point |
| **Deep** | Nikto, ffuf hidden-content discovery (plus framework-specific paths), Nuclei (60 general plus up to 40 platform templates), wpscan with bounded active detection and user enumeration, a larger droopescan module list | more requests; use on targets you control |
| **Active** | Wapiti, sqlmap and dalfox payload testing, including parameterised API URLs found in scripts and API descriptions | can submit payloads and change application state; needs a separate approval tick box; cannot be scheduled |

Use staging or a lab target for Active scans.

## Engines

All tools are run with fixed, bounded arguments from a built-in allow-list. Nothing from a scanned page is ever passed to a tool as a command, and URLs taken from crawled pages are validated before use.

| Engine | What it checks | Profiles | Limits and behaviour |
|---|---|---|---|
| Built-in checks | response headers, CSP, cookie flags, directory listing, redaction of cookie values in evidence | all | low-impact requests only |
| Discovery | links, resources, form targets and script URLs on the same origin | Standard+ | ≤12 URLs, depth 2, forms never submitted, no JavaScript executed, redirects off-origin rejected |
| Platform detection | which of 60+ platforms the site runs, from headers, cookies, markup, URLs and WhatWeb results | all | conservative: generic hints alone are never enough; reported as an Info finding with its evidence |
| Forms & APIs (built-in) | forms (HTTP logins, GET passwords, cross-origin posts, missing CSRF token as a labelled guess, upload forms); API paths named in the site's scripts, checked with GET; OpenAPI/Swagger documents; GraphQL and introspection | Standard+ | GET only, same origin, nothing submitted, scripts are read and never run; about 40 requests and 60 seconds at most |
| [Chromium](https://www.chromium.org/) (headless) | **renders JavaScript single-page apps** so links, forms and API calls that only exist in the browser are found; token-in-browser-storage and mixed-content checks | Standard+ when the site looks like a single-page app | needs your approval to install (`apt install chromium`); ≤10 pages (Deep 14), 45 s (Deep 75 s); GET only; see [Browser crawling](#browser-crawling-single-page-apps) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | known exposures and misconfigurations from a curated local template set, **plus templates written for the detected platform** (for example Jenkins, Spring Boot, Jira) | Standard+ | 30 general (60 in Deep) plus up to 20 (40) platform templates; GET-only templates, with state-changing, raw-request, payload, fuzzing and brute-force templates excluded; at most 5–6 URLs per run; 5 requests/second; redirects and OAST off; partial results kept on timeout. The first run on a fresh machine can be slow while Nuclei prepares its templates |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | technology fingerprinting | Standard+ | aggression level 1, no redirect following |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | TLS configuration | Standard+ (HTTPS) | 75-second cap, JSON report |
| [OWASP ZAP](https://www.zaproxy.org/) | passive alerts on the approved URLs | all, when its API is ready | passive only (no spider, no active scan); waits for ZAP's queue to drain; see [ZAP](#owasp-zap) |
| [wpscan](https://github.com/wpscanteam/wpscan) | WordPress core, plugins, themes, exposed files, user enumeration | Standard+ when WordPress is detected | Standard is passive; Deep adds bounded active detection and user enumeration; plugins and themes are detected passively (no slug brute-forcing); 2 threads; see [wpscan token](#wpscan-api-token) |
| [droopescan](https://github.com/SamJoan/droopescan) | version, modules/plugins, themes and default files for Drupal, Joomla, SilverStripe and Moodle | Standard+ when one is detected | HEAD requests, 2 threads, 100-name (Deep: 500) module and theme list, no redirects, no authentication or password attacks; needs an older Python than the newest releases, which Kali's package handles |
| [Nikto](https://github.com/sullo/nikto) | common web-server files and misconfigurations | Deep+ | bounded runtime and request delay, low-risk test groups only |
| [ffuf](https://github.com/ffuf/ffuf) | hidden files and directories (admin, backup, `.git`, `.env`, config) **plus paths specific to the detected framework** (for example Spring Boot actuator, Laravel Telescope, Tomcat manager) | Deep+ | built-in list of about 230 paths plus up to 120 platform paths, 10 requests/second, 4 threads, no recursion, no redirects followed; response bodies are not inspected, so exposed-file findings say "verify manually" |
| [Wapiti](https://wapiti-scanner.github.io/) | injection, file and configuration weaknesses | Active | depth 2, polite mode, 75-second budget; excludes SSRF, upload, stored XSS, brute force, time-based SQL and takeover modules |
| [sqlmap](https://sqlmap.org/) | SQL injection | Active | up to 4 same-origin parameterised URLs (including API URLs); detection only: level 1, risk 1, boolean/error/union techniques (no stacked queries), no data extraction or shell options |
| [dalfox](https://github.com/hahwul/dalfox) | reflected cross-site scripting | Active | up to 3 URLs; known parameter names only; no headless browser, parameter mining, blind callbacks or BAV; stops at the first verified payload per URL |

Tested against the real tools: ffuf 2.1, Nuclei with the full public template library, sqlmap 1.8, dalfox, wpscan 4.2 and droopescan on local fixtures (a vulnerable test app, a WordPress-style site, a Drupal-style site and a single-page app on Spring Boot with APIs and GraphQL). That proves invocation, scope limits and result parsing. It is not a benchmark of detection rates or false positives across real-world applications.

## Platform coverage

The scanner recognises these platforms and chooses its checks accordingly. "Templates" are Nuclei templates that passed the scanner's safety filters in the public template library at the time of testing. A dedicated tool goes deeper than templates where a good one exists.

| Group | Platforms | How they are checked |
|---|---|---|
| **Content management** | WordPress, Joomla, Drupal, TYPO3, SilverStripe, Ghost, Umbraco, Craft CMS, MODX, Concrete CMS, Adobe Experience Manager, Liferay, Sitecore | WordPress: wpscan + about 900 templates. Joomla and Drupal: droopescan + templates (150 and 16). SilverStripe: droopescan only (no templates exist). The rest: platform templates (2 to 41 each) |
| **E-commerce** | Magento / Adobe Commerce, PrestaShop, OpenCart, WooCommerce, Shopify | platform templates; WooCommerce is checked through the WordPress tools; Shopify is a hosted service, so only the storefront can be assessed (shown as a coverage note) |
| **Learning and community** | Moodle, MediaWiki, phpBB, Discourse, vBulletin | Moodle: droopescan + templates; phpBB, Discourse, vBulletin: templates; MediaWiki has no safe templates yet (coverage note) |
| **Admin and DevOps consoles** | Jenkins, GitLab, Gitea, Grafana, Kibana, SonarQube, Nexus, Artifactory, Portainer, phpMyAdmin, Adminer, Apache Tomcat, Webmin, cPanel, Plesk | platform templates plus framework paths for ffuf (for example Tomcat manager, Jenkins script console) |
| **Business applications** | Confluence, Jira, Nextcloud, ownCloud, Roundcube, Zimbra, SharePoint, Outlook Web App | platform templates (3 to 30 each) |
| **Frameworks and servers** | Laravel, Symfony, Django, Flask, Ruby on Rails, Spring Boot, Express, ASP.NET, Next.js, Nuxt, Struts, ColdFusion | platform templates plus framework-specific paths (Spring actuator, Laravel Telescope and `.env`, Rails routes, ASP.NET `trace.axd`) |
| **Front-end frameworks** | Angular, React, Vue | not a vulnerability target; they mark the site as a single-page app, which limits what a link crawler can see (coverage note, plus script-endpoint extraction) |

Platforms without safe templates, hosted platforms and front-end frameworks are reported in the scan as coverage notes, never silently ignored.

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

Every decision is stored with who and when (see **Decision history**). Decisions are accepted only from the local machine, and package names come only from the built-in list, never from scan output or user input. Tools that can be requested: Nuclei, Nikto, WhatWeb, testssl.sh, Wapiti, ffuf, wpscan, droopescan, sqlmap, dalfox. OWASP ZAP is not offered for automatic install because it needs a configured API service, not just a package.

## Planner and coverage notes

`planner.py` decides which specialist checks apply to a target from the profile, the detected platforms, and what the forms and API analysis found (a login form, a file-upload form, a single-page app, a GraphQL endpoint, API endpoints that want authentication, URLs with query parameters). After each scan, `summary.coverage` lists what was planned, which platforms were recognised and how each is covered, and what applied but **cannot be done by any engine in this version**. For example:

- a login form was found but no credentials were given, so the pages behind the login were not tested (give an [authenticated scan](#authenticated-scanning) credentials to test them);
- API endpoints answered 401/403 and were not tested behind a login (same remedy);
- a file-upload form was found, but upload restrictions were not tested;
- a GraphQL endpoint was found, but only introspection was checked;
- the site is a JavaScript single-page app, so screens that exist only in the browser were not crawled (endpoints named in its scripts were still read and checked);
- a platform was detected but has no safe Nuclei templates, or is a hosted service.

These appear as "Coverage note" cards in the dashboard. Notes do not change the scan status, but they are never hidden. Adding an engine means adding its rule in `planner.py`, its stage in `app.py`, tests and documentation. Platform signatures live in `platforms.py`; form, script, API and GraphQL reading lives in `signals.py`.

## Authenticated scanning

Most of a real application sits behind a login. Open **Assess Website → Authenticated scan (optional)**, choose how the site signs in, and tick the separate confirmation that the scanner may act as that user. **Use a dedicated test account**, never an administrator's.

Supported: a login form (the scanner reads the form, keeps hidden fields such as CSRF tokens, and finds the username/password fields itself), a JSON login API, a Bearer token, a session cookie, an API key or other header, and HTTP Basic. Optionally give a page or a piece of text that proves you are logged in.

What happens:

- The scanner signs in **once**. A wrong password is not retried and passwords are never guessed. If the site wants MFA, a CAPTCHA or a single-sign-on redirect, the scan says so and continues as a visitor; it does not try to get around them.
- It crawls the logged-in site with **GET requests only**, on the same origin, and never follows links that look like logout, delete, remove, reset, pay, checkout or similar. Forms other than the login are never submitted by the logged-in pass (Active scans keep their own separate approval).
- It checks the login itself (cookie flags, session fixation, credentials over plain HTTP, weak JWTs), re-checks the logged-in pages with the same header, form and API analysis, and watches the session; if it expires mid-scan it signs in again once.
- Nuclei, ffuf, sqlmap and dalfox receive the session through private (mode 0600) temporary files that are deleted afterwards, never on a command line. A tool that cannot use a session (ZAP passive, Nikto, WhatWeb, Wapiti and others) runs as a visitor, and the report says which tools were logged in and which were not.
- Credentials live in memory for the scan only. They are not stored in the database, logs, findings or exports; cookie values and tokens are scrubbed from evidence. Because of that, authenticated scans cannot be scheduled, and a tool you approve later runs without the login.

### Access-control testing (compare users)

Add an optional **second account** and the scanner compares who can open what, using only pages and API endpoints the crawl found (GET only, at most 30 pages, nothing guessed):

- **Visitor vs logged in:** a page found while logged in that a visitor can also open with the same content is reported (higher severity when it contains that user's own identifying text).
- **User vs user (broken access control / IDOR):** a page only account 1 was shown, opened directly as account 2 (and the reverse), is reported when it returns the same content. If the owner's identifying text appears in the other user's copy the finding is High; otherwise it is Low confidence and says to verify. Pages that show each user their own data at one URL (for example `/api/me`) are not reported.
- **Vertical (more privileged second account):** choose "more privileged" and pages only that account was shown, opened as the ordinary user, are reported.

Give each account a text that identifies its pages (an e-mail or username) for stronger results; the username is used if you leave it empty. Findings never contain page text, only status, size and similarity. The scan always notes what this cannot test: actions that change data, object IDs that no page links to, and role-specific buttons or fields. A shared page that was meant to be shared can look like a finding, so treat results as leads to verify.

Not supported yet: MFA, CAPTCHA, SSO/OAuth flows and logins that only work through JavaScript. For logged-in single-page apps see [Browser crawling](#browser-crawling-single-page-apps).

## Browser crawling (single-page apps)

Many modern sites send an almost empty page and build everything with JavaScript, so a link crawler sees very little. When a site looks like a single-page app (React, Angular, Vue and similar), the scanner opens it in a headless Chromium and reads what the browser ends up with: links that exist only in the rendered page (including `#/route` pages), forms built by scripts, and the API calls the app makes. Those pages, forms and endpoints then go through the same checks as everything else. With a login, a second browser pass runs as the logged-in user.

- **Approval first.** Chromium is installed only when you approve it (Kali: `apt install chromium`). If you decline, the report says the browser crawl was not assessed. If Chromium or Google Chrome is already installed it is used; set `DKCISSP_BROWSER` to point at a specific browser binary.
- **Read-only.** The scanner never clicks, types or submits anything. Inside the browser every request passes a gate: only GET leaves the browser (the app's own POST/PUT/DELETE calls are blocked and listed as "not sent"), same-origin links that look like logout, delete, pay or reset are blocked, other hosts are reachable only for GET downloads of scripts, styles, fonts and images and never receive your credentials, dialogs are dismissed, and downloads and pop-ups are refused.
- **Private.** Each run uses a throwaway browser profile that is deleted afterwards; a login session is handed to the browser in memory, never written to disk or put on a command line. Page text is not stored, and token-like values found in browser storage are reported by name only.
- **Extra findings:** access tokens kept in `localStorage`/`sessionStorage` (readable by any script on the page), mixed content, and which other hosts supply scripts.
- **Sandbox:** the browser keeps Chromium's sandbox, except when running as root or when you set `DKCISSP_BROWSER_NO_SANDBOX=1` (needed on some CI machines).

What it cannot do yet: it does not click through the app, so screens that appear only after clicking a button, scrolling or filling a form are not reached (the report says so), and JavaScript-only logins are not supported.

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
| `POST /api/scans` | start a scan (`target`, `profile`, `authorized`, `active_testing_approved`, optional `auth`, `auth_second`, `second_account_role` (`peer`/`more_privileged`) + `authenticated_testing_approved`) |
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
- Nuclei only runs templates that pass the scanner's own safety filter: HTTP only, GET only, no state-changing methods, no raw requests, payloads, fuzzing or brute-force, and no more than five requests each. Templates written for a detected platform go through the same filter.
- Software is never installed silently. Installs are limited to a built-in allow-list, need your approval each time, and are recorded.
- Secrets (the ZAP key, the wpscan token and any scan login) are never printed, stored in scan data or placed on command lines. Authenticated scans need their own approval, read pages only and never log out or delete.
- Tool status is verified (executable, version, service readiness), not assumed. A timeout or error is a gap, never a clean result.
- Findings are signals for investigation. Validate context and business impact before acting.

## Testing

```bash
python -m pip install pytest httpx
pytest -q
```

The suite (over 180 tests) uses a throwaway database, so it never touches your real `data.sqlite3`. GitHub Actions runs compilation and the suite on Ubuntu with Python 3.11. CI does not prove a clean Kali install, browser behaviour, or live tool integrations; before a release, follow the [Public-Release Verification Checklist](RELEASE_CHECKLIST.md).

## Repository layout

```text
app.py                 FastAPI application: scan engine, engine adapters, approval flow, API
auth.py                login handling, session, safety rules and token checks for authenticated scans
browser.py             headless-browser crawler for single-page apps (own DevTools client, read-only gate)
access.py              access-control comparison between a visitor and one or two accounts
planner.py             which specialist checks apply to a target; coverage notes
platforms.py           the platform catalogue and detection (60+ platforms)
signals.py             forms, script endpoints, API descriptions, GraphQL, framework paths
static/index.html      the dashboard (single page, no external assets)
wordlists/             built-in content-discovery list used by ffuf
scripts/               selftest.py (the end-to-end checks), testsite.py (a small site with logins) and the Juice Shop smoke test
tests/                 test suite and throwaway-database configuration
install.sh             one-command installer
verify.sh              automated end-to-end install check (also run by GitHub Actions)
run.sh / update.sh     start / update an existing install
requirements.txt       Python dependencies (FastAPI, uvicorn)
RELEASE_CHECKLIST.md   checks before publishing a release
KALI_WEB_SCANNER_TOOL_RESEARCH.md  notes on candidate tools
```

## Roadmap

The goal is a free, community-maintained alternative to commercial vulnerability scanners: web applications first, then your wider network.

| Stage | Status |
|---|---|
| Web-application engine: discovery, passive and active checks, approvals, honest status | **working** |
| Platform detection (60+ platforms) and platform-targeted checks (Nuclei templates, wpscan, droopescan, framework paths) | **working** |
| Forms, script-endpoint, API-documentation and GraphQL analysis | **working** |
| Credentialed (authenticated) scanning: login handling, authenticated crawl, API checks | **working** (MFA/SSO next) |
| Access-control comparison: visitor vs user vs second user (IDOR, vertical access) on crawled pages | **working** (ID enumeration and POST actions not covered) |
| Browser-based crawler for single-page apps (render, read links, forms and API calls; logged-in pass) | **working** (no clicking or form filling yet) |
| Dedicated GraphQL, upload and API-authorization testing | planned |
| Network engine: host discovery, ports, service and version detection | planned |
| CVE matching of detected services (NVD, CISA KEV, EPSS) with prioritisation | planned |
| Compliance and hardening checks, richer reports, multi-user and a service-grade scheduler | planned |

## Known limitations

- Web engine only; there is no network or host scanning yet. Authenticated scanning covers common logins but not MFA, CAPTCHA or SSO, and tools that cannot carry a session run as a visitor.
- Detection quality has been verified on local fixtures, not benchmarked against real-world applications; expect false negatives and false positives like any scanner. Platform detection is signature-based and conservative; a heavily customised site may not be recognised.
- Discovery is a bounded link crawler that does not run JavaScript. Single-page apps are rendered in a headless browser once you approve installing Chromium, but the browser never clicks or types, so screens reachable only through interaction are missed.
- Platform-targeted checks are only as good as the local Nuclei template library; a platform with no safe templates gets general checks only (shown as a coverage note). Keep the library updated.
- ffuf uses a short built-in list on purpose; it finds common exposures, not every hidden path. wpscan's vulnerability data needs an API token.
- droopescan's fingerprint version detection can be ambiguous (it reports a range) and it needs an older Python than the newest releases.
- Active scans of several URLs can take several minutes (dalfox needs up to about 2.5 minutes per clean URL). The first Nuclei run on a fresh machine can be slow.
- Pages found by ffuf are not given the built-in header checks (Nuclei and ZAP still cover them).
- The Schedules and Scanner Setup pages are hidden from the menu in this version; the scheduler needs the app running.

## Contributing

Keep the project safe, transparent and easy to validate. A new integration should include the tool's version detection, fixed invocation arguments, timeout and error handling, normalized findings, tests (including what the tool does when missing or timed out), documentation and an explanation of its scope. Do not include secrets, real customer targets or sensitive scan results in issues or commits.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).
