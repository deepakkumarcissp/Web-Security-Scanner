# DKCISSP Web Security Scanner

**DKCISSP — Where Security Becomes Simple.**  
*Security Is Better Together.*

A community-driven, local-first web application security scanner. The dashboard focuses on security risk, findings, target applications, scan history, scheduling, and reporting.

## MVP features

- DKCISSP white, navy, and red dashboard.
- Passive HTTP and response-header checks.
- Explicit authorization confirmation before scans and schedules.
- Scan history, findings, evidence, confidence, and remediation guidance.
- Daily and weekly recurring schedules with an optional first-run date/time.
- CSV findings export and JSON API endpoints.
- SQLite persistence, with diagnostics separated from the home dashboard.

## Current limitation

This MVP runs its own low-impact HTTP/header checks. **OWASP ZAP and other external Kali scanners are not yet integrated into scan execution.** Quick, Standard, and Deep profiles currently select passive checks only; they do not launch exploitation or intrusive tests.

Only scan systems you own or have explicit authorization to test. The development service binds to localhost and should not be exposed to untrusted networks.

## Run on Kali Linux

Requirements: Python 3.11+.

```bash
./run.sh
```

Then open **http://127.0.0.1:1004**.

The startup script creates a Python virtual environment, installs dependencies, and launches the service on loopback port **1004**. Manual setup is also supported:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 1004
```

## Scheduling

The Schedules page supports daily and weekly recurrence and an optional first-run date/time. Browser-selected time is sent as an ISO timestamp and stored in UTC. **The scanner process must remain running for scheduled scans to execute**; this MVP does not yet install a system service or guarantee scheduling across a reboot.

## CSV reporting

Use **Reports & Export → Download findings.csv**, or run:

```bash
curl -OJ http://127.0.0.1:1004/api/export/findings.csv
```

The CSV includes scan ID, target, severity, finding title, affected URL, evidence, remediation, confidence, and discovery timestamp.

## API endpoints

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/scans`
- `GET /api/scans` and `GET /api/scans/{id}`
- `GET /api/findings`
- `GET /api/export/findings.csv`
- `GET /api/schedules`
- `POST /api/schedules`
- `PATCH /api/schedules/{id}` to pause/resume
- `DELETE /api/schedules/{id}`

## Tests

```bash
python -m pip install pytest httpx
pytest -q
```

## Roadmap

1. Integrate OWASP ZAP through a fixed adapter with timeouts and scope restrictions.
2. Add live job progress, cancellation, and stronger scheduler operations.
3. Add approved optional scanner dependency setup.
4. Add HTML reporting and remediation/retest tracking.
5. Validate scanner integrations against the local Juice Shop lab.
