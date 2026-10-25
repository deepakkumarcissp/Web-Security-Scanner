# Local SQL injection and XSS detection benchmark

This benchmark fixture is intentionally vulnerable and exists only for local scanner testing. It binds to **127.0.0.1** and must never be exposed to a LAN, public interface, or production environment.

## Fixture cases

- GET /search?q=...: deliberately reflects the query parameter into HTML without output encoding (reflected-XSS signal).
- GET /product?id=1%27: currently returns a simulated SQL syntax error; this is **not a reliable SQL-injection oracle**.
- GET /product?id=1: clean control case.
- The product route is not backed by a functioning database query. A generic HTTP 500 response is not evidence that SQL injection was detected.
- This fixture does not include stored XSS.

## Observed direct Wapiti benchmark: local fixture

Recorded from the local run on 2026-10-25 using Wapiti 3.2.10 against http://127.0.0.1:18080/ with scope limited to the fixture, modules `sql,xss`, depth 2, max-links 10, max-files-per-dir 5, max-parameters 10, max scan time 45 seconds, max attack time 8 seconds, one task, polite mode:

- Crawled pages: 5.
- Reflected XSS: 1 finding on GET /search, parameter `q`.
- SQL injection: 0 confirmed findings.
- SQL module anomaly: an HTTP 500 while testing `/product`, parameter `id`. This is recorded as an anomaly, not a SQLi hit.
- XSS module also observed an HTTP 500 anomaly on `/product`; this is not an XSS hit.
- Raw JSON report was saved locally at `/tmp/dkcissp-wapiti-benchmark.json` and is not committed to the repository.

Interpretation: this run demonstrates one narrow reflected-XSS detection path only. It does not establish broad XSS coverage. SQLi remains unverified because the fixture's simulated error does not establish database-backed injection behavior.

## Observed direct Wapiti benchmark: Juice Shop loopback lab

A follow-up run on 2026-10-25 used Wapiti 3.2.10 against `http://127.0.0.1:1003/`, with scope `folder`, only the `sql` module, a fresh isolated Wapiti session, depth 2, at most 10 links per page, 5 files per directory, 10 parameters, 45 seconds total scan time, 8 seconds per attack, one task, and polite mode.

- Crawled pages: 18.
- SQL Injection findings: 0.
- Blind SQL Injection findings: 0.
- SQL-related anomalies: 0.
- Wapiti exit code: 0.
- Raw report: `/tmp/dkcissp-wapiti-juice-shop-sqli-fresh.json` (local-only; not committed).

This is a valid negative result for this specific unauthenticated, bounded crawl—not proof that Juice Shop or SQLi detection generally has no vulnerabilities. The crawler did not demonstrate coverage of a known vulnerable SQLi input in this run, so the expected-positive benchmark remains incomplete.

## Start and verify the fixture

From the repository root:

    python3 scripts/local_vuln_benchmark_fixture.py --port 18080

In another terminal, verify the clean and test cases:

    curl -i 'http://127.0.0.1:18080/product?id=1'
    curl -i 'http://127.0.0.1:18080/product?id=1%27'
    curl -i 'http://127.0.0.1:18080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'

Stop the fixture with Ctrl+C when finished.

## Wapiti benchmark procedure

Run Wapiti only against loopback fixtures or the explicitly local Juice Shop lab, with scope limited to the intended local target. Use a fresh session when repeatability matters and a temporary output path. Record Wapiti version, modules, runtime, process exit code, detected SQLi/XSS records, their URL/parameter/evidence, and any expected signals missed. Do not count a parser-only test or a generic server error as a detection hit.

The scanner adapter's current Wapiti module list includes sql and xss, but its full adapter has broader crawler and exclusions behavior. A direct Wapiti run and a DKCISSP adapter run should be recorded separately. Keep all benchmark targets loopback-only; do not substitute external targets.

## Interpretation and next steps

- A positive result means only that the particular fixture signal was detected in that run.
- A miss is a benchmark failure to investigate, not proof the vulnerability class is unsupported everywhere.
- A finding is not automatically confirmed solely because Wapiti reports it; review evidence and scope.
- Do not claim broad SQLi/XSS coverage from these narrow cases. Stored XSS, blind/time-based SQLi, authenticated flows, framework contexts, and false-positive behavior remain out of scope.
- Historical status note: SQLi was unverified during the initial simulated-error and Juice Shop crawl runs. This was superseded by the end-to-end JSON/SQLite benchmark result recorded in the latest section below.
- XSS has one observed reflected-XSS hit in direct Wapiti; the full DKCISSP adapter path and broader XSS contexts remain unverified.


## Follow-up: known SQLi behavior in Juice Shop login API

A controlled manual request was made on 2026-10-25 to the loopback-only lab endpoint `POST http://127.0.0.1:1003/rest/user/login`. A normal invalid account returned HTTP 401, while a classic SQL-injection test value in the JSON `email` field with an invalid password returned HTTP 200 and an authentication response. The response token was not retained in the repository or documentation. This is evidence that this local training app exposes an expected-positive SQLi behavior at that endpoint; it is not evidence that DKCISSP or Wapiti detected it.

A targeted Wapiti attempt against that endpoint used Wapiti's `--data` option, which sends URL-encoded form data. The Juice Shop endpoint expects JSON, so this was a mismatched request format. Wapiti logged an HTTP 500 anomaly, reported no SQL Injection or Blind SQL Injection findings, and exited with code 0. This attempt is therefore **inconclusive**, not a positive detection and not a valid negative benchmark.

### Historical implementation gap

Historical note: when this attempt was run, the DKCISSP Wapiti adapter did not accept an explicit JSON request body or OpenAPI schema. The OpenAPI-aware SQLMap adapter and the end-to-end SQLite benchmark were added later and are documented below. Juice Shop itself remains a separate unresolved schema-discovery case.


### OpenAPI-driven Wapiti follow-up

A temporary OpenAPI 3.0 specification describing the Juice Shop login endpoint was created under `/tmp` and used with Wapiti's `--swagger` option. The targeted run did send an `application/json` POST to `/rest/user/login`, confirming that Wapiti can exercise this endpoint when given an API schema. It again logged an HTTP 500 anomaly for a generated malformed-input request and reported no SQL Injection or Blind SQL Injection finding. The same result occurred when scope was narrowed to the login URL. Temporary specifications, reports, and session databases were kept outside the repository.

Historical result: OpenAPI enabled Wapiti to send JSON requests to the Juice Shop login route, but its SQL module still did not detect the manually demonstrated bypass. The product now has a separate OpenAPI-aware SQLMap adapter. This earlier Wapiti miss remains valid evidence for that tool/run; the positive SQLMap result on the separate SQLite fixture is documented below. Do not treat a malformed-input 500 as proof of SQLi detection.


## Repeatable Juice Shop API expected-positive oracle

A loopback-only benchmark harness is now available at `scripts/benchmark_juice_shop_sqli.py`. Run it while the local Juice Shop training app is available on port 1003:

    python3 scripts/benchmark_juice_shop_sqli.py

The script sends a normal invalid-login control and a known boolean-based injection test to `POST /rest/user/login`. It only accepts plain HTTP loopback base URLs, suppresses response tokens, and exits non-zero if the control/test behavior does not match expectations. Unit tests verify loopback enforcement, expected-positive classification, token suppression, and that a generic HTTP 500 is not counted as a hit.

Observed result on 2026-10-25: control returned HTTP 401 with the invalid-credentials response; test returned HTTP 200 with an authentication response. The oracle passed. This proves a repeatable expected-positive behavior exists in the local training app, but it does not mean a scanner detected it.

A bounded sqlmap 1.10.8 run against the Juice Shop JSON endpoint (parameter `email`, boolean-based technique, level 2, risk 1, one thread, five-second timeout, no retries) did not identify the parameter as injectable and recorded HTTP 401/500 responses. Wapiti's OpenAPI-driven JSON attempt likewise produced a malformed-input HTTP 500 anomaly but no confirmed SQLi finding. These historical attempts missed the Juice Shop endpoint; they do not represent the later positive SQLMap result on the dedicated SQLite fixture, documented in the latest end-to-end section below.


## OpenAPI-aware SQLMap integration (engineering increment)

The Active profile now has an optional SQLMap adapter. It looks for common OpenAPI/Swagger JSON locations on the exact same origin, accepts only a JSON object with a `paths` map, rejects cross-origin server bases and operation URLs, and tests at most two GET/POST operations and two fields per operation. It uses SQLMap's low risk/level, one thread, short per-request timeouts, no retries, and a bounded injection-test runtime. Only output containing SQLMap's explicit injection-point classification plus parameter/type evidence is normalized as a High finding. HTTP 500 responses or generic response changes are not enough. This adapter runs only in the separately approved Active profile.

Regression tests cover JSON operation extraction, rejection of an external OpenAPI server base, and both negative and explicit-positive SQLMap output parsing. The adapter was also exercised against local Juice Shop; it did not discover a machine-readable OpenAPI schema at the common paths, so it did not launch SQLMap against the login endpoint. Juice Shop's Swagger UI paths returned the app's HTML fallback rather than a raw JSON schema. This is a documented coverage gap, not a positive detection.

The known Juice Shop login benchmark still passes its control-vs-test oracle, but SQLMap/Wapiti have not produced a confirmed finding on that endpoint because schema discovery is unresolved. The separate SQLite-backed fixture now validates the integrated SQLMap path for one narrow case. Remaining work is explicit schema configuration and expansion to more database/query patterns.


## Latest end-to-end SQLi result (2026-10-25): validated narrow case

The database-backed fixture and one-command runner are now committed as source candidates:

- `scripts/local_sqli_api_benchmark_fixture.py` — deliberately vulnerable SQLite-backed JSON login API, bound to loopback only, with a machine-readable OpenAPI document.
- `scripts/run_sqlmap_api_benchmark.py` — starts the fixture, isolates the scanner SQLite database, verifies the control/test oracle, invokes the real DKCISSP SQLMap adapter, prints sanitized JSON evidence, and always stops the fixture.

Run from the repository root:

    python3 scripts/run_sqlmap_api_benchmark.py

Observed end-to-end result: oracle passed; OpenAPI discovery found one POST operation; SQLMap tested two JSON parameters; the DKCISSP adapter normalized two High-severity SQL Injection findings using explicit SQLMap injection-point output. The run completed in about three seconds. No live scanner database was used, and the fixture process was terminated after the run.

This changes the status from unverified to **validated for one narrow JSON/SQLite training-fixture case**. It is not a claim of comprehensive SQLi coverage. Juice Shop still does not expose a raw OpenAPI JSON schema at the common discovery paths, and the adapter needs additional expected-positive cases for other database/query patterns, schema references, and authenticated API flows. Historical Juice Shop/Wapiti misses above remain accurate for those specific attempts and are not overwritten by this separate positive fixture.


## Configurable same-origin OpenAPI discovery

The SQLMap adapter now checks `DKCISSP_OPENAPI_URL` before the common schema paths. Set it to a path such as `/internal/openapi.json` for an API whose machine-readable schema is published at a non-standard location. A configured absolute URL is accepted only when it is on the target's exact origin; a cross-origin schema is ignored and never requested. The configured path does not expand scan scope, and the same bounded operation/field/runtime limits remain in force.

Example for a controlled authorized test:
```bash
DKCISSP_OPENAPI_URL=/internal/openapi.json python3 scripts/run_sqlmap_api_benchmark.py
```
The benchmark fixture already exposes its schema at a common path, so this command is a configuration example rather than a separate positive-result claim. The explicit schema setting is covered by unit tests for a non-standard same-origin path and cross-origin rejection.
