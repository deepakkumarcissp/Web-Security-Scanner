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
- SQLi remains **unverified** until a database-backed local fixture or a known vulnerable lab input produces a reproducible expected finding with useful evidence.
- XSS has one observed reflected-XSS hit in direct Wapiti; the full DKCISSP adapter path and broader XSS contexts remain unverified.
