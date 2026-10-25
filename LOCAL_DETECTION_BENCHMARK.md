# Local SQL injection and XSS detection benchmark

This benchmark fixture is intentionally vulnerable and exists only for local scanner testing. It binds to **127.0.0.1** and must never be exposed to a LAN, public interface, or production environment.

## Fixture cases

- GET /search?q=...: deliberately reflects the query parameter into HTML without output encoding (reflected-XSS signal).
- GET /product?id=1%27: deterministically returns a simulated SQL syntax error (SQLi signal).
- GET /product?id=1: clean control case.
- The SQLi fixture simulates a database error; it is not backed by a real database and cannot establish coverage for blind, time-based, or second-order SQL injection.
- This fixture does not include stored XSS.

## Start and verify the fixture

From the repository root:

    python3 scripts/local_vuln_benchmark_fixture.py --port 18080

In another terminal, verify the clean and vulnerable cases:

    curl -i 'http://127.0.0.1:18080/product?id=1'
    curl -i 'http://127.0.0.1:18080/product?id=1%27'
    curl -i 'http://127.0.0.1:18080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'

Stop the fixture with Ctrl+C when finished.

## Wapiti benchmark procedure

Run Wapiti only against the loopback fixture URL above, with explicit scope limited to the local fixture. Use a temporary output path and retain the raw JSON report alongside the benchmark notes. Record Wapiti version, modules, runtime, process exit code, detected SQLi/XSS records, their URL/parameter/evidence, and any expected signals missed. Do not count a parser-only test as a detection hit.

The scanner adapter's current Wapiti module list includes sql and xss, but its full adapter has broader crawler and exclusions behavior. A direct Wapiti run and a DKCISSP adapter run should be recorded separately. Keep both restricted to 127.0.0.1:18080; do not substitute external targets.

## Interpretation

- A positive result means only that the particular fixture signal was detected in this run.
- A miss is a benchmark failure to investigate, not proof the vulnerability class is unsupported everywhere.
- A finding is not automatically confirmed solely because Wapiti reports it; review evidence and scope.
- Do not claim broad SQLi/XSS coverage from these two narrow cases. Stored XSS, blind/time-based SQLi, authenticated flows, framework contexts, and false-positive behavior remain out of scope.
- The coverage matrix must remain unverified until the live benchmark output is reviewed and recorded.
