# Kali Linux web application security tool research

This is an integration shortlist for DKCISSP, not a claim that every tool is installed or integrated. Choose tools by distinct capability, scoped execution, machine-readable output, and ability to explain evidence. Run only against systems owned by the user or explicitly authorized for assessment.

## Recommended shortlist

| Priority | Tool | Main value | Integration idea | Guardrails |
|---|---|---|---|---|
| 1 | Nuclei | Template-driven detection of known exposures, misconfigurations, and specific vulnerability patterns | JSONL adapter with pinned template set/version, severity filters, rate cap, timeout, and normalized evidence | Never run the entire template ecosystem by default; exclude intrusive, fuzzing, DoS, and out-of-band templates unless separately enabled. Templates are code-like detection logic and require updates/review. |
| 2 | Nikto | Common web-server misconfiguration and outdated-file checks | Optional explicit “server checks” module with machine-readable output if supported by installed version | Can be noisy and generate many requests; separate from Quick scan and cap runtime/request rate. |
| 3 | Wapiti | Black-box web vulnerability testing of pages/forms | Later opt-in active scan adapter for a dedicated lab/profile, with output parser and per-target scope restrictions | Actively submits payloads; do not run in passive profiles or against production without explicit authorization and change approval. |
| 4 | Katana or hakrawler | URL/endpoint discovery for building an application map | First create a discovery-only module that emits candidate URLs; do not scan discovered URLs until same-origin/scope checks approve them | Redirects, subdomains, and discovered links must not silently expand authorized scope. |
| 5 | httpx (ProjectDiscovery) | HTTP service probing and metadata collection for an approved asset list | Add asset verification/HTTP metadata enrichment, not vulnerability severity findings | Feed only approved inventory assets; avoid turning it into unrestricted internet-wide probing. |
| 6 | Wafw00f | Identifies likely web application firewall presence | Informational signal in technology/exposure view | WAF detection is heuristic and must not be treated as proof of protection or bypass. |
| 7 | sqlmap | Specialized SQL injection testing | Keep as a separate, manual/explicitly enabled advanced workflow, not a default background module | Intrusive payloads can alter data or affect availability; requires clear authorization, backup/change plan, and safe test data. |
| 8 | ffuf / dirsearch / Gobuster | Content and path discovery / fuzzing | Consider a separate bounded content-discovery feature after scope and rate-limit controls mature | Can create significant request volume and reveal sensitive paths; never enable by default. |

## Keep existing tools for their distinct jobs

- **Built-in checks:** lightweight HTTP response/security-header observations.
- **WhatWeb:** technology fingerprinting; its output is informational, not a vulnerability verdict.
- **testssl.sh:** TLS protocols, ciphers, and HTTPS configuration.
- **OWASP ZAP:** passive alerts first; any spider or active scan must be a separately visible capability.
- **curl:** connectivity and troubleshooting, not a vulnerability scanner by itself.

## Suggested implementation order

1. Finish controlled local end-to-end validation of testssl.sh and WhatWeb.
2. Make ZAP diagnostics reliable and verify its passive adapter against a real local ZAP instance.
3. **Implemented:** Nuclei uses a curated local HTTP template set selected by category. Standard selects up to 30 templates; Deep up to 60. The selector filters explicit high-risk tags, non-HTTP flows, state-changing methods, raw/payload-driven requests, and templates declaring over five requests. Up to 12 validated same-origin URLs are scanned with a 5 requests/second cap, concurrency 3, 4-second per-request timeout, no retries, redirects and Interactsh disabled. Standard has a 75-second cap; Deep 150 seconds. Valid JSONL findings are retained if the run times out. The latest multi-page behavior still needs controlled-lab validation before treating it as release-ready.
4. Add endpoint discovery (Katana/hakrawler) as a discovery-only inventory workflow, requiring scope approval before any follow-up scan.
5. Evaluate Nikto or Wapiti based on controlled-lab accuracy and duplicate-finding rates.
6. Defer sqlmap and generic fuzzers until scan lifecycle, cancellation, rate limiting, and production-safe controls exist.

## Upstream references

- Kali Nuclei package: https://www.kali.org/tools/nuclei/
- ProjectDiscovery Nuclei documentation: https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md
- ProjectDiscovery tool overview: https://projectdiscovery.io/open-source
- Kali Wapiti package: https://www.kali.org/tools/wapiti/
- Kali web-app testing metapackage (broad inventory; not a recommendation to install everything): https://www.kali.org/tools/kali-meta/
- OWASP Web Security Testing Guide tools resource: https://owasp.github.io/www-project-web-security-testing-guide/stable/6-Appendix/A-Testing_Tools_Resource

Tool availability, flags, output formats, and package versions vary by Kali release. Verify against the installed version before enabling an adapter; tests must include malformed output, timeout, non-zero exit, missing binary, and scope enforcement.
