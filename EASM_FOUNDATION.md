# DKCISSP External Attack Surface Management (EASM) Foundation

## Product direction

Build DKCISSP around one asset-centric workflow, with the existing Web Security Scanner as an assessment engine rather than treating a URL scan as the product boundary. Use the AIAgent repository's `asm/asm_orchestrator.py` and `assessments/domain_recon.py` as architectural references; do not copy their entire implementation or inherit their operational assumptions wholesale.

**Product promise for the current beta:** register an authorized root asset, opt in to passive certificate-transparency discovery, keep discovered names as review candidates, explicitly approve scope, and only then launch a web assessment. The scanner must report what it actually observed, what ran, and what remains unverified.

## Reference review: what is useful

The AIAgent ASM orchestrator provides a useful stage model:

1. **Registry and identity:** start from known, confirmed organization domains rather than arbitrary targets.
2. **Merge, don't duplicate:** reconcile fresh discovery with existing platform inventory and exposure data.
3. **Discovery sources:** combine live subdomain enumeration with historical Certificate Transparency and archive data; keep discovery source/provenance per asset.
4. **Resolve and fingerprint:** distinguish candidate names from resolving hosts and reachable web applications; retain minimal technology and service signals.
5. **Risk/context enrichment:** attach business context such as asset tier, known findings, crown-jewel status, and source freshness when trustworthy data is available.
6. **Scope gate before assessment:** distinguish discovered candidates from assets explicitly permitted for assessment.
7. **Inventory and reporting:** persist a normalized JSON/data representation and provide exportable inventory and summary counts.

The broader `assessments/domain_recon.py` also illustrates a wide enrichment catalogue (DNS/email posture, technologies, exposed files, historical URLs, cloud exposure, and external intelligence). These should be opt-in enrichment modules with explicit data-source status, rate/size bounds, and evidence—not a single long synchronous job that can fail ambiguously.

## What DKCISSP already has

- SQLite-backed asset registry with first/last seen, asset type, source, notes, scope state, review decision, and approval reference.
- First-class organization/root-domain registry API (`GET/POST /api/organizations`) with normalized DNS roots, owner contact/notes, explicit authorization, and asset counts.
- Assets can associate with an organization; automatic association uses exact root-domain or dot-label subdomain boundaries, and discovered candidates inherit the root asset's organization.
- Explicit authorization for asset registration, scope changes, and passive discovery.
- Opt-in Certificate Transparency lookup for an approved DNS root.
- Discovered subdomains enter `needs_review`; discovery starts zero scans.
- Scope promotion for discovered assets requires an approval/change-ticket reference.
- Existing scan engine supports bounded same-origin crawling, evidence-backed findings, severity/confidence, lifecycle tracking, retest comparison, exports, and tool-status reporting.
- Redirect handling was recently hardened so an initial HTTP request cannot follow a cross-origin redirect to another host/port.

## Gaps versus the intended EASM baseline

| Capability | Current scanner state | Recommended next step |
|---|---|---|
| Root organization/brand registry | Single registered asset records; no first-class organization record yet | Add organization/root-domain records and owner/contact metadata, keeping approval references and audit history |
| Subdomain sources | Opt-in `crt.sh` only | Add source adapters behind a common interface: CT first, then optional passive archive and approved subfinder integration |
| Candidate validation | CT name validation; no structured DNS status | Add bounded DNS resolution with A/AAAA/CNAME status, timestamps, source, and errors |
| HTTP/TLS fingerprint | Existing web checks happen during a scan | Add a low-impact, separately reported inventory fingerprint only after scope approval, with strict origin controls and verified TLS diagnostics |
| Asset identity | URL-oriented unique registry | Normalize canonical host/scheme/port identities and keep multiple URLs/endpoints as observations without losing hostname provenance |
| Risk/context | Finding severity and lifecycle | Add explainable exposure signals first; later add business criticality, internet reachability, stale/unknown owner and known findings |
| Change detection | Scan retest comparison exists | Add asset first-seen/last-seen and new/missing/changed asset snapshots before complex attack-path scoring |
| Dashboard | Asset Inventory exists but was hidden | Expose as **Attack Surface (Beta)** and clearly state the current discovery/assessment boundaries |
| Continuous monitoring | Scanner scheduler is process-local | Defer until discovery runs, worker durability, rate limiting, and audit history are reliable |

## Safety and correctness requirements

- Discovery results are **candidates**, not proof of ownership or permission. Keep them in `Needs Review` by default.
- Never automatically scan every newly discovered hostname. Scope approval must be explicit, auditable, revocable, and bound to the precise host/origin/port and permitted assessment profile.
- Keep discovery separate from assessment. Passive third-party data lookup should not silently cause requests to candidate hosts.
- Validate domain relationships by exact label-boundary suffix checks (`host == root` or `host.endswith('.' + root)`), not substring matches.
- Treat all tool and third-party results as untrusted. Normalize hostnames, reject malformed names and embedded credentials, bound response sizes/timeouts/concurrency, and deduplicate without discarding provenance.
- Do not copy a blanket TLS-verification bypass as a general default. Prefer verified TLS checks; where certificate-invalid reachability checks are deliberately supported, isolate the behavior, never send credentials, and record the verification failure as evidence.
- Distinguish `candidate`, `resolves`, `web reachable`, `scope approved`, `assessment executed`, and `finding validated`. Do not use one status to imply another.
- Keep the current local-service binding and authorized-use requirement. Do not expose scanner or tool-install endpoints to untrusted networks.
- EASM findings remain observations until evidence supports stronger claims. AI can summarize and prioritize but cannot silently approve scope or mark findings remediated/false-positive.

## Delivery sequence

### EASM-1 — visible, reliable inventory foundation
- Expose Asset Inventory in navigation as **Attack Surface (Beta)**.
- Keep manual root registration, passive CT discovery, review/approval, and source tracking.
- Add inventory filters/counts for in-scope, out-of-scope, and needs-review assets.
- Add root-domain and subdomain normalization tests; reject false suffix matches and URL-shaped values in hostname candidates.

### EASM-2 — discovery adapter interface
- Define a common adapter contract: `source`, `started_at`, `finished_at`, `status`, `candidates`, `errors`, `rate/limit metadata`.
- Implement CT adapter first (current implementation), add passive historical source adapter next, and subfinder as an optional explicitly invoked source.
- Persist source-specific observations while deduplicating the canonical asset; never overwrite source provenance.

### EASM-3 — resolution and fingerprinting
- Resolve only approved root-derived candidate names through bounded DNS queries.
- Do not automatically HTTP-probe or scan unapproved candidate hosts. Provide a separate explicit action to fingerprint candidates when policy permits.
- Separate DNS resolution state from HTTP reachability and TLS validity.

### EASM-4 — assessment orchestration
- Reuse the current scanner's adapters only for scope-approved assets.
- Require per-asset approved scope and policy before scheduled or batch assessment; active tests retain a separate approval gate.
- Track job and tool lifecycle, including errors, timeouts, partial output, and cancellations.

### EASM-5 — posture and trends
- Snapshot assets and signals over time; report first seen, last seen, newly discovered, disappeared, changed, and unassessed.
- Use explainable prioritization: exposure, confidence/evidence, asset criticality when owner-supplied, and age—not an opaque score alone.
- Export machine-readable inventory and executive/technical reports with coverage boundaries and per-source health.

## Initial acceptance gates

- Every discovery candidate has source and timestamps and starts in `needs_review`.
- Tests demonstrate exact subdomain boundary handling and rejection of suffix lookalikes.
- Discovery never calls the scanner or contacts candidate hosts unless a distinct approved action is invoked.
- Approved-scope scans use exact origin controls and preserve all findings/evidence/tool statuses.
- A report distinguishes discovered candidates, resolved assets, reachable web assets, approved targets, assessed targets, and validated findings.
- No claim of “complete external attack surface” or an overall coverage percentage until a declared benchmark supports it.
