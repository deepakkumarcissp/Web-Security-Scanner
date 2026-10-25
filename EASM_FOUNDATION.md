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
- Dashboard organization/root-domain registration form, organization inventory table, optional organization selection during asset registration, organization-aware asset rows, posture metric cards, and client-side inventory filters for scope/DNS status.
- Opt-in Certificate Transparency lookup for an approved DNS root, normalized through a source adapter contract (`source`, timestamps, status, candidates, errors, and limit metadata).
- Persistent per-root discovery run history, including successful runs and source failures.
- Append-only asset event history for manual registration, passive candidate discovery, scope/approval changes, DNS resolution, and organization reassignment; latest 100 events are available per asset and surfaced in the dashboard.
- Organization event history records registration and edits to organization name, owner contact, and notes.
- Asset organization reassignment is an explicit, authorization-gated action that validates the selected root-domain boundary and records the change reason.
- Successful passive discovery runs persist per-run asset snapshots and classify candidates as new/present or missing from the latest successful source result. A missing result is explicitly not treated as confirmed asset removal; failed source runs do not generate disappearance snapshots.
- Explicit bounded DNS resolution action for registered, organization-linked discovered candidates; stores resolution status, deduplicated A/AAAA addresses, timestamp, and error without HTTP/TLS probing or scan launch.
- Discovered subdomains enter `needs_review`; discovery starts zero scans.
- Scope promotion for discovered assets requires an approval/change-ticket reference.
- Existing scan engine supports bounded same-origin crawling, evidence-backed findings, severity/confidence, lifecycle tracking, retest comparison, exports, and tool-status reporting.
- Redirect handling was recently hardened so an initial HTTP request cannot follow a cross-origin redirect to another host/port.

## Gaps versus the intended EASM baseline

| Capability | Current scanner state | Recommended next step |
|---|---|---|
| Root organization/brand registry | Organization/root-domain API, management form, inventory table, asset association, and posture filters implemented | Extend audit coverage to asset owner contact changes, evidence attachment, and organization root-domain changes |
| Subdomain sources | Opt-in `crt.sh` adapter with persisted per-run status and bounded metadata; no archive/subfinder source yet | Add optional passive archive adapter and explicitly invoked subfinder integration |
| Candidate validation | Explicit bounded DNS resolution persists deduplicated addresses, status, timestamp, and errors; no HTTP/TLS fingerprinting | Add CNAME detail and separately approved low-impact fingerprinting |
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
- [x] Define a common adapter contract: `source`, `started_at`, `finished_at`, `status`, `candidates`, `errors`, `limit_metadata`.
- [x] Wrap CT lookup in the adapter contract and persist source-level successful and failed run history.
- [ ] Add passive historical source adapter and subfinder as an optional explicitly invoked source.
- [ ] Persist source-specific observations while deduplicating canonical assets without overwriting provenance.

### EASM-3 — resolution and fingerprinting
- [x] Add an explicit bounded DNS inventory action with per-asset status, address set, timestamp, and error.
- [x] Require discovered candidates to be linked to a registered organization root before DNS resolution.
- Resolve only approved root-derived candidate names through bounded DNS queries.
- Do not automatically HTTP-probe or scan unapproved candidate hosts. Provide a separate explicit action to fingerprint candidates when policy permits.
- Separate DNS resolution state from HTTP reachability and TLS validity.

### EASM-4 — assessment orchestration
- Reuse the current scanner's adapters only for scope-approved assets.
- Require per-asset approved scope and policy before scheduled or batch assessment; active tests retain a separate approval gate.
- Track job and tool lifecycle, including errors, timeouts, partial output, and cancellations.

### EASM-5 — posture and trends
- [x] Snapshot successful discovery results over time and classify new/present/missing-from-source candidates without treating source failures as disappearance.
- [ ] Extend snapshots to all inventory signals and report changed/unassessed assets with source freshness.
- Use explainable prioritization: exposure, confidence/evidence, asset criticality when owner-supplied, and age—not an opaque score alone.
- Export machine-readable inventory and executive/technical reports with coverage boundaries and per-source health.

## Initial acceptance gates

- Every discovery candidate has source and timestamps and starts in `needs_review`.
- Tests demonstrate exact subdomain boundary handling and rejection of suffix lookalikes.
- Discovery never calls the scanner or contacts candidate hosts unless a distinct approved action is invoked.
- Approved-scope scans use exact origin controls and preserve all findings/evidence/tool statuses.
- A report distinguishes discovered candidates, resolved assets, reachable web assets, approved targets, assessed targets, and validated findings.
- No claim of “complete external attack surface” or an overall coverage percentage until a declared benchmark supports it.


## Current implementation checkpoint — discovery history and DNS

- CT discovery now uses a normalized adapter result contract with source, start/end timestamps, status, candidates, errors, and response/result limits.
- `discovery_runs` persists completed and failed attempts; `GET /api/assets/{id}/discovery-runs` exposes the latest 50 runs.
- `POST /api/assets/{id}/resolve` is an explicit, authorization-gated DNS inventory action. It stores resolved address sets and status, has a short per-lookup timeout, and explicitly reports zero HTTP probes, TLS checks, or scans. Discovered candidates must be tied to an organization root.
- The API/data layer is implemented; the Attack Surface dashboard now exposes controls to trigger DNS resolution and view discovery history; organization management now has a dashboard form/table, and asset inventory includes organization context plus posture summaries/filters. DNS resolution is inventory-only and is not proof that a web service is reachable or in scope for scanning.


### Explainable posture and source health

- GET /api/assets now returns evidence-based posture_signals and a human-readable posture_priority. Signals describe known inventory gaps (scope review, unassigned organization, passive-discovery origin, and DNS status); they are not vulnerability findings or an opaque numeric risk score.
- GET /api/easm/source-health summarizes discovery run counts by source, the latest recorded run and error, plus DNS-resolution inventory counts. It reads persisted data only and makes no external requests.
- The Attack Surface inventory displays posture priority and its supporting signal labels. Discovery and DNS actions remain explicit; no candidate hosts are automatically scanned.
- Validation checkpoint: 118 tests passed; Python compilation and git diff --check passed. Two existing dependency deprecation warnings remain.


### Passive discovery adapter expansion

- Added an explicit Internet Archive Wayback CDX adapter alongside certificate transparency. The UI presents separate CT Discover and History Discover actions; each requires the same explicit user confirmation and an approved in-scope root.
- The Wayback adapter queries only the public CDX index, with a 12-second timeout, 1 MB response cap, bounded record limit, hostname normalization, deduplication, and exact DNS-label boundary checks. It never fetches archived pages or contacts candidate hosts.
- Both adapters use the shared discovery history/snapshot contract. New candidates retain Needs Review, carry their source provenance, and do not trigger scans.
