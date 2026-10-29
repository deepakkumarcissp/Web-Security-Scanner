# Release Verification Checklist

Use this checklist before merging a feature, announcing a release, or making the repository public. A developer checkout is not the release artifact; verify what a new user receives from the default branch.

## 1. Default branch and Git state

- [ ] Confirm the repository's actual default branch in GitHub settings/API.
- [ ] Review `git branch -a`, `git log main --oneline`, and `git log --oneline --all`.
- [ ] Compare the default branch with all active feature branches and open pull requests.
- [ ] Confirm all intended, reviewed, tested implementation commits are merged into the default branch.
- [ ] Open the repository's top-level URL in a clean browser session and confirm the code and README shown there describe the delivered product.

## 2. Fresh-clone quick start

- [ ] Clone the default branch into a new temporary directory or clean VM/container.
- [ ] Follow the README quick-start command exactly, without copying ignored files, local databases, virtual environments, or untracked configuration from a development checkout.
- [ ] Record OS/version, runtime versions, exact commands, exit codes, and observed results.
- [ ] Verify the documented URL/port and a health check or other explicit success criterion.
- [ ] Test a failure path and document recovery/troubleshooting.
- [ ] On a clean Kali VM, run the one-command installer from the README exactly as written (`curl -fsSL …/install.sh | bash`) and confirm it downloads, installs, starts and serves the dashboard. Then run it a second time (update path) and confirm it succeeds without touching `data.sqlite3`.
- [ ] Confirm `dkcissp-scanner`, `dkcissp-scanner update`, `./run.sh` and `./update.sh` work, and that a busy port gives a clear message.
- [ ] Approve and decline one missing-tool request on the Approvals page with a real `apt` install on Kali.

## 3. Documentation hygiene

Search README, docs, scripts, examples, and release notes for unresolved development notes and placeholders, including:

```text
before public
final validation
before release
TODO
FIXME
TBD
note to self
```

- [ ] Resolve each match, convert it into a clearly owned public roadmap item, or remove it.
- [ ] Confirm no private targets, credentials, tokens, local paths, or customer data are included.
- [ ] Verify that roadmap checkboxes and capability claims match shipped code and test evidence.

## 4. Entry points and bootstrap consistency

- [ ] Enumerate every supported installer, bootstrap script, CLI entry point, service launcher, and documented command.
- [ ] Test each entry point independently, including non-root and already-root execution where applicable.
- [ ] Exercise elevation fallback, missing dependency, interrupted setup, and error paths.
- [ ] Compare duplicated/shared bootstrap logic; test every copy rather than assuming a fix in one fixes the others.

## 5. Configuration and documentation consistency

- [ ] Cross-check ports, paths, environment variables, service names, package names, config defaults, and filenames between code, tests, scripts, and docs.
- [ ] Verify sample commands are executable as written.
- [ ] Confirm ignore rules exclude generated databases, secrets, virtual environments, caches, and local output as appropriate.

## 6. Tests and evidence

- [ ] Run syntax/static checks.
- [ ] Run unit tests.
- [ ] Run integration tests against controlled local services or deterministic mocks.
- [ ] Run a fresh-clone quick-start test.
- [ ] Run end-to-end checks for every feature claimed as operational.
- [ ] Review CI workflow contents and describe exactly what it does and does not prove.
- [ ] Record skipped tests and known limitations; do not label unverified integrations as working.

## 7. Final publication decision

- [ ] No release-blocking failures remain.
- [ ] The default branch is the intended release artifact.
- [ ] README, roadmap, release notes, tests, and code agree.
- [ ] Pull request review is complete and required checks pass.
- [ ] The release note states tested environments, evidence, limitations, and follow-up work.

**Release rule:** If the default branch or clean-clone path has not been verified, the project is not ready to be announced as a working release.
