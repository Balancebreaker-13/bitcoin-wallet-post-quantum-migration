# WISDOM NETWORK WALLET — Project Roadmap

## Purpose and project status

This roadmap prioritizes reliable, evidence-backed validation of the current research prototype before adding wallet features or making release claims.

The project explores Bitcoin wallet cryptography and post-quantum migration patterns. The hybrid ECC + ML-DSA signature envelope is **not a Bitcoin consensus authorization mechanism**. The project is not suitable for real funds, beta deployment, or production use.

Roadmap checkboxes are evidence-driven: mark an item complete only when its implementation or validation artifact is present and reviewable in the repository. Historical summaries are not substitutes for current results.

## Current validation snapshot — 2026-11-03

- Latest checked Python CI run: [run 17](https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration/actions/runs/41666739272), commit `17a74762a27837787c5d2260d712b961f3456355`.
- Result: **failed** — 1 failed, 58 passed, 1 skipped. The failed test is `tests/test_bitcoin_integration.py::test_segwit_txid_excludes_witness_but_wtxid_includes_it`; the transaction parser raises `ValueError: transaction is truncated before the locktime field`.
- The Taproot key-path test passed in this run after clarifying 64-byte `SIGHASH_DEFAULT` versus 65-byte explicit-sighash behavior.
- The SegWit txid correction is not validated yet. Do not mark the CI or transaction-serialization gates complete until the failing case is fixed and a new run passes.
- Live Bitcoin Core regtest, authoritative BIP341 sighash cross-checking, deployment-hardware benchmarks, and independent cryptographic/consensus/side-channel reviews remain outstanding.

---

## Milestone 0 — Establish a trustworthy CI baseline (active)

**Goal:** make the normal development workflow installable, reproducible, and able to report actual test results.

- [ ] Verify every dependency in `requirements.txt` exists for the supported Python version and is used by the current code; remove unused or unavailable entries.
- [ ] Keep CI aligned with this Python project: install dependencies and run `python -m pytest -q tests` (not Django commands).
- [ ] Fix `test_segwit_txid_excludes_witness_but_wtxid_includes_it` and confirm txid/wtxid behavior against the test’s intended valid serialization.
- [ ] Confirm a current GitHub Actions run completes dependency installation and reaches pytest with a passing result.
- [ ] Record the actual test result, skips, Python version, and native `liboqs` availability; do not describe an in-progress, failed, or install-failed run as passing.
- [ ] Decide whether native `liboqs` is mandatory in CI. If mandatory, provision and verify the backend explicitly; if optional, separate backend-independent tests from native-backend tests and report the distinction.
- [ ] Validate that the release workflow can build a distributable package. Add packaging metadata only if package distribution is intended; otherwise disable or remove template workflows that imply it.

**Exit criteria:** CI installs dependencies and runs the suite reproducibly, with a recorded passing result and explicit handling of native-backend tests.

---

## Milestone 1 — Freeze scope and correct the design record

**Goal:** distinguish implemented behavior from design proposals and decide what this project is intended to deliver.

- [ ] Keep the primary scope as a research/engineering-validation prototype unless the owner explicitly chooses a consensus-compatible wallet implementation.
- [ ] Mark architecture diagrams and user guides that describe unimplemented features (for example, account management, UTXO selection, address generation, Tapscript execution, and confirmation tracking) as proposed or not implemented.
- [ ] Document that local hybrid signing verifies an application-level envelope; it does not make the transaction spendable under Bitcoin consensus.
- [ ] Choose whether deterministic HD derivation is in scope. If it is, implement standard BIP32 for secp256k1 keys only after the derivation design and test plan are approved. BIP44 path conventions must not be presented as implemented without evidence.
- [ ] Do not derive ML-DSA/ML-KEM keys by simply reusing BIP32. Before implementing PQC recovery, specify a versioned derivation protocol, domain separation, seed handling, algorithm identification, and backup/recovery properties.
- [ ] Reconcile `requirements.txt`, installation guides, architecture docs, phase summaries, and README statements with the code that actually exists.

**Exit criteria:** project scope and implementation boundaries are consistent across code and documentation; BIP32/PQC derivation decisions are explicit.

---

## Milestone 2 — Strengthen local correctness and test evidence

**Goal:** verify implemented primitives against independent, authoritative references before network claims.

- [ ] Run the complete pytest suite after Milestone 0 and fix failures rather than masking them with skips.
- [ ] Add/retain reproducible CI tests for hybrid signing, key-store encryption/recovery, transaction serialization, RPC safety checks, and error handling.
- [ ] Verify BIP340 and BIP341 behavior against authoritative published vectors, including Taproot tweaks and control blocks.
- [ ] Cross-check `taproot_sighash` against authoritative BIP341 sighash vectors for supported hash types and transaction contexts; include annex and script-path cases where implemented.
- [ ] Validate transaction parsing/serialization edge cases, including malformed/truncated SegWit data, and compare `txid`/`wtxid` behavior against reference implementations.
- [ ] If BIP32 is approved, add official BIP32 vectors, hardened and non-hardened derivation tests, invalid-child cases, serialization tests, and recovery tests before exposing it as supported.
- [ ] Keep the distinction between regression/performance tests and security claims explicit. Do not treat timing thresholds as side-channel evidence.

**Exit criteria:** all supported local behavior has repeatable tests, authoritative vectors are checked in or precisely referenced, and known unverified cases are documented.

---

## Milestone 3 — Validate integration boundaries

**Goal:** test only what the current prototype actually supports, without implying that PQC signing is accepted by Bitcoin consensus.

- [ ] Run the documented Bitcoin Core regtest setup in a disposable environment and preserve reproducible instructions and output artifacts.
- [ ] Verify the authenticated RPC client's chain check, `testmempoolaccept` handling, and broadcast behavior against a live regtest node; mocked tests alone do not satisfy this gate.
- [ ] Compare transaction serialization, `txid`, and `wtxid` results with Bitcoin Core for supported transaction forms.
- [ ] Exercise a canonical valid Taproot key-path spend and invalid-spend rejection against Bitcoin Core where the implementation supports it.
- [ ] Do not submit the hybrid ML-DSA envelope as a Bitcoin script or claim a hybrid transaction is consensus-valid. Script-path spend validation is out of scope until a real Tapscript/consensus-compatible layer is selected and implemented.
- [ ] Add confirmation/status tracking only if it is part of the selected project scope; otherwise document it as not implemented.

**Exit criteria:** live regtest results validate the supported standard Bitcoin/RPC integration boundaries, and unsupported hybrid-consensus behavior remains clearly excluded.

---

## Milestone 4 — Native backend and benchmark evidence

**Goal:** characterize the real PQC provider on a defined environment without overstating results.

- [ ] Build and verify the native `liboqs` backend on the project’s declared supported environment(s).
- [ ] Run the benchmark harness using real native crypto; no mock or fallback results count.
- [ ] Record an artifact with Python, OS, CPU, memory, compiler, liboqs/binding versions, parameters, iterations, and results.
- [ ] Review reproducibility and distinguish local microbenchmarks from production capacity, security, and side-channel assessments.

**Exit criteria:** a reviewed, reproducible benchmark artifact exists for explicitly named hardware and software configurations.

---

## Milestone 5 — Independent review and release decision

**Goal:** obtain appropriate independent review and make a release decision from evidence, not feature completion alone.

- [ ] Obtain independent cryptographic-integration review, including the native providers and key handling.
- [ ] Obtain consensus/protocol review for every Bitcoin transaction and Taproot claim.
- [ ] Obtain side-channel/implementation review for supported deployment environments.
- [ ] Review key storage, backup, recovery, password handling, and any approved key derivation protocol.
- [ ] Track findings, severity, remediation, and accepted residual risks in reviewable artifacts.
- [ ] Update `SECURITY_SIGNOFF.md`, `docs/security/audit_report.md`, release checklist, README, and release notes to reflect verified outcomes.
- [ ] Obtain explicit owner/engineering sign-off before any beta label. Production readiness requires a separate decision and evidence; it is not implied by this roadmap.

**Exit criteria:** all critical/high findings are fixed or formally dispositioned, required reviewers sign off, and the documentation matches the evidence.

---

## Later milestone — Beta candidate (conditional)

This milestone may begin only after Milestones 0–5 are complete and the project’s scope supports a beta claim.

- [ ] All required CI and local correctness gates pass on declared supported environments.
- [ ] Live regtest results and benchmark artifacts are published and reproducible.
- [ ] Independent review is complete and remediation is tracked.
- [ ] Installation, upgrade, rollback, backup/recovery, support, and release procedures are tested.
- [ ] Release artifacts build and publish through a validated, least-privilege workflow.
- [ ] Security and project-status documents explicitly define what the beta does and does not support.

Even if this milestone is completed, do not claim that ML-DSA signatures authorize Bitcoin mainnet spends unless a consensus-compatible protocol has been specified, adopted, implemented, and independently reviewed.

---

## Previously reported work (historical; re-verify before relying on it)

- Research and design phases were marked complete in prior roadmap revisions.
- The repository contains ML-DSA/ML-KEM adapters in `src/pqc/core.py`, hybrid signing in `src/hybrid/hybrid_wallet.py`, Bitcoin transaction/RPC/Taproot helpers under `src/bitcoin/`, encrypted key storage, tests, and local benchmarks.
- `PHASE4_COMPLETION_SUMMARY.md` reports a historical local run of 55 passed and 1 skipped with approximately 80% statement coverage. This is not a substitute for a current passing CI run.
- Live Bitcoin Core regtest validation, authoritative BIP341 sighash cross-checking, representative deployment-hardware benchmarks, and independent cryptographic/consensus/side-channel review have not been completed.

---

## Current project posture

Until the applicable exit criteria are met, describe the project as:

- a research and engineering-validation prototype;
- not suitable for real funds, beta deployment, or production use;
- not a consensus-valid post-quantum Bitcoin wallet;
- subject to the open validation and independent-review gates above.
