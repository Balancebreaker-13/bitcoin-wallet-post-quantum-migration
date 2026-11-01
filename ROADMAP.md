# Bitcoin Wallet Post-Quantum Cryptography Migration Roadmap

## Overview

This roadmap outlines the comprehensive plan for migrating Bitcoin wallets from traditional elliptic curve cryptography (ECC) to post-quantum cryptography (PQC) algorithms, while explicitly preserving a careful boundary between research validation and release readiness.

---

## Phase 1: Research & Analysis (Q1 2026) - ✅ COMPLETED

- [x] Study NIST PQC standardization process and finalists
- [x] Analyze lattice-based cryptography
- [x] Evaluate hash-based signatures
- [x] Compare code-based cryptography
- [x] Document the quantum threat timeline for Bitcoin
- [x] Create a threat assessment report

## Phase 2: Design & Planning (Q2 2026) - ✅ COMPLETED

- [x] Design hybrid wallet architecture
- [x] Create data-flow and integration plans
- [x] Define API and storage boundaries
- [x] Document deployment and security constraints
- [x] Plan validation strategy and risk mitigation

## Phase 3: Core Implementation (Q3-Q4 2026) - ✅ IMPLEMENTED

- [x] Set up PQC library access and backend handling
- [x] Implement ML-DSA / Dilithium compatibility wrappers
- [x] Implement ML-KEM / Kyber compatibility wrappers
- [x] Build hybrid wallet and transaction-signing primitives
- [x] Add validation tests for key material and round trips

## Phase 4: Validation Hardening & Release Gates (Q4 2026) - 🔄 IN PROGRESS

This phase is the current gate before any beta or production claim.

### Required release gates

- [ ] Live Bitcoin Core regtest validation against a configured regtest node
- [ ] Authoritative BIP340 / BIP341 / BIP342 vector verification
- [ ] Taproot key-path and script-path spend validation against canonical examples
- [ ] Native `liboqs` backend validation on representative deployment hardware
- [ ] Benchmark artifact capture and reproducibility review
- [ ] Independent cryptographic, consensus, and side-channel review
- [ ] Final release-readiness documentation and sign-off

### Current project posture

The project remains a research and engineering validation prototype until the release gates above are completed.

The repository should continue to describe itself as follows:

- suitable for research and validation work
- not suitable for beta or production deployment
- not a consensus-valid mainnet wallet implementation

---

## Continuing Phase 5: Beta Candidate (post-gates)

This phase is contingent on successful completion of all checks in Phase 4.

- [ ] Full live regtest validation passed
- [ ] Consensus-valid transaction flows reviewed and validated
- [ ] Native backend and hardware benchmark results reviewed
- [ ] Security review remediation closed or accepted
- [ ] Public release notes and deployment guidance published

