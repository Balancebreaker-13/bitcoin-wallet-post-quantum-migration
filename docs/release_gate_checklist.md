# Release Gate Checklist

This document defines the next hard validation gate before the project can be treated as a beta-ready or production-ready Bitcoin wallet migration prototype.

## Scope

The project must complete the following before any release claim:

1. Live Bitcoin Core regtest validation
2. Taproot and sighash vector verification
3. Native liboqs backend validation on representative hardware
4. Independent cryptographic and consensus review
5. Release readiness sign-off and documentation update

## Required validation steps

### 1. Live Bitcoin Core regtest validation

- Build or install Bitcoin Core with regtest enabled.
- Start a local regtest node in a disposable environment.
- Create a wallet and fund it via regtest mining.
- Verify the wallet code can create, sign, and relay valid transactions.
- Confirm `txid` and `wtxid` semantics against Bitcoin Core output.
- Exercise at least one valid Taproot key-path spend and one invalid spend attempt.

Suggested commands:

```bash
# After building Bitcoin Core from source
./src/bitcoind -regtest -daemon
./src/bitcoin-cli -regtest getblockchaininfo
./src/bitcoin-cli -regtest createwallet testwallet
./src/bitcoin-cli -regtest -rpcwallet=testwallet getnewaddress
./src/bitcoin-cli -regtest generatetoaddress 101 <address>
```

Expected exit criteria:

- no invalid transaction construction paths remain
- all script and sighash checks match Bitcoin Core behavior
- no unreviewed consensus assumptions remain

### 2. Taproot vector verification

- Validate against authoritative BIP340 and BIP341 vectors.
- Confirm x-only public key generation, Schnorr signatures, and Taproot tweak values.
- Verify control-block construction and script-path witness layout against known vectors.
- Check invalid sighash bits and malformed witness encoding are rejected.

### 3. Native backend validation

- Build and confirm native `liboqs` / `oqs` backend works on target hardware.
- Run benchmark harness on the target machine and record exact environment details.
- Capture Python version, OS version, CPU, memory, liboqs version, and compiler flags.
- Retain a benchmark artifact in `benchmarks/` or CI output for review.

### 4. Security review gates

Required before release claims:

- independent cryptographic review
- consensus review for wallet-signing assumptions and taproot rules
- side-channel / implementation hardening review
- review of key storage, serialization, and key-derivation workflows

### 5. Release sign-off

The project shall not claim beta or production readiness until all of the following are complete:

- live regtest validation passed
- authoritative Taproot and sighash vectors verified
- native backend benchmark run recorded
- independent review completed and remediation tracked
- documentation updated to reflect actual validation status

## Do not claim

Do not state the project is beta-ready or production-ready while any item above remains open.

The repository should continue to describe itself as a research and validation prototype until these gates have passed.
