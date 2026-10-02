# Security Status — No Beta or Production Signoff

**Status: not approved for beta deployment or production use.**

This status supersedes prior wording that described the project as approved for
beta-stage use. The work to date is a focused engineering review, not an
independent third-party security audit, consensus review, or side-channel
assessment.

## Verified scope

- The full local test suite most recently passed 55 tests, with 1
  backend-dependent test skipped; measured statement coverage was 80%.
- Bitcoin Core RPC behavior is covered by mocked responses only. It has not
  been verified against a live regtest node.
- Published BIP340 signing vectors and BIP341 wallet key-tweak/control-block
  vectors are covered. Sighash and witness behavior has unit coverage but has
  not been cross-checked against an authoritative BIP341 sighash vector.

## Reasons signoff is withheld

- The hybrid ML-DSA envelope is not a Bitcoin consensus script.
- A full Tapscript interpreter and a consensus-compatible post-quantum spending
  protocol are not implemented.
- No independent cryptographic integration or side-channel review has been
  completed.
- No live Bitcoin Core regtest validation or transaction confirmation workflow
  has been completed.

Do not use this prototype to protect real funds or broadcast transactions on
mainnet. Reassess this status only after the outstanding requirements in
[`ROADMAP.md`](ROADMAP.md) have been verified.