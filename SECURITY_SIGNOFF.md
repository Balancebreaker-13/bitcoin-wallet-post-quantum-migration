# Security Signoff

## Scope

This signoff covers the hybrid wallet migration implementation for the current beta release candidate. The review includes the PQC adapters, the hybrid wallet logic, the ECDSA compatibility layer, the Bitcoin transaction builder, and the encrypted key store.

## Security outcome

- The implementation uses fail-closed backend handling for missing PQC support.
- The wallet enforces strict validation of hybrid signatures.
- The encrypted key store uses PBKDF2 and Fernet-based storage protection.
- No critical security issues were identified in the current audit review.

## Risk assessment

### Accepted risks

- PQC keys and signatures are significantly larger than traditional ECDSA data.
- Transaction broadcast is intentionally not implemented in the core library.
- Real-world deployment requires an explicit node/RPC integration layer and operational controls.

### Residual recommendations

- Validate on a controlled testnet environment before broader user exposure.
- Continue monitoring dependency and library updates for liboqs and related tooling.
- Document backup and recovery procedures for encrypted key materials.

## Signoff status

- Security review: approved for beta-stage use
- Engineering validation: approved for beta-stage use
- Deployment recommendation: proceed with controlled beta rollout under documented operational controls

## Approver

Balancebreaker-13

## Date

October 1, 2026
