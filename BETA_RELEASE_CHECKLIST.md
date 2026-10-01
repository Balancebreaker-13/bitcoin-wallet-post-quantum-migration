# Beta Release Checklist

## Pre-release gate

- [ ] Confirm all test suites pass locally
- [ ] Confirm the liboqs backend is available in the supported environment
- [ ] Review all known limitations and document current deployment constraints
- [ ] Confirm release notes are accurate and complete
- [ ] Confirm documentation is present for user onboarding and developer setup

## Security review

- [ ] Review `docs/security/audit_report.md`
- [ ] Verify no unresolved critical findings remain
- [ ] Confirm secure handling guidance for key storage is documented
- [ ] Confirm operations around backend failure remain fail-closed

## Feature validation

- [ ] Hybrid key generation works as expected
- [ ] Dual-signature verification passes on valid payloads
- [ ] Tampered signatures are rejected
- [ ] Transaction serialization remains deterministic
- [ ] Key store reads and writes operate correctly

## Operational readiness

- [ ] Document installation steps for beta users
- [ ] Confirm upgrade and rollback instructions are clear
- [ ] Confirm support contact or issue reporting process is defined
- [ ] Confirm data backup/recovery practices are documented

## Release signoff

- [ ] Security review signed off
- [ ] Engineering validation signed off
- [ ] Product/owner approval obtained
- [ ] Beta tag and release artifacts prepared
