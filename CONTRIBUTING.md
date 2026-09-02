# Contributing to Bitcoin Wallet Post-Quantum Cryptography Migration

Thank you for your interest in contributing! This document outlines guidelines for participating in this project.

## Code of Conduct

Be respectful and constructive in all interactions. We welcome contributors from all backgrounds.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Set up development environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. Make your changes
5. Write/update tests
6. Ensure code passes linting and tests:
   ```bash
   black src/ tests/
   flake8 src/ tests/
   mypy src/
   pytest
   ```
7. Submit a pull request

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Use type hints for all functions
- Write docstrings for all public functions
- Maximum line length: 100 characters

### Testing

- Write tests for all new features
- Maintain 80%+ code coverage
- Use pytest for test framework
- Test both happy path and error cases

### Commit Messages

- Use clear, descriptive commit messages
- Start with an imperative verb ("Add", "Fix", "Update")
- Include context about why the change was made
- Reference relevant issues or PRs

Example:
```
Add ECDSA module for secp256k1 support

Implements ECDSAModule with deterministic signing for Bitcoin wallet integration.
Supports keypair generation, signing, and verification with secp256k1 curve.

Fixes #123
```

## Working with PQC and ECDSA

### PQC Algorithm Guidelines

- Always use liboqs for PQC operations
- Never substitute cryptographic material
- Validate key sizes match algorithm specifications
- Test against all supported security levels (2, 3, 5 for Dilithium; 512, 768, 1024 for Kyber)

### ECDSA Guidelines

- Use deterministic signing (RFC 6979)
- Support both compressed and uncompressed public keys
- Always verify signatures before accepting them
- Use SHA256 for message hashing

## Submitting Issues

When reporting bugs:

1. Describe the issue clearly
2. Include steps to reproduce
3. Provide expected vs actual behavior
4. Include Python version, OS, and dependency versions
5. Attach relevant code snippets or logs

## Phase-Based Development

Contributions should align with the current phase:

- **Phase 3** (Current): Core implementation, testing, integration
- **Phase 4**: Testing and validation
- **Phase 5**: Documentation
- **Phase 6**: Deployment and maintenance

See ROADMAP.md for detailed phase information.

## Security Considerations

If you discover a security vulnerability:

1. **Do NOT** create a public GitHub issue
2. Email the maintainer with details
3. Include reproduction steps and impact assessment
4. Allow time for a fix before public disclosure

## Questions?

Open a discussion in the repository or check existing documentation.

Thank you for contributing!
