# Contributing

Thank you for contributing to the Bitcoin wallet post-quantum migration project.

## Development standards

- Follow PEP 8 for Python code
- Prefer small, focused functions and dataclasses
- Add or update tests for any behavioral change
- Keep security-sensitive code explicit and fail-closed

## Branch workflow

```bash
git checkout -b feature/your-change
# make edits
pytest -q
```

## Pull request expectations

- Include a short summary of the change
- Call out security or compatibility implications
- Include tests covering the affected behavior
- Note any assumptions or known limitations

## Security expectations

- Do not silently fall back to weaker cryptographic primitives
- Document any new risks or limitations
- Keep PQC backend errors explicit

## Review checklist

- Does the change improve migration safety?
- Does it preserve the hybrid wallet contract?
- Has the relevant test suite been updated?
- Are docs updated where needed?
