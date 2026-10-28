## Description

Please include a summary of the change and which issue it fixes. Also include relevant context and rationale.

Fixes #(issue)

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] New detection rule (MITRE ATT&CK mapped Varuna rule)
- [ ] Documentation update
- [ ] Performance improvement / Code hardening

## Verification Checklist

- [ ] My code follows the code style and guidelines of this project (`ruff check` passes).
- [ ] I have executed the full backend test suite (`python -m pytest tests/backend/ -v`).
- [ ] I have run the opaque-box E2E runner (`python tests/e2e/runner.py`).
- [ ] I have executed the frontend test suite (`npm run test` in `frontend/`).
- [ ] I have verified TypeScript types compile (`npx tsc --noEmit`).
- [ ] I have verified production frontend bundle builds (`npm run build`).
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] All new and existing tests passed.
