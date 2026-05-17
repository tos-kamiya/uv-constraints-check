# AGENTS.md

## Project

`uv-constraints-check` is a small Python CLI that:

- runs `security-constraints --output -`
- reads the generated constraints from stdout
- checks the current directory's `uv.lock`

## Conventions

- Target Python 3.10 or newer.
- Use semantic versioning for release and version number changes.
- Use semantic commits such as `feat: ...`, `fix: ...`, or `chore: ...`.
- Use `security-constraints` only. Do not accept the misspelled name.
- Prefer `apply_patch` for edits.
- Keep changes small and focused.
- Update or add tests when CLI behavior changes.

## Verification

Recommended checks after edits:

```console
PYTHONPATH=src python3 -m unittest
python3 -m compileall src tests
```

## Notes

- The package entry point is `uv-constraints-check`.
- The module entry point is `python -m uv_constraints_check`.
