# Agent instructions

## Essential Rules

### Do

- Follow existing patterns — search codebase for similar code
- Keep changes concise and focused
- Run file-scoped commands for fast feedback
- Chain exceptions: `raise ValueError(...) from err`

### Don't

- Don't run full test suite for small changes
- Don't create temporary helper scripts or workarounds
- Don't commit without running quality checks
- Don't make large speculative changes — ask first
- Don't use bare `except:` — always specify exception types

## Commands

### File-Scoped (prefer these)

```sh
tox -e py314 -- tests/test_<module>.py            # Test specific file
tox -e py314 -- tests/test_<module>.py::test_name  # Test specific function
```

### Project-Wide

```sh
tox                # Full test suite
tox -e lint        # Linting and type checking
tox -e fix         # Auto-fix lint issues
```

## Safety and Permissions

### Allowed Without Asking

- Read files, search codebase
- Run tests with tox
- Edit existing files following established patterns

### Ask First

- Installing/updating packages in pyproject.toml
- Git commit or push operations
- Deleting files or entire modules
- Creating new modules or major refactors

## Project Structure

- `src/elfdeps/` — Main package code
- `tests/` — Unit tests

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Always use `git commit --signoff`.
