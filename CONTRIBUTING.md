# Contributing to ReconChain

## Development Setup

Clone the repo and install in development mode:

    git clone https://github.com/franz88-scr/BugBountyV2tool.git
    cd BugBountyV2tool
    pip install -e .
    pip install pytest ruff

## Running Tests

    pytest tests/ -v

    ruff check reconchain/
    ruff format reconchain/

## Code Style

- **Linting**: ruff (enforced via pre-commit hooks)
- **Formatting**: ruff format
- **Line length**: 120 characters max
- **Type hints**: Use typing annotations where practical
- **Docstrings**: Module-level docstrings required; function docstrings for public API

## Adding a New Phase

1. Add the phase function to the appropriate module in reconchain/phases/
2. Add the phase ID to VALID_PHASES in config.py
3. Add the phase to PIPELINE and PHASE_DEPS in phases/__init__.py
4. Add an ArtifactDef in artifacts.py
5. Add the import to phases/__init__.py
6. Add tests for the phase logic (use mocks for external tools)

## Adding a New Vuln Type

1. Add CWE mapping to finding.py: _VULN_TYPE_CWE
2. Add CVSS mapping to finding.py: _VULN_TYPE_CVSS
3. Add severity mapping to finding.py: _VULN_TYPE_SEVERITY
4. Add remediation to remediation.py: REMEDIATIONS
5. Add keyword to artifacts.py: SEVERITY_KEYWORDS
6. Add tests in tests/test_finding.py and tests/test_remediation.py

## Module Guidelines

| Module | Purpose | Can Import From |
|---|---|---|
| config.py | Data structures, constants | Only stdlib |
| utils.py | I/O, HTTP, logging | config.py |
| process.py | Subprocess, resource limits | config.py, utils.py |
| phases/*.py | Phase implementations | helpers.py, process.py, utils.py |
| finding.py | Finding dataclass | utils.py, artifacts.py |
| reporting.py | Report generation | artifacts.py, utils.py |
| api.py | REST API | finding.py, artifacts.py |
| ratelimiter.py | Rate limiting | Only stdlib |

**Rule**: Never import from pipeline.py or cli.py in phase modules.

## Test Conventions

- Test files: tests/test_<module>.py
- Test classes: class Test<Feature>:
- Test methods: def test_<description>(self):
- Use pytest fixtures (tmp_path for file I/O)
- Mock external tools; test phase logic independently
- Aim for: test dataclass creation, serialization, edge cases, error handling
