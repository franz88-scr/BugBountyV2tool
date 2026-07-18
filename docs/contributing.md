# Contributing to ReconChain

## Development Setup

```bash
git clone https://github.com/franz88-scr/BugBountyV2tool.git
cd BugBountyV2tool
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -q

# Run with coverage
python -m pytest tests/ --cov=reconchain --cov-report=term-missing -q

# Run specific test file
python -m pytest tests/test_security.py -v
```

## Code Style

- Python 3.9+ (no walrus operator, no `match` statements)
- `from __future__ import annotations` in all files
- Type hints on all public functions
- Docstrings on all public classes and functions (Google style)
- No external dependencies in core modules (stdlib only)
- Tests use `unittest.mock` for subprocess isolation

## Project Structure

```
reconchain/           # Main package (see docs/architecture.md)
tests/                # Test suite
docs/                 # Documentation
  ├── architecture.md # Module structure and design
  ├── api.md          # REST API reference
  ├── plugins.md      # Plugin development guide
  ├── events.md       # Event bus reference
  └── contributing.md # This file
```

## Adding a New Phase

1. Choose the appropriate module in `reconchain/phases/`
2. Implement the phase function following the standard signature:
   ```python
   async def phase_XX_NAME(outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
   ```
3. Add the phase to `PIPELINE` in `reconchain/phases/__init__.py`
4. Add dependency edges in `PHASE_DEPS`
5. Assign to the correct stage in `STAGES`
6. Add tests in `tests/`

## Adding a New Exception

Add to `reconchain/exceptions.py` following the hierarchy:
```
ReconChainError (base)
├── ConfigError
├── PipelineError
├── ToolError
├── NetworkError
├── PluginError
├── ReportError
└── IntegrationError
```

## Adding a New Test

Tests use `pytest` with `unittest.mock` for subprocess isolation. Key patterns:

```python
import pytest
from unittest.mock import patch, MagicMock

def test_example():
    with patch("reconchain.process.subprocess.Popen") as mock_popen:
        mock_popen.return_value.returncode = 0
        mock_popen.return_value.communicate.return_value = (b"output", b"")
        # ... test code ...
```

## Commit Messages

Use conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding tests
- `refactor:` code change that neither fixes a bug nor adds a feature
- `perf:` performance improvement

## Pull Request Process

1. Create a feature branch from `main`
2. Add tests for new functionality
3. Run `python -m pytest tests/ -q` and ensure all pass
4. Update documentation if adding new features
5. Submit PR with a clear description of changes
