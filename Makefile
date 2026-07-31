.PHONY: test lint typecheck ci

test:
	pytest tests/ -v

lint:
	ruff check vulnforge/
	ruff format --check vulnforge/

typecheck:
	mypy vulnforge/

ci: lint typecheck test
