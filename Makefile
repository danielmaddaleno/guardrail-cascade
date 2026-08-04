.PHONY: install test lint format demo clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

lint:
	black --check .
	flake8 . --max-line-length=120
	mypy guardrail_cascade --ignore-missing-imports

format:
	black .

demo:
	python examples/demo.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage *.egg-info
