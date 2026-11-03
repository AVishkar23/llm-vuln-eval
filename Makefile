.PHONY: run test

run:
	python3 -m vulneval run --detector all --out results/REPORT.md

test:
	@if [ -x .venv/bin/pytest ]; then .venv/bin/python -m pytest -q; else python3 -m pytest -q; fi
