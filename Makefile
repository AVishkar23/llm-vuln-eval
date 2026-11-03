.PHONY: run test

run:
	python3 -m vulneval run --detector heuristic --out results/REPORT.md

test:
	python3 -m pytest -q
