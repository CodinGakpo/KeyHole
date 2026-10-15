# Prefer the repo venv so demo targets work without activating it.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python)

.PHONY: help install test unit hostile lint fmt typecheck demo showtime showtime-dashboard lambda-zip clean

help:
	@echo "make install   - editable install with dev extras"
	@echo "make test      - run all tests"
	@echo "make unit      - unit tests only"
	@echo "make hostile   - the marquee hostile exfiltration suite"
	@echo "make lint      - ruff check"
	@echo "make fmt       - ruff format"
	@echo "make demo      - run the local end-to-end demo"
	@echo "make showtime  - paced, visual interview demo (ARGS=--auto for no pauses)"
	@echo "make showtime-dashboard - dashboard over the showtime runs"
	@echo "make lambda-zip- build dist/controlplane.zip for the control-plane Lambda"

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest -q

unit:
	$(PYTHON) -m pytest -q tests/unit

hostile:
	$(PYTHON) -m pytest -q tests/hostile

lint:
	$(PYTHON) -m ruff check src tests

fmt:
	$(PYTHON) -m ruff format src tests

typecheck:
	$(PYTHON) -m mypy src

demo:
	$(PYTHON) scripts/demo.py

showtime:
	$(PYTHON) scripts/showtime.py $(ARGS)

showtime-dashboard:
	KEYHOLE_HOME=$$HOME/.keyhole-showtime $(PYTHON) -m keyhole.cli.main dashboard

lambda-zip:
	$(PYTHON) scripts/build_lambda.py

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__
