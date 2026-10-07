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
	python -m pip install -e '.[dev]'

test:
	python -m pytest -q

unit:
	python -m pytest -q tests/unit

hostile:
	python -m pytest -q tests/hostile

lint:
	ruff check src tests

fmt:
	ruff format src tests

typecheck:
	mypy src

demo:
	python scripts/demo.py

showtime:
	python scripts/showtime.py $(ARGS)

showtime-dashboard:
	KEYHOLE_HOME=$$HOME/.keyhole-showtime sbx dashboard

lambda-zip:
	python scripts/build_lambda.py

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__
