.PHONY: test example

PYTHON ?= python3
export PYTHONPATH := src

test:
	$(PYTHON) -m unittest discover -s tests -v

example:
	$(PYTHON) docs/examples/run.py
