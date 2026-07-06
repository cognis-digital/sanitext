# sanitext -- developer tasks. Standard-library only; no build step required.
PYTHON ?= python

.PHONY: help install dev test demos lint clean

help:
	@echo "make install   editable install (core)"
	@echo "make dev       editable install + dev deps (pytest)"
	@echo "make test      run the test suite"
	@echo "make demos     run all demos (exits 0)"
	@echo "make clean     remove caches / build artifacts"

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

demos:
	$(PYTHON) demos/run_all.py

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
