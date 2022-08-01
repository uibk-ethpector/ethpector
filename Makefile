SHELL := /bin/bash
PROJECT := ethpector
VENV := .venv

all: format lint test build

dev:
	 pip install -e .[dev]
	 pre-commit install

test:
	pytest -v -m "not slow"

test-all:
	pytest

install-dev:
	pip install -e .

install:
	pip install .

lint:
	flake8 tests src experiments

format:
	black tests src experiments

docs:
	tox -e docs

docs-latex:
	tox -e docs-latex

run:
	$(VENV)/bin/python3 src/$(PROJECT)/main.py -d -v $(bla)

pre-commit:
	pre-commit run --all-files

build:
	tox -e clean
	tox -e build

tpublish: build, version
	tox -e publish

publish: build version
	tox -e publish -- --repository pypi

version:
	python -m setuptools_scm

.PHONY: all run test install lint format build pre-commit docs test-all docs-latex publish tpublish
