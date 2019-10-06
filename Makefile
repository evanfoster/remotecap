.PHONY: default install build lint type-check format format-check ci publish

FILE_NAME=remotecap.py

default: ci

install:
	pip install -r requirements.txt
	pip install -r requirements.build.txt

LINTER=flake8
# E501 = line too long
LINTER_ARGS=--ignore E501 $(FILE_NAME)

lint:
	$(LINTER) $(LINTER_ARGS)

TYPE_CHECKER=mypy
TYPE_CHECKER_ARGS=$(FILE_NAME)

type-check:
	$(TYPE_CHECKER) $(TYPE_CHECKER_ARGS)

FORMATTER=black
FORMATTER_ARGS= --line-length 120 $(FILE_NAME)

format:
	$(FORMATTER) $(FORMATTER_ARGS)

format-check:
	$(FORMATTER) --check $(FORMATTER_ARGS)

ci: lint type-check format-check

publish:
	python setup.py sdist
	twine upload dist/*
