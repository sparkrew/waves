# Run from the repository root:  make -f reproduction/Makefile <target>
PYTHON ?= python

.PHONY: install validate metrics figures helpers test reproduce docker

install:
	$(PYTHON) -m pip install -r reproduction/requirements.txt

validate:
	$(PYTHON) scripts/validate_dataset.py

metrics:
	$(PYTHON) scripts/metrics/compute_metrics.py

figures:
	$(PYTHON) scripts/metrics/make_figures.py

helpers:
	$(PYTHON) scripts/helpers/eval_helpers.py

test:
	$(PYTHON) -m unittest discover -s tests -v

reproduce:
	$(PYTHON) scripts/reproduce_results.py --with-helpers

docker:
	docker build -f reproduction/Dockerfile -t waves .
	docker run --rm waves
