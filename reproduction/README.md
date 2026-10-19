# Reproduction

What can and cannot be reproduced:

| Part | Reproducible here? |
|---|---|
| Dataset integrity, counts, label provenance | Yes: `scripts/validate_dataset.py` |
| The four workflow metrics | Yes: recomputed from the YAML snapshots by `scripts/metrics/compute_metrics.py` |
| Figure 3, Figure 4, Table 3, the statistics of section 5 | Yes: `scripts/metrics/make_figures.py` |
| Helper recall on the 100 reference workflows | Yes: `scripts/helpers/eval_helpers.py` |
| Selection of the sample from the corpus | **No.** The 1,048,857-workflow corpus is proprietary; only the sample is released. `scripts/sampling/` documents the procedure ([docs/sampling.md](../docs/sampling.md)). |
| Manual labels | Not re-derivable by construction; they are the ground truth. |

## Run

```bash
python -m pip install -r reproduction/requirements.txt
python scripts/reproduce_results.py --with-helpers
```

or `make -f reproduction/Makefile reproduce`, or `docker build -f reproduction/Dockerfile -t waves . && docker run --rm waves`.

`reproduce_results.py` exits with status 0 only if the dataset validates, the recomputed metrics equal the released
ones, and the statistics equal those in [`data/expected_counts.json`](../data/expected_counts.json). It writes the
figures to `results/figures/` and the tables to `results/tables/`. Runs are deterministic;
[`random_seeds.json`](random_seeds.json) records the only seed, used by the (non-reproducible) sampling step.

Tested with Python 3.12, pandas 2.2, numpy 2.1, matplotlib 3.10, PyYAML 6.0.

## Optional checks

- `python scripts/fetch_workflows.py --check` verifies that GitHub still serves the recorded bytes (needs network).
- `python -m unittest discover -s tests -v` runs the test suite.
