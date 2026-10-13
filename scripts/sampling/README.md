# Sampling scripts (provenance only)

These files document how the 500 candidate workflows were selected. **They cannot be run from this repository.**
They need the proprietary Boost Security corpus of 1,048,857 workflows (BigQuery tables), which we are not allowed to
publish. Only the resulting sample is released: see [`data/workflows.csv`](../../data/workflows.csv).

| File | Role |
|---|---|
| `diversity_metrics.sql` | BigQuery query: computes the cheap metrics and returns a candidate pool of 55 workflows per cell, 27 cells, 1,485 rows |
| `sample_workflows.py` | Reads the exported pool, computes the content-based metrics, draws the stratified sample with seed 42 |

`sample_workflows.py` is also imported by `scripts/metrics/compute_metrics.py` for the shared regular expressions
(SHA pinning, expression detection, taint sources), so keep it in place. See [`docs/sampling.md`](../../docs/sampling.md).
