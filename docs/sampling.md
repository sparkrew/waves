# Sampling and Workflow Metrics

> **Provenance only.** The workflows were sampled from a proprietary corpus of 1,048,857 public GitHub Actions
> workflows maintained by Boost Security. That corpus is not published and we are only allowed to release our samples.
> The sampling scripts in [`scripts/sampling/`](../scripts/sampling) therefore document the procedure but cannot be re-run
> from this repository. Everything downstream of the sample (metrics, labels, figures) is reproducible: see
> [`reproduction/README.md`](../reproduction/README.md).

The sample is **diversity-oriented**: it exposes the labeling process to heterogeneous workflow configurations. It is not
a random sample of GitHub and must not be used to estimate how common a weakness is.

## The four metrics

Each metric assigns a workflow to one of three levels. The released values are in
[`data/workflows.csv`](../data/workflows.csv) and are recomputed from the snapshots by
[`scripts/metrics/compute_metrics.py`](../scripts/metrics/compute_metrics.py).

| Metric (column) | Levels | Definition |
|---|---|---|
| Structural complexity (`structural_complexity`) | `simple`, `medium`, `complex` | `simple`: one job and at most three steps (J = 1 and S <= 3). `medium`: two to three jobs or four to ten steps (2 <= J <= 3 or 4 <= S <= 10). `complex`: all remaining workflows. Rules are evaluated in the order `simple`, `medium`, then `complex` as the residual class, so a workflow with two jobs and twelve steps is `medium` (2 <= J <= 3) and a workflow with one job and twenty steps is `complex`. Matrix strategies are not used. |
| Trigger trust exposure (`trigger_trust_exposure`) | `low`, `medium`, `high` | `high` if any trigger is `pull_request_target`, `issue_comment`, `issues`, `discussion_comment` or `workflow_run`; `medium` if `pull_request`; `low` for every other event (for example `push`, `schedule`, `workflow_dispatch`). With several triggers the highest level applies. |
| Action pinning profile (`action_pinning_profile`) | `no_third_party`, `pinned_third_party`, `unpinned_third_party` | Over step-level `uses:` references that are neither local (`./`) nor reusable workflows (`.yml`/`.yaml`): `no_third_party` if there are none; `pinned_third_party` if at least half match `@[0-9a-f]{40}$` (a 50/50 workflow is `pinned_third_party`); otherwise `unpinned_third_party`. Job-level `uses:` of reusable workflows is not counted. |
| Untrusted data exposure (`untrusted_data_exposure`) | `no_expressions`, `expressions_no_taint`, `has_taint_sources` | Over `run:` blocks and `env:` values: `no_expressions` if no `run:` block interpolates `${{ ... }}`; `has_taint_sources` if an expression references one of the attacker-controlled contexts of the ARGUS catalog (`TAINT_SOURCES` in `sample_workflows.py`); `expressions_no_taint` otherwise. |

The corpus distribution behind the complexity thresholds (pre-sampling): 75% of workflows declare one job, 17% two or
three jobs and 8% four or more; 38% have at most three steps, 47% four to ten and 15% more than ten.

## Two-phase selection

1. **Candidate pool (BigQuery, [`diversity_metrics.sql`](../scripts/sampling/diversity_metrics.sql)).** Structural
   complexity and trigger trust exposure are computable from the corpus metadata (job and step counts, declared events), so
   they are computed in SQL. The content-based metrics need the workflow text, which is too costly to scan for the whole
   corpus. The query therefore draws a balanced pool over 27 cells: the 9 combinations of complexity x trigger, each
   split by a SQL proxy for action dependency (no third-party actions, few, many). It keeps 55 random workflows per cell,
   **27 x 55 = 1,485 candidates**.
2. **Stratified sample (Python, [`sample_workflows.py`](../scripts/sampling/sample_workflows.py), seed 42).** For the pool,
   the workflow files are retrieved and the pinning and untrusted-data metrics are computed. The four three-level metrics
   define up to 81 sampling cells. The script allocates `floor(N / n_cells)` workflows per cell, distributes the remainder
   round-robin, caps each cell at its size and tops up from unsampled rows to reach N = 500.

## From 500 to the released sample

- The 500 selected rows contain 497 distinct workflow URLs (3 duplicates).
- 465 real-world workflows were manually reviewed and are released: 100 reference workflows (labeled manually by two
  annotators) and 365 helper-reviewed workflows. See [`methodology.md`](methodology.md).
- In the exported 500-row file the content-based columns were not populated (`sha_pinning_ratio` empty and
  `security_surface_bucket` constant), so the sampler could not balance those two axes. For the release, **all four
  metrics were recomputed from the snapshots**, which is what [`data/workflows.csv`](../data/workflows.csv) contains and
  what `compute_metrics.py` verifies.
- Ten synthetic CFW workflows are added (see [`methodology.md`](methodology.md)); their metrics are computed the same way.

## Realized distribution of the 465 real-world workflows

| Metric | Distribution |
|---|---|
| Structural complexity | simple 161, medium 142, complex 162 |
| Trigger trust exposure | low 159, medium 163, high 143 |
| Action pinning profile | no_third_party 220, unpinned_third_party 212, pinned_third_party 33 |
| Untrusted data exposure | no_expressions 378, expressions_no_taint 82, has_taint_sources 5 |

The 465 workflows populate 43 of the 81 four-metric cells; cell sizes range from 1 to 28. Pinned third-party and
taint-source workflows are rare, which is one reason injection weaknesses are infrequent in the labeled set.
