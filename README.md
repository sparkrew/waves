# WAVES: a ground-truth dataset of security weaknesses in GitHub Actions workflows

> **Not yet public.** This repository names real public repositories and annotates them with security weaknesses.
> Public release follows maintainer notification; see [docs/ethics_and_disclosure.md](docs/ethics_and_disclosure.md).

WAVES contains **475 GitHub Actions workflows** (465 real-world snapshots and 10 synthetic ones) manually labeled against
the ten-weakness classification of [Fares et al.](https://arxiv.org/abs/2601.14455) (AIW, CFW, EPW, GRCW, HGW, IW, KVCW,
PTW, SEW, UDW). Labels are multi-label and evidence-linked: **2,424 weakness instances** over 467 workflows, and 8
confirmed all-negative workflows. It is meant to compare workflow security scanners on a common ground truth.

The collection was built in collaboration with an industry partner, which maintains the corpus the workflows were sampled from
and also develops the Poutine scanner (a competing interest, see the ethics document). The corpus itself (1,048,857
workflows) is proprietary and is **not** part of this repository; only our sample is released.

## Quick start

```bash
python -m pip install -r reproduction/requirements.txt
python scripts/validate_dataset.py          # integrity and expected counts
python scripts/reproduce_results.py         # metrics, figures, tables, statistics
python evaluation/evaluate.py evaluation/example_scanner_output.jsonl   # score a scanner
```

## Layout

| Path | Content |
|---|---|
| `data/workflows.csv` | One row per workflow: ids, source, four metrics, subset, license, hash |
| `data/labels.csv` | The ground truth: 2,424 labels keyed by `workflow_id` and `label_id` |
| `data/reference_decisions.csv` | Frozen labels of the 100 reference workflows (two annotators), linked to `labels.csv` by `label_id` |
| `data/helper_candidates.csv` | 2,136 helper candidates and their manual decision; accepted ones are linked to `labels.csv` by `label_id` |
| `data/expected_counts.json` | The counts and statistics checked by the scripts |
| `data/inventories/` | KVCW action inventory, GRCW baseline, sources |
| `workflows/` | The YAML snapshots (`real/`, `synthetic/`) and `checksums.sha256` |
| `docs/` | Annotation guide, data dictionary, sampling, methodology, limitations, provenance, ethics |
| `scripts/` | Helpers (detectors), metrics, action analysis, sampling (provenance only), validation, reproduction |
| `evaluation/` | Scanner output schema, matching rules, `evaluate.py` |
| `reproduction/` | Requirements, Dockerfile, Makefile, seeds |
| `results/` | Regenerated figures and tables |
| `tests/` | Test suite (`python -m unittest discover -s tests -v`) |

The field definitions are in [docs/data_dictionary.md](docs/data_dictionary.md).

## Important caveats

- The sample is diversity-oriented, not representative: counts are not prevalence estimates.
- The 100 reference workflows were labeled by two annotators over all ten categories. For the 365 helper-reviewed
  workflows, only helper-proposed findings were verified, so a missing label there is not a confirmed negative.
- The ten synthetic workflows exist only to cover CFW, which did not occur in real workflows.
- Workflow snapshots keep the licenses of their upstream repositories; see [NOTICE](NOTICE).

See [docs/limitations.md](docs/limitations.md).

## Citation and licenses

See [CITATION.cff](CITATION.cff). Code: MIT ([LICENSE-CODE](LICENSE-CODE)). Data and annotations: CC BY 4.0
([LICENSE-DATA](LICENSE-DATA)). Third-party workflow files: their own licenses ([NOTICE](NOTICE)).
