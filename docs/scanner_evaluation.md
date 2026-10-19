# Evaluating a Scanner with WAVES

WAVES can score any GitHub Actions workflow scanner: run it on the snapshots in `workflows/`, normalize its output to
the format below, and compare it with `data/labels.csv` using [`evaluation/evaluate.py`](../evaluation/evaluate.py).

## 1. Run the scanner

Run it on the 475 files `workflows/real/*.yml` and `workflows/synthetic/*.yml`. File names are the `workflow_id`
(for example `WAVES-0001.yml`). Scanners that need the repository layout can be pointed at a copy of each file placed
at `workflow_path` from `data/workflows.csv`.

## 2. Normalize the output

One JSON object per line (JSON Lines), validated by
[`evaluation/scanner_output.schema.json`](../evaluation/scanner_output.schema.json):

```json
{"workflow_id": "WAVES-0001", "weakness_id": "UDW", "line_number": 12, "rule": "pinned-actions", "message": "..."}
```

`weakness_id` must be one of the ten categories. Mapping the scanner's native rules to the categories is part of the
evaluation and should be published with the results. A finding with no category can be reported as `"weakness_id": null`;
it counts as unmatched.

## 3. Compare

```bash
python evaluation/evaluate.py scanner_output.jsonl --out results/tables/scanner_eval.csv
```

The matching rules are in [`evaluation/matching_rules.md`](../evaluation/matching_rules.md). Report per-category and
overall precision, recall and F1, and report the `subset` breakdown: precision and recall on the 100 reference
workflows are not directly comparable with the 365 helper-reviewed workflows, because missing labels there are not
confirmed negatives (see [limitations.md](limitations.md)). CFW can only be evaluated on the synthetic workflows.
