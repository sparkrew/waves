# Matching Rules

A scanner finding is compared with a ground-truth label of [`data/labels.csv`](../data/labels.csv).
Findings are first normalized to `(workflow_id, weakness_id, line_number)`; duplicates are collapsed.

## Levels

| Level | Key | When to use |
|---|---|---|
| `workflow` (default) | `(workflow_id, weakness_id)` | Compare which categories a scanner finds in a workflow; ignores where. |
| `block` | `(workflow_id, weakness_id, block)` | **Recommended when comparing different tools.** `block` is the innermost step of the snapshot containing the line, else the job, else the workflow (`evaluation/blocks.py`). A finding matches a label if both fall in the same block, so a scanner that points at the start of a `run:` scalar and an annotator who points at the `${{ }}` line inside it still agree. Differences of line numbering vanish; disagreements about *which* step or job remain. |
| `site` | `(workflow_id, weakness_id, line_number)` | Compare the exact location. A finding matches a label of the same workflow and category whose line differs by at most `--line-tolerance` lines (default 0). |

At the `site` level, categories annotated at workflow level (EPW, HGW, PTW; see Table 2 of the paper) are matched on
`(workflow_id, weakness_id)` only, because their evidence is a property of the whole workflow rather than one line.

## Counting

For each category: a **true positive** is a ground-truth key matched by at least one finding; a **false negative** is a
ground-truth key with no matching finding; a **false positive** is a finding key matching no ground-truth key. Each
ground-truth key counts once, however many findings match it. The overall row is the micro average over the ten
categories. Findings whose `weakness_id` is `null` are counted separately as `unmapped` and are not part of any category.

## Scope: where false positives are meaningful

Precision is only meaningful where missing labels are confirmed negatives.

- `--subset reference` (default): the 100 reference workflows, evaluated against all ten categories by two annotators.
- `--subset helper_reviewed`: the 365 helper-reviewed workflows. Recall is meaningful; **precision is not**, because only
  helper-proposed findings were verified there, so a scanner finding without a label may be a real weakness the helpers
  missed. Report it as a lower bound.
- `--subset synthetic`: the ten synthetic workflows carry CFW labels only.
- `--subset all`: all 475 workflows, with the caveats above.

CFW has no instances in the real-world workflows. Whatever subsets are selected, CFW is also scored on the synthetic
workflows (and only CFW findings on them are considered), so that every category can be evaluated.

## Unscanned workflows and unsupported categories

- In the zizmor/poutine run the harness wrote an output file only when a tool reported something, so the 21 workflows
  without a file are workflows with zero findings. They stay in the scoring (their labels count as false negatives).
  If a harness can fail silently, pass `--scanned` and `--tool` to `evaluate.py` to exclude unscanned workflows.
- A scanner usually covers only some categories. The `micro_supported` row aggregates only the categories for which the
  tool has at least one rule in `evaluation/adapters/rule_mapping.csv`; `micro` includes all ten and therefore
  charges the tool with recall on categories it cannot report. Report both.

## Running zizmor and poutine

```
python evaluation/adapters/zizmor_poutine.py PATH/TO/scanners_output   # -> results/scanners/*.jsonl
python evaluation/evaluate_scanners.py                                  # -> results/tables/scanner_eval_*.csv
```

## Reporting checklist

- Publish the mapping from your scanner's rules to WAVES categories.
- Report per-category and overall precision, recall and F1, the level, the line tolerance and the subset.
- Do not read the results as a prevalence estimate: the sample is diversity-oriented.
