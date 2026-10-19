"""Score zizmor and poutine at several matching levels and write the tables.

Run after ``evaluation/adapters/zizmor_poutine.py`` has produced ``results/scanners/*.jsonl``:

    python evaluation/evaluate_scanners.py

Writes ``results/tables/scanner_eval_<tool>_<scope>_<level>.csv`` and
``results/tables/scanner_eval_summary.csv`` (micro precision/recall/F1 per tool, scope and level).

Scopes:
  all        all 475 workflows (headline). Precision is a lower bound: on the 365 helper-reviewed
             workflows only helper-proposed findings were verified.
  reference  the 100 reference workflows, where a missing label is a confirmed negative.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import ROOT, SUBSETS, load_findings, score  # noqa: E402

TOOLS = ["zizmor", "poutine"]
LEVELS = [("workflow", 0), ("block", 0), ("site", 0), ("site", 3)]
SCOPES = {"all": set(SUBSETS), "reference": {"reference"}}


def main() -> int:
    scanners = ROOT / "results" / "scanners"
    manifest = pd.read_csv(ROOT / "data" / "workflows.csv", dtype=str, keep_default_na=False)
    labels = pd.read_csv(ROOT / "data" / "labels.csv", dtype=str, keep_default_na=False)
    labels["line_number"] = labels["line_number"].astype(int)
    mapping = pd.read_csv(ROOT / "evaluation" / "adapters" / "rule_mapping.csv", dtype=str, keep_default_na=False)

    summary = []
    for tool in TOOLS:
        findings = load_findings(scanners / f"{tool}.jsonl")
        supported = set(mapping.loc[mapping["tool"] == tool, "weakness_id"]) - {""}
        for scope_name, subsets in SCOPES.items():
            for level, tolerance in LEVELS:
                table, _ = score(findings, labels, manifest, subsets, level, tolerance, None, supported)
                label = level if level != "site" else f"site_tol{tolerance}"
                out = ROOT / "results" / "tables" / f"scanner_eval_{tool}_{scope_name}_{label}.csv"
                out.parent.mkdir(parents=True, exist_ok=True)
                table.to_csv(out, index=False, lineterminator="\n")
                for row in table[table["weakness_id"].isin(["micro", "micro_supported"])].itertuples():
                    summary.append({"tool": tool, "scope": scope_name, "level": label, "row": row.weakness_id,
                                    "gold": row.gold, "predicted": row.predicted, "tp": row.tp, "fp": row.fp,
                                    "fn": row.fn, "precision": row.precision, "recall": row.recall, "f1": row.f1})
    result = pd.DataFrame(summary)
    result.to_csv(ROOT / "results" / "tables" / "scanner_eval_summary.csv", index=False, lineterminator="\n")
    print(result.to_string(index=False))
    for tool in TOOLS:
        print(f"\n{tool}, all 475 workflows, block level, per category")
        print(pd.read_csv(ROOT / "results" / "tables" / f"scanner_eval_{tool}_all_block.csv").to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
