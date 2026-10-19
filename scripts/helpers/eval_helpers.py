"""Compare helper output with the reference decisions of the 100-workflow subset.

Matching is on (workflow_id, weakness_id), the level at which the helpers were
tuned (docs/methodology.md). A second, stricter table also matches line numbers.
The helpers were developed on exactly these 100 workflows, so the numbers are a
consistency check and not a generalization estimate.

Usage:
    python scripts/helpers/eval_helpers.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from run_helpers import run  # noqa: E402

CATS = ["IW", "PTW", "SEW", "KVCW", "AIW", "CFW", "EPW", "UDW", "GRCW", "HGW"]


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def table(gold: set, pred: set) -> pd.DataFrame:
    """Per-category scores over keys whose second element is the weakness id."""
    rows = []
    for cat in CATS:
        g = {k for k in gold if k[1] == cat}
        p = {k for k in pred if k[1] == cat}
        tp, fp, fn = len(g & p), len(p - g), len(g - p)
        precision, recall, f1 = prf(tp, fp, fn)
        rows.append({"weakness_id": cat, "gold": len(g), "predicted": len(p), "tp": tp,
                     "fp": fp, "fn": fn, "precision": round(precision, 3),
                     "recall": round(recall, 3), "f1": round(f1, 3)})
    return pd.DataFrame(rows)


def main() -> int:
    reference = pd.read_csv(ROOT / "data" / "reference_decisions.csv", dtype=str, keep_default_na=False)
    pred = run({"reference"})

    gold_wc = set(zip(reference["workflow_id"], reference["weakness_id"]))
    pred_wc = set(zip(pred["workflow_id"], pred["weakness_id"]))
    gold_l = set(zip(reference["workflow_id"], reference["weakness_id"], reference["line_number"].astype(int)))
    pred_l = set(zip(pred["workflow_id"], pred["weakness_id"], pred["line_number"].astype(int)))
    print("== workflow x weakness ==")
    print(table(gold_wc, pred_wc).to_string(index=False))
    print("\n== workflow x weakness x line ==")
    print(table(gold_l, pred_l).to_string(index=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
