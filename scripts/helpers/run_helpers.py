"""Run the labeling helpers (decision-tree detectors) on the released snapshots.

The helpers are recall-oriented: they propose candidate weakness instances for
manual review and never assign final labels (see docs/methodology.md).

Usage:
    python scripts/helpers/run_helpers.py                      # all real workflows
    python scripts/helpers/run_helpers.py --subset reference   # only the 100-workflow reference subset
    python scripts/helpers/run_helpers.py --out results/tables/helper_output.csv
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from detectors.parse import load_context  # noqa: E402
from detectors.registry import detect_all  # noqa: E402

COLUMNS = ["workflow_id", "line_number", "weakness_id", "evidence", "explanation"]


def weakness_id(weakness_type: str) -> str:
    return re.search(r"\(([A-Z]+)\)\s*$", weakness_type).group(1)


def run(subsets: set[str] | None = None) -> pd.DataFrame:
    manifest = pd.read_csv(ROOT / "data" / "workflows.csv", dtype=str, keep_default_na=False)
    if subsets:
        manifest = manifest[manifest["subset"].isin(subsets)]
    rows = []
    for row in manifest.itertuples():
        text = (ROOT / row.snapshot_path).read_text(encoding="utf-8", errors="replace")
        ctx = load_context(row.workflow_blob_url, text)
        for label in detect_all(ctx):
            rows.append({
                "workflow_id": row.workflow_id,
                "line_number": label.line_number,
                "weakness_id": weakness_id(label.weakness_type),
                "evidence": label.evidence,
                "explanation": label.explanation,
            })
    return pd.DataFrame(rows, columns=COLUMNS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--subset", action="append",
                        choices=["reference", "helper_reviewed", "synthetic"],
                        help="restrict to a subset (repeatable)")
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "tables" / "helper_output.csv")
    args = parser.parse_args()

    out = run(set(args.subset) if args.subset else None)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False, encoding="utf-8", lineterminator="\n")
    print(f"{len(out)} helper candidates over {out['workflow_id'].nunique()} workflows -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
