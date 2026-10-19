"""Result tables of the scanner evaluation (paper Section 6).

Reads the block-level scores on all 475 workflows written by
``evaluation/evaluate_scanners.py`` (results/tables/scanner_eval_<tool>_all_block.csv) and writes, for each scanner,
one LaTeX table with precision and recall as rows and the weakness categories the scanner supports as columns
(alphabetical order). The overall scores are kept in scanner_results.csv only:

    results/tables/tab_poutine_results.tex
    results/tables/tab_zizmor_results.tex
    results/tables/scanner_results.csv          the numbers behind the tables

A category is supported when at least one rule of the scanner is mapped to it
(evaluation/adapters/rule_mapping.csv). "--" marks an undefined precision (the scanner reports no scorable finding in the
category); precision 0.00 means that it reports findings but none matches a label.

Usage:
    python scripts/metrics/make_scanner_tables.py
    python scripts/metrics/make_scanner_tables.py --paper-dir "PATH/TO/paper/figures"   # also copy the tables
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
TABLES = ROOT / "results" / "tables"
TOOLS = ["poutine", "zizmor"]


def supported_categories(tool: str) -> list[str]:
    mapping = pd.read_csv(ROOT / "evaluation" / "adapters" / "rule_mapping.csv", dtype=str, keep_default_na=False)
    cats = set(mapping.loc[mapping["tool"] == tool, "weakness_id"]) - {""}
    return sorted(cats)  # alphabetical


def scores(tool: str) -> pd.DataFrame:
    table = pd.read_csv(TABLES / f"scanner_eval_{tool}_all_block.csv").set_index("weakness_id")
    rows = []
    for cat in supported_categories(tool) + ["micro_supported"]:
        r = table.loc[cat]
        tp, fp, fn = int(r.tp), int(r.fp), int(r.fn)
        rows.append({
            "tool": tool,
            "category": "Overall" if cat == "micro_supported" else cat,
            "units": int(r.gold), "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else np.nan,
            "recall": tp / (tp + fn) if tp + fn else np.nan,
        })
    return pd.DataFrame(rows)


def fmt(value: float) -> str:
    return "--" if pd.isna(value) else f"{value:.2f}"


def latex(df: pd.DataFrame) -> str:
    df = df[df["category"] != "Overall"]  # overall scores stay in scanner_results.csv and in the paper text
    cats = list(df["category"])
    spec = "@{}l" + "c" * len(cats) + "@{}"
    header = " & ".join(["", *cats]) + r" \\"
    p = " & ".join(["Precision", *[fmt(v) for v in df["precision"]]]) + r" \\"
    r = " & ".join(["Recall", *[fmt(v) for v in df["recall"]]]) + r" \\"
    lines = [rf"\begin{{tabular}}{{{spec}}}", r"\toprule", header, r"\midrule", p, r,
             r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--paper-dir", type=Path, help="copy the tables into the paper's figures/ folder")
    args = parser.parse_args()

    TABLES.mkdir(parents=True, exist_ok=True)
    frames = {tool: scores(tool) for tool in TOOLS}
    pd.concat(frames.values()).round(4).to_csv(TABLES / "scanner_results.csv", index=False, lineterminator="\n")
    out = []
    for tool, df in frames.items():
        path = TABLES / f"tab_{tool}_results.tex"
        path.write_text(latex(df), encoding="utf-8", newline="\n")
        out.append(path)
        print(f"\n{tool}")
        print(df.round(3).to_string(index=False))
    if args.paper_dir:
        args.paper_dir.mkdir(parents=True, exist_ok=True)
        for src in out:
            shutil.copy(src, args.paper_dir / src.name)
        print(f"\ncopied to {args.paper_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
