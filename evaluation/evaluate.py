"""Score a scanner's findings against the WAVES ground truth.

Usage:
    python evaluation/evaluate.py scanner_output.jsonl
    python evaluation/evaluate.py scanner_output.jsonl --level block
    python evaluation/evaluate.py scanner_output.jsonl --level site --line-tolerance 2
    python evaluation/evaluate.py scanner_output.jsonl --subset reference --subset helper_reviewed
    python evaluation/evaluate.py zizmor.jsonl --scanned results/scanners/scanned_workflows.csv --tool zizmor
    python evaluation/evaluate.py scanner_output.jsonl --out results/tables/scanner_eval.csv

Input is JSON Lines following evaluation/scanner_output.schema.json. The matching
rules are documented in evaluation/matching_rules.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blocks import WORKFLOW, block_of  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CATS = ["AIW", "CFW", "EPW", "GRCW", "HGW", "IW", "KVCW", "PTW", "SEW", "UDW"]
WORKFLOW_LEVEL = {"EPW", "HGW", "PTW"}  # annotated at workflow level (Table 2)
SUBSETS = ["reference", "helper_reviewed", "synthetic"]


def load_findings(path: Path) -> list[dict]:
    findings = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            for field in ("workflow_id", "weakness_id"):
                if field not in record:
                    raise SystemExit(f"{path}:{number}: missing field {field!r}")
            if record["weakness_id"] is not None and record["weakness_id"] not in CATS:
                raise SystemExit(f"{path}:{number}: unknown weakness_id {record['weakness_id']!r}")
            findings.append(record)
    return findings


def scope_ids(manifest: pd.DataFrame, subsets: set[str], category: str, scanned: set[str] | None) -> set[str]:
    """Workflows over which a category is scored."""
    ids = set(manifest.loc[manifest["subset"].isin(subsets), "workflow_id"])
    if category == "CFW":
        ids |= set(manifest.loc[manifest["subset"] == "synthetic", "workflow_id"])
    if scanned is not None:
        ids &= scanned
    return ids


def site_key(workflow_id: str, category: str, line, level: str, snapshots: dict[str, str]):
    """Location part of a key, depending on the matching level."""
    if level == "workflow" or category in WORKFLOW_LEVEL:
        return 0 if level != "block" else WORKFLOW
    if level == "block":
        return block_of(snapshots[workflow_id], int(line) if line else None)
    return int(line or 0)


def same_site(a, b, level: str, tolerance: int) -> bool:
    if level == "site" and isinstance(a, int) and isinstance(b, int) and a and b:
        return abs(a - b) <= tolerance
    return a == b


def score(findings: list[dict], labels: pd.DataFrame, manifest: pd.DataFrame, subsets: set[str],
          level: str, tolerance: int, scanned: set[str] | None = None,
          supported: set[str] | None = None) -> tuple[pd.DataFrame, int]:
    snapshots = {r.workflow_id: str(ROOT / r.snapshot_path) for r in manifest.itertuples()}
    unmapped = sum(1 for f in findings if f["weakness_id"] is None)
    rows = []
    for cat in CATS:
        scope = scope_ids(manifest, subsets, cat, scanned)
        gold = sorted({
            (r.workflow_id, site_key(r.workflow_id, cat, r.line_number, level, snapshots))
            for r in labels.itertuples()
            if r.weakness_id == cat and r.workflow_id in scope
        }, key=str)
        pred = sorted({
            (f["workflow_id"], site_key(f["workflow_id"], cat, f.get("line_number"), level, snapshots))
            for f in findings
            if f["weakness_id"] == cat and f["workflow_id"] in scope
        }, key=str)

        def hit(p, g):
            return p[0] == g[0] and same_site(p[1], g[1], level, tolerance)

        tp = sum(1 for g in gold if any(hit(p, g) for p in pred))
        fp = sum(1 for p in pred if not any(hit(p, g) for g in gold))
        rows.append({"weakness_id": cat, "gold": len(gold), "predicted": len(pred),
                     "tp": tp, "fp": fp, "fn": len(gold) - tp})
    table = pd.DataFrame(rows)
    total = table[["gold", "predicted", "tp", "fp", "fn"]].sum()
    table.loc[len(table)] = {"weakness_id": "micro", **total.to_dict()}
    if supported is not None:
        sub = table[table["weakness_id"].isin(supported)][["gold", "predicted", "tp", "fp", "fn"]].sum()
        table.loc[len(table)] = {"weakness_id": "micro_supported", **sub.to_dict()}
    table["precision"] = (table["tp"] / (table["tp"] + table["fp"]).where(table["tp"] + table["fp"] > 0)).round(3)
    table["recall"] = (table["tp"] / (table["tp"] + table["fn"]).where(table["tp"] + table["fn"] > 0)).round(3)
    denominator = (table["precision"] + table["recall"]).where(lambda s: s > 0)
    table["f1"] = (2 * table["precision"] * table["recall"] / denominator).round(3)
    return table, unmapped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("findings", type=Path, help="scanner output (JSON Lines)")
    parser.add_argument("--level", choices=["workflow", "block", "site"], default="workflow")
    parser.add_argument("--line-tolerance", type=int, default=0, help="only for --level site")
    parser.add_argument("--subset", action="append", choices=SUBSETS + ["all"],
                        help="subset(s) to score (default: reference)")
    parser.add_argument("--scanned", type=Path,
                        help="CSV with workflow_id and one boolean column per tool (see evaluation/adapters)")
    parser.add_argument("--tool", help="column of --scanned to use; unscanned workflows are left out of the scoring")
    parser.add_argument("--supported",
                        help="comma-separated categories the scanner can report; adds a micro_supported row "
                             "(default with --tool: categories present in adapters/rule_mapping.csv)")
    parser.add_argument("--out", type=Path, help="write the table as CSV")
    args = parser.parse_args()

    subsets = set(SUBSETS) if (args.subset and "all" in args.subset) else set(args.subset or ["reference"])
    manifest = pd.read_csv(ROOT / "data" / "workflows.csv", dtype=str, keep_default_na=False)
    labels = pd.read_csv(ROOT / "data" / "labels.csv", dtype=str, keep_default_na=False)
    labels["line_number"] = labels["line_number"].astype(int)
    findings = load_findings(args.findings)
    unknown = {f["workflow_id"] for f in findings} - set(manifest["workflow_id"])
    if unknown:
        raise SystemExit(f"unknown workflow_id values: {sorted(unknown)[:5]}")

    scanned = None
    if args.scanned:
        if not args.tool:
            raise SystemExit("--scanned needs --tool")
        coverage = pd.read_csv(args.scanned, dtype=str)
        scanned = set(coverage.loc[coverage[args.tool] == "True", "workflow_id"])

    supported = None
    if args.supported:
        supported = {c.strip() for c in args.supported.split(",")}
    elif args.tool:
        mapping = pd.read_csv(ROOT / "evaluation" / "adapters" / "rule_mapping.csv", dtype=str, keep_default_na=False)
        supported = set(mapping.loc[mapping["tool"] == args.tool, "weakness_id"]) - {""}

    table, unmapped = score(findings, labels, manifest, subsets, args.level, args.line_tolerance, scanned, supported)
    print(f"level={args.level} line_tolerance={args.line_tolerance} subsets={sorted(subsets)}"
          + (f" scanned_only={len(scanned)} workflows" if scanned is not None else ""))
    print(table.to_string(index=False))
    print(f"unmapped findings (weakness_id null): {unmapped}")
    if "helper_reviewed" in subsets:
        print("note: precision on helper_reviewed workflows is a lower bound (see matching_rules.md)")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out, index=False, lineterminator="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
