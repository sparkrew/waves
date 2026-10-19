"""Convert the zizmor + poutine per-workflow JSON files into WAVES scanner-output JSONL.

The scanning harness wrote one JSON file per workflow into a directory, named
``<owner>-<repo>-<workflow-file-stem>.yml.json`` (a ``-<commit[:8]>`` suffix is added
when the same repository and file occur at several commits). This adapter

  1. resolves every file name to a WAVES ``workflow_id``,
  2. maps each finding to a WAVES ``weakness_id`` (``evaluation/adapters/rule_mapping.csv``),
  3. writes one JSON Lines file per tool in the format of
     ``evaluation/scanner_output.schema.json``.

Usage:
    python evaluation/adapters/zizmor_poutine.py PATH/TO/scanners_output \
        --out-dir results/scanners

The harness wrote an output file only for workflows on which at least one tool reported a finding.
A workflow without a file was scanned and had zero findings from both tools, so it stays in the
scoring (as a workflow with no predictions).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MAPPING = Path(__file__).with_name("rule_mapping.csv")

CAPABILITY_TO_WEAKNESS = {
    "excessive-permission-weakness": "EPW",
    "unpinned-dependency-weakness": "UDW",
    "artifact-integrity-weakness": "AIW",
    "injection-weakness": "IW",
    "secrets-exposure-weakness": "SEW",
    "privileged-trigger-weakness": "PTW",
    "control-flow-weakness": "CFW",
    "known-vulnerable-component-weakness": "KVCW",
    "hardening-gap-weakness": "HGW",
}


def stem_key(repository: str, workflow_path: str) -> str:
    stem = re.sub(r"\.ya?ml$", "", workflow_path.rsplit("/", 1)[-1], flags=re.I)
    return f"{repository.replace('/', '-')}-{stem}"


def resolve_names(manifest: pd.DataFrame, names: set[str]) -> tuple[dict[str, str], list[str]]:
    """Map output-file stem -> workflow_id. Returns (mapping, unresolved file stems)."""
    assigned: dict[str, str] = {}
    by_key = defaultdict(list)
    for row in manifest.itertuples():
        by_key[stem_key(row.repository, row.workflow_path)].append(row)

    for key, rows in by_key.items():
        pending = []
        for row in rows:
            suffixed = f"{key}-{row.commit_sha[:8]}"
            if suffixed in names:
                assigned[suffixed] = row.workflow_id
            else:
                pending.append(row)
        if key in names and len(pending) == 1:
            assigned[key] = pending[0].workflow_id
        elif key in names and len(pending) > 1:
            # ambiguous: several workflows share the plain name; leave unresolved
            pass

    # fallback for synthetic workflows: the owner part of `repository` is anonymized in the release, whereas
    # scanner output files keep the original owner. Match on "-<repo>-<stem>" only.
    taken = set(assigned.values())
    for row in manifest.itertuples():
        if row.source_type != "synthetic" or row.workflow_id in taken:
            continue
        repo_name = row.repository.split("/", 1)[-1]
        stem = re.sub(r"\.ya?ml$", "", row.workflow_path.rsplit("/", 1)[-1], flags=re.I)
        hits = [n for n in names - set(assigned) if n.endswith(f"-{repo_name}-{stem}")]
        if len(hits) == 1:
            assigned[hits[0]] = row.workflow_id
            taken.add(row.workflow_id)

    # fallback: "<owner>__<repo>" names (no workflow stem)
    taken = set(assigned.values())
    for name in sorted(names - set(assigned)):
        if "__" not in name:
            continue
        owner, repo = name.split("__", 1)
        hits = manifest[(manifest["repository"] == f"{owner}/{repo}") & ~manifest["workflow_id"].isin(taken)]
        if len(hits) == 1:
            assigned[name] = hits.iloc[0]["workflow_id"]
            taken.add(assigned[name])
    return assigned, sorted(names - set(assigned))


def load_mapping() -> dict[tuple[str, str], str | None]:
    table = pd.read_csv(MAPPING, dtype=str, keep_default_na=False)
    return {(r.tool, r.rule): (r.weakness_id or None) for r in table.itertuples()}


def to_int(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("scanners_dir", type=Path)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results" / "scanners")
    args = parser.parse_args()

    manifest = pd.read_csv(ROOT / "data" / "workflows.csv", dtype=str, keep_default_na=False)
    files = {p.name[: -len(".json")]: p for p in args.scanners_dir.glob("*.json")}
    names = {n[: -len(".yml")] if n.endswith(".yml") else n for n in files}
    name_to_file = {(n[: -len(".yml")] if n.endswith(".yml") else n): p for n, p in files.items()}
    assigned, unresolved = resolve_names(manifest, names)
    if unresolved:
        print(f"WARNING: {len(unresolved)} output files could not be resolved: {unresolved}", file=sys.stderr)

    mapping = load_mapping()
    records: dict[str, list[dict]] = defaultdict(list)
    unknown_rules: set[tuple[str, str]] = set()
    for name, workflow_id in assigned.items():
        data = json.loads(name_to_file[name].read_text(encoding="utf-8"))
        for tool, block in data["tools"].items():
            for finding in block.get("findings", []):
                rule = finding["rule_id"]
                if (tool, rule) not in mapping:
                    unknown_rules.add((tool, rule))
                    continue
                records[tool].append({
                    "workflow_id": workflow_id,
                    "weakness_id": mapping[(tool, rule)],
                    "line_number": to_int(finding.get("line")),
                    "rule": rule,
                    "message": finding.get("message") or finding.get("details") or "",
                })
    if unknown_rules:
        raise SystemExit(f"rules missing from rule_mapping.csv: {sorted(unknown_rules)}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for tool, rows in records.items():
        path = args.out_dir / f"{tool}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        with_findings = len({row["workflow_id"] for row in rows})
        print(f"{tool}: {len(rows)} findings in {with_findings} of {len(manifest)} workflows -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
