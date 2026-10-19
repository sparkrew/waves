"""Recompute the four workflow metrics from the released snapshots.

The metrics are defined in docs/sampling.md. This script derives all four from
the YAML files in workflows/ and compares them with data/workflows.csv:

    structural_complexity     simple | medium | complex
    trigger_trust_exposure    low | medium | high
    action_pinning_profile    no_third_party | pinned_third_party | unpinned_third_party
    untrusted_data_exposure   no_expressions | expressions_no_taint | has_taint_sources

Usage:
    python scripts/metrics/compute_metrics.py            # compare, exit 1 on mismatch
    python scripts/metrics/compute_metrics.py --write    # rewrite the four columns
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sampling"))
from sample_workflows import EXPR_RE, SHA_RE, TAINT_PATTERNS  # noqa: E402

HIGH_EVENTS = {
    "pull_request_target", "issue_comment", "issues",
    "discussion_comment", "workflow_run",
}
METRIC_COLUMNS = {
    "structural_complexity": "complexity",
    "trigger_trust_exposure": "trigger",
    "action_pinning_profile": "pinning",
    "untrusted_data_exposure": "surface",
}


def event_names(doc: dict) -> set[str]:
    # PyYAML (YAML 1.1) parses the bare key `on` as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(e) for e in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def collect(doc: dict) -> tuple[int, int, list[str], list[str], list[str]]:
    """jobs, steps, step-level `uses`, `run` blocks, env values."""
    jobs = doc.get("jobs") or {}
    uses: list[str] = []
    runs: list[str] = []
    envs: list[str] = []

    def add_env(e) -> None:
        if isinstance(e, dict):
            envs.extend(str(v) for v in e.values() if v is not None)

    add_env(doc.get("env"))
    n_steps = 0
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        add_env(job.get("env"))
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            n_steps += 1
            add_env(step.get("env"))
            if isinstance(step.get("uses"), str):
                uses.append(step["uses"])
            if isinstance(step.get("run"), str):
                runs.append(step["run"])
    return len(jobs), n_steps, uses, runs, envs


def collect_regex(text: str) -> tuple[int, int, list[str], list[str], list[str]]:
    """Fallback for files that are not valid YAML (counts are unavailable)."""
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, re.M)
    runs = re.findall(r"^\s*-?\s*run:\s*(.+)$", text, re.M)
    return 0, 0, uses, runs, []


def third_party(uses: list[str]) -> list[str]:
    """Not a local ./ reference and not a reusable workflow (.yml/.yaml)."""
    return [
        u for u in uses
        if not u.startswith("./") and not u.lower().endswith((".yml", ".yaml"))
    ]


def analyze(path: Path) -> dict[str, str]:
    text = path.read_bytes().decode("utf-8", errors="replace")
    try:
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise ValueError("not a mapping")
        n_jobs, n_steps, uses, runs, envs = collect(doc)
        events = event_names(doc)
    except Exception:  # noqa: BLE001
        n_jobs, n_steps, uses, runs, envs = collect_regex(text)
        events = set()

    tp = third_party(uses)
    if not tp:
        pinning = "no_third_party"
    else:
        ratio = sum(1 for u in tp if SHA_RE.search(u)) / len(tp)
        pinning = "pinned_third_party" if ratio >= 0.5 else "unpinned_third_party"

    run_text = "\n".join(runs)
    full_text = run_text + "\n" + "\n".join(envs)
    if not EXPR_RE.search(run_text):
        surface = "no_expressions"
    elif not any(p.search(full_text) for p in TAINT_PATTERNS):
        surface = "expressions_no_taint"
    else:
        surface = "has_taint_sources"

    if n_jobs == 1 and n_steps <= 3:
        complexity = "simple"
    elif 2 <= n_jobs <= 3 or 4 <= n_steps <= 10:
        complexity = "medium"
    else:
        complexity = "complex"

    if events & HIGH_EVENTS:
        trigger = "high"
    elif "pull_request" in events:
        trigger = "medium"
    else:
        trigger = "low"

    return {
        "complexity": complexity, "trigger": trigger,
        "pinning": pinning, "surface": surface,
    }


def recompute(manifest: pd.DataFrame) -> pd.DataFrame:
    rows = [analyze(ROOT / p) for p in manifest["snapshot_path"]]
    return pd.DataFrame(rows, index=manifest.index)


def compare(manifest: pd.DataFrame) -> dict[str, int]:
    """Number of rows whose released value differs from the recomputed one."""
    fresh = recompute(manifest)
    return {
        col: int((manifest[col] != fresh[key]).sum())
        for col, key in METRIC_COLUMNS.items()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--write", action="store_true", help="rewrite the metric columns")
    args = parser.parse_args()

    path = ROOT / "data" / "workflows.csv"
    manifest = pd.read_csv(path, dtype=str, keep_default_na=False)
    diffs = compare(manifest)
    for col, n in diffs.items():
        print(f"{col:<26} {'OK' if n == 0 else f'{n} rows differ'}")
    if args.write and any(diffs.values()):
        fresh = recompute(manifest)
        for col, key in METRIC_COLUMNS.items():
            manifest[col] = fresh[key]
        manifest.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
        print("rewrote", path)
        return 0
    return 1 if any(diffs.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
