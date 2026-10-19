"""Validate the integrity of the WAVES dataset.

Checks, in order:
  1. manifest columns, ids, value domains, lowercase booleans
  2. snapshots exist and their SHA-256 matches both the manifest and checksums.sha256
  3. foreign keys of labels, reference decisions and helper candidates
  4. has_confirmed_finding agrees with labels.csv
  5. label_id links: every reference decision and accepted helper candidate points to its
     row in labels.csv, and together with the synthetic labels they cover labels.csv exactly
  6. counts equal data/expected_counts.json

Usage:
    python scripts/validate_dataset.py
Exit status is 0 only if every check passes.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

WEAKNESS_IDS = {"AIW", "CFW", "EPW", "GRCW", "HGW", "IW", "KVCW", "PTW", "SEW", "UDW"}
MANIFEST_COLUMNS = [
    "workflow_id", "source_type", "repository", "workflow_path", "commit_sha",
    "workflow_blob_url", "subset", "structural_complexity", "trigger_trust_exposure",
    "action_pinning_profile", "untrusted_data_exposure", "has_confirmed_finding",
    "retrieval_date", "file_sha256", "snapshot_path", "license",
]
DOMAINS = {
    "source_type": {"real_world", "synthetic"},
    "subset": {"reference", "helper_reviewed", "synthetic"},
    "structural_complexity": {"simple", "medium", "complex"},
    "trigger_trust_exposure": {"low", "medium", "high"},
    "action_pinning_profile": {"no_third_party", "pinned_third_party", "unpinned_third_party"},
    "untrusted_data_exposure": {"no_expressions", "expressions_no_taint", "has_taint_sources"},
    "has_confirmed_finding": {"true", "false"},
}

errors: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def read(name: str) -> pd.DataFrame:
    return pd.read_csv(DATA / name, dtype=str, keep_default_na=False)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def triples(df: pd.DataFrame) -> list[tuple[str, str, str]]:
    return sorted(zip(df["workflow_id"], df["line_number"], df["weakness_id"]))


def main() -> int:
    manifest = read("workflows.csv")
    labels = read("labels.csv")
    reference = read("reference_decisions.csv")
    candidates = read("helper_candidates.csv")
    expected = json.loads((DATA / "expected_counts.json").read_text(encoding="utf-8"))

    # 1. manifest ---------------------------------------------------------
    check(list(manifest.columns) == MANIFEST_COLUMNS, "workflows.csv: unexpected columns")
    check(manifest["workflow_id"].is_unique, "workflows.csv: duplicate workflow_id")
    check(manifest["workflow_blob_url"].is_unique, "workflows.csv: duplicate workflow_blob_url")
    check(
        manifest["workflow_id"].str.fullmatch(r"WAVES-\d{4}").all(),
        "workflows.csv: workflow_id must look like WAVES-0001",
    )
    for col, allowed in DOMAINS.items():
        bad = set(manifest[col]) - allowed
        check(not bad, f"workflows.csv: {col} has unexpected values {sorted(bad)}")
    check(manifest["commit_sha"].str.fullmatch(r"[0-9a-f]{40}").all(), "workflows.csv: bad commit_sha")
    check(
        manifest["retrieval_date"].str.fullmatch(r"\d{4}-\d{2}-\d{2}").all(),
        "workflows.csv: retrieval_date must be YYYY-MM-DD",
    )

    # 2. snapshots --------------------------------------------------------
    listed = {}
    for line in (ROOT / "workflows" / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, rel = re.split(r"\s+", line.strip(), maxsplit=1)
        listed[rel] = digest
    for row in manifest.itertuples():
        path = ROOT / row.snapshot_path
        if not path.exists():
            errors.append(f"missing snapshot {row.snapshot_path}")
            continue
        digest = sha256(path)
        check(digest == row.file_sha256, f"{row.workflow_id}: SHA-256 differs from manifest")
        check(listed.get(row.snapshot_path) == digest, f"{row.workflow_id}: not in checksums.sha256")
    on_disk = {
        p.relative_to(ROOT).as_posix()
        for sub in ("real", "synthetic")
        for p in (ROOT / "workflows" / sub).glob("*.yml")
    }
    check(on_disk == set(manifest["snapshot_path"]), "workflows/: files do not match the manifest")

    # 3. foreign keys -----------------------------------------------------
    ids = set(manifest["workflow_id"])
    for name, df in (("labels", labels), ("reference_decisions", reference),
                     ("helper_candidates", candidates)):
        check(df["workflow_id"].isin(ids).all(), f"{name}.csv: workflow_id not in workflows.csv")
        check(df["weakness_id"].isin(WEAKNESS_IDS).all(), f"{name}.csv: unknown weakness_id")
        check(
            pd.to_numeric(df["line_number"], errors="coerce").notna().all(),
            f"{name}.csv: non-numeric line_number",
        )
    check(labels["label_id"].is_unique, "labels.csv: duplicate label_id")
    check(reference["decision_id"].is_unique, "reference_decisions.csv: duplicate decision_id")
    check(candidates["candidate_id"].is_unique, "helper_candidates.csv: duplicate candidate_id")
    check(set(candidates["decision"]) <= {"accepted", "rejected"}, "helper_candidates.csv: bad decision")

    # 4. has_confirmed_finding --------------------------------------------
    with_labels = set(labels["workflow_id"])
    flagged = set(manifest.loc[manifest["has_confirmed_finding"] == "true", "workflow_id"])
    check(with_labels == flagged, "has_confirmed_finding disagrees with labels.csv")

    # 5. label provenance --------------------------------------------------
    subset = manifest.set_index("workflow_id")["subset"]
    label_subset = labels["workflow_id"].map(subset)
    accepted = candidates[candidates["decision"] == "accepted"]
    label_by_id = labels.set_index("label_id")
    for name, df, key in (("reference_decisions", reference, "decision_id"),
                          ("helper_candidates (accepted)", accepted, "candidate_id")):
        linked = df[df["label_id"] != ""]
        check(len(linked) == len(df), f"{name}: row without label_id")
        check(linked["label_id"].is_unique, f"{name}: label_id used more than once")
        check(linked["label_id"].isin(label_by_id.index).all(), f"{name}: label_id not in labels.csv")
        joined = linked[linked["label_id"].isin(label_by_id.index)]
        target = label_by_id.loc[joined["label_id"]]
        for col in ("workflow_id", "line_number", "weakness_id", "evidence", "explanation"):
            check(
                (target[col].to_numpy() == joined[col].to_numpy()).all(),
                f"{name}: {col} differs from the linked label",
            )
    check(
        (candidates.loc[candidates["decision"] == "rejected", "label_id"] == "").all(),
        "helper_candidates.csv: rejected candidate has a label_id",
    )
    check(
        set(reference["label_id"]) == set(labels.loc[label_subset == "reference", "label_id"]),
        "reference_decisions.csv does not cover exactly the reference labels",
    )
    check(
        set(accepted["label_id"]) == set(labels.loc[label_subset == "helper_reviewed", "label_id"]),
        "accepted helper candidates do not cover exactly the helper-reviewed labels",
    )
    check(set(candidates["workflow_id"].map(subset)) == {"helper_reviewed"},
          "helper candidates outside the helper_reviewed subset")
    synthetic_labels = labels[label_subset == "synthetic"]
    check(set(synthetic_labels["weakness_id"]) == {"CFW"}, "synthetic workflows must carry CFW only")

    # 6. expected counts ---------------------------------------------------
    actual = {
        "workflows": len(manifest),
        "real_world_workflows": int((manifest["source_type"] == "real_world").sum()),
        "synthetic_workflows": int((manifest["source_type"] == "synthetic").sum()),
        "workflows_with_labels": len(with_labels),
        "all_negative_workflows": int((manifest["has_confirmed_finding"] == "false").sum()),
        "labels": len(labels),
        "labels_by_weakness": labels["weakness_id"].value_counts().sort_index().to_dict(),
        "subsets": manifest["subset"].value_counts().sort_index().to_dict(),
        "reference_decisions": len(reference),
        "helper_candidates": len(candidates),
        "helper_candidates_accepted": len(accepted),
        "helper_candidates_rejected": len(candidates) - len(accepted),
    }
    for key, value in actual.items():
        check(expected.get(key) == value, f"count {key}: expected {expected.get(key)}, got {value}")

    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors[:50]:
            print("  -", e)
        return 1
    print(
        f"OK: {len(manifest)} workflows, {len(labels)} labels, "
        f"{len(reference)} reference decisions, {len(candidates)} helper candidates"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
