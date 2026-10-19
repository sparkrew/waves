"""Shared KVCW watchlist loading and version-aware matching."""

from __future__ import annotations

import re
import os
from functools import lru_cache
from pathlib import Path

import pandas as pd

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
# scripts/helpers/detectors/kvcw_index.py -> repository root is parents[3]
DEFAULT_KVCW_CSV = (
    Path(__file__).resolve().parents[3] / "data" / "inventories" / "kvcw_action_inventory.csv"
)


def parse_versions(cell) -> list[str]:
    if pd.isna(cell) or str(cell).strip() in ("", "nan"):
        return []
    return [p.strip() for p in str(cell).split(";") if p.strip() and p.strip().lower() != "nan"]


def clean_field(val) -> str:
    if pd.isna(val):
        return ""
    s = str(val).strip()
    return "" if s.lower() == "nan" else s


def version_matches_list(used_ver: str, allowed: list[str], resolved_shas: list[str]) -> bool:
    if not allowed and not resolved_shas:
        return True
    if not used_ver:
        return False
    if used_ver in allowed:
        return True
    if SHA_RE.match(used_ver):
        u = used_ver.lower()
        if any(u == a.lower() for a in allowed if SHA_RE.match(a)):
            return True
        if any(u == s.lower() for s in resolved_shas):
            return True
    return False


def build_kvcw_index(kvcw: pd.DataFrame) -> list[dict]:
    rows = []
    for _, r in kvcw.iterrows():
        rows.append(
            {
                "action": r["action"],
                "kvcw_reason": r["kvcw_reason"],
                "versions_with_findings": parse_versions(r.get("versions_with_findings")),
                "parent_versions_affected": parse_versions(r.get("parent_versions_affected")),
                "parent_resolved_shas": parse_versions(r.get("parent_resolved_shas")),
                "nested_child_versions": parse_versions(r.get("nested_child_versions")),
                "via_vulnerable_action": clean_field(r.get("via_vulnerable_action")),
                "categories": clean_field(r.get("categories")),
                "cve_ids": clean_field(r.get("cve_ids")),
                "vulnerable_version_ranges": clean_field(r.get("vulnerable_version_ranges")),
                "nesting_edges": clean_field(r.get("nesting_edges")),
                "max_severity": clean_field(r.get("max_severity")),
            }
        )
    return rows


@lru_cache(maxsize=2)
def load_kvcw_rows(path: str | None = None) -> tuple[dict, ...]:
    configured_path = path or os.environ.get("KVCW_ACTIONS_CSV")
    csv_path = Path(configured_path) if configured_path else DEFAULT_KVCW_CSV
    df = pd.read_csv(csv_path)
    return tuple(build_kvcw_index(df))


def categories_only_deprecated_runtime(categories: str) -> bool:
    parts = [p.strip() for p in (categories or "").split(";") if p.strip()]
    return bool(parts) and all(p == "deprecated_runtime" for p in parts)


def match_uses_to_kvcw(used_path: str, used_ver: str, kvcw_rows: list[dict] | tuple[dict, ...]) -> list[dict]:
    hits = []
    for row in kvcw_rows:
        if used_path != row["action"]:
            continue
        reason = row["kvcw_reason"]
        if reason == "direct":
            ok = version_matches_list(used_ver, row["versions_with_findings"], [])
            if not ok:
                continue
            detail = (
                f"Workflow uses vulnerable action {used_path}@{used_ver or 'unspecified'} "
                f"(kvcw_reason=direct; categories: {row['categories'] or 'n/a'}"
            )
            if row["cve_ids"]:
                detail += f"; CVEs: {row['cve_ids']}"
            detail += ")."
            hits.append({**row, "used_ref": used_ver, "detail": detail})
        elif reason == "transitive":
            ok = version_matches_list(
                used_ver,
                row["parent_versions_affected"] or row["versions_with_findings"],
                row["parent_resolved_shas"],
            )
            if not ok:
                continue
            detail = (
                f"Workflow uses {used_path}@{used_ver} which nests vulnerable action(s) "
                f"{row['via_vulnerable_action']} (kvcw_reason=transitive)."
            )
            hits.append({**row, "used_ref": used_ver, "detail": detail})
        elif reason == "both":
            own_ok = version_matches_list(
                used_ver, row["versions_with_findings"], row["parent_resolved_shas"]
            )
            nest_ok = version_matches_list(
                used_ver,
                row["parent_versions_affected"],
                row["parent_resolved_shas"],
            )
            if not (own_ok or nest_ok):
                continue
            detail = (
                f"Workflow uses {used_path}@{used_ver} (kvcw_reason=both; "
                f"categories: {row['categories'] or 'n/a'})."
            )
            hits.append({**row, "used_ref": used_ver, "detail": detail})
    return hits
