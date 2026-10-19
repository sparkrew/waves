"""
Build kvcw_actions.csv: actions that should trigger a KVCW label when seen
in a workflow (any scanner finding, plus parents that nest vulnerable deps).

For transitive parents, records which parent version(s) nest which child
version(s), and resolves tags to SHAs where possible — so labeling is not
applied to every parent version blindly.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import pandas as pd

BASE = Path(__file__).parent
VULN_CSV = BASE / "vulnerable_actions.csv"
USED_CSV = BASE / "actions_used.csv"
OUTPUT_CSV = BASE / "kvcw_actions.csv"

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)


def _join_unique(values) -> str:
    vals: list[str] = []
    seen: set[str] = set()
    for v in values:
        if pd.isna(v):
            continue
        s = str(v).strip()
        if not s or s == "nan" or s in seen:
            continue
        seen.add(s)
        vals.append(s)
    return "; ".join(vals)


def _parse_action_path(action: str) -> tuple[str, str]:
    parts = str(action).split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", str(action)


def _used_refs_for_action(used: pd.DataFrame, action: str) -> list[str]:
    rows = used[used["action"] == action]
    if rows.empty:
        return []
    r = rows.iloc[0]
    refs: list[str] = []
    for col in ("tag_versions", "sha_versions"):
        raw = r.get(col, "")
        if pd.isna(raw) or str(raw).strip() in ("", "nan"):
            continue
        for part in str(raw).split(";"):
            ref = part.strip()
            if ref and ref not in refs:
                refs.append(ref)
    return refs


def resolve_ref_to_sha(owner: str, repo: str, ref: str, cache: dict[str, str]) -> str:
    """Resolve tag/branch to a 40-char commit SHA via gh api. Returns '' on failure."""
    if not owner or not repo or not ref:
        return ""
    if SHA_RE.match(ref):
        return ref.lower()

    key = f"{owner}/{repo}@{ref}"
    if key in cache:
        return cache[key]

    sha = ""
    # Try tag ref, then branch, then commits API
    for endpoint in (
        f"/repos/{owner}/{repo}/git/ref/tags/{ref}",
        f"/repos/{owner}/{repo}/git/ref/heads/{ref}",
        f"/repos/{owner}/{repo}/commits/{ref}",
    ):
        try:
            result = subprocess.run(
                ["gh", "api", endpoint],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                continue
            data = json.loads(result.stdout)
            if "object" in data:
                obj = data["object"]
                # annotated tags point to tag object; peel to commit when needed
                if obj.get("type") == "commit":
                    sha = obj.get("sha", "")
                elif obj.get("type") == "tag":
                    tag_url = obj.get("url", "")
                    if tag_url:
                        # use gh api with full URL path
                        path = tag_url.split("api.github.com")[-1]
                        t = subprocess.run(
                            ["gh", "api", path],
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        if t.returncode == 0:
                            tobj = json.loads(t.stdout)
                            sha = (tobj.get("object") or {}).get("sha", "") or tobj.get(
                                "sha", ""
                            )
                else:
                    sha = obj.get("sha", "")
            elif "sha" in data:
                sha = data.get("sha", "")
            if sha and SHA_RE.match(sha):
                break
            sha = ""
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            continue

    cache[key] = sha
    return sha


def _ensure_parent_version(df: pd.DataFrame, used: pd.DataFrame) -> pd.DataFrame:
    """Fill parent_version for transitive rows when missing (pre-scan_actions upgrade)."""
    out = df.copy()
    if "parent_version" not in out.columns:
        out["parent_version"] = ""

    mask = (out["is_transitive"] == True) & (
        out["parent_version"].fillna("").astype(str).str.strip().isin(("", "nan"))
    )
    for idx in out.index[mask]:
        parent = out.at[idx, "parent_action"]
        refs = _used_refs_for_action(used, parent)
        # Prefer the single known workflow-used ref for that parent in the sample
        out.at[idx, "parent_version"] = refs[0] if refs else ""
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerabilities", type=Path, default=VULN_CSV)
    parser.add_argument("--actions-used", type=Path, default=USED_CSV)
    parser.add_argument("--output", type=Path, default=OUTPUT_CSV)
    args = parser.parse_args()

    df = pd.read_csv(args.vulnerabilities)
    used = pd.read_csv(args.actions_used)
    df = _ensure_parent_version(df, used)

    # Persist backfilled parent_version into vulnerable_actions.csv for consistency
    df.to_csv(args.vulnerabilities, index=False)

    trans = df[df["is_transitive"] == True]
    parent_to_children = (
        trans.groupby("parent_action")["action"].apply(lambda s: sorted(set(s))).to_dict()
    )

    sha_cache: dict[str, str] = {}

    own: dict[str, dict] = {}
    for action, g in df.groupby("action"):
        cats = sorted(set(g["vulnerability_category"].dropna()))
        severities = set(g["severity"].dropna().astype(str))
        max_sev = (
            "high"
            if "high" in severities
            else ("medium" if "medium" in severities else ("low" if "low" in severities else ""))
        )
        versions = sorted(
            {
                str(v)
                for v in g["version"]
                if pd.notna(v) and str(v).strip() and str(v) != "nan"
            }
        )
        cve_g = g[g["vulnerability_category"] == "known_cve"]
        own[action] = {
            "categories": cats,
            "max_severity": max_sev,
            "finding_count": len(g),
            "versions": versions,
            "cve_ids": _join_unique(cve_g["cve_id"]) if len(cve_g) else "",
            "vulnerable_version_ranges": _join_unique(cve_g["vulnerable_version_range"])
            if len(cve_g)
            else "",
            "first_patched_versions": _join_unique(cve_g["first_patched_version"])
            if len(cve_g)
            else "",
            "version_matches": _join_unique(
                cve_g.apply(
                    lambda r: f"{r.get('version') or 'default'}:{r.get('version_match')}",
                    axis=1,
                )
            )
            if len(cve_g)
            else "",
        }

    watch = set(own.keys()) | set(parent_to_children.keys())
    rows = []

    for action in sorted(watch):
        children = parent_to_children.get(action, [])
        info = own.get(action)
        child_rows = (
            trans[trans["parent_action"] == action] if children else pd.DataFrame()
        )

        if info and children:
            reason = "both"
        elif info:
            reason = "direct"
        else:
            reason = "transitive"

        # --- nested edge details (parent@version -> child@version) ---
        parent_versions_affected: list[str] = []
        nested_child_versions: list[str] = []
        parent_resolved_shas: list[str] = []
        child_resolved_shas: list[str] = []
        nesting_edges: list[str] = []

        if children and len(child_rows):
            for _, r in child_rows.drop_duplicates(
                ["parent_action", "parent_version", "action", "version"]
            ).iterrows():
                pver = str(r.get("parent_version") or "").strip()
                if not pver or pver == "nan":
                    # fallback: all workflow-used refs of parent
                    fallback = _used_refs_for_action(used, action)
                    pver = fallback[0] if fallback else ""
                cver = str(r.get("version") or "").strip()
                if cver == "nan":
                    cver = ""
                child = str(r["action"])

                if pver and pver not in parent_versions_affected:
                    parent_versions_affected.append(pver)
                edge_child = f"{child}@{cver}" if cver else child
                if edge_child not in nested_child_versions:
                    nested_child_versions.append(edge_child)
                edge = f"{action}@{pver or '?'} -> {edge_child}"
                if edge not in nesting_edges:
                    nesting_edges.append(edge)

                po, pr = _parse_action_path(action)
                co, cr = _parse_action_path(child)
                psha = resolve_ref_to_sha(po, pr, pver, sha_cache) if pver else ""
                csha = resolve_ref_to_sha(co, cr, cver, sha_cache) if cver else ""
                if psha and psha not in parent_resolved_shas:
                    parent_resolved_shas.append(psha)
                if csha and csha not in child_resolved_shas:
                    child_resolved_shas.append(csha)

        if reason == "transitive":
            cats = sorted(set(child_rows["vulnerability_category"].dropna()))
            severities = set(child_rows["severity"].dropna().astype(str))
            max_sev = (
                "high"
                if "high" in severities
                else ("medium" if "medium" in severities else "low")
            )
            finding_count = len(child_rows)
            # For transitive parents, versions_with_findings = affected parent versions
            versions = parent_versions_affected
            cve_g = child_rows[child_rows["vulnerability_category"] == "known_cve"]
            cve_ids = _join_unique(cve_g["cve_id"])
            ranges = _join_unique(cve_g["vulnerable_version_range"])
            patched = _join_unique(cve_g["first_patched_version"])
            matches = (
                _join_unique(
                    cve_g.apply(
                        lambda r: f"{r.get('version') or 'default'}:{r.get('version_match')}",
                        axis=1,
                    )
                )
                if len(cve_g)
                else ""
            )
            notes = (
                "Transitive-only: label KVCW only when workflow uses an affected "
                f"parent version ({_join_unique(parent_versions_affected) or 'see nesting_edges'}). "
                "Do not label every parent version."
            )
        elif reason == "both":
            cats = sorted(
                set(info["categories"])
                | set(child_rows["vulnerability_category"].dropna())
            )
            severities = {info["max_severity"]} | set(
                child_rows["severity"].dropna().astype(str)
            )
            max_sev = (
                "high"
                if "high" in severities
                else ("medium" if "medium" in severities else "low")
            )
            finding_count = info["finding_count"]
            # Own finding versions plus parent versions that nest vulns
            versions = sorted(set(info["versions"]) | set(parent_versions_affected))
            cve_child = child_rows[child_rows["vulnerability_category"] == "known_cve"]
            cve_ids = _join_unique(
                list(filter(None, info["cve_ids"].split("; ")))
                + list(cve_child["cve_id"].dropna().astype(str))
            )
            ranges = _join_unique(
                list(filter(None, info["vulnerable_version_ranges"].split("; ")))
                + list(cve_child["vulnerable_version_range"].dropna().astype(str))
            )
            patched = _join_unique(
                list(filter(None, info["first_patched_versions"].split("; ")))
                + list(cve_child["first_patched_version"].dropna().astype(str))
            )
            match_parts = [x for x in info["version_matches"].split("; ") if x]
            if len(cve_child):
                match_parts += list(
                    cve_child.apply(
                        lambda r: f"{r.get('version') or 'default'}:{r.get('version_match')}",
                        axis=1,
                    )
                )
            matches = _join_unique(match_parts)
            notes = (
                "Has own findings AND nests vulnerable action(s). "
                "For nested risk, only affected parent versions in "
                "parent_versions_affected / nesting_edges apply."
            )
        else:
            cats = info["categories"]
            max_sev = info["max_severity"]
            finding_count = info["finding_count"]
            versions = info["versions"]
            cve_ids = info["cve_ids"]
            ranges = info["vulnerable_version_ranges"]
            patched = info["first_patched_versions"]
            matches = info["version_matches"]
            notes = "Has scanner findings. Label KVCW if workflow uses a version in versions_with_findings."

        if ranges:
            notes += f" CVE ranges: {ranges}."

        rows.append(
            {
                "action": action,
                "kvcw_reason": reason,
                "via_vulnerable_action": "; ".join(children),
                "categories": "; ".join(cats),
                "max_severity": max_sev,
                "finding_count": finding_count,
                "versions_with_findings": "; ".join(versions),
                "parent_versions_affected": "; ".join(parent_versions_affected),
                "nested_child_versions": "; ".join(nested_child_versions),
                "parent_resolved_shas": "; ".join(parent_resolved_shas),
                "child_resolved_shas": "; ".join(child_resolved_shas),
                "nesting_edges": "; ".join(nesting_edges),
                "cve_ids": cve_ids,
                "vulnerable_version_ranges": ranges,
                "first_patched_versions": patched,
                "version_matches": matches,
                "notes": notes,
            }
        )

    out = pd.DataFrame(rows)
    sev_order = {"high": 0, "medium": 1, "low": 2}
    reason_order = {"direct": 0, "both": 1, "transitive": 2}
    out["_s"] = out["max_severity"].map(lambda x: sev_order.get(x, 9))
    out["_r"] = out["kvcw_reason"].map(lambda x: reason_order.get(x, 9))
    out = (
        out.sort_values(["_r", "_s", "action"])
        .drop(columns=["_r", "_s"])
        .reset_index(drop=True)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)

    print(f"Wrote {args.output} ({len(out)} actions)")
    print(out["kvcw_reason"].value_counts().to_string())
    nested = out[out["kvcw_reason"].isin(["transitive", "both"])]
    print("\nNested / transitive parent rows:")
    print(
        nested[
            [
                "action",
                "kvcw_reason",
                "parent_versions_affected",
                "nested_child_versions",
                "parent_resolved_shas",
                "child_resolved_shas",
                "nesting_edges",
            ]
        ].to_string(index=False)
    )


if __name__ == "__main__":
    main()
