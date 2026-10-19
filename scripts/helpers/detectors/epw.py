"""EPW — Excessive Permission Weakness."""

from __future__ import annotations

import re
from typing import Any

from detectors.models import EPW, Label, WorkflowContext
from detectors.parse import (
    find_key_line,
    permissions_write_scopes,
    walk_jobs,
)


def _is_justified_writes(writes: list[str], job_name: str, job: dict, wf_text: str) -> bool:
    """Heuristic: write scopes that match common legitimate job purposes."""
    if not writes or writes == ["write-all"]:
        return False
    name = (job_name or "").lower()
    uses = str(job.get("uses") or "").lower()
    blob = f"{name} {uses} {wf_text[:2000]}".lower()
    write_set = set(writes)

    # Single-scope justified cases
    if writes == ["issues"] and re.search(r"label|issue|project|triage", blob):
        return True
    if writes == ["pull-requests"] and re.search(r"label|review|dependabot|comment|pr", blob):
        return True
    if writes == ["packages"] and re.search(r"publish|package|ghcr|docker|ocicl|build", blob):
        return True
    if writes == ["contents"] and re.search(r"release|tag|deploy|commit|push", blob):
        return True
    if write_set <= {"pages", "id-token"} and "pages" in write_set:
        return True
    if write_set <= {"id-token", "attestations"} or write_set == {"id-token"}:
        if re.search(r"attest|oidc|aws|azure|deploy|login", blob):
            return True

    # PR review / status checks: pull-requests + checks (+ optional issues)
    if write_set <= {"pull-requests", "checks", "issues"} and write_set & {
        "pull-requests",
        "checks",
    }:
        if re.search(r"review|comment|dependabot|check|pr\b|pull.?request", blob):
            return True

    # contents:write + id-token is usually excessive for OIDC deploy.
    # Only treat as justified for explicit GitHub Release publishing.
    if write_set == {"contents", "id-token"}:
        return bool(
            re.search(
                r"softprops/action-gh-release|ncipollo/release-action|"
                r"actions/create-release|gh\s+release\b",
                blob,
                re.I,
            )
        )

    return False


def _block_excessive(perm: Any, job_name: str, job: dict, wf_text: str) -> bool:
    if perm is None:
        return True
    if perm == "write-all":
        return True
    if perm == "read-all":
        return False
    if isinstance(perm, dict) and not perm:
        return False  # permissions: {} — explicit least privilege
    writes = permissions_write_scopes(perm)
    if not writes:
        return False
    if _is_justified_writes(writes, job_name, job, wf_text):
        return False
    if "write-all" in writes:
        return True
    if any(w in writes for w in ("contents", "id-token", "packages", "actions", "security-events")):
        if set(writes) <= {"pages", "id-token"}:
            return False
        return True
    if len(writes) >= 2:
        return True
    return False


def _workflow_permissions_empty(perm: Any) -> bool:
    return isinstance(perm, dict) and not perm


def _has_write_candidate(perm: Any) -> bool:
    """Recall-first signal for manual review of every explicit write grant."""
    return perm == "write-all" or bool(permissions_write_scopes(perm))


def detect(ctx: WorkflowContext) -> list[Label]:
    data = ctx.data
    jobs = walk_jobs(data)
    wf_has = "permissions" in data
    labels: list[Label] = []

    # Missing permissions entirely (neither workflow nor every job declares
    # them). Do not return early: explicit job-level write grants must also be
    # emitted as separate manual-review candidates at their exact lines.
    if not wf_has:
        if not jobs or not all("permissions" in j for _, j in jobs):
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=1,
                    weakness_type=EPW,
                    evidence="missing permissions: block",
                    explanation=(
                        "No permissions: block at workflow or all job levels. Effective "
                        "GITHUB_TOKEN access depends on repository/organization defaults, "
                        "so least privilege cannot be verified from this workflow."
                    ),
                )
            )
        for jname, job in jobs:
            if "permissions" in job and _has_write_candidate(job.get("permissions")):
                pline = _perm_line_for_job(ctx, jname) or 1
                labels.append(
                    Label(
                        workflow_blob_url=ctx.url,
                        line_number=pline,
                        weakness_type=EPW,
                        evidence=_perm_evidence(ctx, pline),
                        explanation=(
                            "Explicit job-level write permission requires manual review "
                            "to confirm that the scope is necessary and actually used."
                        ),
                    )
                )
        return _dedupe(labels)

    # Workflow-level permissions present.
    # permissions: {} is intentional least privilege — not missing, not excessive.
    if not _workflow_permissions_empty(data.get("permissions")):
        if _has_write_candidate(data.get("permissions")):
            pline = find_key_line(ctx.text, "permissions") or 1
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=pline,
                    weakness_type=EPW,
                    evidence=_perm_evidence(ctx, pline),
                    explanation=(
                        "Explicit workflow-level write permission requires manual review "
                        "to confirm that every granted scope is necessary."
                    ),
                )
            )

    # Job overrides that are excessive (including when workflow is permissions: {})
    for jname, job in jobs:
        if "permissions" not in job:
            continue
        if _has_write_candidate(job.get("permissions")):
            pline = _perm_line_for_job(ctx, jname) or find_key_line(ctx.text, "permissions") or 1
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=pline,
                    weakness_type=EPW,
                    evidence=_perm_evidence(ctx, pline),
                    explanation=(
                        "Explicit job-level write permission requires manual review to "
                        "confirm that the scope is necessary and actually used."
                    ),
                )
            )

    # NOTE: when workflow sets permissions: {}, jobs without a job-level block
    # inherit that empty map (no GITHUB_TOKEN scopes). That is not EPW.

    return _dedupe(labels)


def _perm_line_for_job(ctx: WorkflowContext, job_name: str) -> int | None:
    lines = ctx.lines
    job_pat = re.compile(rf"^(\s*){re.escape(job_name)}\s*:")
    start = None
    base_indent = 0
    for i, line in enumerate(lines):
        m = job_pat.match(line)
        if m:
            start = i
            base_indent = len(m.group(1))
            break
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= base_indent and re.match(r"^\s*\S", line):
            break
        if re.match(r"^\s+permissions\s*:", line):
            return j + 1
    return None


def _perm_evidence(ctx: WorkflowContext, pline: int) -> str:
    if pline <= 0 or pline > len(ctx.lines):
        return "permissions:"
    lines = ctx.lines
    evidence = lines[pline - 1].strip()
    bits = [evidence]
    for j in range(pline, min(len(lines), pline + 6)):
        if re.match(r"^\s+\S", lines[j]) and ":" in lines[j]:
            bits.append(lines[j].strip())
        elif j >= pline and re.match(r"^\S", lines[j]):
            break
    return " / ".join(bits[:5])


def _dedupe(labels: list[Label]) -> list[Label]:
    seen = set()
    out = []
    for lab in labels:
        key = (lab.line_number, lab.evidence[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(lab)
    return out
