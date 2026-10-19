"""UDW - unpinned external ``uses:`` references and Git clones only."""

from __future__ import annotations

import re

from detectors.models import UDW, Label, WorkflowContext
from detectors.parse import extract_uses_with_lines, is_local_ref, is_sha, split_ref

GIT_CLONE_RE = re.compile(r"\bgit\s+clone\b[^\n]*(https?://\S+|git@\S+)", re.I)
COMMIT_IN_URL_RE = re.compile(r"(?:/|@)[0-9a-f]{40}(?:/|$)", re.I)
COMMIT_CHECKOUT_RE = re.compile(
    r"\bgit(?:\s+-C\s+\S+)?\s+checkout\s+[0-9a-f]{40}\b", re.I
)


def _label(ctx: WorkflowContext, line_no: int, evidence: str, subject: str) -> Label:
    return Label(
        workflow_blob_url=ctx.url,
        line_number=line_no,
        weakness_type=UDW,
        evidence=evidence[:200],
        explanation=(
            f"{subject} is referenced by a mutable version instead of an immutable "
            "full commit SHA."
        ),
    )


def _clone_is_commit_pinned(ctx: WorkflowContext, line_no: int, line: str) -> bool:
    if COMMIT_IN_URL_RE.search(line):
        return True
    nearby = "\n".join(
        ctx.lines[max(0, line_no - 1) : min(len(ctx.lines), line_no + 11)]
    )
    return bool(COMMIT_CHECKOUT_RE.search(nearby))


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []

    for line_no, uses_val in extract_uses_with_lines(ctx.text):
        path, version = split_ref(uses_val)
        if is_local_ref(path) or is_sha(version):
            continue
        labels.append(
            _label(
                ctx,
                line_no,
                f"uses: {uses_val}",
                f"Action/workflow version '{version or 'missing'}'",
            )
        )

    for line_no, line in enumerate(ctx.lines, 1):
        if GIT_CLONE_RE.search(line) and not _clone_is_commit_pinned(ctx, line_no, line):
            labels.append(_label(ctx, line_no, line.strip(), "Git clone dependency"))

    return labels
