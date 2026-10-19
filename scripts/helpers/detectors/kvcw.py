"""KVCW — Known Vulnerable Component Weakness (non-deprecated watchlist hits)."""

from __future__ import annotations

from detectors.kvcw_index import (
    categories_only_deprecated_runtime,
    load_kvcw_rows,
    match_uses_to_kvcw,
)
from detectors.models import KVCW, Label, WorkflowContext
from detectors.parse import extract_uses_with_lines, is_local_ref, split_ref


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    seen: set[tuple[int, str]] = set()
    kvcw_rows = load_kvcw_rows()

    for line_no, uses_val in extract_uses_with_lines(ctx.text):
        path, ver = split_ref(uses_val)
        if is_local_ref(path):
            continue
        for hit in match_uses_to_kvcw(path, ver, kvcw_rows):
            cats = hit.get("categories", "")
            # Pure deprecated_runtime → GRCW, not KVCW
            if categories_only_deprecated_runtime(cats):
                continue
            key = (line_no, uses_val)
            if key in seen:
                continue
            seen.add(key)
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=line_no,
                    weakness_type=KVCW,
                    evidence=f"uses: {uses_val}",
                    explanation=hit.get("detail")
                    or (
                        f"Workflow uses known-vulnerable action {path}@{ver or 'unspecified'} "
                        f"(categories: {cats or 'n/a'})."
                    ),
                )
            )
    return labels
