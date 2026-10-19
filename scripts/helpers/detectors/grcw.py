"""GRCW — GitHub Runner Compatibility Weakness."""

from __future__ import annotations

import re

from detectors.kvcw_index import (
    categories_only_deprecated_runtime,
    load_kvcw_rows,
    match_uses_to_kvcw,
)
from detectors.models import GRCW, Label, WorkflowContext
from detectors.parse import extract_uses_with_lines, is_local_ref, split_ref

# Official actions known to use Node 12 (v2) / Node 16 (v3)
DEPRECATED_MAJOR = {
    ("actions/checkout", "v2"),
    ("actions/checkout", "v3"),
    ("actions/setup-python", "v2"),
    ("actions/setup-python", "v3"),
    ("actions/setup-node", "v2"),
    ("actions/setup-node", "v3"),
    ("actions/cache", "v2"),
    ("actions/cache", "v3"),
    ("actions/upload-artifact", "v2"),
    ("actions/upload-artifact", "v3"),
    ("actions/download-artifact", "v2"),
    ("actions/download-artifact", "v3"),
    ("actions/github-script", "v5"),
    ("actions/github-script", "v6"),
    ("actions/setup-python", "v4"),

}


def _major_tag(ver: str) -> str | None:
    m = re.match(r"^(v?\d+)", ver.strip())
    if not m:
        return None
    tag = m.group(1)
    if not tag.startswith("v"):
        tag = f"v{tag}"
    return tag


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    seen: set[tuple[int, str]] = set()
    kvcw_rows = load_kvcw_rows()

    for line_no, uses_val in extract_uses_with_lines(ctx.text):
        path, ver = split_ref(uses_val)
        if is_local_ref(path):
            continue

        maj = _major_tag(ver) if ver else None
        if maj and (path, maj) in DEPRECATED_MAJOR:
            key = (line_no, uses_val)
            if key not in seen:
                seen.add(key)
                labels.append(
                    Label(
                        workflow_blob_url=ctx.url,
                        line_number=line_no,
                        weakness_type=GRCW,
                        evidence=f"uses: {uses_val}",
                        explanation=(
                            f"{path}@{maj} relies on a deprecated Node.js runtime "
                            "(Node 12/16), which may fail or be unsupported on current runners."
                        ),
                    )
                )

        for hit in match_uses_to_kvcw(path, ver, kvcw_rows):
            if not categories_only_deprecated_runtime(hit.get("categories", "")):
                continue
            key = (line_no, uses_val)
            if key in seen:
                continue
            seen.add(key)
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=line_no,
                    weakness_type=GRCW,
                    evidence=f"uses: {uses_val}",
                    explanation=(
                        f"Action {path}@{ver or 'unspecified'} is flagged for deprecated_runtime "
                        "compatibility issues on current GitHub-hosted runners."
                    ),
                )
            )

    for i, line in enumerate(ctx.lines, 1):
        if "::set-output" in line or "::save-state" in line:
            cmd = "::set-output" if "::set-output" in line else "::save-state"
            key = (i, cmd)
            if key in seen:
                continue
            seen.add(key)
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=i,
                    weakness_type=GRCW,
                    evidence=line.strip()[:120],
                    explanation=(
                        f"Uses removed workflow command {cmd}, which is no longer "
                        "supported and can break job execution."
                    ),
                )
            )

    return labels
