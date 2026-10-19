"""Map a line of a workflow snapshot to the YAML block it belongs to.

Scanners and annotators do not agree on which physical line represents a finding: zizmor points at the
start of a ``run:`` scalar while an annotator points at the line holding ``${{ ... }}`` inside it,
and a ``secrets: inherit`` finding may be reported on the ``secrets:`` line or on the ``uses:`` line of
the same job. These are differences of numbering, not of judgment. Comparing the *block* that contains
the line removes them: the block of a line is the innermost step, else the job, else the workflow level.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

WORKFLOW = "workflow"


def _mapping_items(node):
    return node.value if isinstance(node, yaml.MappingNode) else []


@lru_cache(maxsize=None)
def block_ranges(path: str) -> tuple | None:
    """Return (jobs, steps) as lists of (first_line, last_line, block_id), 1-based, or None if unparsable."""
    try:
        root = yaml.compose(Path(path).read_text(encoding="utf-8", errors="replace"), Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return None
    if root is None:
        return None
    jobs, steps = [], []
    for key, value in _mapping_items(root):
        if getattr(key, "value", None) != "jobs":
            continue
        for job_key, job_node in _mapping_items(value):
            job_id = f"job:{job_key.value}"
            jobs.append((job_key.start_mark.line + 1, job_node.end_mark.line, job_id))
            for field, field_node in _mapping_items(job_node):
                if getattr(field, "value", None) == "steps" and isinstance(field_node, yaml.SequenceNode):
                    for index, step in enumerate(field_node.value):
                        steps.append((step.start_mark.line + 1, step.end_mark.line, f"{job_id}/step:{index}"))
    return jobs, steps


def block_of(path: str, line: int | None) -> str:
    """Innermost block containing `line` ("workflow" when the line is outside every job)."""
    if not line:
        return WORKFLOW
    ranges = block_ranges(path)
    if ranges is None:
        return f"line:{line}"  # unparsable snapshot: fall back to exact line
    jobs, steps = ranges
    for first, last, block in steps:
        if first <= line <= max(last, first):
            return block
    for first, last, block in jobs:
        if first <= line <= max(last, first):
            return block
    return WORKFLOW
