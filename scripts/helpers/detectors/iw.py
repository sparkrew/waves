"""IW — Injection Weakness (untrusted ${{ }} directly inside run: only)."""

from __future__ import annotations

import re

from detectors.models import IW, Label, WorkflowContext
from detectors.parse import UNTRUSTED_PATTERNS, extract_run_blocks


EXPR_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")

UNTRUSTED_RE = re.compile(
    "|".join(f"(?:{pattern})" for pattern in UNTRUSTED_PATTERNS)
)


def _input_key(expr: str) -> str:
    """Normalize expression text so the same input path dedupes within a block."""
    return re.sub(r"\s+", "", expr.strip())


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []

    for start_line, block in extract_run_blocks(ctx.text):
        # One label per distinct untrusted input in this run: block
        # (first occurrence line). Same input in another block → new label.
        seen_inputs: set[str] = set()

        for match in EXPR_RE.finditer(block):
            expr = match.group(1).strip()
            if not UNTRUSTED_RE.search(expr):
                continue

            key = _input_key(expr)
            if key in seen_inputs:
                continue
            seen_inputs.add(key)

            text_before_match = block[: match.start()]
            line_no = start_line + text_before_match.count("\n")

            line_start = block.rfind("\n", 0, match.start()) + 1
            line_end = block.find("\n", match.end())
            if line_end == -1:
                line_end = len(block)
            script_line = block[line_start:line_end].strip()

            same_line_untrusted = [
                m2.group(1).strip()
                for m2 in EXPR_RE.finditer(block[line_start:line_end])
                if UNTRUSTED_RE.search(m2.group(1))
            ]
            if len(same_line_untrusted) > 1:
                evidence = f"${{{{ {expr} }}}}"
            else:
                evidence = script_line[:200] or f"${{{{ {expr} }}}}"

            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=line_no,
                    weakness_type=IW,
                    evidence=evidence[:200],
                    explanation=(
                        f"Untrusted input {expr} expanded inside a run: shell script "
                        "(first occurrence of this distinct input in the run block)."
                    ),
                )
            )

    return labels
