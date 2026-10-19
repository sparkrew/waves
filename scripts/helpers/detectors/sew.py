"""SEW — Secrets Exposure Weakness."""

from __future__ import annotations

import re

from detectors.models import SEW, Label, WorkflowContext
from detectors.parse import is_local_ref, split_ref

INHERIT_RE = re.compile(r"""secrets\s*:\s*['\"]?inherit['\"]?\s*(?:#.*)?$""", re.I)
USES_RE = re.compile(r"""uses:\s*['\"]?([^'\"\s#]+)""")
CONTAINER_PASSWORD_RE = re.compile(
    r"^\s*password\s*:\s*['\"]?\$\{\{\s*secrets\.\w+\s*\}\}", re.I
)


def _associated_uses(lines: list[str], inherit_line: int) -> str | None:
    """Find the ``uses:`` for a ``secrets: inherit`` line.

    GitHub Actions allows either order under a job (``uses`` then ``secrets``,
    or ``secrets`` then ``uses``). Prefer a nearby following ``uses:``; otherwise
    fall back to the nearest preceding one.
    """
    # Same-job style: secrets: inherit then uses: on a following line
    forward = "\n".join(lines[inherit_line - 1 : min(len(lines), inherit_line + 10)])
    fwd_matches = list(USES_RE.finditer(forward))
    if fwd_matches:
        return fwd_matches[0].group(1).strip()

    window = "\n".join(lines[max(0, inherit_line - 40) : inherit_line])
    matches = list(USES_RE.finditer(window))
    if not matches:
        return None
    return matches[-1].group(1).strip()


def _inside_credentials(lines: list[str], line_index: int) -> bool:
    """Return whether a password line belongs to a nearby credentials map."""
    password_line = lines[line_index]
    password_indent = len(password_line) - len(password_line.lstrip(" "))
    for j in range(line_index - 1, max(-1, line_index - 12), -1):
        line = lines[j]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent < password_indent and re.match(r"^\s*credentials\s*:", line, re.I):
            return True
        if indent < password_indent and re.match(r"^\s*(?:steps|env|with|runs-on)\s*:", line):
            break
    return False


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    lines = ctx.lines
    for i, line in enumerate(lines, 1):
        if not INHERIT_RE.search(line.strip()):
            continue
        target = _associated_uses(lines, i)
        if not target:
            continue
        path, _ = split_ref(target)
        local = is_local_ref(path)
        kind = "local" if local else "external"
        labels.append(
            Label(
                workflow_blob_url=ctx.url,
                line_number=i,
                weakness_type=SEW,
                evidence="secrets: inherit",
                explanation=(
                    f"secrets: inherit forwards all repository secrets to the {kind} "
                    f"reusable workflow ({target}), exposing every secret."
                ),
            )
        )

    for i, line in enumerate(lines, 1):
        if not CONTAINER_PASSWORD_RE.search(line):
            continue
        if not _inside_credentials(lines, i - 1):
            continue
        labels.append(
            Label(
                workflow_blob_url=ctx.url,
                line_number=i,
                weakness_type=SEW,
                evidence=line.strip()[:120],
                explanation=(
                    "A repository secret is passed to a container/service credentials "
                    "password field, exposing it to that execution boundary."
                ),
            )
        )

    for i, line in enumerate(lines, 1):
        if not re.search(r"secrets\.\w+", line):
            continue
        if re.search(
            r"GITHUB_ENV|GITHUB_OUTPUT|echo\s+[\"'].*\$\{\{\s*secrets",
            line,
        ):
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=i,
                    weakness_type=SEW,
                    evidence=line.strip()[:120],
                    explanation=(
                        "Secret value written to environment files or logged, "
                        "risking credential leakage."
                    ),
                )
            )
    return labels
