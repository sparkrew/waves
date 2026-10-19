"""PTW — Privileged Trigger Weakness."""

from __future__ import annotations

import re

from detectors.models import PTW, Label, WorkflowContext
from detectors.parse import (
    extract_uses_with_lines,
    extract_triggers,
    find_key_line,
    find_line_containing,
    permissions_write_scopes,
    walk_jobs,
)

PRIVILEGED = {"pull_request_target", "issue_comment", "workflow_run"}

UNTRUSTED_FIELD = re.compile(
    r"github\.event\.(pull_request|issue|comment|discussion|review)\.|github\.head_ref|inputs\."
)

PRIVILEGED_SIDE_EFFECT = re.compile(
    r"\b(comment|approve|merge|label|release|publish|deploy|push|"
    r"create[-_ ]?(?:issue|pull|project)|add[-_ ]?to[-_ ]?project)\b",
    re.I,
)


def _has_write_perms(ctx: WorkflowContext) -> bool:
    data = ctx.data
    if data.get("permissions") == "write-all":
        return True
    if permissions_write_scopes(data.get("permissions")):
        return True
    for _, job in walk_jobs(data):
        if job.get("permissions") == "write-all":
            return True
        if permissions_write_scopes(job.get("permissions")):
            return True
    return False


def _has_secrets(text: str) -> bool:
    return bool(re.search(r"secrets\.\w+|secrets\s*:\s*inherit", text))


def _has_pr_head_checkout(text: str) -> bool:
    return bool(
        re.search(
            r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)",
            text,
        )
        or re.search(r"pull_request\.head\.(sha|ref)", text)
    )


def _has_untrusted_fields(text: str) -> bool:
    return bool(UNTRUSTED_FIELD.search(text))


def _has_privileged_action_side_effect(ctx: WorkflowContext) -> bool:
    """Infer obvious write-side effects performed inside referenced actions.

    This deliberately uses both the action identifier and the human-readable
    step/job names.  It catches wrapper actions such as a "Post comment" step
    even when the action implementation is not part of the workflow corpus.
    """
    if PRIVILEGED_SIDE_EFFECT.search(ctx.text):
        return True
    return any(PRIVILEGED_SIDE_EFFECT.search(uses) for _, uses in extract_uses_with_lines(ctx.text))


def _calls_reusable_workflow(ctx: WorkflowContext) -> bool:
    """A privileged caller delegates behavior that must be treated transitively."""
    return any(
        isinstance(job.get("uses"), str) and ".github/workflows/" in job["uses"].replace("\\", "/")
        for _, job in walk_jobs(ctx.data)
    )


def _missing_explicit_permissions(ctx: WorkflowContext) -> bool:
    """True when effective token access depends on repository/org settings."""
    if "permissions" in ctx.data:
        return False
    jobs = walk_jobs(ctx.data)
    return not jobs or not all("permissions" in job for _, job in jobs)


def detect(ctx: WorkflowContext) -> list[Label]:
    triggers = set(extract_triggers(ctx.data))
    priv = triggers & PRIVILEGED
    if not priv:
        return []

    dangerous = (
        _has_secrets(ctx.text)
        or _has_write_perms(ctx)
        or _has_pr_head_checkout(ctx.text)
        or _has_untrusted_fields(ctx.text)
        or _has_privileged_action_side_effect(ctx)
        or _calls_reusable_workflow(ctx)
        or _missing_explicit_permissions(ctx)
    )
    if not dangerous:
        return []

    line = 1
    for t in sorted(priv):
        found = find_line_containing(ctx.text, t)
        if found >= 1:
            line = found
            break
    on_line = find_key_line(ctx.text, "on")
    if line == 1 and on_line:
        line = on_line

    combo_bits = []
    if _has_pr_head_checkout(ctx.text):
        combo_bits.append("PR-head checkout")
    if _has_secrets(ctx.text):
        combo_bits.append("secrets access")
    if _has_write_perms(ctx):
        combo_bits.append("write permissions")
    if _has_untrusted_fields(ctx.text):
        combo_bits.append("untrusted event fields")
    if _has_privileged_action_side_effect(ctx):
        combo_bits.append("privileged action side effect")
    if _calls_reusable_workflow(ctx):
        combo_bits.append("reusable-workflow delegation")
    if _missing_explicit_permissions(ctx):
        combo_bits.append("configuration-dependent default token access")

    return [
        Label(
            workflow_blob_url=ctx.url,
            line_number=line,
            weakness_type=PTW,
            evidence=f"on: {', '.join(sorted(priv))}",
            explanation=(
                f"Privileged trigger ({', '.join(sorted(priv))}) combined with "
                f"{', '.join(combo_bits) or 'dangerous patterns'}, allowing untrusted "
                "actors to influence a trusted-context workflow."
            ),
        )
    ]
