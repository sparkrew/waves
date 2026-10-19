"""CFW — Control Flow Weakness.

Families detected:

1. Block-scalar truthiness: ``if: >`` and ``if: |`` keep the trailing newline, so
   an interpolated ``${{ false }}`` becomes the non-empty string ``"false\\n"``
   and the condition passes. The ``-`` chomping variants strip it and are safe.
2. Partial ``${{ }}`` wrapping: operators or literals outside the braces mean
   GitHub interpolates first and then treats the leftover as a non-empty string,
   so the intended comparison never runs
   (e.g. ``if: ${{ matrix.os }} == 'ubuntu-latest'``).
3. Conditions that cannot evaluate to false where they run: ``always()``,
   literal truths, repository / owner guards that only fail in forks, and
   guards that merely restate the workflow's own trigger.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from detectors.models import CFW, Label, WorkflowContext

IF_LINE = re.compile(r"^(\s*)(?:-\s*)?if:\s*(.*?)\s*$")
KEEP_NEWLINE = (">", ">+", "|", "|+")
STRIP_NEWLINE = (">-", "|-")
BLOCK_INDICATORS = KEEP_NEWLINE + STRIP_NEWLINE
EXPR_WRAP = re.compile(r"^\$\{\{((?:(?!\}\}).)*)\}\}$", re.S)
EXPR_SPAN = re.compile(r"\$\{\{((?:(?!\}\}).)*)\}\}", re.S)
# Leftover operators/literals after stripping ${{ }} spans => partial wrap.
OUTSIDE_EXPR = re.compile(r"""[=!<>]|&&|\|\||['"]|\b(?:true|false)\b""")

ALWAYS_TRUE_ATOMS = {"true", "always()", "!false", "! false", "${{true}}"}
# Upstream-only guards: always true in the owning repository, dead outside forks.
REPO_GUARD = re.compile(
    r"^github\.(repository|repository_owner)\s*==\s*(['\"])([^'\"]+)\2$"
)
EVENT_GUARD = re.compile(r"^github\.event_name\s*==\s*(['\"])(\w+)\1$")
ACTION_SET_GUARD = re.compile(
    r"^contains\(\s*fromJSON\(\s*(['\"])(.+?)\1\s*\)\s*,\s*github\.event\.action\s*\)$"
)
CANCELLED = re.compile(r"^!\s*cancelled\(\)$")


def _has_partial_expression_wrap(raw: str) -> bool:
    """True when ``${{ }}`` is mixed with operators or literals outside the braces.

    GitHub interpolates expressions first. Anything left over becomes a string;
    non-empty strings are truthy, so ``${{ matrix.os }} == 'ubuntu-latest'`` and
    ``${{ a }} && ${{ b }}`` never evaluate as the intended boolean expression.
    A single fully-wrapped ``${{ ... }}`` is fine and is handled elsewhere.
    """
    collapsed = re.sub(r"\s+", " ", raw).strip()
    if "${{" not in collapsed:
        return False
    spans = list(EXPR_SPAN.finditer(collapsed))
    # One span covering the whole condition is a proper full wrap.
    if len(spans) == 1 and spans[0].span() == (0, len(collapsed)):
        return False
    if not spans:
        return False
    stripped = EXPR_SPAN.sub("", collapsed)
    return bool(OUTSIDE_EXPR.search(stripped))


def _unwrap(text: str) -> str:
    """Strip a single ``${{ }}`` wrapper and collapse whitespace."""
    collapsed = re.sub(r"\s+", " ", text).strip()
    match = EXPR_WRAP.match(collapsed)
    if match:
        collapsed = re.sub(r"\s+", " ", match.group(1)).strip()
    if len(collapsed) > 1 and collapsed[0] == collapsed[-1] and collapsed[0] in "'\"":
        inner = collapsed[1:-1]
        if collapsed[0] not in inner:
            collapsed = inner
    return collapsed.strip()


def _conjuncts(text: str) -> list[str]:
    """Split on ``&&`` at paren/quote/expression depth zero; ``||`` makes truth undecidable."""
    if not text:
        return []
    # Fully-wrapped `${{ a && b }}` must be unwrapped before splitting, otherwise
    # the && inside the braces is invisible to the always-true rules below.
    collapsed = re.sub(r"\s+", " ", text).strip()
    if EXPR_WRAP.match(collapsed):
        text = _unwrap(collapsed)
        if not text:
            return []

    parts: list[str] = []
    depth = 0
    expr_depth = 0
    quote = ""
    current = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            current += char
            if char == quote:
                quote = ""
            index += 1
            continue
        # Keep && / || inside any remaining ${{ }} from splitting the expression apart.
        if char == "$" and text[index : index + 3] == "${{":
            expr_depth += 1
            current += "${{"
            index += 3
            continue
        if char == "}" and expr_depth and text[index : index + 2] == "}}":
            expr_depth -= 1
            current += "}}"
            index += 2
            continue
        if char in "'\"":
            quote = char
            current += char
        elif char in "([":
            depth += 1
            current += char
        elif char in ")]":
            depth -= 1
            current += char
        elif (
            char == "|"
            and text[index : index + 2] == "||"
            and depth == 0
            and expr_depth == 0
        ):
            return []  # a disjunction can be false; do not reason about it
        elif (
            char == "&"
            and text[index : index + 2] == "&&"
            and depth == 0
            and expr_depth == 0
        ):
            parts.append(current.strip())
            current = ""
            index += 2
            continue
        else:
            current += char
        index += 1
    parts.append(current.strip())
    return [_unwrap(p) for p in parts if p.strip()]


def iter_conditions(lines: list[str]) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line_number, condition_text, block_indicator)`` for each ``if:``.

    Block scalars put the expression on following lines, so they are joined here;
    without that, multi-line conditions are invisible to every rule below.
    """
    index = 0
    while index < len(lines):
        match = IF_LINE.match(lines[index])
        if not match:
            index += 1
            continue

        indent = len(match.group(1))
        rest = match.group(2).strip()
        line_no = index + 1

        # ``if: > ${{ ... }}`` keeps the expression on the same line as the marker.
        if rest and rest[0] in "|>" and rest not in BLOCK_INDICATORS:
            marker = rest[:2] if rest[1:2] in "-+" else rest[:1]
            yield line_no, rest[len(marker) :].strip(), marker
            index += 1
            continue

        if rest in BLOCK_INDICATORS or rest == "":
            chunk: list[str] = []
            scan = index + 1
            while scan < len(lines):
                line = lines[scan]
                if not line.strip():
                    scan += 1
                    continue
                lead = len(line) - len(line.lstrip(" "))
                if lead <= indent:
                    break
                chunk.append(line.strip())
                scan += 1
            yield line_no, " ".join(chunk), rest
            index = max(scan, index + 1)
            continue

        yield line_no, rest, ""
        index += 1


def _trigger_map(data: dict) -> dict[str, Any]:
    """The ``on:`` mapping, allowing for YAML 1.1 parsing ``on`` as True."""
    on = data.get("on")
    if on is None and True in data:
        on = data[True]
    if isinstance(on, dict):
        return {str(k): v for k, v in on.items()}
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {str(x): None for x in on}
    return {}


def _declared_types(spec: Any) -> set[str]:
    if isinstance(spec, dict):
        types = spec.get("types")
        if isinstance(types, str):
            return {types}
        if isinstance(types, list):
            return {str(t) for t in types}
    return set()


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    seen: set[int] = set()
    triggers = _trigger_map(ctx.data)

    def add(line_no: int, evidence: str, explanation: str) -> None:
        if line_no in seen:
            return
        seen.add(line_no)
        labels.append(
            Label(
                workflow_blob_url=ctx.url,
                line_number=line_no,
                weakness_type=CFW,
                evidence=evidence[:120],
                explanation=explanation,
            )
        )

    for line_no, condition, marker in iter_conditions(ctx.lines):
        raw = condition.strip()
        if not raw:
            continue
        evidence = (f"if: {marker} {raw}" if marker else f"if: {raw}").strip()

        if marker in KEEP_NEWLINE and "${{" in raw:
            add(
                line_no,
                evidence,
                f"if: {marker} with ${{{{ }}}} appends a trailing newline, making the "
                f"string 'false\\n' truthy and bypassing the intended condition.",
            )
            continue

        if _has_partial_expression_wrap(raw):
            add(
                line_no,
                evidence,
                "Operators or literals sit outside ${{ }}, so GitHub interpolates first "
                "and treats the leftover as a non-empty (always-true) string; the intended "
                "comparison never runs.",
            )
            continue

        normalized = _unwrap(raw)
        parts = _conjuncts(raw)

        if normalized in ALWAYS_TRUE_ATOMS:
            add(
                line_no,
                evidence,
                "Condition is always true, so the guard never blocks anything; with "
                "always() the step also runs after failure or cancellation.",
            )
            continue

        if parts and all(p in ALWAYS_TRUE_ATOMS for p in parts):
            add(line_no, evidence, "Every clause is a constant truth, so the condition never blocks.")
            continue

        if any(p == "always()" for p in parts) and any(CANCELLED.match(p) for p in parts):
            add(
                line_no,
                evidence,
                "always() && !cancelled() is self-defeating: always() exists to run on "
                "cancellation, so pairing it with !cancelled() leaves an unclear guard.",
            )
            continue

        repo = next((REPO_GUARD.match(p) for p in parts if REPO_GUARD.match(p)), None)
        if repo:
            field, value = repo.group(1), repo.group(3)
            add(
                line_no,
                evidence,
                f"github.{field} == '{value}' is always true in the upstream repository, "
                f"so the guard is dead code outside forks.",
            )
            continue

        event = next((EVENT_GUARD.match(p) for p in parts if EVENT_GUARD.match(p)), None)
        if event and set(triggers) == {event.group(2)}:
            add(
                line_no,
                evidence,
                f"The workflow only triggers on {event.group(2)}, so this event_name "
                f"check is always true.",
            )
            continue

        action = next((ACTION_SET_GUARD.match(p) for p in parts if ACTION_SET_GUARD.match(p)), None)
        if action:
            listed = set(re.findall(r"['\"]([\w-]+)['\"]", action.group(2)))
            declared = set().union(*(_declared_types(v) for v in triggers.values())) if triggers else set()
            if declared and declared <= listed:
                add(
                    line_no,
                    evidence,
                    "The action list already matches the trigger's own types: filter, so "
                    "the condition is always true when the workflow runs.",
                )

    return labels
