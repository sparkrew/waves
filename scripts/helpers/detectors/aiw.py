"""AIW - Artifact Integrity Weakness."""

from __future__ import annotations

import re

from detectors.models import AIW, Label, WorkflowContext
from detectors.parse import (
    BUILD_TEST_HINTS,
    UNTRUSTED_PATTERNS,
    extract_triggers,
    extract_uses_with_lines,
    split_ref,
)

DOWNLOAD_ARTIFACT = re.compile(r"actions/download-artifact", re.I)
CURL_WGET = re.compile(
    r"(?:curl|wget)\s+[^\n]*(?:https?://|\.sh|\.bin|\.exe|\.tar|\.zip|\.deb|\.rpm)",
    re.I,
)
GIT_CLONE = re.compile(r"\bgit\s+clone\b[^\n]*https?://", re.I)
LOCAL_DOWNLOAD_SCRIPT = re.compile(
    r"(?:^\s*(?:run:\s*)?|[;&|]\s*)\.?/?[\w./-]*(?:download|fetch|get-latest|install-[\w-]+)[\w.-]*\.sh\b",
    re.I,
)
CHECKSUM = re.compile(
    r"sha256sum|sha512sum|shasum|openssl\s+dgst|checksum|gpg\s+--verify|cosign\s+verify",
    re.I,
)
CACHE_ACTION = re.compile(r"actions/cache(?:/restore)?", re.I)
SETUP_CACHE_ACTION = re.compile(r"(?:actions/setup-python|ruby/setup-ruby)", re.I)
PR_TRIGGERS = {"pull_request", "pull_request_target"}
TRUSTED_TRIGGERS = {"push", "workflow_run", "release", "schedule", "workflow_dispatch"}
UNTRUSTED_CACHE = re.compile(
    "|".join(f"(?:{pattern})" for pattern in UNTRUSTED_PATTERNS)
    + r"|hashFiles\s*\(|github\.(?:sha|ref|head_ref)|matrix\.",
    re.I,
)
SECURITY_IMPACT = re.compile(
    r"\b(?:deploy|publish|release|package|upload|docker\s+(?:build|push)|gh\s+release|"
    r"npm\s+publish|twine\s+upload|cargo\s+publish|sudo\b)",
    re.I,
)
CONSUMPTION = re.compile(
    r"\b(?:chmod\s+\+x|source\s+|bash\s+|sh\s+|python\s+|node\s+|java\s+|"
    r"unzip\s+|tar\s+|dpkg\s+|rpm\s+|cp\s+|mv\s+|make\b|build\b|test\b|"
    r"install\b|deploy\b|publish\b|upload\b|execute\b)",
    re.I,
)


def _window(lines: list[str], line_no: int, after: int = 14) -> str:
    return "\n".join(lines[max(0, line_no - 1) : min(len(lines), line_no - 1 + after)])


def _is_verified(lines: list[str], line_no: int) -> bool:
    return bool(CHECKSUM.search(_window(lines, line_no, 10)))


def _is_consumed(lines: list[str], line_no: int, evidence: str = "") -> bool:
    """Require evidence that restored/downloaded bytes affect a later step."""
    if re.search(r"-o\s+/|--output\s+/|\|\s*(?:bash|sh)\b", evidence, re.I):
        return True
    if re.search(r"\.(?:sh|bin|exe|tar|zip|deb|rpm|whl)(?:\W|$)", evidence, re.I):
        return True
    return bool(CONSUMPTION.search(_window(lines, line_no + 1, 24)))


def _cache_is_reportable(ctx: WorkflowContext, line_no: int) -> bool:
    """Implement the refined three-part cache policy.

    A cache must be attacker influenced, restored without verification, and
    reach a cross-trust or security-sensitive consumer.
    """
    triggers = set(extract_triggers(ctx.data))
    if not (triggers & PR_TRIGGERS):
        return False
    window = _window(ctx.lines, line_no, 24)
    attacker_influenced = bool(UNTRUSTED_CACHE.search(window))
    if not attacker_influenced:
        return False
    if CHECKSUM.search(window):
        return False
    consumed = CONSUMPTION.search(window) or any(
        re.search(pattern, window, re.I) for pattern in BUILD_TEST_HINTS
    )
    if not consumed:
        return False
    cross_trust = "pull_request_target" in triggers or bool(triggers & TRUSTED_TRIGGERS)
    sensitive = bool(SECURITY_IMPACT.search(ctx.text))
    return cross_trust or sensitive


def _label(ctx: WorkflowContext, line_no: int, evidence: str, explanation: str) -> Label:
    return Label(
        workflow_blob_url=ctx.url,
        line_number=line_no,
        weakness_type=AIW,
        evidence=evidence[:200],
        explanation=explanation,
    )


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    text = ctx.text

    for line_no, uses_val in extract_uses_with_lines(text):
        path, _ = split_ref(uses_val)
        if DOWNLOAD_ARTIFACT.search(path):
            if not _is_verified(ctx.lines, line_no) and _is_consumed(ctx.lines, line_no):
                labels.append(
                    _label(
                        ctx,
                        line_no,
                        f"uses: {uses_val}",
                        "Downloads an artifact that is subsequently consumed without "
                        "checksum, signature, or attestation verification.",
                    )
                )

        cache_action = CACHE_ACTION.search(path)
        setup_cache = SETUP_CACHE_ACTION.search(path) and re.search(
            r"^\s*cache\s*:", _window(ctx.lines, line_no, 12), re.I | re.M
        )
        if (cache_action or setup_cache) and _cache_is_reportable(ctx, line_no):
            labels.append(
                _label(
                    ctx,
                    line_no,
                    f"uses: {uses_val}",
                    "An attacker-influenced cache is consumed without verification in "
                    "a cross-trust or security-sensitive workflow.",
                )
            )

    for i, line in enumerate(ctx.lines, 1):
        if GIT_CLONE.search(line) and not _is_verified(ctx.lines, i):
            labels.append(
                _label(
                    ctx,
                    i,
                    line.strip(),
                    "Clones remote content without pinning and consumes it without an "
                    "integrity verification step.",
                )
            )
            continue

        if LOCAL_DOWNLOAD_SCRIPT.search(line) and not _is_verified(ctx.lines, i):
            labels.append(
                _label(
                    ctx,
                    i,
                    line.strip(),
                    "Executes a local download/installer script whose retrieved content "
                    "is consumed without visible integrity verification.",
                )
            )
            continue

        if CURL_WGET.search(line) and not _is_verified(ctx.lines, i):
            if re.search(r"\.(json|yml|yaml|txt|md)(\s|$|[\"'])", line, re.I):
                continue
            if not _is_consumed(ctx.lines, i, line):
                continue
            labels.append(
                _label(
                    ctx,
                    i,
                    line.strip(),
                    "Downloads remote content that is subsequently consumed without "
                    "checksum or signature verification.",
                )
            )

    seen: set[tuple[int, str]] = set()
    out: list[Label] = []
    for lab in labels:
        key = (lab.line_number, lab.evidence[:80])
        if key not in seen:
            seen.add(key)
            out.append(lab)
    return out
