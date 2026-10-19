"""Line-aware workflow parsing helpers for decision-tree detectors."""

from __future__ import annotations

import re
from typing import Any

import yaml

from detectors.models import WorkflowContext

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
USES_LINE_RE = re.compile(
    r"^(\s*)(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?\s*(?:#.*)?$"
)
OFFICIAL_OWNERS = {"actions", "github"}

UNTRUSTED_PATTERNS = [
    r"github\.event\.pull_request\.(title|body|head\.ref|head\.repo|head\.sha|user\.login)",
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.comment\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.review\.body",
    r"github\.head_ref",
    r"\binputs\.",
]

SECURITY_SCAN_HINTS = [
    r"codeql",
    r"dependency-review",
    r"trivy",
    r"snyk",
    r"ggshield",
    r"secret.?scan",
    r"semgrep",
    r"sonar",
    r"bandit",
    r"gosec",
    r"npm audit",
    r"pip-audit",
    r"osv-scanner",
    r"grype",
    r"gitleaks",
    r"trufflehog",
]

BUILD_TEST_HINTS = [
    r"\bnpm (ci|install|run|test|build)\b",
    r"\byarn\b",
    r"\bpnpm\b",
    r"\bpytest\b",
    r"\bmvn\b",
    r"\bgradle\b",
    r"\bcargo (build|test)\b",
    r"\bmake\b",
    r"\bgo (build|test)\b",
    r"\bdotnet (build|test)\b",
    r"\bpip install\b",
    r"\btox\b",
    r"\bjest\b",
    r"\bgolangci-lint\b",
    r"\beslint\b",
    r"\bpre-commit\b",
]


def split_ref(uses: str) -> tuple[str, str]:
    uses = uses.strip().strip("'\"")
    if uses.startswith("./") or uses.startswith(".\\"):
        return uses, ""
    if "@" in uses:
        path, ver = uses.rsplit("@", 1)
        return path.strip(), ver.strip()
    return uses, ""


def is_local_ref(path: str) -> bool:
    return path.startswith("./") or path.startswith(".\\")


def is_sha(ver: str) -> bool:
    return bool(ver and SHA_RE.match(ver))


def is_reusable_workflow(path: str) -> bool:
    return ".github/workflows/" in path.replace("\\", "/")


def load_context(url: str, text: str, purpose: str = "") -> WorkflowContext:
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return WorkflowContext(
        url=url,
        text=text,
        data=data,
        lines=text.splitlines(),
        purpose=purpose or "",
    )


def extract_uses_with_lines(text: str) -> list[tuple[int, str]]:
    found = []
    for i, line in enumerate(text.splitlines(), 1):
        m = USES_LINE_RE.match(line)
        if m:
            found.append((i, m.group(2).strip()))
    return found


def extract_triggers(data: dict) -> list[str]:
    on = data.get("on")
    if on is None and True in data:
        on = data[True]
    if on is None:
        return []
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(x) for x in on]
    if isinstance(on, dict):
        return [str(k) for k in on.keys()]
    return []


def walk_jobs(data: dict) -> list[tuple[str, dict]]:
    jobs = data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return []
    return [(str(n), j) for n, j in jobs.items() if isinstance(j, dict)]


def find_key_line(text: str, key: str) -> int | None:
    pat = re.compile(rf"^(\s*){re.escape(key)}\s*:")
    for i, line in enumerate(text.splitlines(), 1):
        if pat.match(line):
            return i
    return None


def find_line_containing(text: str, substr: str) -> int:
    for i, line in enumerate(text.splitlines(), 1):
        if substr in line:
            return i
    return 1


def extract_run_blocks(text: str) -> list[tuple[int, str]]:
    """Return (start_line_1based, block_text) for each run: scalar."""
    lines = text.splitlines()
    blocks: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        # A step may consist solely of ``- run: ...``.  In that form the YAML
        # sequence marker is on the run line itself rather than on a preceding
        # ``- name:`` line.
        m = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2)
        if rest.startswith("|") or rest.startswith(">"):
            chunk = []
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if line.strip() == "":
                    chunk.append(line)
                    j += 1
                    continue
                lead = len(line) - len(line.lstrip(" "))
                if lead <= indent and line.strip():
                    break
                chunk.append(line)
                j += 1
            # start_line is the first content line (1-based), not the run: line
            start = i + 2
            blocks.append((start, "\n".join(chunk)))
            i = j
            continue
        blocks.append((i + 1, rest))
        i += 1
    return blocks


def permissions_write_scopes(perm: Any) -> list[str]:
    if perm is None:
        return []
    if perm == "write-all":
        return ["write-all"]
    if perm == "read-all" or perm == {}:
        return []
    if isinstance(perm, dict):
        return [str(k) for k, v in perm.items() if str(v).lower() == "write"]
    return []


def job_is_reusable_only(job: dict) -> bool:
    uses = job.get("uses")
    return isinstance(uses, str) and bool(uses.strip()) and not job.get("steps")


def solely_reusable_orchestrator(data: dict) -> bool:
    jobs = walk_jobs(data)
    if not jobs:
        return False
    return all(job_is_reusable_only(j) for _, j in jobs)


def _step_is_trivial(step: Any) -> bool:
    """True for status-only steps (echo/true) with no action uses."""
    if not isinstance(step, dict):
        return False
    if step.get("uses"):
        return False
    run = str(step.get("run") or "").strip()
    if not run:
        return True
    # Writing outputs/env is real orchestration, not a no-op status line.
    if re.search(r"GITHUB_(OUTPUT|ENV|PATH|STEP_SUMMARY)", run):
        return False
    for line in run.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^(echo|true|:|printf)\b", line):
            return False
    return True


def effectively_reusable_orchestrator(data: dict) -> bool:
    """Reusable-workflow caller whose only local jobs are trivial no-op steps."""
    jobs = walk_jobs(data)
    if not jobs:
        return False
    saw_reusable = False
    for _, job in jobs:
        if job_is_reusable_only(job):
            saw_reusable = True
            continue
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            return False
        if not all(_step_is_trivial(step) for step in steps):
            return False
    return saw_reusable


def workflow_title_blob(text: str, data: dict | None = None) -> str:
    """Workflow name plus job ids/names for lightweight purpose detection."""
    parts: list[str] = []
    m = re.search(r"^name:\s*['\"]?(.+?)['\"]?\s*$", text, re.M)
    if m:
        parts.append(m.group(1))
    if data:
        for job_name, job in walk_jobs(data):
            parts.append(str(job_name))
            if isinstance(job.get("name"), str):
                parts.append(job["name"])
    return " ".join(parts).lower()


def text_has_security_scan(text: str) -> bool:
    return any(re.search(p, text, re.I) for p in SECURITY_SCAN_HINTS)


def looks_like_ci(text: str, purpose: str = "", data: dict | None = None) -> bool:
    """True for build/test/publish-style pipelines that HGW should consider.

    Corpus ``purpose`` tags are coarse (e.g. ``ci_test`` on token-validation
    workflows), so they are only a weak signal and never override clear
    anti-patterns or missing in-repo CI evidence.
    """
    titles = workflow_title_blob(text, data)
    purpose_l = (purpose or "").lower()

    # Manual credential checks are not CI build/test pipelines.
    if re.search(r"validate\s+api\s+tokens|manual:\s*validate\b.*\btoken", titles):
        return False
    if re.search(r"\b(stale|label|assign|triage|greet|notify)\b", titles):
        if not any(re.search(p, text, re.I) for p in BUILD_TEST_HINTS):
            return False

    has_build_cmds = any(re.search(p, text, re.I) for p in BUILD_TEST_HINTS)
    has_ci_title = bool(
        re.search(
            r"\b(build|tests?|testing|ci|lint|release|deploy(?:ment)?|publish|"
            r"package|compile|unittest|pytest|checks?)\b",
            titles,
        )
    )

    # In-file CI title/commands are sufficient. Checkout alone is not
    # (autotaggers, license audits, codeowner validators).
    if has_build_cmds or has_ci_title:
        return True

    # Weak purpose hint for managed reusable PR checks with no local commands.
    if re.search(r"\b(build|test|ci|cd|release|package|deploy|lint)\b", purpose_l):
        if re.search(
            r"\b(pr|pull.?request).*\bcheck|\bcheck\b.*\b(pr|workflow)\b",
            titles,
        ):
            return True
    return False
