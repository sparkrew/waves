"""
sample_workflows.py
-------------------
Reads the BigQuery candidate pool from a CSV file (exported from the BigQuery
console), computes expensive metrics locally, then stratifies and samples a
diverse final set of 500 workflows.

BigQuery exports array columns as JSON strings in CSV. The script parses
all_step_uses, all_run_blocks, and all_env_values back into Python lists
before processing.

Usage:
    pip install pandas tqdm
    python sample_workflows.py \
        --candidates candidates.csv \
        --out sample_500.csv

Optional flags:
    --target 500   (default: 500)
    --seed 42      (random seed for reproducibility)
"""

import argparse
import json
import re
from pathlib import Path

import pandas as pd
from tqdm import tqdm


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_N = 500

# Array columns that BigQuery serialises as JSON strings in CSV export
ARRAY_COLUMNS = ["all_step_uses", "all_run_blocks", "all_env_values"]

KNOWN_SAFE_OWNERS = {
    "actions", "github", "azure", "aws-actions", "docker",
    "google-github-actions", "hashicorp", "gradle", "codecov",
    "coverallsapp", "peter-evans", "EndBug", "dawidd6", "stefanzweifel",
    "peaceiris", "crazy-max", "ncipollo", "release-drafter", "rtCamp",
    "appleboy", "goreleaser", "snyk", "slackapi", "microsoft",
    "JamesIves", "cirrus-labs", "dependabot", "ossf", "security-crob",
}

TAINT_SOURCES = [
    "github.event.issue.body", "github.event.pull_request.body",
    "github.event.comment.body", "github.event.review.body",
    "github.event.review_comment.body", "github.event.head_commit.message",
    "github.event.discussion.body", "github.event.discussion_comment.body",
    "github.event.discussion.title", "github.event.changes.body.from",
    "github.event.workflow_run.head_commit.message",
    "github.event.check_run.output.text", "github.event.check_run.output.summary",
    "github.event.check_suite.head_commit.message",
    "github.event.issue.title", "github.event.pull_request.title",
    "github.event.pull_request.head.ref", "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    "github.event.changes.title.from",
    "github.event.workflow.path", "github.event.workflow.name",
    "github.event.workflow_run.path", "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository.description",
    "github.event.workflow_run.display_title",
    "github.event.check_run.output.title",
    "github.event.check_run.check_suite.head_branch",
    "github.event.check_suite.head_branch",
    "github.event.deployment.environment",
    "github.event.deployment.original_environment",
    "github.event.deployment_status.environment",
    "github.event.deployment_status.environment_url",
    "github.head_ref",
]

TAINT_PATTERNS = [
    re.compile(re.escape(src), re.IGNORECASE) for src in TAINT_SOURCES
]
EXPR_RE = re.compile(r'\$\{\{')
SHA_RE  = re.compile(r'@[0-9a-f]{40}$')


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def parse_array_cell(value) -> list:
    """
    BigQuery CSV export serialises arrays as JSON arrays, e.g.:
        ["actions/checkout@v3","actions/setup-node@v3"]
    Empty arrays come through as [] or as NaN/empty string.
    """
    if pd.isna(value) or value == "":
        return []
    if isinstance(value, list):
        return value
    v = str(value).strip()
    if not v or v == "[]":
        return []
    try:
        parsed = json.loads(v)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        # BigQuery occasionally exports arrays with single-quoted strings.
        # Replace outer single quotes around items and retry as JSON.
        # Do NOT use ast.literal_eval — workflow content may contain
        # arbitrary escape sequences that trigger SyntaxWarning or worse.
        try:
            v_json = v.replace("'", '"')
            parsed = json.loads(v_json)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []


def load_candidates(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    for col in ARRAY_COLUMNS:
        if col in df.columns:
            df[col] = df[col].apply(parse_array_cell)
        else:
            # Column absent from CSV — fill with empty lists so downstream
            # code doesn't need to special-case missing columns
            df[col] = [[] for _ in range(len(df))]
    return df


# ---------------------------------------------------------------------------
# Expensive metrics (run locally)
# ---------------------------------------------------------------------------

def compute_expensive_metrics(row: pd.Series) -> dict:
    uses: list = row["all_step_uses"]
    runs: list = row["all_run_blocks"]
    envs: list = row["all_env_values"]

    # Guard against None/float entries that json.loads produces from JSON null values
    uses      = [u for u in uses if isinstance(u, str)]
    run_text  = "\n".join(r for r in runs if isinstance(r, str))
    env_text  = "\n".join(e for e in envs if isinstance(e, str))
    full_text = run_text + "\n" + env_text

    # 3.3 SHA pinning ratio
    if uses:
        pinned = sum(1 for u in uses if SHA_RE.search(u))
        sha_pinning_ratio = round(pinned / len(uses), 3)
    else:
        sha_pinning_ratio = None

    # 3.5 Uses unverified / obscure actions
    uses_unverified = any(
        not u.startswith("./")
        and "/" in u
        and u.split("/")[0] not in KNOWN_SAFE_OWNERS
        for u in uses
    )

    # 4.1 Expressions in run blocks
    expressions_in_run = bool(EXPR_RE.search(run_text))

    # 4.2 Taint source count
    taint_source_count = sum(
        1 for pat in TAINT_PATTERNS if pat.search(full_text)
    )

    # 4.7 Env vars with expressions
    env_vars_with_expressions = bool(EXPR_RE.search(env_text))

    # Security surface bucket (4th primary stratification axis)
    if not expressions_in_run:
        security_surface_bucket = "no_expressions"
    elif taint_source_count == 0:
        security_surface_bucket = "expressions_no_taint"
    else:
        security_surface_bucket = "has_taint_sources"

    # Refined action dependency bucket (replaces BQ proxy)
    n3p = row.get("num_third_party_action_refs") or 0
    if n3p == 0:
        action_dependency_bucket = "no_third_party"
    elif sha_pinning_ratio is not None and sha_pinning_ratio >= 0.5:
        action_dependency_bucket = "pinned_third_party"
    else:
        action_dependency_bucket = "unpinned_third_party"

    return {
        "sha_pinning_ratio":         sha_pinning_ratio,
        "uses_unverified_actions":   uses_unverified,
        "expressions_in_run_blocks": expressions_in_run,
        "taint_source_count":        taint_source_count,
        "env_vars_with_expressions": env_vars_with_expressions,
        "security_surface_bucket":   security_surface_bucket,
        "action_dependency_bucket":  action_dependency_bucket,
    }


# ---------------------------------------------------------------------------
# Stratified sampling
# ---------------------------------------------------------------------------

PRIMARY_AXES = [
    "structural_complexity_bucket",
    "trigger_risk_level",
    "action_dependency_bucket",
    "security_surface_bucket",
]

def stratified_sample(df: pd.DataFrame, target: int, seed: int) -> pd.DataFrame:
    rng = df.sample(frac=1, random_state=seed)

    groups  = rng.groupby(PRIMARY_AXES, dropna=False)
    n_cells = len(groups)
    base    = max(1, target // n_cells)
    extra   = target - base * n_cells

    parts = []
    for i, (_, grp) in enumerate(groups):
        n = min(base + (1 if i < extra else 0), len(grp))
        parts.append(grp.sample(n=n, random_state=seed))

    result = pd.concat(parts, ignore_index=True)

    if len(result) < target:
        already  = set(result["gha_fingerprint"])
        leftover = df[~df["gha_fingerprint"].isin(already)]
        shortfall = min(target - len(result), len(leftover))
        if shortfall > 0:
            result = pd.concat(
                [result, leftover.sample(n=shortfall, random_state=seed)],
                ignore_index=True,
            )

    return result.sample(frac=1, random_state=seed).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_distribution(df: pd.DataFrame) -> None:
    print("\n── Distribution across primary axes ──────────────────────────")
    for ax in PRIMARY_AXES:
        print(f"\n{ax}:")
        print(df[ax].value_counts().to_string())

    print("\n── Secondary axes ────────────────────────────────────────────")
    for ax in ["workflow_purpose", "popularity_bucket", "primary_language"]:
        if ax in df.columns:
            print(f"\n{ax}:")
            print(df[ax].value_counts().head(10).to_string())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", required=True,
                        help="CSV file exported from BigQuery (the candidate pool)")
    parser.add_argument("--out",    default="sample_500.csv")
    parser.add_argument("--target", type=int, default=TARGET_N)
    parser.add_argument("--seed",   type=int, default=42)
    args = parser.parse_args()

    # ── 1. Load CSV ───────────────────────────────────────────────────────────
    print(f"Loading {args.candidates}…")
    df = load_candidates(args.candidates)
    print(f"  Candidate pool: {len(df):,} rows, {len(df.columns)} columns")

    if len(df) < args.target:
        raise SystemExit(
            f"Only {len(df)} candidates — fewer than target {args.target}. "
            "Re-run the BigQuery query with a higher rn_in_cell limit."
        )

    # ── 2. Compute expensive metrics locally ──────────────────────────────────
    print("Computing expensive metrics…")
    expensive = [
        compute_expensive_metrics(row)
        for _, row in tqdm(df.iterrows(), total=len(df))
    ]
    exp_df = pd.DataFrame(expensive, index=df.index)

    # Drop raw array columns and BQ proxy bucket; attach refined metrics
    df = df.drop(columns=ARRAY_COLUMNS + ["action_dependency_bucket"],
                 errors="ignore")
    df = pd.concat([df, exp_df], axis=1)

    # ── 3. Stratified sample → target N ───────────────────────────────────────
    print(f"\nSampling {args.target} workflows from {len(df):,} candidates…")
    sample = stratified_sample(df, args.target, args.seed)
    print(f"  Final sample: {len(sample):,} rows")

    print_distribution(sample)

    # ── 4. Save ───────────────────────────────────────────────────────────────
    out = Path(args.out)
    sample.to_csv(out, index=False)
    print(f"\nSaved → {out}  ({out.stat().st_size // 1024:,} KB)")


if __name__ == "__main__":
    main()