"""Regenerate the figures and tables of the paper from the released data.

Outputs (results/):
    figures/findings_per_workflow.{png,pdf}   Figure 3
    figures/findings_by_type.{png,pdf}        Figure 4
    tables/helper_candidates_by_type.csv      Table 3 (helper candidates and retained findings)
    tables/summary_statistics.json            numbers quoted in section 5

Usage:
    python scripts/metrics/make_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
FIGURES = ROOT / "results" / "figures"
TABLES = ROOT / "results" / "tables"

CATS = ["IW", "PTW", "SEW", "KVCW", "AIW", "CFW", "EPW", "UDW", "GRCW", "HGW"]
BLUE, ORANGE, RED = "#1f77b4", "#ff7f0e", "#d62728"


def save(fig: plt.Figure, name: str) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(FIGURES / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote results/figures/{name}.pdf and .png")


def load() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    read = lambda n: pd.read_csv(DATA / n, dtype=str, keep_default_na=False)  # noqa: E731
    return read("workflows.csv"), read("labels.csv"), read("helper_candidates.csv")


def findings_per_workflow(manifest: pd.DataFrame, labels: pd.DataFrame) -> dict:
    """Figure 3: confirmed findings per workflow, sorted ascending, zeros included."""
    per_workflow = labels.groupby("workflow_id").size()
    zeros = int((manifest["has_confirmed_finding"] == "false").sum())
    counts = np.sort(np.concatenate([np.zeros(zeros, dtype=int), per_workflow.to_numpy()]))
    assert len(counts) == len(manifest)
    x = np.arange(1, len(counts) + 1)
    median, mean, peak = float(np.median(counts)), counts.mean(), int(counts.max())
    q1, q3 = np.percentile(counts, [25, 75])

    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    ax.fill_between(x, counts, step="mid", color=BLUE, alpha=0.35, lw=0)
    ax.step(x, counts, where="mid", color=BLUE, lw=1.3)
    ax.axhline(median, color=ORANGE, ls="--", lw=1.0, alpha=0.85)
    ax.axhline(mean, color=RED, ls=":", lw=1.0, alpha=0.85)
    ax.text(
        0.02, 0.98,
        f"mean {mean:.2f}\nmedian {median:.0f}\n{zeros} workflows with 0 findings\nmax {peak}",
        transform=ax.transAxes, va="top", ha="left", fontsize=8.5, linespacing=1.45,
        bbox=dict(boxstyle="round,pad=0.45", facecolor="white", edgecolor="0.75", alpha=0.92),
    )
    ax.set_xlim(1, len(counts))
    ax.set_ylim(0, peak * 1.08)
    ax.set_xticks([])
    ax.set_xlabel(f"workflows, sorted by finding count (n={len(counts)})")
    ax.set_ylabel("security findings per workflow")
    ax.grid(axis="y", color="0.9", lw=0.8)
    ax.set_axisbelow(True)
    ax.set_title(
        f"Findings per workflow ({int(counts.sum()):,} confirmed labels over {len(counts)} workflows)",
        fontsize=10, pad=10,
    )
    fig.tight_layout()
    save(fig, "findings_per_workflow")

    categories = labels.groupby("workflow_id")["weakness_id"].nunique()
    return {
        "workflows": len(counts), "with_labels": int((counts > 0).sum()), "all_negative": zeros,
        "labels": int(counts.sum()), "mean_labels_per_workflow": round(float(mean), 2),
        "median": median, "q1": float(q1), "q3": float(q3), "max": peak,
        "multi_category_workflows": int((categories > 1).sum()),
        "mean_categories_per_labeled_workflow": round(float(categories.mean()), 2),
    }


def findings_by_type(labels: pd.DataFrame) -> dict:
    """Figure 4: confirmed instances per weakness category."""
    confirmed = labels["weakness_id"].value_counts()
    cats = sorted(CATS, key=lambda c: confirmed.get(c, 0), reverse=True)
    counts = np.array([confirmed.get(c, 0) for c in cats])
    y = np.arange(len(cats))

    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    ax.barh(y, counts, color=BLUE, height=0.66)
    for i, count in enumerate(counts):
        ax.text(count + counts.max() * 0.015, i, f"{count:,}", va="center", fontsize=8)
    ax.set_yticks(y, cats, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, counts.max() * 1.18)
    ax.set_xlabel("confirmed findings")
    ax.grid(axis="x", color="0.9", lw=0.8)
    ax.set_axisbelow(True)
    ax.set_title(
        f"Findings by weakness type across {labels['workflow_id'].nunique()} workflows "
        f"({int(counts.sum()):,} confirmed labels)", fontsize=10, pad=10,
    )
    fig.tight_layout()
    save(fig, "findings_by_type")
    return {c: int(confirmed.get(c, 0)) for c in cats}


def helper_table(candidates: pd.DataFrame) -> pd.DataFrame:
    """Table 3: helper candidates and findings retained after manual verification."""
    grouped = candidates.groupby("weakness_id")["decision"].value_counts().unstack(fill_value=0)
    table = pd.DataFrame({
        "candidates": grouped.sum(axis=1),
        "retained": grouped.get("accepted", 0),
        "rejected": grouped.get("rejected", 0),
    })
    table.loc["Total"] = table.sum()
    TABLES.mkdir(parents=True, exist_ok=True)
    table.astype(int).to_csv(TABLES / "helper_candidates_by_type.csv", index_label="weakness_id")
    print("  wrote results/tables/helper_candidates_by_type.csv")
    return table.astype(int)


def main() -> None:
    manifest, labels, candidates = load()
    stats = findings_per_workflow(manifest, labels)
    stats["labels_by_weakness"] = findings_by_type(labels)
    table = helper_table(candidates)
    stats["helper_candidates"] = int(table.loc["Total", "candidates"])
    stats["helper_retained"] = int(table.loc["Total", "retained"])
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / "summary_statistics.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print("  wrote results/tables/summary_statistics.json")
    print(table.to_string())


if __name__ == "__main__":
    main()
