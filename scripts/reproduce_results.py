"""Reproduce the numbers, figures and tables of the paper from the released data.

The 1,048,857-workflow corpus that the sample was drawn from is proprietary and
is NOT part of this artifact. Reproduction therefore starts from the released
sample (data/workflows.csv and the snapshots in workflows/) and covers:

  1. dataset integrity and expected counts          scripts/validate_dataset.py
  2. the four workflow metrics, from the YAML files scripts/metrics/compute_metrics.py
  3. Figure 3, Figure 4, Table 3, section 5 numbers scripts/metrics/make_figures.py
  4. (optional) helper recall on the reference set   scripts/helpers/eval_helpers.py

Usage:
    python scripts/reproduce_results.py
    python scripts/reproduce_results.py --with-helpers
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
failures: list[str] = []


def step(title: str, script: str) -> int:
    print(f"\n== {title} ==", flush=True)
    code = subprocess.run([sys.executable, str(ROOT / script)], cwd=ROOT).returncode
    if code:
        failures.append(title)
    return code


def check_statistics() -> None:
    print("\n== section 5 statistics vs. expected ==")
    expected = json.loads((ROOT / "data" / "expected_counts.json").read_text(encoding="utf-8"))["statistics"]
    actual = json.loads((ROOT / "results" / "tables" / "summary_statistics.json").read_text(encoding="utf-8"))
    for key, want in expected.items():
        got = actual.get(key)
        ok = got == want
        print(f"  {key:<40} expected {want!s:<8} got {got!s:<8} {'OK' if ok else 'MISMATCH'}")
        if not ok:
            failures.append(f"statistic {key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--with-helpers", action="store_true", help="also run the helpers (slower)")
    args = parser.parse_args()

    step("1. dataset validation", "scripts/validate_dataset.py")
    step("2. metric recomputation", "scripts/metrics/compute_metrics.py")
    if step("3. figures and tables", "scripts/metrics/make_figures.py") == 0:
        check_statistics()
    if args.with_helpers:
        step("4. helpers on the reference subset", "scripts/helpers/eval_helpers.py")

    print()
    if failures:
        print("FAILED:", "; ".join(failures))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
