"""Tests for the WAVES artifact. Run with:  python -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(ROOT / "scripts" / "metrics"))
sys.path.insert(0, str(ROOT / "evaluation"))

import compute_metrics  # noqa: E402
import evaluate  # noqa: E402


def read(name: str) -> pd.DataFrame:
    return pd.read_csv(ROOT / "data" / name, dtype=str, keep_default_na=False)


class DatasetCounts(unittest.TestCase):
    def test_validator_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "validate_dataset.py")],
            capture_output=True, text=True, cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_headline_numbers(self) -> None:
        workflows, labels = read("workflows.csv"), read("labels.csv")
        self.assertEqual(len(workflows), 475)
        self.assertEqual((workflows["source_type"] == "real_world").sum(), 465)
        self.assertEqual((workflows["source_type"] == "synthetic").sum(), 10)
        self.assertEqual(len(labels), 2424)
        self.assertEqual(labels["workflow_id"].nunique(), 467)
        self.assertEqual((workflows["has_confirmed_finding"] == "false").sum(), 8)

    def test_expected_counts_file_is_consistent(self) -> None:
        expected = json.loads((ROOT / "data" / "expected_counts.json").read_text(encoding="utf-8"))
        self.assertEqual(sum(expected["labels_by_weakness"].values()), expected["labels"])
        self.assertEqual(sum(expected["subsets"].values()), expected["workflows"])

    def test_booleans_are_lowercase(self) -> None:
        self.assertEqual(set(read("workflows.csv")["has_confirmed_finding"]), {"true", "false"})


class Metrics(unittest.TestCase):
    def test_released_metrics_match_snapshots(self) -> None:
        diffs = compute_metrics.compare(read("workflows.csv"))
        self.assertEqual(diffs, {k: 0 for k in diffs})

    def test_invalid_yaml_falls_back_to_regex(self) -> None:
        result = compute_metrics.analyze(FIXTURES / "not_valid_yaml.yml")
        # one pinned and one unpinned third-party action -> ratio 0.5 -> pinned
        self.assertEqual(result["pinning"], "pinned_third_party")
        self.assertEqual(result["surface"], "has_taint_sources")


class Evaluation(unittest.TestCase):
    def test_perfect_scanner_scores_one(self) -> None:
        labels, manifest = read("labels.csv"), read("workflows.csv")
        findings = [
            {"workflow_id": r.workflow_id, "weakness_id": r.weakness_id, "line_number": int(r.line_number)}
            for r in labels.itertuples()
        ]
        table, unmapped = evaluate.score(findings, labels, manifest, {"reference"}, "site", 0)
        micro = table[table["weakness_id"] == "micro"].iloc[0]
        self.assertEqual((micro["fp"], micro["fn"]), (0, 0))
        self.assertEqual((micro["precision"], micro["recall"]), (1.0, 1.0))
        self.assertEqual(unmapped, 0)

    def test_empty_scanner_finds_nothing(self) -> None:
        labels, manifest = read("labels.csv"), read("workflows.csv")
        table, _ = evaluate.score([], labels, manifest, {"reference"}, "workflow", 0)
        micro = table[table["weakness_id"] == "micro"].iloc[0]
        self.assertEqual((micro["tp"], micro["fp"]), (0, 0))
        self.assertGreater(micro["fn"], 0)

    def test_example_output_is_valid(self) -> None:
        findings = evaluate.load_findings(ROOT / "evaluation" / "example_scanner_output.jsonl")
        self.assertEqual(len(findings), 5)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "eval.csv"
            result = subprocess.run(
                [sys.executable, str(ROOT / "evaluation" / "evaluate.py"),
                 str(ROOT / "evaluation" / "example_scanner_output.jsonl"), "--out", str(out)],
                capture_output=True, text=True, cwd=ROOT,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
