# Detectors (labeling helpers)

Deterministic, category-specific checks that flag candidate security weaknesses in GitHub Actions workflows.

They implement the annotation criteria in the [decision tree](../../../docs/annotation_guide.md). Detector outputs were used to propose labels on workflows beyond the manually adjudicated reference set; every output was then reviewed by a human, and false positives were discarded. The helpers are recall-oriented and are not scanners: their precision is not a result of this work.

Run them with [`../run_helpers.py`](../run_helpers.py) and compare them with the reference decisions with [`../eval_helpers.py`](../eval_helpers.py). The KVCW helper reads [`data/inventories/kvcw_action_inventory.csv`](../../../data/inventories/kvcw_action_inventory.csv) (override with the `KVCW_ACTIONS_CSV` environment variable).
