# Data Dictionary

All files are UTF-8 CSV with a header row, `\n` line endings, and lowercase booleans (`true`/`false`).
Spreadsheet programs (Excel) display `true`/`false` as `TRUE`/`FALSE`; the files on disk are lowercase.

Identifiers are stable keys that join the tables:

| Identifier | Format | Defined in |
|---|---|---|
| `workflow_id` | `WAVES-0001` ... `WAVES-0475` | `workflows.csv` |
| `label_id` | `WAVES-L0001` ... `WAVES-L2424` | `labels.csv`; referenced by the two files below |
| `decision_id` | `WAVES-R0001` ... `WAVES-R0445` | `reference_decisions.csv` (the annotators' record of a label) |
| `candidate_id` | `WAVES-C0001` ... `WAVES-C2136` | `helper_candidates.csv` (a helper proposal, accepted or rejected) |
| `weakness_id` | `AIW CFW EPW GRCW HGW IW KVCW PTW SEW UDW` | all label tables |

## `data/workflows.csv` (475 rows, one per workflow)

| Column | Description |
|---|---|
| `workflow_id` | Primary key |
| `source_type` | `real_world` (465) or `synthetic` (10) |
| `repository` | `owner/repo` of the upstream repository |
| `workflow_path` | Path of the workflow file in the repository |
| `commit_sha` | 40-character commit the snapshot was taken at |
| `workflow_blob_url` | GitHub blob URL at that commit |
| `subset` | `reference` (100, manually labeled by two annotators), `helper_reviewed` (365, helper candidates manually verified), `synthetic` (10) |
| `structural_complexity` | `simple`, `medium`, `complex` (see [sampling.md](sampling.md)) |
| `trigger_trust_exposure` | `low`, `medium`, `high` |
| `action_pinning_profile` | `no_third_party`, `pinned_third_party`, `unpinned_third_party` |
| `untrusted_data_exposure` | `no_expressions`, `expressions_no_taint`, `has_taint_sources` |
| `has_confirmed_finding` | `true` if the workflow has at least one label (467); `false` for confirmed all-negative workflows (8) |
| `retrieval_date` | `2026-06-10` for real-world snapshots; the commit date of the synthetic benchmark (`2026-09-06`) for synthetic ones |
| `file_sha256` | SHA-256 of the snapshot file |
| `snapshot_path` | Path of the snapshot relative to the repository root |
| `license` | SPDX id of the upstream repository license from the GitHub API; `NOASSERTION`, `none` or `unavailable` if not known; `CC-BY-4.0` for synthetic workflows |

## `data/labels.csv` (2,424 rows, the ground truth)

One row per confirmed weakness instance.

| Column | Description |
|---|---|
| `label_id` | Primary key |
| `workflow_id` | Foreign key to `workflows.csv` |
| `workflow_blob_url` | Blob URL (denormalized for readability) |
| `line_number` | Line of the evidence in the snapshot |
| `weakness_id` | One of the ten categories (Fares et al.) |
| `evidence` | Statement or block that establishes the weakness |
| `explanation` | Short justification |

Workflows with no rows in this file are exactly those with `has_confirmed_finding = false`. For the 100 reference
workflows every workflow-category pair was evaluated, so a missing label is a confirmed negative. For the 365
helper-reviewed workflows only helper-proposed findings were manually verified, so a missing label is not a confirmed
negative (see [limitations.md](limitations.md)).

## `data/reference_decisions.csv` (445 rows)

Labels of the 100 reference workflows after cross-labeling and adjudication. Columns: `decision_id` (primary key),
`label_id` (foreign key to the same finding in `labels.csv`), then `workflow_id`, `line_number`, `weakness_id`,
`evidence`, `explanation` as in `labels.csv`. These decisions are frozen and were never changed to match helper output.
They are exactly the rows of `labels.csv` whose workflow has `subset = reference`, and `validate_dataset.py` checks
that each `label_id` points to an identical row.

## `data/helper_candidates.csv` (2,136 rows)

Candidates proposed by the labeling helpers on the 365 helper-reviewed workflows.

| Column | Description |
|---|---|
| `candidate_id` | Primary key |
| `label_id` | Foreign key to `labels.csv` for accepted candidates (1,969); empty for rejected ones, which never became labels |
| `workflow_id`, `line_number`, `weakness_id`, `evidence`, `explanation` | As in `labels.csv` |
| `decision` | `accepted` (1,969) or `rejected` (167) after manual verification |
| `review_batch` | Review session that verified the candidate |

Accepted candidates are exactly the rows of `labels.csv` whose workflow has `subset = helper_reviewed`.

## `data/expected_counts.json`

The counts and statistics that `scripts/validate_dataset.py` and `scripts/reproduce_results.py` check, and that the
paper reports.

## `data/inventories/`

| File | Rows | Content |
|---|---|---|
| `kvcw_action_inventory.csv` | 74 | Decision table: one row per action with the reason it is listed (direct, transitive, both), the affected versions and the categories. Used to assign KVCW and, for `deprecated_runtime` entries, GRCW |
| `vulnerable_actions.csv` | 220 | Scan evidence behind the inventory: one row per finding (action, version, pattern or advisory), with parent and depth for nested findings |
| `grcw_runtime_baseline.csv` | 17 | GRCW baseline: official action major versions on deprecated Node.js runtimes and removed workflow commands |
| `sources.csv` | 8 | Advisories, changelogs and documentation the baselines are derived from |

Column definitions, how the inventories are built and how a workflow reference is matched against them are in
[kvcw_inventory.md](kvcw_inventory.md).

`grcw_runtime_baseline.csv` columns: `kind` (`action_major_version` or `workflow_command`), `action` (empty for
commands), `version` (a major version such as `v3`, or the command such as `::set-output`), `reason`
(`deprecated_node_runtime` or `removed_workflow_command`).
`sources.csv` columns: `source_id`, `title`, `url`, `accessed` (date), `used_for` (`GRCW`, `KVCW` or `classification`).

## `workflows/`

`real/WAVES-NNNN.yml` and `synthetic/WAVES-NNNN.yml` are the snapshots, named by `workflow_id`. `checksums.sha256` lists
`sha256  path` for every snapshot. See [`NOTICE`](../NOTICE) for licensing of the snapshots.
