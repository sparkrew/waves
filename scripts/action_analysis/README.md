# Action analysis (version-aware inventory)

Scripts used to build the KVCW inventory ([`data/inventories/kvcw_action_inventory.csv`](../../data/inventories/kvcw_action_inventory.csv))
and the list of vulnerable action versions ([`vulnerable_actions.csv`](../../data/inventories/vulnerable_actions.csv)).

| File | Role |
|---|---|
| `extract_actions.py` | Lists the third-party actions referenced by the sampled workflows and how they are pinned |
| `scan_actions.py` | Inspects the source of each action at the exact referenced version (including nested actions) for known-vulnerable patterns and deprecated runtimes |
| `build_kvcw_actions.py` | Merges the scan results with GitHub security advisories into the KVCW inventory, direct and transitive |

See [`docs/kvcw_inventory.md`](../../docs/kvcw_inventory.md) for the columns of both inventories, how they are built and how
they are matched against workflows.

These scripts query GitHub and reference intermediate files from the original labeling workspace (for example
`sample_500_full.csv`, `action_cache/`), which are not part of the release. They are provided for transparency; the
inventories they produced are released as data, and candidate inventory entries were manually reviewed before use.
