"""Re-download workflow snapshots from GitHub and verify them against the manifest.

The repository already ships every snapshot in workflows/. This script is for
checking that upstream still serves the same bytes, or for restoring a snapshot
after removing it (for example in a trimmed-down copy of the dataset).

Files are fetched at the exact commit recorded in data/workflows.csv from
raw.githubusercontent.com and compared with file_sha256. Synthetic workflows
are not fetched (they are only distributed with this repository).

Usage:
    python scripts/fetch_workflows.py --check             # report only, change nothing
    python scripts/fetch_workflows.py --restore           # download missing snapshots
    python scripts/fetch_workflows.py --restore --force   # overwrite existing ones too
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]


def download(repository: str, sha: str, path: str) -> bytes | None:
    url = f"https://raw.githubusercontent.com/{repository}/{sha}/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "waves-fetch"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403, 451):
                return None
        except urllib.error.URLError:
            pass
        time.sleep(2 * (attempt + 1))
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="compare upstream with the manifest")
    mode.add_argument("--restore", action="store_true", help="write missing snapshots")
    parser.add_argument("--force", action="store_true", help="with --restore, overwrite existing files")
    args = parser.parse_args()

    manifest = pd.read_csv(ROOT / "data" / "workflows.csv", dtype=str, keep_default_na=False)
    real = manifest[manifest["source_type"] == "real_world"]

    counts = {"ok": 0, "changed": 0, "gone": 0, "restored": 0, "skipped": 0}
    for row in real.itertuples():
        target = ROOT / row.snapshot_path
        if args.restore and target.exists() and not args.force:
            counts["skipped"] += 1
            continue
        content = download(row.repository, row.commit_sha, row.workflow_path)
        if content is None:
            counts["gone"] += 1
            print(f"{row.workflow_id}: not available upstream ({row.workflow_blob_url})")
            continue
        if hashlib.sha256(content).hexdigest() != row.file_sha256:
            counts["changed"] += 1
            print(f"{row.workflow_id}: upstream bytes differ from the manifest")
            continue
        if args.restore:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            counts["restored"] += 1
        else:
            counts["ok"] += 1

    print(counts)
    return 0 if counts["changed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
