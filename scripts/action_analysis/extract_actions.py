import pandas as pd
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR = Path(__file__).parent
FULL_CSV = BASE_DIR / "sample_500_full.csv"
OUTPUT_CSV = BASE_DIR / "actions_used.csv"

df = pd.read_csv(FULL_CSV)

SHA_RE = re.compile(r'^[0-9a-f]{40}$')
USES_RE = re.compile(r"'uses': '([^']+)'")

action_data = defaultdict(lambda: {
    'usage_count': 0,
    'workflow_count': 0,
    'versions_used': set(),
    'example_workflows': [],
})

for _, row in df.iterrows():
    jobs_str = str(row.get('jobs', ''))
    uses_refs = USES_RE.findall(jobs_str)

    seen_in_workflow = set()

    for ref in uses_refs:
        if ref.startswith('./'):
            continue

        if '@' in ref:
            action_path, version = ref.rsplit('@', 1)
        else:
            action_path = ref
            version = 'unspecified'

        action_data[action_path]['usage_count'] += 1
        action_data[action_path]['versions_used'].add(version)

        if action_path not in seen_in_workflow:
            seen_in_workflow.add(action_path)
            action_data[action_path]['workflow_count'] += 1
            if len(action_data[action_path]['example_workflows']) < 3:
                action_data[action_path]['example_workflows'].append(row['source_git_repo'])

rows = []
for action_path, info in action_data.items():
    parts = action_path.split('/')

    if len(parts) >= 2:
        owner = parts[0]
        repo = parts[1]
        sub_path = '/'.join(parts[2:]) if len(parts) > 2 else ''
        github_url = f'https://github.com/{owner}/{repo}'
        marketplace_url = f'https://github.com/marketplace/actions/{repo}' if not sub_path else ''
    else:
        owner = ''
        repo = action_path
        sub_path = ''
        github_url = ''
        marketplace_url = ''

    versions = info['versions_used']
    sha_pinned = [v for v in versions if SHA_RE.match(v)]
    tag_versions = [v for v in versions if not SHA_RE.match(v)]

    rows.append({
        'action': action_path,
        'owner': owner,
        'repo': repo,
        'sub_path': sub_path,
        'github_url': github_url,
        'marketplace_url': marketplace_url,
        'usage_count': info['usage_count'],
        'workflow_count': info['workflow_count'],
        'tag_versions': '; '.join(sorted(tag_versions)),
        'sha_versions': '; '.join(sorted(sha_pinned)),
        'sha_pinned_versions': len(sha_pinned),
        'is_sha_pinned': len(sha_pinned) > 0,
        'is_mixed_pinning': len(sha_pinned) > 0 and len(tag_versions) > 0,
        'example_workflows': '; '.join(info['example_workflows']),
    })

result = pd.DataFrame(rows).sort_values('workflow_count', ascending=False).reset_index(drop=True)

print(f"Total unique actions: {len(result)}")
print(f"Total action references: {result['usage_count'].sum()}")
print(f"Actions with SHA pinning: {result['is_sha_pinned'].sum()}")
print(f"Actions with tag-only: {(~result['is_sha_pinned']).sum()}")
print(f"\nTop 20 most used actions:")
print(result[['action', 'workflow_count', 'usage_count', 'tag_versions']].head(20).to_string())

result.to_csv(OUTPUT_CSV, index=False)
print(f"\nSaved {len(result)} actions to {OUTPUT_CSV}")
