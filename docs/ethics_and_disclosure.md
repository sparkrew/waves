# Ethics and Disclosure

## Competing interests

The initial corpus was collected by our industry partner, which also develops Poutine, one of the scanners this benchmark is
intended to evaluate; Poutine findings are stored alongside the corpus. The reference labels were produced from the
workflow sources and the labeling guide: Poutine findings did not determine any label. The planned evaluation of
Poutine against this reference set is subject to this competing interest and will be reported as such.

## Data

All analyzed material is publicly available and no access controls were circumvented. No exploits were developed or
executed against any repository. The weaknesses annotated are configuration patterns identifiable by existing public
scanners rather than novel vulnerabilities. The workflow files under `workflows/real/` remain the property of their
authors and keep the license of their repository (see [`NOTICE`](../NOTICE) and the `license` column of
`data/workflows.csv`). Rights holders can ask for removal of a snapshot.

## Disclosure

The benchmark annotates named public repositories with security weaknesses, which creates a disclosure obligation.
Maintainer notification for the higher-severity findings, in particular privileged-trigger (PTW) and
secrets-exposure (SEW) labels, is a precondition for the public release of the artifact. Until that process is
complete this repository is not to be made public or announced. The notification procedure and its outcomes will be
reported at release.

Status: **notification not started** (update this line, and `CHANGELOG.md`, when it begins and when it ends).

## Synthetic data

The ten synthetic CFW workflows were generated with an LLM (Anthropic Claude Sonnet 5), which was used to propose
workflows and not to assign ground-truth labels. Every synthetic workflow was manually reviewed against the CFW
criterion. They are identified as `synthetic` and must not be read as evidence of weakness prevalence.
