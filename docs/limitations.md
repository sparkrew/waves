# Limitations

**Diversity-oriented sample, not a prevalence sample.** The workflows were selected for heterogeneity of structure,
trigger, dependency pinning and untrusted-data exposure. Counts describe the labeled set, not GitHub Actions at large.
The corpus covers public repositories and default-branch snapshots; near-duplicates (forks, templates, generators) may
inflate frequencies, and deduplication remains future work. 43 of the 81 metric cells are populated and the pinned
third-party (33) and taint-source (5) groups are small.

**Two label qualities.** The 100 reference workflows were labeled by two annotators with cross-review and adjudication.
The other 365 were labeled by verifying helper-proposed candidates only. Use the `subset` column to separate them.

**No confirmed negatives for the helper-reviewed workflows.** Manual verification only covered helper-proposed findings;
workflow-category pairs where a helper reported nothing were not inspected. The helpers are recall-oriented, but false
negatives may remain, so a missing label in a `helper_reviewed` workflow is not a confirmed negative. Helper precision
on the verified candidates (1,969 of 2,136) is a verification workload number, not a scanner evaluation result.

**Helpers were developed on the reference subset.** Recall of 1.0 on the reference workflows is therefore not a
generalization estimate.

**Annotators are authors.** Adjudication agreement does not establish transfer to independent labelers.

**Category issues.** Several categories require contextual judgment (AIW, HGW, IW, PTW, SEW). EPW treats a missing
`permissions:` block as excessive under a worst-case reading of repository defaults; on the reference set this affects
76 of 266 positive workflow-category pairs. HGW is a process gap rather than an immediately exploitable flaw; it is
retained for compatibility with Fares et al. and can be excluded. UDW, KVCW and GRCW overlap by design and partition
dependency issues by consequence rather than precedence. The KVCW inventory covers third-party actions only
(`actions/*` and `github/*` are out of scope for KVCW; GRCW covers all referenced actions).

**CFW is synthetic.** No natural CFW instance was observed; the ten synthetic cases complete the taxonomy but must not
be read as prevalence and may under-represent real control-flow flaws. IW is rare in the real workflows because
sampling did not balance untrusted-data exposure.

**Metric definitions.** The action pinning profile counts step-level `uses:` references only; job-level reusable
workflow references are not counted.

**Snapshots age.** Workflows are pinned to a commit and retrieved on `retrieval_date`; upstream files may change or be
deleted, which is why snapshots are included. GitHub Actions evolves, so some weaknesses (for example deprecated
runtimes) may disappear over time.

**Competing interest.** The initial corpus was collected by our industry partner, which also develops the Poutine scanner;
see [`ethics_and_disclosure.md`](ethics_and_disclosure.md).
