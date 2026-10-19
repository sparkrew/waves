# Annotation Guide: Multi-Label Decision Tree for Workflow Weaknesses

This guide is the annotation procedure used for the WAVES labels. The labeling helpers in
[`scripts/helpers/detectors`](../scripts/helpers/detectors) implement it; the field definitions of the released files are in
[`data_dictionary.md`](data_dictionary.md) and the overall procedure is in [`methodology.md`](methodology.md).

# Multi-Label Decision Tree for Workflow Vulnerability Classification

## Approach

Each workflow is evaluated against **all 10 weakness checks independently**. A workflow receives every label whose condition is satisfied, there is no early exit. This reflects the reality that a single workflow can exhibit multiple distinct vulnerabilities simultaneously.

Nine checks are decided from the workflow text. **KVCW (Check 4) is not**: it is
decided by looking each referenced action up in the vulnerable-action inventory,
which is built before labeling begins by scanning every action reachable from the
corpus, directly or transitively. The inventory covers third-party actions only;
the well-known first-party namespaces `actions/*` and `github/*` were
deliberately skipped.

An action is in the inventory for a recorded **reason**. Every reason yields KVCW
except runner compatibility, which does not, because GRCW (Check 9) already names
that consequence. GRCW is evaluated independently and over all referenced
actions, first-party included.

## Overview Diagram

```mermaid
flowchart LR
    WF[Read Workflow File] --> C1[Check IW]
    WF --> C2[Check PTW]
    WF --> C3[Check SEW]
    WF --> C4[Check KVCW]
    WF --> C5[Check AIW]
    WF --> C6[Check CFW]
    WF --> C7[Check EPW]
    WF --> C8[Check UDW]
    WF --> C9[Check GRCW]
    WF --> C10[Check HGW]
    INV[(Vulnerable-action inventory\nthird-party actions\nbuilt before labeling)] --> C4
    C1 --> Result[Assign All Matching Labels]
    C2 --> Result
    C3 --> Result
    C4 --> Result
    C5 --> Result
    C6 --> Result
    C7 --> Result
    C8 --> Result
    C9 --> Result
    C10 --> Result
```

---

## Check 1: Injection Weakness (IW)

Injection risks such as unsafe uses of untrusted inputs within shell or JavaScript contexts or environment variables in CI workflows allow attackers to execute arbitrary code by manipulating such inputs. They can inject commands through pull request metadata or workflow inputs, leading to code execution, data exfiltration, or alteration of pipeline behavior. (Fares et al., 2026)

```mermaid
flowchart TD
    Start1["Check IW"] --> Q1A{"Does any run: or env:\nblock contain ${{ }}?"}
    Q1A -->|No| NoIW[Not IW]
    Q1A -->|Yes| Q1B{"Does the expression\nreference untrusted input?"}
    Q1B -->|No| NoIW
    Q1B -->|Yes| YesIW["Label: IW"]
```

**Untrusted inputs (expanded in `run:` or `env:`):**
- `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.repo.full_name`
- `github.event.issue.title`, `.body`
- `github.event.comment.body`
- `github.event.discussion.title`, `.body`
- `github.event.pages.*.page_name`
- `github.head_ref`
- `inputs.*` from `workflow_dispatch`
- `inputs.*` from `workflow_call` (if caller passes user-controlled data)

**Safe patterns (NOT IW):**
- `${{ github.workspace }}`, `${{ runner.os }}`, `${{ matrix.* }}` — runner/workflow-controlled
- Values set via `env:` block and referenced as `$VAR` in shell (environment variable indirection)
- `${{ steps.*.outputs.* }}` from trusted actions with validated outputs
- `${{ secrets.* }}` — not user-controlled (though may raise SEW concerns)

---

## Check 2: Privileged Trigger Weakness (PTW)

Some workflows are triggered by events that run in a trusted, base repository context, such as `pull_request_target` and issue or comment-driven automation. This means that users who do not have write access on the repository can still pass inputs (e.g., the name of an issue) to a workflow that runs with write-access privileges. A workflow that combines one of these triggers with instructions that process untrusted data or code paths turns into a serious risk. If the workflow checks out or executes PR-controlled code, or uses event fields in scripts, it can enable secret exfiltration or repository modification. (Fares et al., 2026)

```mermaid
flowchart TD
    Start2["Check PTW"] --> Q2A{"Trigger is pull_request_target,\nissue_comment, or\nworkflow_run?"}
    Q2A -->|No| NoPTW[Not PTW]
    Q2A -->|Yes| Q2B{"Combined with any of:\n- checkout of PR/fork code\n- processing untrusted event fields\n- write permissions\n- secrets access?"}
    Q2B -->|No| NoPTW
    Q2B -->|Yes| YesPTW["Label: PTW"]
```

**Dangerous combinations:**
- `pull_request_target` + `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`
- `issue_comment` + write permissions + `secrets: inherit` or secret-using steps
- `workflow_run` + checkout of the triggering PR's head ref

**NOT PTW:**
- `pull_request_target` that only reads metadata without checking out PR code
- `issue_comment` with `permissions: {}` and no secret access

---

## Check 3: Secrets Exposure Weakness (SEW)

When sensitive credentials in workflows are not properly scoped or protected — such as hardcoded secrets, unnecessary exposure, or unsafe propagation across jobs — attackers can intercept them through log output, injected commands, or untrusted jobs. Leaked tokens, API keys, or credentials can be used to pivot into external infrastructure, spoof maintainers, or extract sensitive data, often without triggering immediate alarms in the CI environment. (Fares et al., 2026)

```mermaid
flowchart TD
    Start3["Check SEW"] --> Q3A{"secrets: inherit used?"}
    Q3A -->|Yes| Q3B{"Target is external\n(non-local) workflow?"}
    Q3B -->|Yes| YesSEW["Label: SEW"]
    Q3B -->|No| Q3C{"Are secrets written to\nGITHUB_ENV, GITHUB_OUTPUT,\nor logged?"}
    Q3A -->|No| Q3C
    Q3C -->|Yes| YesSEW
    Q3C -->|No| Q3D{"Secrets passed to\ncontainer/services\ndefinitions?"}
    Q3D -->|Yes| YesSEW
    Q3D -->|No| NoSEW[Not SEW]
```

**Indicators:**
- `secrets: inherit` with `uses: org/repo/.github/workflows/...@ref` (external)
- `echo "${{ secrets.TOKEN }}" >> $GITHUB_ENV`
- Secrets expanded in `run:` steps that pipe to files or stdout
- Secret values passed to container `env:` or services definitions

**NOT SEW:**
- `secrets: inherit` to a local workflow (`./.github/workflows/...`)
- Secrets passed as `with:` parameters to trusted pinned actions (normal usage)

---

## Check 4: Known Vulnerable Component Weakness (KVCW)

Workflows that reuse and rely on components or actions with known vulnerabilities may expose the CI pipeline to existing exploits. An adversary can leverage these unpatched weaknesses to hijack execution, gain unauthorized access, or execute arbitrary code, especially in environments where updates are not regularly enforced. (Fares et al., 2026)

KVCW is **not** decided by reading the workflow. It is decided by looking the
referenced action up in the vulnerable-action inventory
([`kvcw_action_inventory.csv`](../data/inventories/kvcw_action_inventory.csv),
backed by the per-finding rows in
[`vulnerable_actions.csv`](../data/inventories/vulnerable_actions.csv); see
[`kvcw_inventory.md`](kvcw_inventory.md)), which was built
before labeling started by scanning every action reachable from the sampled
workflows, directly or transitively. The scan covered third-party actions only;
`actions/*` and `github/*` were skipped, so they never produce a KVCW label.

```mermaid
flowchart TD
    Start4["Check KVCW"] --> Q4A{"Is the action (or one of its\ntransitive dependencies) in\nthe inventory?"}
    Q4A -->|No| NoKVCW[Not KVCW]
    Q4A -->|Yes| Q4B{"Is the referenced ref in\nversions_with_findings?"}
    Q4B -->|No| NoKVCW
    Q4B -->|Yes| Q4C{"What is the recorded reason?"}
    Q4C -->|"runner compatibility only"| NoKVCW2["Not KVCW - GRCW covers it (Check 9)"]
    Q4C -->|"any other reason"| YesKVCW["Label: KVCW"]
```

**The rule.** An action is in the list for a reason, and the reason decides
whether KVCW applies:

| recorded reason (`categories`) | KVCW? |
| --- | --- |
| `input_injection`, `known_cve`, `unsafe_cred_handling`, `network_exfil`, `insecure_download` | yes |
| `deprecated_runtime` only | no — this is what GRCW is for |
| a runtime reason **and** a non-runtime reason | yes, on the strength of the non-runtime reason |

Rationale: a deprecated runtime makes the step fail or be skipped, whereas the
other reasons hand an attacker a capability. Since GRCW already names the first
consequence, we do not also call it a known-vulnerable component. Four of the 60
flagged actions carry both kinds of reason (`docker/build-push-action`,
`cla-assistant/github-action`, `atlassian/gajira-create`,
`LouisBrunner/checks-action`); they are KVCW, and GRCW picks them up separately.

**How to verify:**
- Match `uses: owner/repo@ref` against the `action` column of `kvcw_action_inventory.csv`
- Confirm the `ref` appears in `versions_with_findings` for that entry; a hit on
  the action but not the version is **not** a label
- Read `categories` and apply the table above
- `kvcw_reason` records whether the hit is `direct`, `transitive`, or `both`;
  record the dependency path for transitive hits
- Where the entry carries a CVE, `vulnerable_version_ranges` further constrains
  the affected refs

---

## Check 5: Artifact Integrity Weakness (AIW)

GitHub Actions Workflows that do not validate the integrity of artifacts or reused dependencies are vulnerable to supply chain attacks. Malicious actors can poison caches or inject backdoored artifacts into later stages of the pipeline, leading to compromised artifacts or lateral movement into trusted systems. (Fares et al., 2026)

```mermaid
flowchart TD
    Start5["Check AIW"] --> Q5A{"Does the workflow download\nor restore artifacts/cache?"}
    Q5A -->|No| NoAIW[Not AIW]
    Q5A -->|Yes| Q5B{"Is checksum/signature\nverified after download?"}
    Q5B -->|Yes| NoAIW
    Q5B -->|No| YesAIW["Label: AIW"]
```

**Indicators:**
- `actions/download-artifact` without subsequent hash verification
- `actions/cache` restore in PR-triggered workflow (cache poisoning risk)
- `wget`/`curl` downloading binaries without checksum validation
- Consuming outputs from prior workflow runs without attestation

---

## Check 6: Control Flow Weakness (CFW)

In GitHub Actions Workflows, developers use conditions to control when specific steps should be executed. However, attackers can exploit flawed conditions — such as ones that are always true (overly permissive) — to bypass intended safeguards. This may lead to the unauthorized execution of sensitive jobs, including deployments or access to secrets. (Fares et al., 2026)

```mermaid
flowchart TD
    Start6["Check CFW"] --> Q6A{"Does any if: use a YAML\nfolded scalar with\n${{ }} expression?"}
    Q6A -->|No| Q6B{"Any if: condition\nthat is always true\ndue to logic flaw?"}
    Q6A -->|Yes| Q6C{"Uses > without strip?\n(appends newline)"}
    Q6C -->|Yes| YesCFW["Label: CFW"]
    Q6C -->|No| Q6B
    Q6B -->|Yes| YesCFW
    Q6B -->|No| NoCFW[Not CFW]
```

**Key patterns:**
- `if: >` with `${{ boolean_expr }}` — the `>` appends `\n`, making `"false\n"` truthy
- `if: >-` is safer (strips trailing newline) but can still have logic errors
- Any condition that logically always evaluates to true (dead code)

---

## Check 7: Excessive Permission Weakness (EPW)

Overprivileged workflows, tokens, jobs, or permissions create opportunities for privilege escalation attacks. If a workflow does not explicitly restrict its `GITHUB_TOKEN` permissions, an attacker who gains control of a job via injection or logic flaws can abuse broad permissions to push code, access secrets, or modify critical repository settings. (Fares et al., 2026)

```mermaid
flowchart TD
    Start7["Check EPW"] --> Q7A{"Is permissions: block\npresent at workflow\nor all job levels?"}
    Q7A -->|No| YesEPW["Label: EPW"]
    Q7A -->|Yes| Q7B{"Does it grant write\npermissions beyond what\nthe workflow needs?"}
    Q7B -->|Yes| YesEPW
    Q7B -->|No| NoEPW[Not EPW]
```

**Indicators:**
- No `permissions:` key at either workflow-level or job-level (defaults to broad)
- `permissions: write-all`
- `contents: write` when the workflow only reads code
- `pull-requests: write` + `contents: write` + `id-token: write` for simple automation

**NOT EPW:**
- `permissions: contents: read` (explicit minimal)
- `permissions: {}` (no permissions)
- Write permissions that match the workflow's actual function (e.g., `issues: write` for issue-labeling workflow)

---

## Check 8: Unpinned Dependency Weakness (UDW)

The absence of pinned versioning for actions or dependencies exposes workflows to substitution attacks, where an adversary introduces malicious updates into upstream components. By exploiting floating tags or unverified references, attackers can inject backdoors or tampered logic into workflows without any change in the workflow's own source code, making the attack stealthy and persistent. (Fares et al., 2026)

```mermaid
flowchart TD
    Start8["Check UDW"] --> Q8A{"Any uses: references\na third-party or external\naction/workflow?"}
    Q8A -->|No| NoUDW[Not UDW]
    Q8A -->|Yes| Q8B{"Referenced by full\n40-char commit SHA?"}
    Q8B -->|Yes| NoUDW
    Q8B -->|No| YesUDW["Label: UDW"]
```

**Unpinned (vulnerable):**
- `uses: owner/action@main` — branch (mutable, can be force-pushed)
- `uses: owner/action@v4` — major tag (can be moved to any commit)
- `uses: owner/action@v1.2.3` — semver tag (can be deleted and recreated)
- `uses: owner/action@branch-25.08` — branch name

**Pinned (safe):**
- `uses: owner/action@a1b2c3d4e5f6789...` — 40-char SHA (immutable)

**NOT UDW:**
- Local actions: `uses: ./.github/actions/my-action` (same repo, same commit)
- Local workflows: `uses: ./.github/workflows/reusable.yml` (same repo)

---

## Check 9: GitHub Runner Compatibility Weakness (GRCW)

This weakness occurs when a workflow references an action, runtime, or workflow construct that cannot be reliably resolved, interpreted, or supported in the current GitHub Actions environment. Common root causes include outdated major versions of actions that rely on deprecated language runtimes, as well as unrecognized or renamed workflow keys, contexts, or expressions that do not resolve under the GitHub Actions specification. These incompatibilities can cause jobs to fail or be skipped, unintentionally disabling required checks or security steps. (Fares et al., 2026)

GRCW is evaluated over **all** referenced actions, first-party included, so it is
not scoped by the inventory. Where the inventory does record a
`deprecated_runtime` reason for a third-party action, that is corroborating
evidence for GRCW and the signal that KVCW is withheld (Check 4).

```mermaid
flowchart TD
    Start9["Check GRCW"] --> Q9A{"Does the referenced action major\ndeclare a runtime past EOL?"}
    Q9A -->|Yes| YesGRCW["Label: GRCW"]
    Q9A -->|No| Q9B{"Uses unrecognized or\nremoved workflow\nconstructs?"}
    Q9B -->|Yes| YesGRCW
    Q9B -->|No| NoGRCW[Not GRCW]
```

**Deprecated runtimes:**
- Node.js 12 (EOL April 2022): `actions/checkout@v2`, `actions/setup-python@v2`, `actions/setup-node@v2`
- Node.js 16 (EOL September 2023): `actions/checkout@v3`, `actions/setup-node@v3`

For third-party actions, cross-check `kvcw_actions.csv` so the version constraint
is applied consistently; for `actions/*` and `github/*` the inventory is silent by
design and this table is the whole procedure.

**Other indicators** (decided from the workflow text, no inventory involved):
- Removed workflow commands: `::set-output`, `::save-state`
- Unsupported `runs-on` labels

---

## Check 10: Hardening Gap Weakness (HGW)

Workflows that lack integrated security scanning tools (e.g., SAST, dependency auditing, or secret scanning) create a hardening gap, giving attackers a broader surface to operate undetected. Without static analysis, dependency updates, or review enforcement, adversaries can introduce vulnerable code, exploit unpatched components, or suppress controls that would otherwise expose their actions. (Fares et al., 2026)

```mermaid
flowchart TD
    Start10["Check HGW"] --> Q10A{"Is this a CI/CD build\nor test pipeline?"}
    Q10A -->|No| NoHGW[Not HGW]
    Q10A -->|Yes| Q10B{"Contains any security\nscanning step?\n(SAST/audit/secret scan)"}
    Q10B -->|Yes| NoHGW
    Q10B -->|No| YesHGW["Label: HGW"]
```

**Applies to workflows that:**
- Execute builds (`mvn install`, `npm run build`, `make`, `cargo build`)
- Run tests (`pytest`, `jest`, `bundle exec rake spec`)
- Package/deploy artifacts

**Does NOT apply to:**
- Issue/PR automation (assignment, labeling, stale cleanup)
- Notification workflows
- Workflows that solely delegate to reusable workflows (cannot inspect their content)

**Security scanning examples:**
- CodeQL / `github/codeql-action`
- Dependency review / `actions/dependency-review-action`
- Trivy, Snyk, Dependabot
- Secret scanning / ggshield
