-- =============================================================================
-- GHA Workflow Diversity Sampling — BigQuery candidate pool
--
-- NOTE: the table identifiers in the FROM/JOIN clauses are redacted. The source
-- corpus is proprietary and is not part of this artifact; this query is kept as
-- documentation of the selection logic and cannot be run as is.
--
-- Computes cheap structural/trigger/permission metrics on all 1M rows,
-- joins repo metadata for stars + language, stratifies across 4 axes,
-- and returns ~1500 candidates for the Python script to refine to 500.
--
-- ~1500 candidates (≈3× target) gives Python enough headroom to:
--   - compute expensive metrics (SHA pinning, expressions, taint sources)
--   - rebalance across all four primary axes including security surface
--   - absorb sparse cells without dropping below 500
--
-- =============================================================================

WITH

cheap AS (
  SELECT
    w.gha_fingerprint,
    w.workflow_blob_url,
    w.source_git_repo,
    w.package_namespace,
    w.package_name,
    w.workflow_path,
    w.workflow_name,

    -- ── Repo metadata (joined here so it travels with each candidate row) ─────
    r.primary_language,
    r.stars_count,
    CASE
      WHEN r.stars_count IS NULL    THEN 'unknown'
      WHEN r.stars_count < 10       THEN 'q1_low'
      WHEN r.stars_count < 100      THEN 'q2_medium'
      WHEN r.stars_count < 1000     THEN 'q3_high'
      ELSE                               'q4_top'
    END AS popularity_bucket,
    r.license,
    r.is_fork,

    -- ── 1. Structural ─────────────────────────────────────────────────────────

    ARRAY_LENGTH(w.jobs) AS num_jobs,

    (SELECT IFNULL(SUM(ARRAY_LENGTH(job.steps)), 0)
     FROM UNNEST(w.jobs) AS job
    ) AS total_steps,

    EXISTS(
      SELECT 1 FROM UNNEST(w.jobs) AS job
      WHERE job.strategy IS NOT NULL AND job.strategy.matrix IS NOT NULL
    ) AS has_matrix_strategy,

    EXISTS(
      SELECT 1 FROM UNNEST(w.jobs) AS job
      WHERE ARRAY_LENGTH(job.needs) > 0
    ) AS has_job_dependencies,

    EXISTS(
      SELECT 1 FROM UNNEST(w.jobs) AS job
      WHERE job.uses IS NOT NULL
        AND (ENDS_WITH(SPLIT(job.uses, '@')[OFFSET(0)], '.yml')
             OR ENDS_WITH(SPLIT(job.uses, '@')[OFFSET(0)], '.yaml'))
    ) AS uses_reusable_workflows,

    -- ── 2. Triggers ───────────────────────────────────────────────────────────

    (SELECT COUNT(DISTINCT e.name)
     FROM UNNEST(w.events) AS e
    ) AS trigger_diversity_count,

    CASE
      WHEN EXISTS(
        SELECT 1 FROM UNNEST(w.events) AS e
        WHERE e.name IN (
          'pull_request_target', 'issue_comment', 'issues',
          'discussion_comment', 'workflow_run'
        )
      ) THEN 'high'
      WHEN EXISTS(
        SELECT 1 FROM UNNEST(w.events) AS e
        WHERE e.name = 'pull_request'
      ) THEN 'medium'
      ELSE 'low'
    END AS trigger_risk_level,

    EXISTS(
      SELECT 1 FROM UNNEST(w.events) AS e
      WHERE e.name = 'workflow_dispatch' AND ARRAY_LENGTH(e.inputs) > 0
    ) AS has_workflow_dispatch_inputs,

    -- ── 3. Actions (counts; regex deferred to Python) ─────────────────────────

    (SELECT COUNT(*)
     FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
     WHERE step.uses IS NOT NULL
       AND NOT STARTS_WITH(step.uses, './')
       AND NOT (ENDS_WITH(SPLIT(step.uses, '@')[OFFSET(0)], '.yml')
                OR ENDS_WITH(SPLIT(step.uses, '@')[OFFSET(0)], '.yaml'))
    ) AS num_third_party_action_refs,

    (SELECT COUNT(*)
     FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
     WHERE step.uses IS NOT NULL
    ) AS num_uses_steps,

    (SELECT COUNT(*)
     FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
     WHERE step.run IS NOT NULL
    ) AS num_run_steps,

    -- Raw arrays passed through to Python for expensive metric computation
    ARRAY(
      SELECT step.uses
      FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
      WHERE step.uses IS NOT NULL
    ) AS all_step_uses,

    ARRAY(
      SELECT step.run
      FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
      WHERE step.run IS NOT NULL
    ) AS all_run_blocks,

    -- Env values: filter inside each branch to avoid outer-alias scoping error
    ARRAY(
      SELECT val
      FROM (
        SELECT e.value AS val FROM UNNEST(w.env) AS e
        WHERE e.value IS NOT NULL
        UNION ALL
        SELECT e.value AS val
        FROM UNNEST(w.jobs) AS job, UNNEST(job.env) AS e
        WHERE e.value IS NOT NULL
        UNION ALL
        SELECT e.value AS val
        FROM UNNEST(w.jobs) AS job,
             UNNEST(job.steps) AS step,
             UNNEST(step.env) AS e
        WHERE e.value IS NOT NULL
      )
    ) AS all_env_values,

    -- ── 4. Security (cheap proxies; expressions deferred to Python) ───────────

    (
      ARRAY_LENGTH(w.permissions) > 0
      OR EXISTS(
        SELECT 1 FROM UNNEST(w.jobs) AS job
        WHERE ARRAY_LENGTH(job.permissions) > 0
      )
    ) AS has_permissions_block,

    CASE
      WHEN ARRAY_LENGTH(w.permissions) = 0
        AND NOT EXISTS(
          SELECT 1 FROM UNNEST(w.jobs) AS job
          WHERE ARRAY_LENGTH(job.permissions) > 0
        ) THEN 'not_set'
      WHEN (SELECT COUNT(*) FROM UNNEST(w.permissions)) = 0
        THEN 'empty_locked_down'
      WHEN EXISTS(
          SELECT 1 FROM UNNEST(w.permissions) AS p WHERE p.permission = 'write'
        ) AND (SELECT COUNT(*) FROM UNNEST(w.permissions)) > 1
        THEN 'write_all'
      WHEN EXISTS(
          SELECT 1 FROM UNNEST(w.permissions) AS p WHERE p.permission = 'read'
        ) AND NOT EXISTS(
          SELECT 1 FROM UNNEST(w.permissions) AS p WHERE p.permission = 'write'
        ) AND (SELECT COUNT(*) FROM UNNEST(w.permissions)) > 1
        THEN 'read_all'
      ELSE 'granular'
    END AS permission_scope,

    -- Pre-parsed by ingestion layer; no regex needed
    (SELECT IFNULL(SUM(ARRAY_LENGTH(job.references_secrets)), 0)
     FROM UNNEST(w.jobs) AS job
    ) AS secrets_usage_count,

    (
      EXISTS(
        SELECT 1 FROM UNNEST(w.jobs) AS job WHERE job.if IS NOT NULL
      )
      OR EXISTS(
        SELECT 1 FROM UNNEST(w.jobs) AS job, UNNEST(job.steps) AS step
        WHERE step.if IS NOT NULL
      )
    ) AS has_conditional_expressions,

    -- ── 5. Ecosystem ──────────────────────────────────────────────────────────

    CASE
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(codeql|security|scan|sast|snyk|trivy|semgrep)'
      ) THEN 'security_scan'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(dependabot|deps|dependency|renovate)'
      ) THEN 'dependency_management'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(deploy|release|publish)'
      ) THEN 'deploy_release'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(build|compile|package)'
      ) THEN 'build'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(lint|format|style|quality|prettier|eslint)'
      ) THEN 'code_quality'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(ci|test|check|validate|verify)'
      ) THEN 'ci_test'
      WHEN REGEXP_CONTAINS(
        LOWER(IFNULL(w.workflow_name, '') || ' ' || w.workflow_path),
        r'(docs|pages|documentation)'
      ) THEN 'documentation'
      ELSE 'other'
    END AS workflow_purpose,

    EXISTS(
      SELECT 1 FROM UNNEST(w.jobs) AS job, UNNEST(job.runs_on) AS runner
      WHERE LOWER(runner) = 'self-hosted'
         OR STARTS_WITH(LOWER(runner), 'self-hosted,')
    ) AS has_self_hosted_runner,

    EXISTS(
      SELECT 1 FROM UNNEST(w.jobs) AS job
      WHERE job.container IS NOT NULL AND job.container.image IS NOT NULL
    ) AS uses_container

  FROM `<PROJECT>.<DATASET>.<WORKFLOWS_TABLE>` AS w
  LEFT JOIN `<PROJECT>.<DATASET>.<REPO_METADATA_TABLE>` AS r
    USING (gha_fingerprint)
),

bucketed AS (
  SELECT
    *,
    CASE
      WHEN num_jobs = 1 AND total_steps <= 3                         THEN 'simple'
      WHEN num_jobs BETWEEN 2 AND 3 OR total_steps BETWEEN 4 AND 10 THEN 'medium'
      ELSE 'complex'
    END AS structural_complexity_bucket,

    -- Proxy for action dependency axis; Python refines with real SHA pinning ratio
    CASE
      WHEN num_third_party_action_refs = 0  THEN 'no_third_party'
      WHEN num_third_party_action_refs <= 2 THEN 'few_third_party'
      ELSE 'many_third_party'
    END AS action_dependency_bucket

  FROM cheap
),

-- Stratified candidate pool
-- Primary axes used here: structural (3) × trigger_risk (3) × action_dep (3) = 27 cells
-- Python adds security_surface as a 4th axis after computing expressions locally.
-- 55 per cell × 27 cells = ~1500 candidates → plenty of room for Python to
-- rebalance across all four axes and still land at 500.
ranked AS (
  SELECT
    *,
    ROW_NUMBER() OVER (
      PARTITION BY
        structural_complexity_bucket,
        trigger_risk_level,
        action_dependency_bucket
      ORDER BY RAND()
    ) AS rn_in_cell
  FROM bucketed
)

SELECT * EXCEPT (rn_in_cell)
FROM ranked
WHERE rn_in_cell <= 55
ORDER BY
  structural_complexity_bucket,
  trigger_risk_level,
  action_dependency_bucket,
  RAND();
