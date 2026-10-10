-- 002_sandbox_reset.sql : track post-run environment reset verification separately from execution outcome
ALTER TABLE sandbox_jobs ADD COLUMN reset_status TEXT CHECK (reset_status IN ('pending', 'verified', 'failed', 'not_applicable'));
ALTER TABLE sandbox_jobs ADD COLUMN reset_detail TEXT;
ALTER TABLE sandbox_jobs ADD COLUMN execution_outcome TEXT;
ALTER TABLE sandbox_jobs ADD COLUMN reset_wait_started_at TEXT;
