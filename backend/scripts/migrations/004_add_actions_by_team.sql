-- Migration: Add actions_by_team to response_plans
-- Date: 2026-08-30
-- response_planner_agent groups response actions by assigned_team, but the column
-- to persist that view was never added, so it was silently dropped on every save.

ALTER TABLE response_plans ADD COLUMN IF NOT EXISTS actions_by_team JSONB DEFAULT '{}'::jsonb;
