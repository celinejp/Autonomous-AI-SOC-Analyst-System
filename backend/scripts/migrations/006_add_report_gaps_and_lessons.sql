-- Migration: Persist detection_gaps and lessons_learned on incident_reports
-- Date: 2026-09-20
-- analyst_agent generates both on every report, but the columns to persist them
-- were never added, so they were silently dropped on save and the incident page's
-- "Lessons Learned" / "Detection Gaps" sections could never render (same class of
-- bug as 004 and 005).

ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS detection_gaps JSONB DEFAULT NULL;
ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS lessons_learned JSONB DEFAULT NULL;
