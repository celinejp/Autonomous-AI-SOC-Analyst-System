-- Migration: Add indicators_of_compromise to incident_reports
-- Date: 2026-09-13
-- analyst_agent now populates IncidentReport.indicators_of_compromise (structured
-- IOCs: IPs, domains, urls, file hashes, email addresses), but the column to
-- persist it was never added, so it was silently dropped on every save - same
-- class of bug as 004_add_actions_by_team.sql.

ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS indicators_of_compromise JSONB DEFAULT NULL;
