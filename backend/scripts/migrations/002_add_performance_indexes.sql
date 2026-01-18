-- Performance optimization indexes
-- Run this migration to add database indexes for faster queries

-- Single column indexes
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_confidence_score ON incidents(confidence_score DESC);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_incidents_status_created ON incidents(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_created ON incidents(severity, created_at DESC);

-- Indexes for related tables
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_mitre_techniques_incident_id ON mitre_techniques(incident_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_incident_id ON log_entries(incident_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_log_entries_source_ip ON log_entries(source_ip);

-- Index for full-text search on incident reports (if needed)
-- CREATE INDEX IF NOT EXISTS idx_reports_search_text ON incident_reports USING gin(to_tsvector('english', executive_summary || ' ' || technical_findings));

-- Analyze tables to update statistics
ANALYZE incidents;
ANALYZE alerts;
ANALYZE mitre_techniques;
ANALYZE log_entries;

