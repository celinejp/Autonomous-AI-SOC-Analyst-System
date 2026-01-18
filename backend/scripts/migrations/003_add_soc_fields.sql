-- Migration: Add SOC enhancement fields
-- Date: 2026-01-17

-- Add new columns to incidents table
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS executive_summary TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS data_completeness_score FLOAT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS regulatory_impact JSONB;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detection_gaps JSONB;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS lessons_learned JSONB;

-- Create IOCs table
CREATE TABLE IF NOT EXISTS incident_iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    reputation VARCHAR(50),
    confidence VARCHAR(20),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    related_techniques TEXT[],
    recommended_action VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_iocs_incident_id ON incident_iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_iocs_type_value ON incident_iocs(ioc_type, value);

-- Create response actions table
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    target TEXT NOT NULL,
    assigned_team VARCHAR(50),
    requires_approval BOOLEAN DEFAULT false,
    status VARCHAR(20) DEFAULT 'pending',
    priority VARCHAR(20),
    requested_at TIMESTAMP DEFAULT NOW(),
    approved_at TIMESTAMP,
    executed_at TIMESTAMP,
    result TEXT,
    automation_available BOOLEAN DEFAULT false,
    automated BOOLEAN DEFAULT false,
    depends_on TEXT[],
    success_criteria TEXT,
    verification_steps TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_response_actions_incident_id ON response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_actions_team ON response_actions(assigned_team);

-- Create organization profile table
CREATE TABLE IF NOT EXISTS organization_profile (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100),
    regulations TEXT[],
    risk_appetite VARCHAR(50),
    internal_ip_ranges TEXT[],
    trusted_domains TEXT[],
    approved_cloud_services TEXT[],
    crown_jewels JSONB,
    escalation_matrix JSONB,
    notification_contacts JSONB,
    acceptable_downtime_hours JSONB,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_organization_profile_name ON organization_profile(name);

-- Create SOC metrics table
CREATE TABLE IF NOT EXISTS soc_metrics_hourly (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    mttd_seconds FLOAT,
    mttr_seconds FLOAT,
    mttc_seconds FLOAT,
    false_positive_rate FLOAT,
    true_positive_rate FLOAT,
    escalation_accuracy FLOAT,
    alerts_received INT,
    alerts_closed INT,
    alerts_escalated INT,
    incidents_created INT,
    ai_accuracy FLOAT,
    ai_triage_rate FLOAT,
    alert_reduction_ratio FLOAT,
    attack_technique_coverage JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soc_metrics_period ON soc_metrics_hourly(period_start, period_end);

-- Create endpoint actions table (for EDR integration)
CREATE TABLE IF NOT EXISTS endpoint_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_host_id VARCHAR(255),
    process_id INT,
    process_name VARCHAR(255),
    file_path TEXT,
    file_hash VARCHAR(255),
    script_content TEXT,
    justification TEXT,
    attack_technique VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    requested_at TIMESTAMP DEFAULT NOW(),
    requested_by VARCHAR(100),
    approved_at TIMESTAMP,
    approved_by VARCHAR(100),
    executed_at TIMESTAMP,
    completed_at TIMESTAMP,
    result TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_endpoint_actions_incident_id ON endpoint_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_actions_status ON endpoint_actions(status);
CREATE INDEX IF NOT EXISTS idx_endpoint_actions_host ON endpoint_actions(target_host);

-- Add new columns to log_entries table for enhanced fields
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS process_name VARCHAR(255);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS process_id INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS parent_process_name VARCHAR(255);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS parent_process_id INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS command_line TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS return_code INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS file_hash_md5 VARCHAR(32);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS file_hash_sha256 VARCHAR(64);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS file_path TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS registry_key TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS event_id INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS auth_result VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS geo_country VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS geo_city VARCHAR(100);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS asn VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS asn_org VARCHAR(255);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS protocol VARCHAR(20);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS bytes_in INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS bytes_out INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS packets INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS duration_ms INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS dns_query TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS dns_response TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS http_method VARCHAR(10);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS http_path TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS http_status INT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS email_subject TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS email_sender VARCHAR(255);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS email_recipients TEXT[];
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS attachment_names TEXT[];
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS log_source_type VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS resource TEXT;
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS aws_region VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS aws_account VARCHAR(50);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS azure_tenant VARCHAR(100);
ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS gcp_project VARCHAR(100);

-- Create indexes on new log_entries fields for performance
CREATE INDEX IF NOT EXISTS idx_log_entries_process_name ON log_entries(process_name);
CREATE INDEX IF NOT EXISTS idx_log_entries_command_line ON log_entries USING gin(to_tsvector('english', command_line)) WHERE command_line IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_log_entries_file_hash ON log_entries(file_hash_sha256) WHERE file_hash_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_log_entries_event_id ON log_entries(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_log_entries_source_type ON log_entries(log_source_type) WHERE log_source_type IS NOT NULL;

