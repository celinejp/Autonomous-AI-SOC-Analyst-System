/** TypeScript type definitions for the SOC Analyst System */

export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "new" | "in_progress" | "investigating" | "resolved" | "false_positive";

export interface LogEntry {
  id?: string;
  timestamp: string;
  source_ip: string;
  destination_ip?: string;
  destination_port?: number;
  user?: string;
  action: string;
  status: string;
  log_source: "dns" | "auth" | "http" | "system";
  raw_log: string;
  metadata?: Record<string, any>;
}

export interface Alert {
  id?: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
  detection_rule: string;
  evidence: Array<Record<string, any>>;
  related_logs: string[];
  mitre_techniques: string[];
}

export interface MITRETechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string;
  detection_methods: string[];
}

export interface IncidentReport {
  executive_summary: string;
  technical_findings: string;
  timeline: Array<{
    timestamp: string;
    event: string;
    severity?: string;
  }>;
  affected_assets: string[];
  root_cause: string;
  impact_assessment: string;
  confidence_score: number;
  reasoning_process: string[];
}

export interface ResponseAction {
  priority: "immediate" | "high" | "medium" | "low";
  action: string;
  description: string;
  status: string;
}

export interface ResponsePlan {
  containment_actions: ResponseAction[];
  investigation_steps: ResponseAction[];
  remediation_actions: ResponseAction[];
  long_term_improvements: ResponseAction[];
}

export interface Incident {
  id?: string;
  created_at: string;
  updated_at: string;
  status: IncidentStatus;
  severity: Severity;
  alerts: Alert[];
  threat_intel: Record<string, any>;
  mitre_techniques: MITRETechnique[];
  report?: IncidentReport;
  response_plan?: ResponsePlan;
  agent_execution_log: Array<{
    agent_name: string;
    timestamp: string;
    input_data?: Record<string, any>;
    output_data?: Record<string, any>;
    tools_used?: string[];
    reasoning?: string;
    duration_ms?: number;
  }>;
  confidence_score: number;
  false_positive_reason?: string;
}

export interface AgentExecutionEvent {
  type: "state_update" | "complete" | "error" | "end";
  data?: any;
  timestamp: string;
  incident_id?: string;
  error?: string;
}

