export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
}

export enum IncidentStatus {
  NEW = "new",
  IN_PROGRESS = "in_progress",
  INVESTIGATING = "investigating",
  RESOLVED = "resolved",
  FALSE_POSITIVE = "false_positive",
}

export interface Alert {
  id?: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
  detection_rule: string;
  evidence: Record<string, any>[];
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

export interface ResponseAction {
  id: string;
  priority: string;
  action_type: string;
  action: string;
  description: string;
  target: string;
  status: string;
  assigned_team: string;
  requires_approval: boolean;
  approval_level?: string;
  automated: boolean;
  automation_available: boolean;
  manual_steps?: string[];
  sla_hours?: number;
  depends_on: string[];
  success_criteria: string;
  verification_steps: string[];
}

export interface IncidentReport {
  executive_summary: string;
  technical_findings: string;
  timeline: Record<string, any>[];
  affected_assets: string[];
  root_cause: string;
  impact_assessment: string;
  confidence_score: number;
  reasoning_process: string[];
  impacted_assets?: any[];
  indicators_of_compromise?: any;
  data_completeness?: any;
  confidence_assessment?: any;
  regulatory_impact?: any;
  detection_gaps?: any[];
  proposed_detection_rules?: any[];
  lessons_learned?: string[];
}

export interface ResponsePlan {
  incident_id: string;
  generated_at: string;
  immediate_actions: ResponseAction[];
  short_term_actions: ResponseAction[];
  long_term_actions: ResponseAction[];
  actions_by_team: Record<string, ResponseAction[]>;
  stakeholder_notifications?: any[];
  ioc_blocklist_updates?: any;
  detection_rule_updates?: any[];
}

export interface Incident {
  id: string;
  created_at: string;
  updated_at?: string;
  status: IncidentStatus;
  severity: Severity;
  confidence_score: number;
  alerts: Alert[];
  mitre_techniques?: MITRETechnique[];
  report?: IncidentReport;
  response_plan?: ResponsePlan;
  logs?: any[];
}

export interface DashboardStats {
  total_incidents?: number;
  recent_24h?: number;
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  status_counts?: Record<string, number>;
  avg_confidence?: number;
  top_mitre_techniques?: Array<{ technique_id: string; count: number }>;
  top_techniques?: Array<{ technique_id: string; count: number }>;
}

export interface SOCMetrics {
  mttd_seconds: number;
  mttr_seconds: number;
  mttc_seconds: number;
  false_positive_rate: number;
  true_positive_rate: number;
  escalation_accuracy: number;
  alerts_received: number;
  alerts_closed: number;
  alerts_escalated: number;
  incidents_created: number;
  ai_triage_rate: number;
  ai_accuracy: number;
  alert_reduction_ratio: number;
  attack_technique_coverage: Record<string, boolean>;
  period_start: string;
  period_end: string;
}

