export interface StreamEvent {
  type: string;
  agent?: string;
  data?: any;
  message?: string;
  incident_id?: string;
  timestamp?: string;
  current_agent?: string;
  progress_percent?: number;
  status?: string;
  elapsed_seconds?: number;
  estimated_total_seconds?: number;
}

export interface AgentStreamState {
  current_agent: string;
  progress: number;
  status: 'analyzing' | 'completed' | 'failed';
  events: StreamEvent[];
  start_time?: number;
}

