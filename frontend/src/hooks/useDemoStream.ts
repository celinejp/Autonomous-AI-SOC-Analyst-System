import { useState, useCallback } from 'react';
import { demoScenarios } from '@/lib/api';
import { StreamEvent } from '@/types/stream';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

type DemoScenarioKey = keyof typeof demoScenarios;

export type DemoStreamStatus = 'idle' | 'streaming' | 'done' | 'error';

export function useDemoStream() {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [status, setStatus] = useState<DemoStreamStatus>('idle');
  const [error, setError] = useState<string | null>(null);

  const runDemo = useCallback(async (scenario: DemoScenarioKey) => {
    const logs = demoScenarios[scenario];
    if (!logs || logs.length === 0) {
      setError('No logs for scenario');
      setStatus('error');
      return null;
    }

    setEvents([]);
    setIncidentId(null);
    setError(null);
    setStatus('streaming');

    try {
      const response = await fetch(`${API_URL}/v1/incidents/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_logs: logs }),
      });

      if (!response.ok) {
        const errBody = await response.text();
        throw new Error(errBody || `HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) {
        throw new Error('No response body');
      }

      let buffer = '';
      let resolvedId: string | null = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const json = line.slice(6);
              if (json === '[DONE]' || json === '') continue;
              const payload = JSON.parse(json) as { event?: string; incident_id?: string; [k: string]: unknown };
              const eventType = payload.event || (payload.type as string | undefined);
              const ev: StreamEvent = {
                type: eventType || 'message',
                incident_id: payload.incident_id as string | undefined,
                timestamp: payload.timestamp as string | undefined,
                agent: payload.agent as string | undefined,
                data: payload.data ?? payload,
              };
              if (payload.incident_id) {
                resolvedId = payload.incident_id as string;
                setIncidentId(resolvedId);
              }
              setEvents((prev) => [...prev, ev]);

              if (eventType === 'workflow_complete' || eventType === 'saved' || eventType === 'end') {
                setStatus('done');
                if (payload.incident_id) setIncidentId(payload.incident_id as string);
              } else if (eventType === 'error') {
                setStatus('error');
                const dataObj = payload.data as { message?: string } | undefined;
                setError((payload.message as string | undefined) || dataObj?.message || 'Stream error');
              }
            } catch (e) {
              // ignore parse errors for non-JSON lines
            }
          }
        }
      }

      if (resolvedId) {
        setIncidentId(resolvedId);
        setStatus('done');
      }
      return resolvedId;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Demo stream failed';
      setError(message);
      setStatus('error');
      return null;
    }
  }, []);

  return { runDemo, events, incidentId, status, error, reset: () => { setEvents([]); setIncidentId(null); setError(null); setStatus('idle'); } };
}
