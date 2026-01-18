import { useEffect, useState } from 'react';
import { StreamEvent } from '@/types/stream';

/**
 * Hook for streaming agent execution events.
 * Note: The backend currently only supports POST /incidents/stream to start a new stream.
 * For existing incidents, we use polling instead of SSE.
 */
export function useAgentStream(incidentId: string) {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

  useEffect(() => {
    if (!incidentId) return;

    // Since backend doesn't have GET endpoint for existing incident streams,
    // we use polling to check incident status
    // This could be enhanced to use SSE if endpoint is added
    const interval = setInterval(async () => {
      try {
        const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';
        const response = await fetch(`${API_URL}/incidents/${incidentId}/status`);
        if (response.ok) {
          const status = await response.json();
          if (status.status === 'analyzing') {
            setIsStreaming(true);
            // Simulate events based on status
            setEvents((prev) => {
              const lastEvent = prev[prev.length - 1];
              if (!lastEvent || lastEvent.type !== 'progress_update') {
                return [...prev, {
                  type: 'progress_update',
                  incident_id: incidentId,
                  timestamp: new Date().toISOString(),
                  current_agent: status.current_agent || 'unknown',
                  progress_percent: parseInt(status.progress_percent || '0'),
                  status: 'analyzing',
                  elapsed_seconds: Math.floor((Date.now() - new Date(status.started_at || Date.now()).getTime()) / 1000),
                  estimated_total_seconds: parseInt(status.estimated_duration || '45'),
                } as StreamEvent];
              }
              return prev;
            });
          } else if (status.status === 'completed') {
            setIsStreaming(false);
          }
        }
      } catch (error) {
        console.error('Failed to poll incident status:', error);
      }
    }, 2000); // Poll every 2 seconds

    return () => {
      clearInterval(interval);
      setIsStreaming(false);
    };
  }, [incidentId]);

  return { events, isStreaming };
}

