'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { useAgentStream } from '@/hooks/useAgentStream';
import { StreamEvent } from '@/types/stream';

interface IncidentStreamViewerProps {
  incidentId: string;
}

const AGENT_INFO: Record<string, { name: string; order: number }> = {
  ingest: { name: 'Ingest Agent', order: 1 },
  detect: { name: 'Detection Agent', order: 2 },
  enrich: { name: 'Threat Intel Agent', order: 3 },
  analyze: { name: 'Analyst Agent', order: 4 },
  critique: { name: 'Critic Agent', order: 5 },
  plan_response: { name: 'Response Planner', order: 6 },
};

export function IncidentStreamViewer({ incidentId }: IncidentStreamViewerProps) {
  const { events, isStreaming } = useAgentStream(incidentId);
  const [agentStatuses, setAgentStatuses] = useState<Record<string, 'pending' | 'running' | 'complete'>>({});
  const [startTime] = useState(Date.now());
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    return () => clearInterval(interval);
  }, [isStreaming, startTime]);

  useEffect(() => {
    events.forEach((event: StreamEvent) => {
      if (event.type === 'agent_start' && event.agent) {
        setAgentStatuses((prev) => ({ ...prev, [event.agent!]: 'running' }));
      } else if (event.type === 'agent_complete' && event.agent) {
        setAgentStatuses((prev) => ({ ...prev, [event.agent!]: 'complete' }));
      }
    });
  }, [events]);

  const totalAgents = Object.keys(AGENT_INFO).length;
  const completedAgents = Object.values(agentStatuses).filter((s) => s === 'complete').length;
  const progress = totalAgents > 0 ? (completedAgents / totalAgents) * 100 : 0;

  const agents = Object.entries(AGENT_INFO)
    .sort(([, a], [, b]) => a.order - b.order)
    .map(([id, info]) => ({
      id,
      ...info,
      status: agentStatuses[id] || 'pending',
    }));

  return (
    <Card className="bg-gray-900 border-gray-800">
      <CardHeader>
        <CardTitle className="text-white flex items-center justify-between">
          <span>Agent Execution Progress</span>
          {isStreaming && (
            <Badge variant="secondary" className="animate-pulse">Streaming</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <div className="flex justify-between text-sm text-gray-400">
            <span>Progress</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <Progress value={progress} />
        </div>

        <div className="text-sm text-gray-400">
          Elapsed: {Math.floor(elapsedSeconds / 60)}:{(elapsedSeconds % 60).toString().padStart(2, '0')}
        </div>

        <div className="space-y-2">
          {agents.map((agent) => (
            <div
              key={agent.id}
              className={`p-3 rounded-lg border ${
                agent.status === 'complete'
                  ? 'bg-green-900/20 border-green-500/50'
                  : agent.status === 'running'
                  ? 'bg-blue-900/20 border-blue-500/50'
                  : 'bg-gray-800 border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-white font-medium">{agent.name}</span>
                <Badge
                  variant={
                    agent.status === 'complete'
                      ? 'default'
                      : agent.status === 'running'
                      ? 'secondary'
                      : 'outline'
                  }
                >
                  {agent.status === 'complete'
                    ? 'Complete'
                    : agent.status === 'running'
                    ? 'Running'
                    : 'Pending'}
                </Badge>
              </div>
            </div>
          ))}
        </div>

        {events.length > 0 && (
          <div className="mt-4 p-3 bg-gray-800 rounded-lg max-h-48 overflow-y-auto">
            <div className="text-xs text-gray-400 mb-2">Recent Events:</div>
            <div className="space-y-1 font-mono text-xs">
              {events.slice(-5).map((event: StreamEvent, idx: number) => (
                <div key={idx} className="text-gray-300">
                  {event.type}: {event.agent || ''}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

