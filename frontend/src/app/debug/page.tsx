'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Loader2, Search, Activity, AlertCircle, Gauge, CheckCircle } from 'lucide-react';
import Link from 'next/link';

export default function DebugPage() {
  const [incidentId, setIncidentId] = useState('');
  const [fetchId, setFetchId] = useState('');
  const [validationId, setValidationId] = useState('');
  const [validationFetchId, setValidationFetchId] = useState('');

  const { data: lastAnalysis, isLoading: loadingAnalysis, isFetching: fetchingAnalysis } = useQuery({
    queryKey: ['debug', 'last-analysis', fetchId],
    queryFn: () => api.debug.getLastAnalysis(fetchId),
    enabled: !!fetchId,
  });

  const { data: traces, isLoading: loadingTraces } = useQuery({
    queryKey: ['debug', 'agent-traces'],
    queryFn: () => api.debug.getAgentTraces(20),
  });

  const { data: validationMetrics, isLoading: loadingValidation } = useQuery({
    queryKey: ['validation', 'metrics', validationFetchId],
    queryFn: () => api.validation.incidentMetrics(validationFetchId),
    enabled: !!validationFetchId,
  });

  const { data: validationAggregate } = useQuery({
    queryKey: ['validation', 'aggregate'],
    queryFn: () => api.validation.aggregate(),
  });

  const { data: perfMetrics } = useQuery({
    queryKey: ['performance', 'metrics'],
    queryFn: () => api.performance.metrics(),
  });

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-5xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Debug & Traces</h1>
          <p className="text-gray-400">Inspect last analysis and agent execution traces</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Search className="h-5 w-5" />
                <span>Last analysis by incident</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  value={incidentId}
                  onChange={(e) => setIncidentId(e.target.value)}
                  placeholder="Incident UUID"
                  className="bg-gray-800 border-gray-700 text-white"
                />
                <Button
                  onClick={() => setFetchId(incidentId.trim())}
                  disabled={!incidentId.trim() || fetchingAnalysis}
                >
                  {fetchingAnalysis ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                </Button>
              </div>
              <p className="text-xs text-gray-500">
                Paste an incident ID from <Link href="/incidents" className="text-blue-400 hover:underline">Incidents</Link> to load its workflow trace.
              </p>
              {fetchId && (loadingAnalysis ? (
                <div className="flex items-center gap-2 text-gray-400">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading...
                </div>
              ) : lastAnalysis ? (
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400">Status:</span>
                    <span className={lastAnalysis.overall_status === 'completed' ? 'text-green-400' : 'text-red-400'}>
                      {lastAnalysis.overall_status}
                    </span>
                  </div>
                  {lastAnalysis.agent_failures?.length > 0 && (
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertCircle className="h-4 w-4" />
                      Failures: {lastAnalysis.agent_failures.join(', ')}
                    </div>
                  )}
                  <div className="p-3 bg-gray-800 rounded-lg overflow-auto max-h-64">
                    <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                      {JSON.stringify(lastAnalysis, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <p className="text-gray-500">No data or incident not found.</p>
              ))}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Activity className="h-5 w-5" />
                <span>Recent agent traces</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {loadingTraces ? (
                <div className="flex items-center gap-2 text-gray-400">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading...
                </div>
              ) : traces?.traces?.length > 0 ? (
                <ul className="space-y-2 max-h-80 overflow-y-auto">
                  {traces.traces.map((t: any, i: number) => (
                    <li key={i} className="p-2 bg-gray-800 rounded text-sm flex justify-between items-center">
                      <span className="text-white font-mono">{t.agent_name}</span>
                      <span className="text-gray-400 text-xs">{t.duration_ms != null ? `${t.duration_ms}ms` : ''}</span>
                      <Link href={`/incident/${t.incident_id}`} className="text-blue-400 hover:underline text-xs truncate max-w-[120px]">
                        {t.incident_id?.slice(0, 8)}...
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-gray-500">No traces yet. Run a demo or analyze logs to generate traces.</p>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <CheckCircle className="h-5 w-5" />
                <span>Validation</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  value={validationId}
                  onChange={(e) => setValidationId(e.target.value)}
                  placeholder="Incident ID for metrics"
                  className="bg-gray-800 border-gray-700 text-white"
                />
                <Button onClick={() => setValidationFetchId(validationId.trim())} disabled={!validationId.trim() || loadingValidation}>
                  {loadingValidation ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Load'}
                </Button>
              </div>
              {validationMetrics && (
                <div className="p-3 bg-gray-800 rounded text-xs overflow-auto max-h-48">
                  <pre className="text-gray-300 whitespace-pre-wrap">{JSON.stringify(validationMetrics, null, 2)}</pre>
                </div>
              )}
              {validationAggregate && (
                <div className="pt-2 border-t border-gray-700">
                  <p className="text-gray-400 text-sm mb-1">Aggregate</p>
                  <pre className="text-xs text-gray-300 overflow-auto max-h-32">{JSON.stringify(validationAggregate, null, 2)}</pre>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Gauge className="h-5 w-5" />
                <span>Performance</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {perfMetrics ? (
                <div className="p-3 bg-gray-800 rounded text-sm space-y-1">
                  <p className="text-gray-400">Redis: {perfMetrics.redis?.connected ? 'connected' : 'disconnected'}</p>
                  {perfMetrics.redis?.memory_used_mb != null && (
                    <p className="text-gray-400">Memory: {perfMetrics.redis.memory_used_mb.toFixed(1)} MB</p>
                  )}
                  <pre className="text-xs text-gray-300 mt-2 overflow-auto max-h-40">{JSON.stringify(perfMetrics, null, 2)}</pre>
                </div>
              ) : (
                <p className="text-gray-500">Load performance metrics from API.</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
