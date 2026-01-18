'use client';

import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { formatDate, getSeverityColor } from '@/lib/utils';

export default function IncidentDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const { data: incident, isLoading, error } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => api.incidents.get(id),
    refetchInterval: 5000,
    retry: 2,
  });

  // Show structure immediately while loading
  if (!incident && !isLoading) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-3xl font-bold text-white mb-8">Incident not found</h1>
          <Link href="/incidents">
            <span className="text-blue-400 hover:text-blue-300">← Back to incidents</span>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <Link href="/incidents">
              <span className="text-blue-400 hover:text-blue-300 text-sm mb-2 block">← Back to incidents</span>
            </Link>
            <h1 className="text-3xl font-bold text-white mb-2">Incident Details</h1>
            {isLoading ? (
              <div className="h-4 w-48 bg-gray-800 rounded animate-pulse mt-2"></div>
            ) : (
              <p className="text-gray-400 font-mono text-sm">{incident?.id || 'Loading...'}</p>
            )}
          </div>
          <div className="flex items-center space-x-4">
            {isLoading ? (
              <>
                <div className="h-6 w-20 bg-gray-800 rounded animate-pulse"></div>
                <div className="h-6 w-24 bg-gray-800 rounded animate-pulse"></div>
              </>
            ) : incident ? (
              <>
                <Badge className={getSeverityColor(incident.severity)}>
                  {incident.severity.toUpperCase()}
                </Badge>
                <Badge variant="outline">{incident.status}</Badge>
              </>
            ) : null}
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-400 text-sm">
              ⚠️ {error instanceof Error ? error.message : 'Failed to load incident'}
            </p>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg">Confidence Score</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-12 w-24 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-3xl font-bold text-blue-400">
                  {incident ? ((incident.confidence_score * 100).toFixed(1) + '%') : '0%'}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg">Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-12 w-16 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-3xl font-bold text-white">
                  {incident?.alerts?.length || 0}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg">Created</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-4 w-40 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-sm text-gray-400">
                  {incident ? formatDate(incident.created_at) : 'Loading...'}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {incident?.report && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Executive Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 whitespace-pre-wrap">{incident.report.executive_summary}</p>
            </CardContent>
          </Card>
        )}

        {incident?.report && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Technical Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 whitespace-pre-wrap">{incident.report.technical_findings}</p>
            </CardContent>
          </Card>
        )}

        {incident?.alerts && incident.alerts.length > 0 && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Security Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {incident.alerts.map((alert: any, idx: number) => (
                  <div key={idx} className="p-4 bg-gray-800 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-white">{alert.title}</h3>
                      <Badge className={getSeverityColor(alert.severity)}>
                        {alert.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-gray-300 text-sm mb-2">{alert.description}</p>
                    {alert.mitre_techniques && alert.mitre_techniques.length > 0 && (
                      <div className="mt-2">
                        <span className="text-gray-400 text-xs">MITRE: </span>
                        {alert.mitre_techniques.map((tech: string, i: number) => (
                          <Badge key={i} variant="outline" className="mr-1 text-xs">
                            {tech}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {incident?.response_plan && (
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Response Plan</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {incident.response_plan.immediate_actions && incident.response_plan.immediate_actions.length > 0 && (
                  <div>
                    <h3 className="font-semibold text-white mb-2">Immediate Actions</h3>
                    {incident.response_plan.immediate_actions.map((action: any, idx: number) => (
                      <div key={idx} className="p-3 bg-gray-800 rounded mb-2">
                        <p className="text-white text-sm">{action.description}</p>
                        <p className="text-gray-400 text-xs mt-1">Team: {action.assigned_team}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}


