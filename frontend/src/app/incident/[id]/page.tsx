'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useIncident } from '@/hooks/useIncident';
import { useUpdateIncidentStatus } from '@/hooks/useUpdateIncidentStatus';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { formatDate, getSeverityColor, showNotification } from '@/lib/utils';
import { Incident, IncidentStatus } from '@/types';
import { IOCsTable } from '@/components/IOCsTable';
import { ResponsePlanViewer } from '@/components/ResponsePlanViewer';
import { IncidentStreamViewer } from '@/components/IncidentStreamViewer';
import { TimelineChart } from '@/components/charts';
import { Download, Copy, CheckCircle2, XCircle, Clock, Loader2, Shield, List } from 'lucide-react';

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const id = params.id as string;
  const [blockIp, setBlockIp] = useState('');
  const [blockHours, setBlockHours] = useState(24);
  const [disableUser, setDisableUser] = useState('');
  const [disableReason, setDisableReason] = useState('');
  const [responseLog, setResponseLog] = useState<any>(null);
  const [responseLoading, setResponseLoading] = useState(false);

  const { data: incident, isLoading, error, isError } = useIncident(id);
  const updateStatusMutation = useUpdateIncidentStatus();

  const handleBlockIp = async () => {
    if (!blockIp.trim()) return;
    setResponseLoading(true);
    try {
      await api.response.blockIp(blockIp.trim(), blockHours);
      showNotification(`Block IP request sent: ${blockIp}`, 'success');
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Block IP failed', 'error');
    } finally {
      setResponseLoading(false);
    }
  };

  const handleDisableAccount = async () => {
    if (!disableUser.trim()) return;
    setResponseLoading(true);
    try {
      await api.response.disableAccount(disableUser.trim(), disableReason || 'Incident response');
      showNotification(`Disable account request sent: ${disableUser}`, 'success');
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Disable account failed', 'error');
    } finally {
      setResponseLoading(false);
    }
  };

  const handleLoadExecutionLog = async () => {
    setResponseLoading(true);
    setResponseLog(null);
    try {
      const res = await api.response.executionLog();
      setResponseLog(res?.log ?? res);
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Load log failed', 'error');
    } finally {
      setResponseLoading(false);
    }
  };

  const isAnalyzing = incident?.status === IncidentStatus.IN_PROGRESS || incident?.status === 'analyzing';
  
  // Show "Creating incident..." when we get 404 (incident not in DB yet) or while retrying
  const isNotFound = isError && (
    (error as Error)?.message?.includes('404') ||
    (error as Error)?.message?.toLowerCase().includes('not found')
  );

  const handleStatusUpdate = async (status: IncidentStatus) => {
    try {
      await updateStatusMutation.mutateAsync({ id, status });
    } catch {
      showNotification('Failed to update status', 'error');
    }
  };

  const handleDownloadJSON = () => {
    if (!incident) return;
    const blob = new Blob([JSON.stringify(incident, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-${id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopySummary = async () => {
    if (!incident?.report) return;
    const summary = incident.report.executive_summary;
    await navigator.clipboard.writeText(summary);
    alert('Summary copied to clipboard!');
  };

  // Show "Creating incident..." when 404 (not in DB yet) so user knows we're waiting
  if (isNotFound) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center py-20">
            <Loader2 className="h-12 w-12 animate-spin text-blue-400 mx-auto mb-4" />
            <h1 className="text-2xl font-bold text-white mb-2">
              {isLoading ? 'Loading incident...' : 'Creating incident...'}
            </h1>
            <p className="text-gray-400">Incident ID: {id.substring(0, 8)}...</p>
            <p className="text-gray-500 text-sm mt-2">
              Analysis may still be running. This page will update when the incident is ready.
            </p>
            <p className="text-gray-500 text-xs mt-4">Retrying automatically...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!incident && !isLoading && !isNotFound) {
    return (
      <div className="min-h-screen bg-gray-950 p-8">
        <div className="max-w-7xl mx-auto">
          <h1 className="text-3xl font-bold text-white mb-8">Incident not found</h1>
          <p className="text-gray-400 mb-4">Incident ID: {id}</p>
          <Link href="/incidents">
            <span className="text-blue-400 hover:text-blue-300">← Back to incidents</span>
          </Link>
        </div>
      </div>
    );
  }

  // Extract timeline data from report
  const timelineData = incident?.report?.timeline
    ? incident.report.timeline.map((entry: any, idx: number) => ({
        time: entry.timestamp || entry.time || `${idx}`,
        incidents: 1,
        alerts: entry.alerts || 0,
      }))
    : [];

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between flex-wrap gap-4">
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
          <div className="flex items-center space-x-4 flex-wrap">
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
                {isAnalyzing && (
                  <Badge variant="secondary" className="animate-pulse">
                    <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                    Analyzing...
                  </Badge>
                )}
              </>
            ) : null}
          </div>
        </div>

        {/* Action Buttons */}
        {incident && (
          <div className="mb-6 flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleStatusUpdate(IncidentStatus.INVESTIGATING)}
              disabled={updateStatusMutation.isPending}
            >
              <CheckCircle2 className="h-4 w-4 mr-2" />
              Mark as Contained
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleStatusUpdate(IncidentStatus.RESOLVED)}
              disabled={updateStatusMutation.isPending}
            >
              <XCircle className="h-4 w-4 mr-2" />
              Mark as Closed
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadJSON}
            >
              <Download className="h-4 w-4 mr-2" />
              Download JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCopySummary}
              disabled={!incident?.report}
            >
              <Copy className="h-4 w-4 mr-2" />
              Copy Summary
            </Button>
          </div>
        )}

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-400 text-sm">
              ⚠️ {error instanceof Error ? error.message : 'Failed to load incident'}
            </p>
          </div>
        )}

        {/* Response actions (block IP, disable account, execution log) */}
        {incident && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Response actions</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-400 mb-2">Block IP</p>
                  <div className="flex gap-2 flex-wrap">
                    <Input
                      value={blockIp}
                      onChange={(e) => setBlockIp(e.target.value)}
                      placeholder="IP address"
                      className="bg-gray-900 border-gray-700 text-white flex-1 min-w-[120px]"
                    />
                    <Input
                      type="number"
                      value={blockHours}
                      onChange={(e) => setBlockHours(parseInt(e.target.value, 10) || 24)}
                      className="bg-gray-900 border-gray-700 text-white w-20"
                    />
                    <span className="text-gray-500 text-sm self-center">hours</span>
                    <Button size="sm" onClick={handleBlockIp} disabled={responseLoading || !blockIp.trim()}>
                      {responseLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Block'}
                    </Button>
                  </div>
                </div>
                <div className="p-3 bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-400 mb-2">Disable account</p>
                  <div className="flex gap-2 flex-wrap">
                    <Input
                      value={disableUser}
                      onChange={(e) => setDisableUser(e.target.value)}
                      placeholder="Username"
                      className="bg-gray-900 border-gray-700 text-white flex-1 min-w-[100px]"
                    />
                    <Input
                      value={disableReason}
                      onChange={(e) => setDisableReason(e.target.value)}
                      placeholder="Reason"
                      className="bg-gray-900 border-gray-700 text-white flex-1 min-w-[100px]"
                    />
                    <Button size="sm" onClick={handleDisableAccount} disabled={responseLoading || !disableUser.trim()}>
                      {responseLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Disable'}
                    </Button>
                  </div>
                </div>
              </div>
              <div>
                <Button variant="outline" size="sm" onClick={handleLoadExecutionLog} disabled={responseLoading} className="flex items-center gap-2">
                  <List className="h-4 w-4" />
                  {responseLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Load execution log'}
                </Button>
                {responseLog != null && (
                  <pre className="mt-2 p-3 bg-gray-800 rounded text-xs text-gray-300 overflow-auto max-h-32">
                    {Array.isArray(responseLog) ? responseLog.join('\n') : JSON.stringify(responseLog, null, 2)}
                  </pre>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Real-time Analysis Stream */}
        {isAnalyzing && incident && (
          <div className="mb-6">
            <IncidentStreamViewer incidentId={incident.id} />
          </div>
        )}

        {/* Summary Cards */}
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

        {/* Executive Summary */}
        {incident?.report?.executive_summary && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Executive Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 whitespace-pre-wrap leading-relaxed">
                {incident.report.executive_summary}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Attack Timeline */}
        {timelineData.length > 0 && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Attack Timeline</CardTitle>
            </CardHeader>
            <CardContent>
              <TimelineChart data={timelineData} />
            </CardContent>
          </Card>
        )}

        {/* MITRE ATT&CK Techniques */}
        {incident?.mitre_techniques && incident.mitre_techniques.length > 0 && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">MITRE ATT&CK Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {incident.mitre_techniques.map((tech, idx) => (
                  <div key={idx} className="p-4 bg-gray-800 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <Badge variant="outline" className="font-mono">
                        {tech.technique_id}
                      </Badge>
                      <Badge variant="secondary" className="text-xs">
                        {tech.tactic}
                      </Badge>
                    </div>
                    <h4 className="font-semibold text-white mb-1">{tech.name}</h4>
                    <p className="text-sm text-gray-400">{tech.description}</p>
                    {tech.detection_methods && tech.detection_methods.length > 0 && (
                      <div className="mt-2">
                        <p className="text-xs text-gray-500 mb-1">Detection Methods:</p>
                        <ul className="list-disc list-inside text-xs text-gray-400 space-y-1">
                          {tech.detection_methods.slice(0, 3).map((method, i) => (
                            <li key={i}>{method}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Indicators of Compromise */}
        {incident?.report?.indicators_of_compromise && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Indicators of Compromise (IOCs)</CardTitle>
            </CardHeader>
            <CardContent>
              <IOCsTable iocs={incident.report.indicators_of_compromise} />
            </CardContent>
          </Card>
        )}

        {/* Technical Findings */}
        {incident?.report?.technical_findings && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Technical Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300 whitespace-pre-wrap leading-relaxed">
                {incident.report.technical_findings}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Security Alerts */}
        {incident?.alerts && incident.alerts.length > 0 && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Security Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {incident.alerts.map((alert, idx) => (
                  <div key={idx} className="p-4 bg-gray-800 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-white">{alert.title}</h3>
                      <Badge className={getSeverityColor(alert.severity)}>
                        {alert.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-gray-300 text-sm mb-2">{alert.description}</p>
                    {alert.mitre_techniques && alert.mitre_techniques.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        <span className="text-gray-400 text-xs">MITRE: </span>
                        {alert.mitre_techniques.map((tech, i) => (
                          <Badge key={i} variant="outline" className="text-xs">
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

        {/* Response Plan */}
        {incident?.response_plan && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Response Plan</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsePlanViewer
                plan={incident.response_plan}
                onActionUpdate={async (actionId, status) => {
                  try {
                    await api.incidents.updateActionStatus(id, actionId, status);
                    queryClient.invalidateQueries({ queryKey: ['incident', id] });
                  } catch {
                    showNotification('Failed to update action status', 'error');
                  }
                }}
              />
            </CardContent>
          </Card>
        )}

        {/* Regulatory Impact & Lessons Learned */}
        {(incident?.report?.regulatory_impact || incident?.report?.lessons_learned) && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {incident.report.regulatory_impact && (
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Regulatory Impact</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-gray-300 text-sm whitespace-pre-wrap">
                    {typeof incident.report.regulatory_impact === 'string'
                      ? incident.report.regulatory_impact
                      : JSON.stringify(incident.report.regulatory_impact, null, 2)}
                  </div>
                </CardContent>
              </Card>
            )}

            {incident.report.lessons_learned && incident.report.lessons_learned.length > 0 && (
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Lessons Learned</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="list-disc list-inside space-y-2 text-gray-300 text-sm">
                    {incident.report.lessons_learned.map((lesson, idx) => (
                      <li key={idx}>{lesson}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Detection Gaps */}
        {incident?.report?.detection_gaps && incident.report.detection_gaps.length > 0 && (
          <Card className="bg-gray-900 border-gray-800 mt-6">
            <CardHeader>
              <CardTitle className="text-white">Detection Gaps</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="list-disc list-inside space-y-2 text-gray-300 text-sm">
                {incident.report.detection_gaps.map((gap, idx) => (
                  <li key={idx}>
                    {typeof gap === 'string' ? gap : JSON.stringify(gap)}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
