'use client';

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useSOCMetrics } from '@/hooks/useSOCMetrics';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import { AlertTriangle, Activity, Shield, BarChart3, Upload, Play, Heart } from 'lucide-react';
import { SOCMetricsDashboard } from '@/components/SOCMetricsDashboard';
import { SeverityChart } from '@/components/charts';

export default function DashboardPage() {
  const [currentTime, setCurrentTime] = useState<string>('');
  
  useEffect(() => {
    // Only set time on client side to avoid hydration mismatch
    setCurrentTime(new Date().toLocaleTimeString());
    const interval = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.dashboard.stats(),
    refetchInterval: 30000,
    retry: 1,
    placeholderData: {
      total_incidents: 0,
      recent_24h: 0,
      severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
      status_counts: {},
      avg_confidence: 0,
      top_mitre_techniques: [],
    },
  });

  const { data: socMetrics } = useSOCMetrics(24);

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">SOC Analyst Dashboard</h1>
          <p className="text-gray-400">Multi-agent threat detection and analysis system</p>
        </div>

        {error && !stats && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-400 text-sm mb-2">
              ⚠️ {error instanceof Error ? error.message : 'Failed to connect to backend API'}
            </p>
            <p className="text-gray-400 text-xs">
              Make sure the backend is running at http://localhost:8000
            </p>
          </div>
        )}

        <div className="mb-8">
          <SOCMetricsDashboard hours={24} />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-400">Total Incidents</CardTitle>
              <AlertTriangle className="h-4 w-4 text-gray-400" />
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 w-16 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-2xl font-bold text-white">{stats?.total_incidents || stats?.recent_24h || 0}</div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-400">Active</CardTitle>
              <Activity className="h-4 w-4 text-orange-400" />
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 w-16 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-2xl font-bold text-orange-400">
                  {stats?.status_counts 
                    ? Object.values(stats.status_counts).reduce((sum: number, val: unknown) => sum + (typeof val === 'number' ? val : 0), 0)
                    : 0}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-400">Critical</CardTitle>
              <Shield className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 w-16 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-2xl font-bold text-red-400">{stats?.severity_counts?.critical || 0}</div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-gray-400">Avg Confidence</CardTitle>
              <BarChart3 className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 w-16 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <div className="text-2xl font-bold text-blue-400">
                  {stats?.avg_confidence ? (stats.avg_confidence * 100).toFixed(1) : '0'}%
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Link href="/ingest">
                <Button variant="outline" className="w-full justify-start">
                  <Upload className="h-4 w-4 mr-2" />
                  <div className="text-left">
                    <div className="font-semibold">Upload Logs</div>
                    <div className="text-xs text-gray-400">Analyze security logs</div>
                  </div>
                </Button>
              </Link>
              <Link href="/ingest?tab=demo">
                <Button variant="outline" className="w-full justify-start">
                  <Play className="h-4 w-4 mr-2" />
                  <div className="text-left">
                    <div className="font-semibold">Demo Mode</div>
                    <div className="text-xs text-gray-400">Test with sample scenarios</div>
                  </div>
                </Button>
              </Link>
              <Link href="/incidents">
                <Button variant="outline" className="w-full justify-start">
                  <Activity className="h-4 w-4 mr-2" />
                  <div className="text-left">
                    <div className="font-semibold">View Incidents</div>
                    <div className="text-xs text-gray-400">Browse all incidents</div>
                  </div>
                </Button>
              </Link>
              <Link href="/insights">
                <Button variant="outline" className="w-full justify-start">
                  <BarChart3 className="h-4 w-4 mr-2" />
                  <div className="text-left">
                    <div className="font-semibold">View Insights</div>
                    <div className="text-xs text-gray-400">Analytics and metrics</div>
                  </div>
                </Button>
              </Link>
              <Link href="/health">
                <Button variant="outline" className="w-full justify-start">
                  <Heart className="h-4 w-4 mr-2" />
                  <div className="text-left">
                    <div className="font-semibold">System Health</div>
                    <div className="text-xs text-gray-400">Service status</div>
                  </div>
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Top MITRE Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {isLoading ? (
                  [...Array(3)].map((_, i) => (
                    <div key={i} className="h-10 bg-gray-800 rounded animate-pulse"></div>
                  ))
                ) : stats?.top_mitre_techniques?.length > 0 ? (
                  stats.top_mitre_techniques.slice(0, 5).map((tech: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between p-2 bg-gray-800 rounded">
                      <span className="text-sm text-white font-mono">{tech.technique_id}</span>
                      <Badge variant="secondary">{tech.count}</Badge>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-400 text-sm">No techniques detected yet</p>
                )}
              </div>
            </CardContent>
          </Card>

          {stats?.severity_counts && (
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Severity Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <SeverityChart data={[
                  { name: 'Critical', value: stats.severity_counts.critical || 0 },
                  { name: 'High', value: stats.severity_counts.high || 0 },
                  { name: 'Medium', value: stats.severity_counts.medium || 0 },
                  { name: 'Low', value: stats.severity_counts.low || 0 },
                ].filter(d => d.value > 0)} />
              </CardContent>
            </Card>
          )}
        </div>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">System Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-sm text-gray-400">All systems operational</span>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Backend API: {isLoading ? (
                <span className="text-yellow-400">Connecting...</span>
              ) : error ? (
                <span className="text-red-400">Disconnected</span>
              ) : (
                <span className="text-green-400">Connected</span>
              )}
              {currentTime && ` | Last updated: ${currentTime}`}
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
