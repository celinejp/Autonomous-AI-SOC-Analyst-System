'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useSOCMetrics } from '@/hooks/useSOCMetrics';
import { useAttackCoverage } from '@/hooks/useAttackCoverage';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Badge } from '@/components/ui/badge';
import { SOCMetricsDashboard } from '@/components/SOCMetricsDashboard';
import { Clock, TrendingDown, AlertCircle, Target, Zap, Activity } from 'lucide-react';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

export default function InsightsPage() {
  const [timeRange, setTimeRange] = useState<24 | 168>(24); // 24h or 7d (168h)
  
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.dashboard.stats(),
  });

  const { data: socMetrics24h, isLoading: metrics24hLoading } = useSOCMetrics(24);
  const { data: socMetrics7d, isLoading: metrics7dLoading } = useSOCMetrics(168);
  const { data: coverage, isLoading: coverageLoading } = useAttackCoverage();

  const currentMetrics = timeRange === 24 ? socMetrics24h : socMetrics7d;
  const isLoading = timeRange === 24 ? metrics24hLoading : metrics7dLoading;

  const severityData = stats?.severity_counts ? [
    { name: 'Critical', value: stats.severity_counts.critical || 0 },
    { name: 'High', value: stats.severity_counts.high || 0 },
    { name: 'Medium', value: stats.severity_counts.medium || 0 },
    { name: 'Low', value: stats.severity_counts.low || 0 },
  ].filter(d => d.value > 0) : [];

  // Prepare ATT&CK coverage data
  const coverageData = coverage?.coverage
    ? Object.entries(coverage.coverage)
        .filter(([_, covered]) => covered)
        .map(([technique, _]) => ({
          technique_id: technique,
          covered: true,
        }))
        .slice(0, 20)
    : [];

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Insights & Analytics</h1>
            <p className="text-gray-400">SOC metrics and threat intelligence insights</p>
          </div>
          <div className="flex space-x-2">
            <Button
              variant={timeRange === 24 ? 'default' : 'outline'}
              size="sm"
              onClick={() => setTimeRange(24)}
            >
              24 Hours
            </Button>
            <Button
              variant={timeRange === 168 ? 'default' : 'outline'}
              size="sm"
              onClick={() => setTimeRange(168)}
            >
              7 Days
            </Button>
          </div>
        </div>

        {/* SOC KPI Metrics */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-white mb-4">SOC KPI Metrics ({timeRange === 24 ? '24 Hours' : '7 Days'})</h2>
          <SOCMetricsDashboard hours={timeRange} />
        </div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-gray-400 text-center py-12">No data available</p>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Top MITRE Techniques</CardTitle>
            </CardHeader>
            <CardContent>
              {(stats?.top_mitre_techniques || stats?.top_techniques) && (stats.top_mitre_techniques || stats.top_techniques)!.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={(stats.top_mitre_techniques || stats.top_techniques || []).slice(0, 10)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis 
                      dataKey="technique_id" 
                      stroke="#9ca3af"
                      angle={-45}
                      textAnchor="end"
                      height={80}
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                    />
                    <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff', borderRadius: '6px' }} 
                    />
                    <Bar dataKey="count" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-gray-400 text-center py-12">No techniques detected yet</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ATT&CK Coverage */}
        {coverage && (
          <Card className="bg-gray-900 border-gray-800 mb-8">
            <CardHeader>
              <CardTitle className="text-white">MITRE ATT&CK Coverage</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <div>
                  <p className="text-gray-400 text-sm">Total Techniques</p>
                  <p className="text-2xl font-bold text-white">{coverage.summary?.total_techniques || 0}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Covered</p>
                  <p className="text-2xl font-bold text-green-400">{coverage.summary?.covered_techniques || 0}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Coverage</p>
                  <p className="text-2xl font-bold text-blue-400">
                    {coverage.summary?.coverage_percentage?.toFixed(1) || 0}%
                  </p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Gap</p>
                  <p className="text-2xl font-bold text-yellow-400">
                    {coverage.summary?.total_techniques && coverage.summary?.covered_techniques
                      ? (coverage.summary.total_techniques - coverage.summary.covered_techniques)
                      : 0}
                  </p>
                </div>
              </div>
              {coverageData.length > 0 && (
                <div className="mt-4">
                  <p className="text-sm text-gray-400 mb-2">Recently Detected Techniques:</p>
                  <div className="flex flex-wrap gap-2">
                    {coverageData.slice(0, 15).map((item, idx) => (
                      <Badge key={idx} variant="outline" className="font-mono text-xs">
                        {item.technique_id}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* System Metrics Summary */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">System Metrics Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-gray-400 text-sm">Total Incidents</p>
                <p className="text-2xl font-bold text-white">{stats?.total_incidents || stats?.recent_24h || 0}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Resolved</p>
                <p className="text-2xl font-bold text-green-400">{stats?.status_counts?.resolved || stats?.status_counts?.RESOLVED || 0}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Active</p>
                <p className="text-2xl font-bold text-orange-400">
                  {stats?.status_counts 
                    ? Object.entries(stats.status_counts)
                        .filter(([k]) => k !== 'resolved' && k !== 'RESOLVED' && k !== 'false_positive' && k !== 'FALSE_POSITIVE')
                        .reduce((sum: number, [, v]) => sum + (typeof v === 'number' ? v : 0), 0)
                    : 0}
                </p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Avg Confidence</p>
                <p className="text-2xl font-bold text-blue-400">
                  {stats?.avg_confidence ? (stats.avg_confidence * 100).toFixed(1) : '0'}%
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
