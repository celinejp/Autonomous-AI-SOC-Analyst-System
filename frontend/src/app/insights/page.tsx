'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

export default function InsightsPage() {
  const { data: stats } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.dashboard.stats(),
  });

  const severityData = stats?.severity_counts ? [
    { name: 'Critical', value: stats.severity_counts.critical || 0 },
    { name: 'High', value: stats.severity_counts.high || 0 },
    { name: 'Medium', value: stats.severity_counts.medium || 0 },
    { name: 'Low', value: stats.severity_counts.low || 0 },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Insights & Analytics</h1>
          <p className="text-gray-400">System metrics and threat intelligence insights</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
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
                    <XAxis dataKey="technique_id" stroke="#9ca3af" />
                    <YAxis stroke="#9ca3af" />
                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', color: '#fff' }} />
                    <Bar dataKey="count" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-gray-400 text-center py-12">No techniques detected yet</p>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="bg-gray-900 border-gray-800 mt-6">
          <CardHeader>
            <CardTitle className="text-white">System Metrics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-gray-400 text-sm">Total Incidents</p>
                <p className="text-2xl font-bold text-white">{stats?.total_incidents || stats?.recent_24h || 0}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Resolved</p>
                <p className="text-2xl font-bold text-green-400">{stats?.status_counts?.RESOLVED || 0}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">Active</p>
                <p className="text-2xl font-bold text-orange-400">
                  {stats?.status_counts 
                    ? Object.entries(stats.status_counts)
                        .filter(([k]) => k !== 'RESOLVED' && k !== 'FALSE_POSITIVE')
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

