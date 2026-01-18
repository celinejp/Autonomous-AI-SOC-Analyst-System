'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import Link from 'next/link';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { Incident, IncidentStatus, Severity } from '@/types';

export default function IncidentsPage() {
  const { data: incidents, isLoading, error } = useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.incidents.list({ limit: 100 }),
    retry: 2,
    placeholderData: [],
  });

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Security Incidents</h1>
          <p className="text-gray-400">View and manage all security incidents</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-400 text-sm">
              ⚠️ {error instanceof Error ? error.message : 'Failed to load incidents'}
            </p>
          </div>
        )}

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">All Incidents</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-16 bg-gray-800 rounded animate-pulse"></div>
                ))}
              </div>
            ) : incidents && incidents.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-800">
                    <TableHead className="text-gray-400">ID</TableHead>
                    <TableHead className="text-gray-400">Severity</TableHead>
                    <TableHead className="text-gray-400">Status</TableHead>
                    <TableHead className="text-gray-400">Confidence</TableHead>
                    <TableHead className="text-gray-400">Alerts</TableHead>
                    <TableHead className="text-gray-400">Created</TableHead>
                    <TableHead className="text-gray-400">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {incidents.map((incident: Incident) => (
                    <TableRow key={incident.id} className="border-gray-800">
                      <TableCell className="font-mono text-sm text-white">
                        {incident.id.substring(0, 8)}...
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(incident.severity)}>
                          {incident.severity.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{incident.status}</Badge>
                      </TableCell>
                      <TableCell className="text-white">
                        {(incident.confidence_score * 100).toFixed(1)}%
                      </TableCell>
                      <TableCell className="text-white">
                        {incident.alerts?.length || 0}
                      </TableCell>
                      <TableCell className="text-gray-400 text-sm">
                        {formatDate(incident.created_at)}
                      </TableCell>
                      <TableCell>
                        <Link href={`/incident/${incident.id}`}>
                          <span className="text-blue-400 hover:text-blue-300 cursor-pointer">
                            View →
                          </span>
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-400 mb-4">No incidents found</p>
                <Link href="/ingest">
                  <span className="text-blue-400 hover:text-blue-300">Upload logs to create incidents</span>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

