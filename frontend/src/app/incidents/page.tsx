'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useIncidents } from '@/hooks/useIncidents';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { Incident, IncidentStatus, Severity } from '@/types';
import { Filter, X } from 'lucide-react';

export default function IncidentsPage() {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [offset, setOffset] = useState(0);
  const limit = 20;

  const { data: incidents, isLoading, error } = useIncidents({
    severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
    status: selectedStatus !== 'all' ? selectedStatus : undefined,
    limit,
    offset,
  });

  const hasActiveFilters = selectedSeverity !== 'all' || selectedStatus !== 'all';
  const clearFilters = () => {
    setSelectedSeverity('all');
    setSelectedStatus('all');
    setOffset(0);
  };

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Security Incidents</h1>
            <p className="text-gray-400">View and manage all security incidents</p>
          </div>
          <Link href="/ingest">
            <Button>
              <span>Analyze New Logs</span>
            </Button>
          </Link>
        </div>

        {/* Filters */}
        <Card className="bg-gray-900 border-gray-800 mb-6">
          <CardHeader>
            <CardTitle className="text-white flex items-center space-x-2">
              <Filter className="h-5 w-5" />
              <span>Filters</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Severity</label>
                <select
                  value={selectedSeverity}
                  onChange={(e) => {
                    setSelectedSeverity(e.target.value);
                    setOffset(0);
                  }}
                  className="bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                >
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">Status</label>
                <select
                  value={selectedStatus}
                  onChange={(e) => {
                    setSelectedStatus(e.target.value);
                    setOffset(0);
                  }}
                  className="bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                >
                  <option value="all">All</option>
                  <option value="new">New</option>
                  <option value="in_progress">In Progress</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              {hasActiveFilters && (
                <div className="flex items-end">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={clearFilters}
                    className="flex items-center space-x-1"
                  >
                    <X className="h-4 w-4" />
                    <span>Clear Filters</span>
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-400 text-sm">
              ⚠️ {error instanceof Error ? error.message : 'Failed to load incidents'}
            </p>
          </div>
        )}

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-white">All Incidents</CardTitle>
            {incidents && (
              <span className="text-sm text-gray-400">
                {incidents.length} incident{incidents.length !== 1 ? 's' : ''}
              </span>
            )}
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-16 bg-gray-800 rounded animate-pulse"></div>
                ))}
              </div>
            ) : incidents && incidents.length > 0 ? (
              <>
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
                      <TableRow 
                        key={incident.id} 
                        className="border-gray-800 hover:bg-gray-800/50 cursor-pointer"
                        onClick={() => window.location.href = `/incident/${incident.id}`}
                      >
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
                            <span 
                              className="text-blue-400 hover:text-blue-300 cursor-pointer"
                              onClick={(e) => e.stopPropagation()}
                            >
                              View →
                            </span>
                          </Link>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {/* Pagination */}
                <div className="mt-6 flex items-center justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                    disabled={offset === 0 || isLoading}
                  >
                    Previous
                  </Button>
                  <span className="text-sm text-gray-400">
                    Showing {offset + 1}-{offset + incidents.length}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setOffset(offset + limit)}
                    disabled={incidents.length < limit || isLoading}
                  >
                    Next
                  </Button>
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-400 mb-4">
                  {hasActiveFilters ? 'No incidents match your filters' : 'No incidents found'}
                </p>
                {hasActiveFilters ? (
                  <Button variant="outline" onClick={clearFilters}>
                    Clear Filters
                  </Button>
                ) : (
                  <Link href="/ingest">
                    <Button variant="outline">
                      Upload logs to create incidents
                    </Button>
                  </Link>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
