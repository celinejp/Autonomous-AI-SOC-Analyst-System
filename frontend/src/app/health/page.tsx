'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CheckCircle2, XCircle, Loader2, Activity } from 'lucide-react';
import Link from 'next/link';

export default function HealthPage() {
  const { data: health, isLoading, refetch } = useQuery({
    queryKey: ['health', 'basic'],
    queryFn: () => api.health.basic(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: deepHealth, isLoading: isLoadingDeep, refetch: refetchDeep } = useQuery({
    queryKey: ['health', 'deep'],
    queryFn: () => api.health.deep(),
    enabled: false, // Only fetch on demand
  });

  const isHealthy = health?.status === 'healthy' || health?.status === 'ok';
  const checkPassed = (check: unknown) =>
    check === 'ok' || check === 'connected' ||
    (typeof check === 'object' && check !== null && (check as { status?: string }).status === 'pass');
  const dbStatus = checkPassed(health?.checks?.database ?? health?.database);
  const redisStatus = checkPassed(health?.checks?.redis ?? health?.redis);
  const qdrantStatus = checkPassed(health?.checks?.qdrant ?? health?.qdrant);

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">System Health</h1>
            <p className="text-gray-400">Monitor system components and service status</p>
          </div>
          <div className="flex space-x-2">
            <Button onClick={() => refetch()} variant="outline" size="sm">
              <Activity className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button 
              onClick={() => refetchDeep()} 
              variant="outline" 
              size="sm"
              disabled={isLoadingDeep}
            >
              {isLoadingDeep ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Activity className="h-4 w-4 mr-2" />
              )}
              Deep Check
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg flex items-center justify-between">
                <span>Backend API</span>
                {isHealthy ? (
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <>
                  <Badge variant={isHealthy ? 'default' : 'destructive'}>
                    {isHealthy ? 'Healthy' : 'Unhealthy'}
                  </Badge>
                  <p className="text-sm text-gray-400 mt-2">Port: 8000</p>
                  {health?.latency_ms && (
                    <p className="text-xs text-gray-500 mt-1">Latency: {health.latency_ms.toFixed(0)}ms</p>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg flex items-center justify-between">
                <span>PostgreSQL</span>
                {dbStatus ? (
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <>
                  <Badge variant={dbStatus ? 'default' : 'destructive'}>
                    {dbStatus ? 'Connected' : 'Disconnected'}
                  </Badge>
                  <p className="text-sm text-gray-400 mt-2">Port: 5433</p>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg flex items-center justify-between">
                <span>Redis</span>
                {redisStatus ? (
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <>
                  <Badge variant={redisStatus ? 'default' : 'destructive'}>
                    {redisStatus ? 'Connected' : 'Disconnected'}
                  </Badge>
                  <p className="text-sm text-gray-400 mt-2">Port: 6379</p>
                </>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white text-lg flex items-center justify-between">
                <span>Qdrant</span>
                {qdrantStatus ? (
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-8 bg-gray-800 rounded animate-pulse"></div>
              ) : (
                <>
                  <Badge variant={qdrantStatus ? 'default' : 'destructive'}>
                    {qdrantStatus ? 'Connected' : 'Disconnected'}
                  </Badge>
                  <p className="text-sm text-gray-400 mt-2">Port: 6333</p>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        {deepHealth && (
          <Card className="bg-gray-900 border-gray-800 mb-6">
            <CardHeader>
              <CardTitle className="text-white">Deep Health Check Results</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-gray-950 p-4 rounded-lg text-xs text-gray-300 overflow-x-auto">
                {JSON.stringify(deepHealth, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Link href="/">
                <Button variant="outline" className="w-full justify-start">
                  ← Back to Dashboard
                </Button>
              </Link>
              <Link href="/incidents">
                <Button variant="outline" className="w-full justify-start">
                  View Incidents
                </Button>
              </Link>
              <Link href="/ingest">
                <Button variant="outline" className="w-full justify-start">
                  Upload Logs
                </Button>
              </Link>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">System Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Environment:</span>
                  <span className="text-white">Development</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">API URL:</span>
                  <span className="text-white font-mono text-xs">{process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api'}</span>
                </div>
                {health?.version && (
                  <div className="flex justify-between">
                    <span className="text-gray-400">Version:</span>
                    <span className="text-white">{health.version}</span>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

