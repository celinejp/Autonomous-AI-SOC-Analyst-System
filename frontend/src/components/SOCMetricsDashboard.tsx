'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useSOCMetrics } from '@/hooks/useSOCMetrics';
import { AlertCircle, Target } from 'lucide-react';

interface SOCMetricsDashboardProps {
  hours?: number;
}

export function SOCMetricsDashboard({ hours = 24 }: SOCMetricsDashboardProps) {
  const { data: metrics, isLoading } = useSOCMetrics(hours);

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {[...Array(2)].map((_, i) => (
          <Card key={i} className="bg-gray-900 border-gray-800">
            <CardContent className="p-6">
              <div className="h-20 bg-gray-800 rounded animate-pulse"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const fpRate = metrics?.false_positive_rate ? (metrics.false_positive_rate * 100).toFixed(1) : '0';
  const alertReduction = metrics?.alert_reduction_ratio ? metrics.alert_reduction_ratio.toFixed(1) : '0';

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">False Positive</CardTitle>
          <AlertCircle className="h-4 w-4 text-yellow-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-yellow-400">{fpRate}%</div>
          <p className="text-xs text-gray-500 mt-1">Incidents marked false positive</p>
        </CardContent>
      </Card>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">Alerts per Incident</CardTitle>
          <Target className="h-4 w-4 text-purple-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-purple-400">{alertReduction}:1</div>
          <p className="text-xs text-gray-500 mt-1">Alerts grouped into each incident</p>
        </CardContent>
      </Card>
    </div>
  );
}
