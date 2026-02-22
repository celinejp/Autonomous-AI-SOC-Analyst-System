'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useSOCMetrics } from '@/hooks/useSOCMetrics';
import { Clock, TrendingDown, AlertCircle, Target, Zap } from 'lucide-react';

interface SOCMetricsDashboardProps {
  hours?: number;
}

export function SOCMetricsDashboard({ hours = 24 }: SOCMetricsDashboardProps) {
  const { data: metrics, isLoading } = useSOCMetrics(hours);

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}min`;
    return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}min`;
  };

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(5)].map((_, i) => (
          <Card key={i} className="bg-gray-900 border-gray-800">
            <CardContent className="p-6">
              <div className="h-20 bg-gray-800 rounded animate-pulse"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const mttd = metrics?.mttd_seconds ? formatDuration(metrics.mttd_seconds) : 'N/A';
  const mttr = metrics?.mttr_seconds ? formatDuration(metrics.mttr_seconds) : 'N/A';
  const fpRate = metrics?.false_positive_rate ? (metrics.false_positive_rate * 100).toFixed(1) : '0';
  const alertReduction = metrics?.alert_reduction_ratio ? metrics.alert_reduction_ratio.toFixed(1) : '0';
  const aiAccuracy = metrics?.ai_accuracy ? (metrics.ai_accuracy * 100).toFixed(1) : '0';

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">MTTD</CardTitle>
          <Clock className="h-4 w-4 text-blue-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-blue-400">{mttd}</div>
          <p className="text-xs text-gray-500 mt-1">Mean Time To Detect</p>
        </CardContent>
      </Card>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">MTTR</CardTitle>
          <TrendingDown className="h-4 w-4 text-green-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-green-400">{mttr}</div>
          <p className="text-xs text-gray-500 mt-1">Mean Time To Respond</p>
        </CardContent>
      </Card>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">False Positive</CardTitle>
          <AlertCircle className="h-4 w-4 text-yellow-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-yellow-400">{fpRate}%</div>
          <p className="text-xs text-gray-500 mt-1">False Positive Rate</p>
        </CardContent>
      </Card>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">Alert Reduction</CardTitle>
          <Target className="h-4 w-4 text-purple-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-purple-400">{alertReduction}:1</div>
          <p className="text-xs text-gray-500 mt-1">Alert Reduction Ratio</p>
        </CardContent>
      </Card>

      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium text-gray-400">AI Accuracy</CardTitle>
          <Zap className="h-4 w-4 text-orange-400" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-orange-400">{aiAccuracy}%</div>
          <p className="text-xs text-gray-500 mt-1">AI Detection Accuracy</p>
        </CardContent>
      </Card>
    </div>
  );
}

