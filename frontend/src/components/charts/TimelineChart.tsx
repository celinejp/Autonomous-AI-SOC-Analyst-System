'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

interface TimelineChartProps {
  data: Array<{ time: string; incidents: number; alerts: number }>;
}

export function TimelineChart({ data }: TimelineChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        No data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
        <XAxis 
          dataKey="time" 
          stroke="#9ca3af"
          tick={{ fill: '#9ca3af' }}
        />
        <YAxis 
          stroke="#9ca3af"
          tick={{ fill: '#9ca3af' }}
        />
        <Tooltip 
          contentStyle={{ 
            backgroundColor: '#1f2937', 
            border: '1px solid #374151', 
            color: '#fff',
            borderRadius: '6px'
          }} 
        />
        <Legend />
        <Line 
          type="monotone" 
          dataKey="incidents" 
          stroke="#3b82f6" 
          strokeWidth={2}
          name="Incidents"
        />
        <Line 
          type="monotone" 
          dataKey="alerts" 
          stroke="#ef4444" 
          strokeWidth={2}
          name="Alerts"
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

