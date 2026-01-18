'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Upload, FileText, Play } from 'lucide-react';

export default function IngestPage() {
  const [logs, setLogs] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const router = useRouter();

  const handleAnalyze = async () => {
    if (!logs.trim()) return;
    
    setIsAnalyzing(true);
    try {
      const logLines = logs.split('\n').filter(line => line.trim());
      const result = await api.ingest.analyze(logLines);
      
      if (result.incident_id) {
        router.push(`/incident/${result.incident_id}`);
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      alert('Failed to analyze logs. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setLogs(content);
    };
    reader.readAsText(file);
  };

  const demoLogs = [
    '2024-01-15 10:00:00 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:01 sshd[1234]: Failed password for admin from 203.0.113.45',
    '2024-01-15 10:00:02 sshd[1234]: Failed password for admin from 203.0.113.45',
  ];

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Log Ingestion</h1>
          <p className="text-gray-400">Upload or paste security logs for analysis</p>
        </div>

        <Card className="bg-gray-900 border-gray-800 mb-6">
          <CardHeader>
            <CardTitle className="text-white">Upload Logs</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center space-x-4">
              <label className="cursor-pointer">
                <input
                  type="file"
                  className="hidden"
                  accept=".log,.txt,.json"
                  onChange={handleFileUpload}
                />
                <div className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white">
                  <Upload className="h-4 w-4" />
                  <span>Upload File</span>
                </div>
              </label>
              <span className="text-gray-400 text-sm">or paste logs below</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800 mb-6">
          <CardHeader>
            <CardTitle className="text-white">Paste Logs</CardTitle>
          </CardHeader>
          <CardContent>
            <textarea
              value={logs}
              onChange={(e) => setLogs(e.target.value)}
              placeholder="Paste your security logs here, one per line..."
              className="w-full h-64 bg-gray-800 text-white p-4 rounded-lg border border-gray-700 font-mono text-sm"
            />
            <div className="mt-4 flex items-center justify-between">
              <span className="text-gray-400 text-sm">
                {logs.split('\n').filter(l => l.trim()).length} log entries
              </span>
              <button
                onClick={handleAnalyze}
                disabled={!logs.trim() || isAnalyzing}
                className="px-6 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:cursor-not-allowed rounded-lg text-white flex items-center space-x-2"
              >
                {isAnalyzing ? (
                  <>
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    <span>Analyze Logs</span>
                  </>
                )}
              </button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Demo Mode</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-400 mb-4 text-sm">
              Try the system with sample logs:
            </p>
            <button
              onClick={() => setLogs(demoLogs.join('\n'))}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg text-white flex items-center space-x-2"
            >
              <FileText className="h-4 w-4" />
              <span>Load Demo Logs (Brute Force Attack)</span>
            </button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

