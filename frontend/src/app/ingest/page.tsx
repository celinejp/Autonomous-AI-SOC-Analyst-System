'use client';

import { Suspense, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useSearchParams } from 'next/navigation';
import { api, demoScenarios } from '@/lib/api';
import { useDemoStream } from '@/hooks/useDemoStream';
import { useAnalyzeLogs } from '@/hooks/useAnalyzeLogs';
import { showNotification } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Upload, FileText, Play, Loader2, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';
import { IncidentStreamViewer } from '@/components/IncidentStreamViewer';
import { DemoStreamViewer } from '@/components/DemoStreamViewer';

const DEMO_SCENARIOS = [
  { id: 'brute_force', name: 'Brute Force (T1110)', description: 'SSH brute force attack with multiple failed login attempts' },
  { id: 'powershell', name: 'PowerShell Execution (T1059.001)', description: 'Suspicious PowerShell commands and encoded scripts' },
  { id: 'rdp_lateral', name: 'RDP Lateral Movement (T1021.001)', description: 'Lateral movement via Remote Desktop Protocol' },
  { id: 'ransomware', name: 'Ransomware (T1486)', description: 'File encryption and ransomware indicators' },
  { id: 'cloud_iam', name: 'Cloud IAM Abuse', description: 'AWS IAM privilege escalation and backdoor creation' },
  { id: 'port_scan', name: 'Port Scan (T1046)', description: 'Network reconnaissance port scanning activity' },
] as const;

export default function IngestPage() {
  return (
    <Suspense fallback={null}>
      <IngestPageInner />
    </Suspense>
  );
}

function IngestPageInner() {
  const searchParams = useSearchParams();
  const initialTab = searchParams?.get('tab') === 'demo' ? 'demo' : 'upload';
  const [activeTab, setActiveTab] = useState(initialTab);
  const [logs, setLogs] = useState('');
  const [selectedDemo, setSelectedDemo] = useState<string>('brute_force');
  const [analyzingIncidentId, setAnalyzingIncidentId] = useState<string | null>(null);
  
  const router = useRouter();
  const analyzeMutation = useAnalyzeLogs();
  const { runDemo, events: streamEvents, incidentId: streamIncidentId, status: streamStatus, error: streamError, reset: resetStream } = useDemoStream();
  const [generatingSynthetic, setGeneratingSynthetic] = useState(false);

  const handleGenerateSynthetic = async () => {
    setGeneratingSynthetic(true);
    try {
      const res = await api.synthetic.generate(10);
      if (res?.logs?.length) {
        setLogs(res.logs.join('\n'));
        showNotification(`Generated ${res.count} synthetic log entries`, 'success');
      } else {
        showNotification('No logs returned', 'error');
      }
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Generate failed', 'error');
    } finally {
      setGeneratingSynthetic(false);
    }
  };

  const handleAnalyze = async () => {
    if (!logs.trim()) {
      showNotification('Please enter logs to analyze', 'error');
      return;
    }
    
    try {
      const logLines = logs.split('\n').filter(line => line.trim());
      showNotification(`Analyzing ${logLines.length} log entries...`, 'info');
      
      const result = await analyzeMutation.mutateAsync(logLines);
      
      if (result?.incident_id) {
        showNotification(`✅ Analysis started! Incident ID: ${result.incident_id.substring(0, 8)}...`, 'success');
        setAnalyzingIncidentId(result.incident_id);
        // Wait a bit longer for incident to be saved to DB
        setTimeout(() => {
          showNotification('🔄 Loading incident details...', 'info');
          router.push(`/incident/${result.incident_id}`);
        }, 3000); // Increased to 3 seconds to allow DB write
      } else {
        showNotification('Analysis started but no incident ID returned', 'error');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to analyze logs';
      showNotification(`Analysis failed: ${errorMessage}`, 'error');
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setLogs(content);
      const lineCount = content.split('\n').filter(l => l.trim()).length;
      showNotification(`📄 Loaded ${lineCount} log entries from file`, 'success');
    };
    reader.readAsText(file);
  };

  const handleDemo = async () => {
    if (streamStatus === 'streaming') return;
    showNotification(`🚀 Running ${DEMO_SCENARIOS.find(s => s.id === selectedDemo)?.name} demo...`, 'info');
    setAnalyzingIncidentId(null);
    resetStream();
    const id = await runDemo(selectedDemo as keyof typeof demoScenarios);
    if (id) {
      setAnalyzingIncidentId(id);
      showNotification(`✅ Demo complete! Incident ID: ${id.substring(0, 8)}...`, 'success');
    } else if (streamError) {
      showNotification(`❌ Demo failed: ${streamError}`, 'error');
    }
  };

  // Redirect to incident when stream completes with an ID
  useEffect(() => {
    if (streamStatus === 'done' && streamIncidentId) {
      showNotification('🔄 Opening incident...', 'info');
      router.push(`/incident/${streamIncidentId}`);
    }
  }, [streamStatus, streamIncidentId, router]);

  const isDemoRunning = streamStatus === 'streaming';
  const isLoading = analyzeMutation.isPending || isDemoRunning;

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Log Ingestion</h1>
          <p className="text-gray-400">Upload logs or run demo scenarios to test the system</p>
        </div>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v)} className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-6">
            <TabsTrigger value="upload">Upload Logs</TabsTrigger>
            <TabsTrigger value="demo">Demo Mode</TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="space-y-6">
            <Card className="bg-gray-900 border-gray-800">
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
                      disabled={isLoading}
                    />
                    <Button variant="outline" className="flex items-center space-x-2" disabled={isLoading}>
                      <Upload className="h-4 w-4" />
                      <span>Upload File</span>
                    </Button>
                  </label>
                  <span className="text-gray-400 text-sm">or paste logs below</span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleGenerateSynthetic}
                    disabled={generatingSynthetic || isLoading}
                    className="flex items-center space-x-2"
                  >
                    {generatingSynthetic ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                    <span>Generate synthetic</span>
                  </Button>
                </div>

                <textarea
                  value={logs}
                  onChange={(e) => setLogs(e.target.value)}
                  placeholder="Paste your security logs here, one per line..."
                  className="w-full h-64 bg-gray-800 text-white p-4 rounded-lg border border-gray-700 font-mono text-sm"
                  disabled={isLoading}
                />

                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm">
                    {logs.split('\n').filter(l => l.trim()).length} log entries
                  </span>
                  <Button
                    onClick={handleAnalyze}
                    disabled={!logs.trim() || isLoading}
                    className="flex items-center space-x-2"
                    size="lg"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4" />
                        <span>Analyze Logs</span>
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {analyzingIncidentId && (
              <IncidentStreamViewer incidentId={analyzingIncidentId} />
            )}
          </TabsContent>

          <TabsContent value="demo" className="space-y-6">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Demo Scenarios</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Select Scenario
                  </label>
                  <select
                    value={selectedDemo}
                    onChange={(e) => setSelectedDemo(e.target.value)}
                    className="w-full bg-gray-800 text-white p-3 rounded-lg border border-gray-700"
                    disabled={isLoading}
                  >
                    {DEMO_SCENARIOS.map((scenario) => (
                      <option key={scenario.id} value={scenario.id}>
                        {scenario.name}
                      </option>
                    ))}
                  </select>
                </div>

                {selectedDemo && (
                  <div className="p-4 bg-gray-800 rounded-lg">
                    <p className="text-sm text-gray-400 mb-2">
                      {DEMO_SCENARIOS.find(s => s.id === selectedDemo)?.description}
                    </p>
                    <div className="mt-3 p-3 bg-gray-950 rounded font-mono text-xs text-gray-400 max-h-32 overflow-y-auto">
                      {demoScenarios[selectedDemo as keyof typeof demoScenarios]?.slice(0, 3).map((log, i) => (
                        <div key={i}>{log}</div>
                      ))}
                      {demoScenarios[selectedDemo as keyof typeof demoScenarios]?.length > 3 && (
                        <div className="text-gray-500">... and {demoScenarios[selectedDemo as keyof typeof demoScenarios]!.length - 3} more</div>
                      )}
                    </div>
                  </div>
                )}

                <Button
                  onClick={handleDemo}
                  disabled={isDemoRunning}
                  className="w-full flex items-center justify-center space-x-2"
                  size="lg"
                >
                  {isDemoRunning ? (
                    <>
                      <Loader2 className="h-5 w-5 animate-spin" />
                      <span>Running Demo...</span>
                    </>
                  ) : (
                    <>
                      <FileText className="h-5 w-5" />
                      <span>Run Demo Scenario</span>
                    </>
                  )}
                </Button>

                {streamError && (
                  <div className="p-4 bg-red-900/20 border border-red-500/50 rounded-lg flex items-center space-x-2 text-red-400">
                    <AlertCircle className="h-5 w-5" />
                    <span>Demo failed: {streamError}</span>
                  </div>
                )}

                {streamStatus === 'done' && streamIncidentId && (
                  <div className="p-4 bg-green-900/20 border border-green-500/50 rounded-lg flex items-center space-x-2 text-green-400">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>Demo completed! Redirecting to incident...</span>
                  </div>
                )}
              </CardContent>
            </Card>

            {isDemoRunning && (
              <DemoStreamViewer events={streamEvents} isStreaming={true} />
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
