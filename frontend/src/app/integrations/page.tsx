'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Loader2, Upload, Download, Server } from 'lucide-react';
import { showNotification } from '@/lib/utils';

const SPLUNK_SAMPLE = `[
  {
    "time": "2024-01-15T10:00:00Z",
    "host": "splunk-server",
    "source": "ssh",
    "sourcetype": "linux:auth",
    "event": {
      "src_ip": "203.0.113.45",
      "dst_ip": "192.168.1.10",
      "user": "admin",
      "action": "login",
      "status": "failed"
    }
  }
]`;

const ELK_SAMPLE = `[
  {
    "timestamp": "2024-01-15T10:00:00Z",
    "source": "auth",
    "message": {
      "source_ip": "203.0.113.45",
      "user": "admin",
      "action": "login",
      "status": "failed"
    }
  }
]`;

export default function IntegrationsPage() {
  const [splunkJson, setSplunkJson] = useState('');
  const [elkJson, setElkJson] = useState('');
  const [loadingSplunk, setLoadingSplunk] = useState(false);
  const [loadingElk, setLoadingElk] = useState(false);
  const [exportIncidentId, setExportIncidentId] = useState('');
  const [exportLoading, setExportLoading] = useState(false);
  const [exportResult, setExportResult] = useState<any>(null);

  const handleSplunkIngest = async () => {
    try {
      const events = JSON.parse(splunkJson || '[]');
      if (!Array.isArray(events) || events.length === 0) {
        showNotification('Paste a JSON array of Splunk events', 'error');
        return;
      }
      setLoadingSplunk(true);
      const res = await api.siem.splunkIngest(events);
      showNotification(`Ingested ${res.events_processed ?? res.log_entries_created ?? 0} Splunk events`, 'success');
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Ingest failed', 'error');
    } finally {
      setLoadingSplunk(false);
    }
  };

  const handleElkIngest = async () => {
    try {
      const events = JSON.parse(elkJson || '[]');
      if (!Array.isArray(events) || events.length === 0) {
        showNotification('Paste a JSON array of ELK events', 'error');
        return;
      }
      setLoadingElk(true);
      const res = await api.siem.elkIngest(events);
      showNotification(`Ingested ${res.events_processed ?? res.log_entries_created ?? 0} ELK events`, 'success');
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Ingest failed', 'error');
    } finally {
      setLoadingElk(false);
    }
  };

  const handleExport = async (format: 'splunk' | 'elk') => {
    setExportLoading(true);
    setExportResult(null);
    try {
      const res = format === 'splunk'
        ? await api.siem.splunkExport(exportIncidentId || undefined, 100)
        : await api.siem.elkExport(exportIncidentId || undefined, 100);
      setExportResult({ format, ...res });
      showNotification(`Exported ${res.events?.length ?? 0} events`, 'success');
    } catch (e) {
      showNotification(e instanceof Error ? e.message : 'Export failed', 'error');
    } finally {
      setExportLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Integrations</h1>
          <p className="text-gray-400">SIEM ingest (Splunk / ELK) and export</p>
        </div>

        <Tabs defaultValue="ingest" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="ingest">Ingest</TabsTrigger>
            <TabsTrigger value="export">Export</TabsTrigger>
          </TabsList>

          <TabsContent value="ingest" className="space-y-6">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center space-x-2">
                  <Server className="h-5 w-5" />
                  <span>Splunk events</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-400">Paste a JSON array of Splunk-style events. Each event: time, host, source, sourcetype, event (object with src_ip, user, action, etc.).</p>
                <textarea
                  value={splunkJson}
                  onChange={(e) => setSplunkJson(e.target.value)}
                  placeholder={SPLUNK_SAMPLE}
                  className="w-full h-48 bg-gray-800 text-white p-3 rounded-lg border border-gray-700 font-mono text-sm"
                />
                <Button onClick={handleSplunkIngest} disabled={loadingSplunk}>
                  {loadingSplunk ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Upload className="h-4 w-4 mr-2" />}
                  Ingest Splunk events
                </Button>
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center space-x-2">
                  <Server className="h-5 w-5" />
                  <span>ELK / Elasticsearch events</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-400">Paste a JSON array of ELK-style events. Each event: timestamp, source, message (object).</p>
                <textarea
                  value={elkJson}
                  onChange={(e) => setElkJson(e.target.value)}
                  placeholder={ELK_SAMPLE}
                  className="w-full h-48 bg-gray-800 text-white p-3 rounded-lg border border-gray-700 font-mono text-sm"
                />
                <Button onClick={handleElkIngest} disabled={loadingElk}>
                  {loadingElk ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Upload className="h-4 w-4 mr-2" />}
                  Ingest ELK events
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="export" className="space-y-6">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center space-x-2">
                  <Download className="h-5 w-5" />
                  <span>Export to SIEM format</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-400">Export incidents/logs as Splunk or ELK-compatible JSON. Leave incident ID empty for recent logs.</p>
                <input
                  value={exportIncidentId}
                  onChange={(e) => setExportIncidentId(e.target.value)}
                  placeholder="Optional: incident UUID"
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700 font-mono text-sm"
                />
                <div className="flex gap-2">
                  <Button onClick={() => handleExport('splunk')} disabled={exportLoading} variant="outline">
                    {exportLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Export as Splunk
                  </Button>
                  <Button onClick={() => handleExport('elk')} disabled={exportLoading} variant="outline">
                    {exportLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                    Export as ELK
                  </Button>
                </div>
                {exportResult && (
                  <div className="mt-4 p-3 bg-gray-800 rounded-lg max-h-64 overflow-auto">
                    <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                      {JSON.stringify(exportResult, null, 2)}
                    </pre>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
