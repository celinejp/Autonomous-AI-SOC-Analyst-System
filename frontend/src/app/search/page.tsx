'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Search as SearchIcon, Loader2, Shield, FileSearch } from 'lucide-react';
import Link from 'next/link';

export default function SearchPage() {
  const [semanticQuery, setSemanticQuery] = useState('');
  const [mitreQuery, setMitreQuery] = useState('');
  const [submittedSemantic, setSubmittedSemantic] = useState('');
  const [submittedMitre, setSubmittedMitre] = useState('');

  const { data: semanticResults, isLoading: semanticLoading } = useQuery({
    queryKey: ['search', 'semantic', submittedSemantic],
    queryFn: () => api.search.semantic(submittedSemantic, 15),
    enabled: submittedSemantic.length >= 2,
  });

  const { data: mitreResults, isLoading: mitreLoading } = useQuery({
    queryKey: ['search', 'mitre', submittedMitre],
    queryFn: () => api.search.mitre(submittedMitre, 15),
    enabled: submittedMitre.length >= 2,
  });

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-5xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Search</h1>
          <p className="text-gray-400">Semantic incident search and MITRE ATT&CK technique search</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <FileSearch className="h-5 w-5" />
                <span>Incident search (semantic)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-gray-400">Find incidents by meaning (e.g. &quot;brute force SSH&quot;, &quot;ransomware&quot;).</p>
              <div className="flex gap-2">
                <Input
                  value={semanticQuery}
                  onChange={(e) => setSemanticQuery(e.target.value)}
                  placeholder="Describe what you're looking for..."
                  className="bg-gray-800 border-gray-700 text-white"
                />
                <Button
                  onClick={() => setSubmittedSemantic(semanticQuery.trim())}
                  disabled={semanticQuery.trim().length < 2 || semanticLoading}
                >
                  {semanticLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <SearchIcon className="h-4 w-4" />}
                </Button>
              </div>
              {semanticResults && (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {semanticResults.results?.length > 0 ? (
                    semanticResults.results.map((r: any) => (
                      <Link key={r.id} href={`/incident/${r.id}`}>
                        <div className="p-3 bg-gray-800 rounded-lg hover:bg-gray-700 transition">
                          <div className="flex justify-between items-start">
                            <span className="text-white font-mono text-sm truncate flex-1">{r.id?.slice(0, 8)}...</span>
                            <Badge variant="outline" className="text-xs">{(r.similarity * 100).toFixed(0)}%</Badge>
                          </div>
                          <p className="text-gray-400 text-xs mt-1 truncate">{r.search_text || r.severity}</p>
                        </div>
                      </Link>
                    ))
                  ) : (
                    <p className="text-gray-500 text-sm">No incidents with embeddings found. Run analysis first.</p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>MITRE ATT&CK search</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-gray-400">Search techniques by keyword (e.g. &quot;lateral movement&quot;, &quot;credential&quot;).</p>
              <div className="flex gap-2">
                <Input
                  value={mitreQuery}
                  onChange={(e) => setMitreQuery(e.target.value)}
                  placeholder="e.g. credential dumping"
                  className="bg-gray-800 border-gray-700 text-white"
                />
                <Button
                  onClick={() => setSubmittedMitre(mitreQuery.trim())}
                  disabled={mitreQuery.trim().length < 2 || mitreLoading}
                >
                  {mitreLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <SearchIcon className="h-4 w-4" />}
                </Button>
              </div>
              {mitreResults && (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {mitreResults.results?.length > 0 ? (
                    mitreResults.results.map((r: any, i: number) => (
                      <div key={i} className="p-3 bg-gray-800 rounded-lg">
                        <div className="flex justify-between items-start">
                          <span className="text-white font-mono text-sm">{r.technique_id}</span>
                          <Badge variant="outline" className="text-xs">{(r.similarity * 100).toFixed(0)}%</Badge>
                        </div>
                        <p className="text-gray-300 text-sm font-medium mt-1">{r.name}</p>
                        <p className="text-gray-500 text-xs mt-1 line-clamp-2">{r.description}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-sm">No results or Qdrant collection not loaded.</p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
