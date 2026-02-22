'use client';

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Shield, AlertTriangle, FileText, Globe } from 'lucide-react';

interface IOC {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  value: string;
  threat_level?: 'high' | 'medium' | 'low';
  first_seen?: string;
  last_seen?: string;
}

interface IOCsTableProps {
  iocs: IOC[] | Record<string, any>;
}

export function IOCsTable({ iocs }: IOCsTableProps) {
  // Normalize IOCs from various formats
  let normalizedIOCs: IOC[] = [];

  if (Array.isArray(iocs)) {
    normalizedIOCs = iocs;
  } else if (typeof iocs === 'object' && iocs !== null) {
    // Handle object format: { ips: [], domains: [], hashes: [] }
    if (iocs.ips) {
      normalizedIOCs.push(...(iocs.ips as string[]).map(ip => ({ type: 'ip' as const, value: ip })));
    }
    if (iocs.domains) {
      normalizedIOCs.push(...(iocs.domains as string[]).map(domain => ({ type: 'domain' as const, value: domain })));
    }
    if (iocs.hashes) {
      normalizedIOCs.push(...(iocs.hashes as string[]).map(hash => ({ type: 'hash' as const, value: hash })));
    }
    if (iocs.urls) {
      normalizedIOCs.push(...(iocs.urls as string[]).map(url => ({ type: 'url' as const, value: url })));
    }
    if (iocs.emails) {
      normalizedIOCs.push(...(iocs.emails as string[]).map(email => ({ type: 'email' as const, value: email })));
    }
  }

  if (normalizedIOCs.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
        <p>No IOCs found</p>
      </div>
    );
  }

  const getIcon = (type: string) => {
    switch (type) {
      case 'ip':
        return <Globe className="h-4 w-4" />;
      case 'domain':
        return <Globe className="h-4 w-4" />;
      case 'hash':
        return <FileText className="h-4 w-4" />;
      case 'url':
        return <Globe className="h-4 w-4" />;
      case 'email':
        return <FileText className="h-4 w-4" />;
      default:
        return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const getThreatBadge = (level?: string) => {
    if (!level) return null;
    const colors: Record<string, string> = {
      high: 'bg-red-500/20 text-red-400',
      medium: 'bg-yellow-500/20 text-yellow-400',
      low: 'bg-blue-500/20 text-blue-400',
    };
    return (
      <Badge className={colors[level] || 'bg-gray-500/20 text-gray-400'}>
        {level.toUpperCase()}
      </Badge>
    );
  };

  return (
    <Table>
      <TableHeader>
        <TableRow className="border-gray-800">
          <TableHead className="text-gray-400">Type</TableHead>
          <TableHead className="text-gray-400">Value</TableHead>
          <TableHead className="text-gray-400">Threat Level</TableHead>
          <TableHead className="text-gray-400">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {normalizedIOCs.map((ioc, idx) => (
          <TableRow key={idx} className="border-gray-800">
            <TableCell>
              <div className="flex items-center space-x-2">
                {getIcon(ioc.type)}
                <span className="text-white capitalize">{ioc.type}</span>
              </div>
            </TableCell>
            <TableCell>
              <code className="text-sm text-white bg-gray-800 px-2 py-1 rounded">
                {ioc.value}
              </code>
            </TableCell>
            <TableCell>
              {getThreatBadge(ioc.threat_level)}
            </TableCell>
            <TableCell>
              <Button variant="outline" size="sm" className="mr-2">
                <Shield className="h-3 w-3 mr-1" />
                Block
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

