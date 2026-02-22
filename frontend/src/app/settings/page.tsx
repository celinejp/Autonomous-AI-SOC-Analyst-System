'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Loader2, Save, Building2 } from 'lucide-react';
import { showNotification } from '@/lib/utils';
import { useState, useEffect } from 'react';

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data: profile, isLoading } = useQuery({
    queryKey: ['organization', 'profile'],
    queryFn: () => api.organization.getProfile(),
  });

  const [name, setName] = useState('');
  const [industry, setIndustry] = useState('');
  const [riskAppetite, setRiskAppetite] = useState('moderate');
  const [internalIpRanges, setInternalIpRanges] = useState('');
  const [regulations, setRegulations] = useState('');

  useEffect(() => {
    if (profile) {
      setName(profile.name ?? '');
      setIndustry(profile.industry ?? '');
      setRiskAppetite(profile.risk_appetite ?? 'moderate');
      setInternalIpRanges((profile.internal_ip_ranges ?? []).join('\n'));
      setRegulations((profile.applicable_regulations ?? []).join(', '));
    }
  }, [profile]);

  const updateMutation = useMutation({
    mutationFn: (data: any) => api.organization.updateProfile(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organization', 'profile'] });
      showNotification('Organization profile saved', 'success');
    },
    onError: (e: Error) => showNotification(e.message, 'error'),
  });

  const handleSave = () => {
    updateMutation.mutate({
      name: name || 'Default Organization',
      industry: industry || 'technology',
      risk_appetite: riskAppetite,
      applicable_regulations: regulations ? regulations.split(',').map((r) => r.trim()).filter(Boolean) : [],
      internal_ip_ranges: internalIpRanges ? internalIpRanges.split('\n').map((r) => r.trim()).filter(Boolean) : [],
      crown_jewels: profile?.crown_jewels ?? [],
      acceptable_downtime_hours: profile?.acceptable_downtime_hours ?? {},
      incident_notification_contacts: profile?.incident_notification_contacts ?? [],
      trusted_domains: profile?.trusted_domains ?? [],
      approved_cloud_services: profile?.approved_cloud_services ?? [],
    });
  };

  return (
    <div className="min-h-screen bg-gray-950 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Organization Settings</h1>
          <p className="text-gray-400">Context for SOC analysis (industry, regulations, network ranges)</p>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
          </div>
        ) : (
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center space-x-2">
                <Building2 className="h-5 w-5" />
                <span>Profile</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Organization name</label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                  placeholder="Default Organization"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Industry</label>
                <select
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                >
                  <option value="technology">Technology</option>
                  <option value="healthcare">Healthcare</option>
                  <option value="finance">Finance</option>
                  <option value="retail">Retail</option>
                  <option value="government">Government</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Risk appetite</label>
                <select
                  value={riskAppetite}
                  onChange={(e) => setRiskAppetite(e.target.value)}
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                >
                  <option value="conservative">Conservative</option>
                  <option value="moderate">Moderate</option>
                  <option value="aggressive">Aggressive</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Applicable regulations (comma-separated)</label>
                <input
                  value={regulations}
                  onChange={(e) => setRegulations(e.target.value)}
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700"
                  placeholder="GDPR, HIPAA, PCI-DSS"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Internal IP ranges (one per line)</label>
                <textarea
                  value={internalIpRanges}
                  onChange={(e) => setInternalIpRanges(e.target.value)}
                  className="w-full bg-gray-800 text-white p-2 rounded-lg border border-gray-700 h-24 font-mono text-sm"
                  placeholder="10.0.0.0/8&#10;172.16.0.0/12"
                />
              </div>
              <Button
                onClick={handleSave}
                disabled={updateMutation.isPending}
                className="w-full sm:w-auto"
              >
                {updateMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <Save className="h-4 w-4 mr-2" />
                )}
                Save profile
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
