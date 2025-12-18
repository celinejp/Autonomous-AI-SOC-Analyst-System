/** Dashboard - Main overview page */

"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchIncidents } from "@/lib/api";
import Link from "next/link";
import { formatDate, getSeverityColor } from "@/lib/utils";
import { useEffect, useState } from "react";

export default function Dashboard() {
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const { data: incidents, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => fetchIncidents({ limit: 100 }),
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdate(new Date());
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black text-white p-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center">Loading dashboard...</div>
        </div>
      </div>
    );
  }

  const criticalCount = incidents?.filter((i) => i.severity === "critical").length || 0;
  const highCount = incidents?.filter((i) => i.severity === "high").length || 0;
  const recentIncidents = incidents?.slice(0, 10) || [];

  return (
    <div className="min-h-screen bg-black text-white">
      <nav className="border-b border-gray-800 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link href="/" className="text-xl font-bold text-green-400">
                AI SOC Analyst
              </Link>
              <Link href="/" className="text-gray-300 hover:text-white">
                Dashboard
              </Link>
              <Link href="/incidents" className="text-gray-300 hover:text-white">
                Incidents
              </Link>
              <Link href="/ingest" className="text-gray-300 hover:text-white">
                Ingest
              </Link>
              <Link href="/insights" className="text-gray-300 hover:text-white">
                Insights
              </Link>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto p-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Security Operations Dashboard</h1>
          <p className="text-gray-400">Last updated: {formatDate(lastUpdate)}</p>
        </div>

        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Total Incidents (24h)</div>
            <div className="text-3xl font-bold">{incidents?.length || 0}</div>
          </div>
          <div className="bg-gray-900 border border-red-500/20 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Critical</div>
            <div className="text-3xl font-bold text-red-500">{criticalCount}</div>
          </div>
          <div className="bg-gray-900 border border-orange-500/20 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">High</div>
            <div className="text-3xl font-bold text-orange-500">{highCount}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Avg Confidence</div>
            <div className="text-3xl font-bold">
              {incidents?.length
                ? (
                    incidents.reduce((sum, i) => sum + i.confidence_score, 0) /
                    incidents.length
                  ).toFixed(2)
                : "0.00"}
            </div>
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-bold mb-4">Recent Incidents</h2>
          <div className="space-y-4">
            {recentIncidents.length === 0 ? (
              <div className="text-gray-400 text-center py-8">No incidents yet</div>
            ) : (
              recentIncidents.map((incident) => (
                <Link
                  key={incident.id}
                  href={`/incident/${incident.id}`}
                  className="block p-4 bg-gray-800/50 rounded-lg hover:bg-gray-800 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(
                          incident.severity
                        )}`}
                      >
                        {incident.severity.toUpperCase()}
                      </span>
                      <div>
                        <div className="font-semibold">
                          {incident.alerts[0]?.title || "Security Incident"}
                        </div>
                        <div className="text-sm text-gray-400">
                          {formatDate(incident.created_at)}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-gray-400">
                        {incident.alerts.length} alert{incident.alerts.length !== 1 ? "s" : ""}
                      </div>
                      <div className="text-xs text-gray-500">
                        Confidence: {(incident.confidence_score * 100).toFixed(0)}%
                      </div>
                    </div>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

