/** Insights and Analytics Page */

"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchIncidents } from "@/lib/api";
import Link from "next/link";

export default function InsightsPage() {
  const { data: incidents } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => fetchIncidents({ limit: 1000 }),
  });

  const allIncidents = incidents || [];

  // Calculate statistics
  const severityCounts = {
    critical: allIncidents.filter((i) => i.severity === "critical").length,
    high: allIncidents.filter((i) => i.severity === "high").length,
    medium: allIncidents.filter((i) => i.severity === "medium").length,
    low: allIncidents.filter((i) => i.severity === "low").length,
  };

  const statusCounts = {
    new: allIncidents.filter((i) => i.status === "new").length,
    in_progress: allIncidents.filter((i) => i.status === "in_progress").length,
    investigating: allIncidents.filter((i) => i.status === "investigating").length,
    resolved: allIncidents.filter((i) => i.status === "resolved").length,
    false_positive: allIncidents.filter((i) => i.status === "false_positive").length,
  };

  const avgConfidence =
    allIncidents.length > 0
      ? allIncidents.reduce((sum, i) => sum + i.confidence_score, 0) /
        allIncidents.length
      : 0;

  const falsePositiveRate =
    allIncidents.length > 0 ? statusCounts.false_positive / allIncidents.length : 0;

  // MITRE technique frequency
  const mitreCounts: Record<string, number> = {};
  allIncidents.forEach((incident) => {
    incident.mitre_techniques.forEach((tech) => {
      mitreCounts[tech.technique_id] = (mitreCounts[tech.technique_id] || 0) + 1;
    });
  });

  const topMitreTechniques = Object.entries(mitreCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return (
    <div className="min-h-screen bg-black text-white">
      <nav className="border-b border-gray-800 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <Link href="/" className="text-xl font-bold text-green-400">
              AI SOC Analyst
            </Link>
            <Link href="/" className="text-gray-300 hover:text-white">
              ← Dashboard
            </Link>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto p-8">
        <h1 className="text-3xl font-bold mb-8">Insights & Analytics</h1>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Total Incidents</div>
            <div className="text-3xl font-bold">{allIncidents.length}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Average Confidence</div>
            <div className="text-3xl font-bold">{(avgConfidence * 100).toFixed(1)}%</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">False Positive Rate</div>
            <div className="text-3xl font-bold">{(falsePositiveRate * 100).toFixed(1)}%</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-sm text-gray-400 mb-2">Resolved</div>
            <div className="text-3xl font-bold">{statusCounts.resolved}</div>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
          <h2 className="text-xl font-bold mb-4">Severity Distribution</h2>
          <div className="space-y-4">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div key={severity}>
                <div className="flex justify-between mb-1">
                  <span className="capitalize">{severity}</span>
                  <span>{count}</span>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      severity === "critical"
                        ? "bg-red-500"
                        : severity === "high"
                        ? "bg-orange-500"
                        : severity === "medium"
                        ? "bg-yellow-500"
                        : "bg-blue-500"
                    }`}
                    style={{
                      width: `${
                        allIncidents.length > 0 ? (count / allIncidents.length) * 100 : 0
                      }%`,
                    }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top MITRE Techniques */}
        {topMitreTechniques.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-bold mb-4">Top MITRE ATT&CK Techniques</h2>
            <div className="space-y-2">
              {topMitreTechniques.map(([techniqueId, count]) => (
                <div key={techniqueId} className="flex justify-between items-center">
                  <span className="font-mono text-green-400">{techniqueId}</span>
                  <span className="text-gray-300">{count} incidents</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

