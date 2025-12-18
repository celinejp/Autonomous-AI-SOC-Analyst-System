/** Incident Detail Page */

"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import { fetchIncident } from "@/lib/api";
import Link from "next/link";
import { formatDate, getSeverityColor } from "@/lib/utils";
import { useState } from "react";

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentId = params.id as string;

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => fetchIncident(incidentId),
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black text-white p-8">
        <div className="max-w-7xl mx-auto">Loading incident...</div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="min-h-screen bg-black text-white p-8">
        <div className="max-w-7xl mx-auto">Incident not found</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white">
      <nav className="border-b border-gray-800 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <Link href="/" className="text-xl font-bold text-green-400">
              AI SOC Analyst
            </Link>
            <Link href="/incidents" className="text-gray-300 hover:text-white">
              ← Back to Incidents
            </Link>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-4">
              <span
                className={`px-4 py-2 rounded-lg text-sm font-semibold ${getSeverityColor(
                  incident.severity
                )}`}
              >
                {incident.severity.toUpperCase()}
              </span>
              <span className="px-4 py-2 rounded-lg bg-gray-800 text-sm">
                {incident.status}
              </span>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-400">Confidence</div>
              <div className="text-2xl font-bold">
                {(incident.confidence_score * 100).toFixed(0)}%
              </div>
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-2">
            {incident.alerts[0]?.title || "Security Incident"}
          </h1>
          <p className="text-gray-400">
            Created: {formatDate(incident.created_at)} | Updated:{" "}
            {formatDate(incident.updated_at)}
          </p>
        </div>

        {/* Agent Execution Timeline */}
        {incident.agent_execution_log && incident.agent_execution_log.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
            <h2 className="text-xl font-bold mb-4">Agent Execution Timeline</h2>
            <div className="space-y-4">
              {incident.agent_execution_log.map((log, idx) => (
                <div key={idx} className="border-l-2 border-green-500 pl-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <span className="font-semibold text-green-400">{log.agent_name}</span>
                    <span className="text-xs text-gray-500">{log.timestamp}</span>
                    {log.duration_ms && (
                      <span className="text-xs text-gray-500">
                        ({log.duration_ms.toFixed(0)}ms)
                      </span>
                    )}
                  </div>
                  {log.tools_used && log.tools_used.length > 0 && (
                    <div className="text-sm text-gray-400 mb-2">
                      Tools: {log.tools_used.join(", ")}
                    </div>
                  )}
                  {log.reasoning && (
                    <div className="text-sm text-gray-300">{log.reasoning}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Incident Report */}
        {incident.report && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
            <h2 className="text-xl font-bold mb-4">Analysis Report</h2>
            <div className="space-y-6">
              <div>
                <h3 className="font-semibold mb-2">Executive Summary</h3>
                <p className="text-gray-300">{incident.report.executive_summary}</p>
              </div>
              <div>
                <h3 className="font-semibold mb-2">Technical Findings</h3>
                <p className="text-gray-300 whitespace-pre-wrap">
                  {incident.report.technical_findings}
                </p>
              </div>
              <div>
                <h3 className="font-semibold mb-2">Root Cause</h3>
                <p className="text-gray-300">{incident.report.root_cause}</p>
              </div>
              <div>
                <h3 className="font-semibold mb-2">Affected Assets</h3>
                <div className="flex flex-wrap gap-2">
                  {incident.report.affected_assets.map((asset, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1 bg-gray-800 rounded text-sm"
                    >
                      {asset}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* MITRE ATT&CK Techniques */}
        {incident.mitre_techniques && incident.mitre_techniques.length > 0 && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
            <h2 className="text-xl font-bold mb-4">MITRE ATT&CK Techniques</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {incident.mitre_techniques.map((tech, idx) => (
                <div key={idx} className="border border-gray-700 rounded p-4">
                  <div className="font-semibold text-green-400 mb-1">
                    {tech.technique_id}: {tech.name}
                  </div>
                  <div className="text-sm text-gray-400 mb-2">{tech.tactic}</div>
                  <div className="text-sm text-gray-300">{tech.description}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Response Plan */}
        {incident.response_plan && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-bold mb-4">Response Plan</h2>
            <div className="space-y-6">
              {incident.response_plan.containment_actions.length > 0 && (
                <div>
                  <h3 className="font-semibold text-red-400 mb-3">
                    Immediate Containment Actions
                  </h3>
                  <ul className="space-y-2">
                    {incident.response_plan.containment_actions.map((action, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <input
                          type="checkbox"
                          className="mt-1"
                          disabled={action.status === "completed"}
                          checked={action.status === "completed"}
                        />
                        <div>
                          <div className="font-medium">{action.action}</div>
                          <div className="text-sm text-gray-400">{action.description}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {incident.response_plan.investigation_steps.length > 0 && (
                <div>
                  <h3 className="font-semibold text-orange-400 mb-3">
                    Investigation Steps
                  </h3>
                  <ul className="space-y-2">
                    {incident.response_plan.investigation_steps.map((action, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <input type="checkbox" className="mt-1" />
                        <div>
                          <div className="font-medium">{action.action}</div>
                          <div className="text-sm text-gray-400">{action.description}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {incident.response_plan.remediation_actions.length > 0 && (
                <div>
                  <h3 className="font-semibold text-yellow-400 mb-3">
                    Remediation Actions
                  </h3>
                  <ul className="space-y-2">
                    {incident.response_plan.remediation_actions.map((action, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <input type="checkbox" className="mt-1" />
                        <div>
                          <div className="font-medium">{action.action}</div>
                          <div className="text-sm text-gray-400">{action.description}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

