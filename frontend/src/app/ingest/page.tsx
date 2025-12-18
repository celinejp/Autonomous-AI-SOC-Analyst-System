/** Log Ingestion Page */

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { uploadLogs, streamAnalysis } from "@/lib/api";
import { AgentExecutionEvent } from "@/types";

export default function IngestPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState("");
  const [logs, setLogs] = useState<string[]>([]);
  const [currentAgent, setCurrentAgent] = useState<string>("");

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
    }
  };

  const processFile = async () => {
    if (!file) return;

    setIsProcessing(true);
    setProgress("Reading file...");

    try {
      const text = await file.text();
      const fileLogs = text.split("\n").filter((line) => line.trim());
      setLogs(fileLogs);
      setProgress(`Read ${fileLogs.length} log entries. Starting analysis...`);

      // Stream analysis
      let incidentId: string | undefined;

      for await (const event of streamAnalysis(fileLogs)) {
        if (event.type === "state_update") {
          const agentLogs = event.data?.agent_execution_log || [];
          if (agentLogs.length > 0) {
            const lastLog = agentLogs[agentLogs.length - 1];
            setCurrentAgent(lastLog.agent_name);
            setProgress(
              `Agent: ${lastLog.agent_name} - ${lastLog.reasoning || "Processing..."}`
            );
          }
        } else if (event.type === "complete") {
          incidentId = event.incident_id;
          setProgress("Analysis complete!");
          setIsProcessing(false);
          
          // Navigate to incident page
          if (incidentId) {
            router.push(`/incident/${incidentId}`);
          }
        } else if (event.type === "error") {
          setProgress(`Error: ${event.error}`);
          setIsProcessing(false);
        }
      }
    } catch (error) {
      setProgress(`Error: ${error instanceof Error ? error.message : "Unknown error"}`);
      setIsProcessing(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white">
      <nav className="border-b border-gray-800 bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16 items-center">
            <Link href="/" className="text-xl font-bold text-green-400">
              AI SOC Analyst
            </Link>
            <Link href="/" className="text-gray-300 hover:text-white">
              ← Back to Dashboard
            </Link>
          </div>
        </div>
      </nav>

      <main className="max-w-4xl mx-auto p-8">
        <h1 className="text-3xl font-bold mb-8">Upload Security Logs</h1>

        <div
          className="border-2 border-dashed border-gray-700 rounded-lg p-12 text-center mb-6"
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
          {file ? (
            <div>
              <div className="text-green-400 mb-2">✓ File selected</div>
              <div className="text-gray-300">{file.name}</div>
              <div className="text-sm text-gray-500 mt-2">
                {(file.size / 1024).toFixed(2)} KB
              </div>
            </div>
          ) : (
            <div>
              <div className="text-gray-400 mb-4">
                Drag and drop a log file here, or click to select
              </div>
              <input
                type="file"
                accept=".log,.txt,.json"
                onChange={handleFileSelect}
                className="hidden"
                id="file-input"
              />
              <label
                htmlFor="file-input"
                className="inline-block px-6 py-3 bg-green-600 hover:bg-green-700 rounded-lg cursor-pointer"
              >
                Select File
              </label>
            </div>
          )}
        </div>

        {file && !isProcessing && (
          <button
            onClick={processFile}
            className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold"
          >
            Analyze Logs
          </button>
        )}

        {isProcessing && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="flex items-center space-x-4 mb-4">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-green-500"></div>
              <div>
                <div className="font-semibold">{currentAgent || "Processing..."}</div>
                <div className="text-sm text-gray-400">{progress}</div>
              </div>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div className="bg-green-500 h-2 rounded-full animate-pulse" style={{ width: "60%" }}></div>
            </div>
          </div>
        )}

        {progress && !isProcessing && (
          <div className="mt-4 p-4 bg-gray-900 border border-gray-800 rounded-lg">
            {progress}
          </div>
        )}
      </main>
    </div>
  );
}

