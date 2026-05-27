/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from "react";
import { ScanResult } from "./types.ts";
import { Dashboard } from "./components/Dashboard.tsx";
import { ScanConsole } from "./components/ScanConsole.tsx";
import { VulnerabilityDB } from "./components/VulnerabilityDB.tsx";
import { ThreatSandbox } from "./components/ThreatSandbox.tsx";
import { ReportViewer } from "./components/ReportViewer.tsx";
import { ShieldCheck, Cpu, Database, Play, BookOpen, Layers, Terminal, Server, ExternalLink } from "lucide-react";

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "scan" | "vulndb" | "sandbox">("dashboard");
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  
  // Server State Details
  const [engineMode, setEngineMode] = useState<{ hasGeminiKey: boolean; text: string }>({
    hasGeminiKey: false,
    text: "Offline Local Signature Engine",
  });

  // Verify server setup on mount
  useEffect(() => {
    async function checkServerHealth() {
      try {
        const response = await fetch("/api/health");
        if (response.ok) {
          const data = await response.json();
          setEngineMode({
            hasGeminiKey: data.hasGeminiKey,
            text: data.engine || "Local Advanced SAST Engine",
          });
        }
      } catch (err) {
        console.error("Connection failure to Threat Analyzer Express Server:", err);
      }
    }
    checkServerHealth();
  }, []);

  // Handle addition of a new scan result
  const handleAddNewScan = (newScan: ScanResult) => {
    setScans((prev) => [...prev, newScan]);
    setSelectedScan(newScan); // Route immediately to the report page
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans flex flex-col selection:bg-zinc-750 selection:text-white">
      {/* Top Header Banner Control (Hidden in Print) */}
      <header className="bg-zinc-900 border-b border-zinc-800/80 sticky top-0 z-40 transition-all duration-200 print:hidden px-4 md:px-8">
        <div className="max-w-7xl mx-auto flex items-center justify-between h-16">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-zinc-800 border border-zinc-700/60 rounded-lg text-zinc-100 shadow-sm">
              <ShieldCheck className="text-zinc-100" size={20} />
            </div>
            <div>
              <span className="text-sm font-bold tracking-tight text-zinc-150">THR3AT_ANALYZER_SYS</span>
              <span className="text-[10px] bg-zinc-800 border border-zinc-750 text-zinc-400 font-bold block px-1 rounded font-mono uppercase text-center mt-0.5 max-w-fit">
                V1.0.2 SECURE
              </span>
            </div>
          </div>
          
          <div className="flex items-center gap-4 text-xs font-mono text-zinc-400">
            <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-zinc-950/40 border border-zinc-850 rounded-lg">
              <Server size={12} className="text-zinc-500" />
              <span>Host Node: <strong className="text-zinc-200 font-semibold">Cloud Sandbox Ingress Gate 3000</strong></span>
            </div>
          </div>
        </div>
      </header>

      {/* Main split dashboard pane */}
      <div className="flex-1 flex max-w-7xl w-full mx-auto md:px-6 lg:px-8 py-8 gap-8">
        {/* Navigation Sidebar (Hidden in Print) */}
        <nav className="w-64 shrink-0 hidden md:flex flex-col space-y-2 border-r border-zinc-900 pr-6 print:hidden">
          <div className="pb-4 pl-3">
            <span className="text-[10px] font-mono font-bold text-zinc-500 tracking-wider uppercase">Navigation System</span>
          </div>

          <button
            onClick={() => {
              setActiveTab("dashboard");
              setSelectedScan(null);
            }}
            className={`w-full flex items-center gap-3 p-3 text-sm font-bold rounded-xl transition-all text-left cursor-pointer ${
              activeTab === "dashboard" && !selectedScan
                ? "bg-zinc-900 text-zinc-100"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/45"
            }`}
          >
            <Layers size={18} /> Stats Dashboard
          </button>

          <button
            onClick={() => {
              setActiveTab("scan");
              setSelectedScan(null);
            }}
            className={`w-full flex items-center gap-3 p-3 text-sm font-bold rounded-xl transition-all text-left cursor-pointer ${
              activeTab === "scan" && !selectedScan
                ? "bg-zinc-900 text-zinc-100"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/45"
            }`}
          >
            <Play size={18} /> Scan Console
          </button>

          <button
            onClick={() => {
              setActiveTab("vulndb");
              setSelectedScan(null);
            }}
            className={`w-full flex items-center gap-3 p-3 text-sm font-bold rounded-xl transition-all text-left cursor-pointer ${
              activeTab === "vulndb" && !selectedScan
                ? "bg-zinc-900 text-zinc-100"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/45"
            }`}
          >
            <Database size={18} /> Knowledgebase (VulnDB)
          </button>

          <button
            onClick={() => {
              setActiveTab("sandbox");
              setSelectedScan(null);
            }}
            className={`w-full flex items-center gap-3 p-3 text-sm font-bold rounded-xl transition-all text-left cursor-pointer ${
              activeTab === "sandbox" && !selectedScan
                ? "bg-zinc-900 text-zinc-100"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/45"
            }`}
          >
            <Terminal size={18} /> Threat Sandbox
          </button>

          {selectedScan && (
            <div className="pt-4 border-t border-zinc-900 mt-4 space-y-1">
              <span className="text-[10px] font-mono font-bold text-zinc-550 uppercase tracking-wider block pl-3 mb-1">
                Active Audit Report
              </span>
              <button
                onClick={() => setActiveTab("dashboard")}
                className="w-full flex items-center gap-3 p-3 text-xs font-bold rounded-xl transition-all text-left bg-zinc-900/40 text-blue-400 border border-zinc-800 cursor-pointer"
              >
                <Cpu size={14} /> View Report Details
              </button>
            </div>
          )}
        </nav>

        {/* Dynamic active viewport display panel */}
        <main className="flex-1 bg-zinc-950 px-4 md:px-0 scrollbar-thin">
          {/* Mobile responsive Quick Tabs - HIDDEN ON DESKTOP & PRINT */}
          <div className="flex md:hidden bg-zinc-900 p-1 border border-zinc-800 rounded-xl mb-6 flex-wrap gap-1 print:hidden">
            <button
              onClick={() => {
                setActiveTab("dashboard");
                setSelectedScan(null);
              }}
              className={`flex-1 min-w-[100px] text-center p-2 rounded-lg text-xs font-bold transition-all ${
                activeTab === "dashboard" && !selectedScan ? "bg-zinc-805 text-zinc-100" : "text-zinc-400"
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => {
                setActiveTab("scan");
                setSelectedScan(null);
              }}
              className={`flex-1 min-w-[100px] text-center p-2 rounded-lg text-xs font-bold transition-all ${
                activeTab === "scan" && !selectedScan ? "bg-zinc-805 text-zinc-100" : "text-zinc-400"
              }`}
            >
              Scan
            </button>
            <button
              onClick={() => {
                setActiveTab("vulndb");
                setSelectedScan(null);
              }}
              className={`flex-1 min-w-[100px] text-center p-2 rounded-lg text-xs font-bold transition-all ${
                activeTab === "vulndb" ? "bg-zinc-805 text-zinc-100" : "text-zinc-400"
              }`}
            >
              VulnDB
            </button>
            <button
              onClick={() => {
                setActiveTab("sandbox");
                setSelectedScan(null);
              }}
              className={`flex-1 min-w-[100px] text-center p-2 rounded-lg text-xs font-bold transition-all ${
                activeTab === "sandbox" ? "bg-zinc-805 text-zinc-100" : "text-zinc-400"
              }`}
            >
              Sandbox
            </button>
          </div>

          {/* Core Viewport router panels */}
          {selectedScan ? (
            <ReportViewer
              scan={selectedScan}
              onBack={() => {
                setSelectedScan(null);
                setActiveTab("dashboard");
              }}
              engineMode={engineMode}
            />
          ) : (
            <>
              {activeTab === "dashboard" && (
                <Dashboard
                  scans={scans}
                  onSelectScan={(scan) => setSelectedScan(scan)}
                  onNavigateToScan={() => setActiveTab("scan")}
                />
              )}
              {activeTab === "scan" && (
                <ScanConsole
                  onScanCompleted={handleAddNewScan}
                  engineMode={engineMode}
                />
              )}
              {activeTab === "vulndb" && <VulnerabilityDB />}
              {activeTab === "sandbox" && <ThreatSandbox />}
            </>
          )}
        </main>
      </div>

      {/* Persistent Footer design (Hidden in Print) */}
      <footer className="border-t border-zinc-900 bg-zinc-950 py-6 mt-16 print:hidden">
        <div className="max-w-7xl mx-auto px-4 md:px-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs font-mono text-zinc-550">
          <span>
            © 2026 Threat Analyzer Sandbox. Curated for educational secure software development training.
          </span>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1">
              OWASP Standard compliant <ExternalLink size={12} />
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
