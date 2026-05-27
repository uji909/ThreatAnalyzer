/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ScanResult, Finding, Severity } from "../types.ts";
import { ShieldAlert, ShieldCheck, Printer, ArrowLeft, AlertTriangle, Cpu, Tag, Flame, CheckCircle, FileText } from "lucide-react";

interface ReportViewerProps {
  scan: ScanResult;
  onBack: () => void;
  engineMode: { hasGeminiKey: boolean; text: string };
}

export function ReportViewer({ scan, onBack, engineMode }: ReportViewerProps) {
  const getSeverityStyle = (sev: Severity) => {
    switch (sev) {
      case "CRITICAL":
        return "bg-rose-500/10 border-rose-500/30 text-rose-400";
      case "HIGH":
        return "bg-amber-500/10 border-amber-500/30 text-amber-400";
      case "MEDIUM":
        return "bg-yellow-500/10 border-yellow-500/30 text-yellow-300";
      case "LOW":
        return "bg-blue-500/10 border-blue-500/30 text-blue-400";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
    if (score >= 75) return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    return "text-rose-500 border-rose-500/30 bg-rose-500/10";
  };

  const handlePrint = () => {
    // Standard window print. The clean CSS utility @media print below ensures a formatted layout
    window.print();
  };

  return (
    <div id="security_report_viewer" className="space-y-6 print:p-8 print:bg-white print:text-zinc-950">
      {/* Navigation and Actions - HIDDEN IN PRINT */}
      <div className="flex items-center justify-between border-b border-zinc-850 pb-5 pt-1 print:hidden">
        <button
          onClick={onBack}
          className="px-4 py-2 bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-300 hover:text-zinc-100 rounded-lg text-xs transition-all flex items-center gap-2 cursor-pointer"
        >
          <ArrowLeft size={14} /> Back to Dashboard
        </button>

        <button
          onClick={handlePrint}
          className="px-4 py-2 bg-zinc-100 hover:bg-zinc-200 text-zinc-950 font-bold rounded-lg text-xs transition-all flex items-center gap-2 cursor-pointer shadow-md shadow-zinc-100/10"
        >
          <Printer size={14} /> Export / Print Audit Report
        </button>
      </div>

      {/* Main Report Body Canvas */}
      <div className="space-y-6">
        {/* Header Block */}
        <div className="bg-zinc-950 p-6 border border-zinc-900 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-6 print:border-zinc-305 print:bg-zinc-50 print:p-5">
          <div className="space-y-1.5 text-left">
            <span className="text-[10px] font-extrabold text-zinc-500 uppercase tracking-widest font-mono block">
              Security Static Audit Report
            </span>
            <h2 className="text-xl md:text-2xl font-extrabold text-zinc-100 tracking-tight print:text-zinc-900">
              {scan.name}
            </h2>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-450 font-mono print:text-zinc-645">
              <span>Audited on: {new Date(scan.createdAt).toLocaleString()}</span>
              <span>•</span>
              <span className="capitalize">Target: <strong className="text-zinc-300 font-semibold print:text-zinc-800">{scan.target}</strong></span>
              <span>•</span>
              <span className="capitalize">Audit Type: <strong className="text-zinc-300 font-semibold print:text-zinc-800">{scan.type}</strong></span>
            </div>
          </div>

          {/* Large Security Rating Indicator */}
          <div className={`p-4 border rounded-xl text-center min-w-[130px] flex flex-col justify-center items-center ${getScoreColor(scan.securityScore)} print:border-zinc-300`}>
            <span className="text-2xl font-black font-mono tracking-tighter">
              {scan.securityScore}/100
            </span>
            <span className="text-[9px] font-bold uppercase tracking-wider block mt-1 opacity-80">
              SECURITY SCORE
            </span>
          </div>
        </div>

        {/* Executive Summary Narrative */}
        <div className="p-5 bg-zinc-900/40 border border-zinc-850 rounded-2xl text-left space-y-2 print:border-zinc-300">
          <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 font-mono print:text-zinc-500">
            <FileText size={14} /> Executive Summary Guidance
          </h3>
          <p className="text-sm text-zinc-250 leading-relaxed font-sans print:text-zinc-800 pr-2">
            {scan.summary}
          </p>
          <div className="text-[10px] font-mono text-zinc-500 pt-1 block print:text-zinc-600">
            Scanning engine invoked: <strong>{engineMode.hasGeminiKey ? "Gemini 3.5 secure AI pipeline" : "Local Security signature scanner"}</strong>. Standards mapping: OWASP Top 10 guidelines and CWE indexing.
          </div>
        </div>

        {/* Metric breakdowns column grids */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="bg-zinc-900/60 border border-zinc-850 p-4 rounded-xl text-center print:border-zinc-300">
            <span className="text-[11px] font-extrabold font-mono text-rose-400 block tracking-wider">CRITICAL</span>
            <span className="text-2xl font-extrabold text-zinc-100 block mt-1 print:text-zinc-900">{scan.metrics?.critical || 0}</span>
          </div>
          <div className="bg-zinc-900/60 border border-zinc-850 p-4 rounded-xl text-center print:border-zinc-300">
            <span className="text-[11px] font-extrabold font-mono text-amber-500 block tracking-wider">HIGH</span>
            <span className="text-2xl font-extrabold text-zinc-100 block mt-1 print:text-zinc-900">{scan.metrics?.high || 0}</span>
          </div>
          <div className="bg-zinc-900/60 border border-zinc-850 p-4 rounded-xl text-center print:border-zinc-300">
            <span className="text-[11px] font-extrabold font-mono text-yellow-500 block tracking-wider">MEDIUM</span>
            <span className="text-2xl font-extrabold text-zinc-100 block mt-1 print:text-zinc-900">{scan.metrics?.medium || 0}</span>
          </div>
          <div className="bg-zinc-900/60 border border-zinc-850 p-4 rounded-xl text-center print:border-zinc-300">
            <span className="text-[11px] font-extrabold font-mono text-blue-400 block tracking-wider">LOW</span>
            <span className="text-2xl font-extrabold text-zinc-100 block mt-1 print:text-zinc-900">{scan.metrics?.low || 0}</span>
          </div>
          <div className="col-span-2 md:col-span-1 bg-zinc-900/60 border border-zinc-850 p-4 rounded-xl text-center print:border-zinc-300">
            <span className="text-[11px] font-extrabold font-mono text-zinc-400 block tracking-wider">TOTAL RISK</span>
            <span className="text-2xl font-extrabold text-zinc-100 block mt-1 print:text-zinc-900">{scan.findings.length}</span>
          </div>
        </div>

        {/* Main Findings breakdown rows */}
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-850 pb-2 print:border-zinc-300">
            <h3 className="text-sm font-bold text-zinc-300 uppercase tracking-wider print:text-zinc-900">
              Detailed Auditing Discoveries ({scan.findings.length} records)
            </h3>
            <span className="text-[11px] font-mono text-zinc-500 print:hidden">Expand detail lines below</span>
          </div>

          {scan.findings.length === 0 ? (
            <div className="p-12 text-center bg-zinc-950/40 border border-zinc-900 rounded-2xl flex flex-col items-center justify-center space-y-3">
              <CheckCircle size={40} className="text-emerald-400 animate-pulse" />
              <div>
                <span className="text-sm font-bold text-zinc-200 block">No Security Risks Vetted!</span>
                <p className="text-xs text-zinc-500 max-w-sm mt-1 leading-relaxed">
                  Excellent development! The files, URLs, or manifests are clean of baseline signature targets. Continuous scanning is encouraged.
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-4 print:space-y-6">
              {scan.findings.map((f, idx) => (
                <div
                  key={f.id || idx}
                  className="bg-zinc-900/50 border border-zinc-850 rounded-xl overflow-hidden text-left space-y-4 p-5 print:break-inside-avoid print:bg-white print:border-zinc-300 print:shadow-none"
                >
                  {/* Finding Title Header row */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-zinc-850/60 pb-3 print:border-zinc-300">
                    <div className="space-y-1 flex-1 pr-4">
                      <div className="flex items-center gap-2 flex-wrap">
                        {f.cweId && (
                          <span className="px-2 py-0.5 bg-blue-900/20 border border-blue-900/40 rounded text-[9px] font-mono font-extrabold text-blue-400 tracking-wider">
                            {f.cweId}
                          </span>
                        )}
                        <span className="text-[10px] text-zinc-500 font-mono flex items-center gap-1">
                          <Tag size={10} /> {f.category}
                        </span>
                        {f.context && (
                          <span className="text-[10px] text-zinc-500 font-mono truncate max-w-[200px]">
                            • {f.context}
                          </span>
                        )}
                      </div>
                      <h4 className="text-sm font-extrabold text-zinc-200 mt-1 print:text-zinc-950 leading-snug">
                        {f.name}
                      </h4>
                    </div>

                    <span className={`px-2.5 py-1 rounded text-[10px] font-extrabold font-mono tracking-wider text-center block h-fit border ${getSeverityStyle(f.severity)} print:border-zinc-300`}>
                      {f.severity} IMPACT
                    </span>
                  </div>

                  {/* Finding Description detail */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-extrabold text-zinc-500 uppercase tracking-widest font-mono block print:text-zinc-500">
                      Discovery & Assessment Explanations
                    </span>
                    <p className="text-xs text-zinc-350 leading-relaxed font-sans print:text-zinc-850">
                      {f.description}
                    </p>
                  </div>

                  {/* Finding Evidence code block detail */}
                  {f.evidence && (
                    <div className="space-y-1 print:break-inside-avoid">
                      <span className="text-[10px] font-extrabold text-zinc-500 uppercase tracking-widest font-mono block print:text-zinc-550">
                        Vulnerable Segment Matched (Evidence)
                      </span>
                      <pre className="p-3 bg-zinc-950 font-mono text-[9px] text-zinc-300 overflow-x-auto whitespace-pre leading-relaxed border border-zinc-900/80 rounded-lg max-h-[140px] print:bg-zinc-50 print:text-zinc-800 print:border-zinc-300">
                        {f.evidence}
                      </pre>
                    </div>
                  )}

                  {/* Remediation Guide instructions */}
                  <div className="space-y-1.5 border-t border-zinc-850/40 pt-3.5 print:break-inside-avoid print:border-zinc-300">
                    <span className="text-[10px] font-extrabold text-emerald-400 uppercase tracking-widest font-mono flex items-center gap-1 pr-1 print:text-emerald-600">
                      <CheckCircle size={12} /> SECURE RESOLUTION REMEDIATION
                    </span>
                    <p className="text-xs text-zinc-300 font-sans leading-relaxed bg-zinc-950/20 p-3 border border-zinc-900 rounded-lg border-l-2 border-l-emerald-500 print:bg-emerald-50/20 print:text-zinc-900 print:border-zinc-300">
                      {f.remediation}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
