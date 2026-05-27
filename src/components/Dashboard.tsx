/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from "react";
import { ScanResult, SecurityStats } from "../types.ts";
import { ShieldAlert, ShieldCheck, Activity, Award, Calendar, ChevronRight, RefreshCw, BarChart2 } from "lucide-react";

interface DashboardProps {
  scans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onNavigateToScan: () => void;
}

export function Dashboard({ scans, onSelectScan, onNavigateToScan }: DashboardProps) {
  // Compute overall statistics
  const stats: SecurityStats = {
    totalScans: scans.length,
    criticalCount: scans.reduce((acc, s) => acc + (s.metrics?.critical || 0), 0),
    highCount: scans.reduce((acc, s) => acc + (s.metrics?.high || 0), 0),
    mediumCount: scans.reduce((acc, s) => acc + (s.metrics?.medium || 0), 0),
    lowCount: scans.reduce((acc, s) => acc + (s.metrics?.low || 0), 0),
    averageScore: scans.length > 0 
      ? Math.round(scans.reduce((acc, s) => acc + s.securityScore, 0) / scans.length) 
      : 100,
    mostFrequentThreat: "N/A",
  };

  // Find most frequent threat category from scans
  const categoryCounts: Record<string, number> = {};
  scans.forEach((s) => {
    s.findings.forEach((f) => {
      categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
    });
  });
  let topCat = "None";
  let maxCount = 0;
  Object.entries(categoryCounts).forEach(([cat, val]) => {
    if (val > maxCount) {
      maxCount = val;
      topCat = cat;
    }
  });
  stats.mostFrequentThreat = topCat === "None" ? "N/A" : `${topCat} (${maxCount} found)`;

  // Dynamic visual ratings
  const getRatingColor = (score: number) => {
    if (score >= 90) return "text-emerald-400";
    if (score >= 75) return "text-amber-400";
    return "text-rose-500";
  };

  const getRatingBg = (score: number) => {
    if (score >= 90) return "bg-emerald-500/10 border-emerald-500/30";
    if (score >= 75) return "bg-amber-500/10 border-amber-500/30";
    return "bg-rose-500/10 border-rose-500/30";
  };

  const scoreDescription = (score: number) => {
    if (score >= 90) return "Secure Status — Code demonstrates strong security posture with low-risk metrics.";
    if (score >= 75) return "Warning Status — Unresolved medium-to-high severity vectors detected.";
    return "Critical Risk — Extreme vulnerability exposures require immediate remediation actions.";
  };

  // Calculate SVGs angles for a circular gauge
  const radius = 55;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (stats.averageScore / 100) * circumference;

  return (
    <div id="dashboard_panel" className="space-y-8">
      {/* Top Welcome Title Grid */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-6">
        <div>
          <h1 className="text-3xl font-extrabold text-zinc-100 tracking-tight">Threat Analytics Hub</h1>
          <p className="text-zinc-400 text-sm mt-1">
            Real-time Static Application Security Testing (SAST) and Dependency Intelligence Dashboard.
          </p>
        </div>
        <button
          onClick={onNavigateToScan}
          id="btn_trigger_scan_nav"
          className="px-5 py-2.5 bg-zinc-100 hover:bg-zinc-200 text-zinc-950 font-semibold rounded-lg text-sm transition-all duration-200 flex items-center gap-2 cursor-pointer shadow-sm shadow-zinc-100/10"
        >
          <Activity size={16} /> Run Security Scan
        </button>
      </div>

      {/* Grid of Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-zinc-900 border border-zinc-800/80 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 font-medium tracking-wider uppercase block">Audits Executed</span>
            <span className="text-3xl font-bold text-zinc-100">{stats.totalScans}</span>
          </div>
          <div className="p-3 bg-zinc-800/40 border border-zinc-800 rounded-lg text-blue-400">
            <Calendar size={20} />
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800/80 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 font-medium tracking-wider uppercase block">Critical Findings</span>
            <span className="text-3xl font-bold text-rose-500">{stats.criticalCount}</span>
          </div>
          <div className="p-3 bg-rose-950/20 border border-rose-900/40 rounded-lg text-rose-400 animate-pulse">
            <ShieldAlert size={20} />
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800/80 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 font-medium tracking-wider uppercase block">High/Med Findings</span>
            <span className="text-3xl font-bold text-amber-500">{stats.highCount + stats.mediumCount}</span>
          </div>
          <div className="p-3 bg-amber-950/20 border border-amber-900/40 rounded-lg text-amber-400">
            <Activity size={20} />
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800/80 p-5 rounded-xl flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-zinc-500 font-medium tracking-wider uppercase block">Primary Risk Vector</span>
            <span className="text-sm font-bold text-zinc-200 truncate max-w-[150px] block" title={stats.mostFrequentThreat}>
              {stats.mostFrequentThreat}
            </span>
          </div>
          <div className="p-3 bg-zinc-800/40 border border-zinc-800 rounded-lg text-amber-400">
            <BarChart2 size={20} />
          </div>
        </div>
      </div>

      {stats.totalScans === 0 ? (
        /* Empty State Dashboard Display */
        <div className="p-12 text-center bg-zinc-950/60 border border-zinc-800/80 rounded-2xl flex flex-col items-center justify-center space-y-4">
          <div className="p-4 bg-zinc-900/80 border border-zinc-800 text-zinc-500 rounded-full">
            <ShieldCheck size={40} />
          </div>
          <div className="max-w-md">
            <h3 className="text-lg font-bold text-zinc-200">No Audits Pending</h3>
            <p className="text-sm text-zinc-500 mt-2">
              Run your first static code, URL, or third-party dependency file scan to populate threat reports, metrics trends, and risk grades.
            </p>
          </div>
          <button
            onClick={onNavigateToScan}
            className="px-4 py-2 bg-zinc-100 text-zinc-950 rounded-lg hover:bg-zinc-200 font-medium text-xs mt-2 transition-all cursor-pointer"
          >
            Launch Scan Console
          </button>
        </div>
      ) : (
        /* Populated Statistics Grid */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Circular Security Index Gauge */}
          <div className="bg-zinc-900/60 border border-zinc-800 p-6 rounded-2xl flex flex-col items-center justify-center space-y-6">
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider text-center self-start">
              Average Security Score
            </h3>

            <div className="relative flex items-center justify-center w-40 h-40">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  className="stroke-zinc-800 fill-none"
                  strokeWidth="10"
                />
                <circle
                  cx="80"
                  cy="80"
                  r={radius}
                  className={`fill-none transition-all duration-1000 ${
                    stats.averageScore >= 90 
                      ? "stroke-emerald-400" 
                      : stats.averageScore >= 75 
                        ? "stroke-amber-400" 
                        : "stroke-rose-500"
                  }`}
                  strokeWidth="12"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute text-center">
                <span className="text-4xl font-extrabold text-zinc-100">{stats.averageScore}</span>
                <span className="text-zinc-500 text-xs block font-bold uppercase mt-0.5">PTS</span>
              </div>
            </div>

            <div className={`p-4 border rounded-xl w-full text-center ${getRatingBg(stats.averageScore)}`}>
              <span className={`text-sm font-extrabold ${getRatingColor(stats.averageScore)} uppercase tracking-wider block`}>
                {stats.averageScore >= 90 ? "A Grade — Secure" : stats.averageScore >= 75 ? "B Grade — Warning" : "F Grade — Critical"}
              </span>
              <p className="text-xs text-zinc-450 mt-1 line-clamp-2 leading-relaxed">
                {scoreDescription(stats.averageScore)}
              </p>
            </div>
          </div>

          {/* Severity & Threat Categorization */}
          <div className="bg-zinc-900/60 border border-zinc-800 p-6 rounded-2xl flex flex-col justify-between">
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider block mb-4">
              Severity Distribution
            </h3>

            <div className="space-y-4">
              {/* Critical Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-rose-500 uppercase tracking-wider">Critical Impact</span>
                  <span className="text-zinc-300">{stats.criticalCount} threats</span>
                </div>
                <div className="h-2.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-rose-500 transition-all duration-500 rounded-full"
                    style={{ width: `${stats.criticalCount > 0 ? Math.min(100, (stats.criticalCount / stats.totalScans) * 40 + 10) : 0}%` }}
                  />
                </div>
              </div>

              {/* High Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-amber-500 uppercase tracking-wider">High Impact</span>
                  <span className="text-zinc-300">{stats.highCount} threats</span>
                </div>
                <div className="h-2.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-amber-500 transition-all duration-500 rounded-full"
                    style={{ width: `${stats.highCount > 0 ? Math.min(100, (stats.highCount / stats.totalScans) * 40 + 10) : 0}%` }}
                  />
                </div>
              </div>

              {/* Medium Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-yellow-500 uppercase tracking-wider">Medium Impact</span>
                  <span className="text-zinc-300">{stats.mediumCount} threats</span>
                </div>
                <div className="h-2.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-yellow-500 transition-all duration-500 rounded-full"
                    style={{ width: `${stats.mediumCount > 0 ? Math.min(100, (stats.mediumCount / stats.totalScans) * 40 + 10) : 0}%` }}
                  />
                </div>
              </div>

              {/* Low Bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-xs font-bold">
                  <span className="text-blue-400 uppercase tracking-wider">Low Impact</span>
                  <span className="text-zinc-300">{stats.lowCount} threats</span>
                </div>
                <div className="h-2.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-400 transition-all duration-500 rounded-full"
                    style={{ width: `${stats.lowCount > 0 ? Math.min(100, (stats.lowCount / stats.totalScans) * 40 + 10) : 0}%` }}
                  />
                </div>
              </div>
            </div>

            <div className="border-t border-zinc-800 mt-5 pt-4 flex justify-between text-xs text-zinc-500">
              <span>Total vulnerabilities detected</span>
              <span className="font-bold text-zinc-300">{stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount}</span>
            </div>
          </div>

          {/* Quick Threat Categorization Breakdown (Visual Chart) */}
          <div className="bg-zinc-900/60 border border-zinc-800 p-6 rounded-2xl flex flex-col justify-between">
            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider mb-4">
              Vulnerability Categories Vetted
            </h3>

            {Object.keys(categoryCounts).length === 0 ? (
              <div className="flex-1 flex items-center justify-center py-6 text-xs text-zinc-600 font-mono">
                No threats captured yet.
              </div>
            ) : (
              <div className="space-y-2.5 flex-1 flex flex-col justify-center">
                {Object.entries(categoryCounts).slice(0, 4).map(([category, count]) => {
                  const percent = Math.round((count / (stats.criticalCount + stats.highCount + stats.mediumCount + stats.lowCount)) * 100);
                  return (
                    <div key={category} className="flex items-center justify-between text-xs">
                      <span className="text-zinc-300 font-medium truncate max-w-[200px]">{category}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-zinc-500 text-xs font-mono">{count}x</span>
                        <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-[10px] text-zinc-300 font-mono font-bold">
                          {percent}%
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="border-t border-zinc-800 mt-4 pt-4 text-xs text-zinc-500 text-center leading-relaxed font-mono">
              Intelligence integrated with OWASP Top 10 Standards
            </div>
          </div>
        </div>
      )}

      {/* Historically run scans listing */}
      {scans.length > 0 && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-md font-bold text-zinc-200 uppercase tracking-wider">
              Recent Scan Intelligence Reports
            </h3>
            <span className="text-[11px] font-mono text-zinc-500">
              {scans.length} active historical records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border-collapse">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase tracking-wider">
                  <th className="py-3 px-4 font-semibold">Report Title</th>
                  <th className="py-3 px-4 font-semibold">Type</th>
                  <th className="py-3 px-4 font-semibold">Security Score</th>
                  <th className="py-3 px-4 font-semibold">Threat Volume</th>
                  <th className="py-3 px-4 font-semibold">Execution Date</th>
                  <th className="py-3 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {scans.slice().reverse().map((scan) => {
                  const hasThreats = scan.findings.length > 0;
                  return (
                    <tr 
                      key={scan.id} 
                      className="hover:bg-zinc-800/30 transition-all cursor-pointer group"
                      onClick={() => onSelectScan(scan)}
                    >
                      <td className="py-3.5 px-4 font-semibold text-zinc-200">
                        <div className="flex flex-col">
                          <span className="group-hover:text-zinc-100 transition-colors">{scan.name}</span>
                          <span className="text-zinc-500 text-xs font-mono mt-0.5 truncate max-w-[220px]">
                            {scan.target}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                          scan.type === "code" 
                            ? "bg-purple-500/10 border border-purple-500/20 text-purple-300"
                            : scan.type === "dependencies"
                              ? "bg-blue-500/10 border border-blue-500/20 text-blue-300"
                              : "bg-amber-500/10 border border-amber-500/20 text-amber-300"
                        }`}>
                          {scan.type}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`font-mono font-bold ${getRatingColor(scan.securityScore)}`}>
                          {scan.securityScore}/100
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-1.5 font-mono text-xs text-zinc-300">
                          {hasThreats ? (
                            <span className="flex items-center gap-1 text-rose-400">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                              {scan.findings.length} findings
                            </span>
                          ) : (
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              ✓ Clean
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 text-xs font-mono text-zinc-500">
                        {new Date(scan.createdAt).toLocaleDateString()}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button 
                          className="p-1 px-2.5 hover:bg-zinc-800 hover:text-zinc-100 border border-transparent hover:border-zinc-700 text-zinc-400 text-xs rounded transition-all inline-flex items-center gap-0.5 font-medium cursor-pointer"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectScan(scan);
                          }}
                        >
                          Details <ChevronRight size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
