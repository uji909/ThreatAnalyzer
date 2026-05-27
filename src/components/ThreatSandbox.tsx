/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from "react";
import { Finding, ScanResult } from "../types.ts";
import { ShieldCheck, ShieldAlert, Sparkles, Terminal, Play, RotateCcw, AlertCircle, FileCode, CheckCircle2 } from "lucide-react";

const PLAYGROUND_PRESETS = [
  {
    name: "CWE-89: SQL Injection",
    code: `public User lookUpUser(String inputName) {
    // concatenate direct input strings
    String query = "SELECT * FROM accounts WHERE owner = '" + inputName + "'";
    return db.query(query, new UserRowMapper());
}`,
    remediation: `public User lookUpUser(String inputName) {
    // SECURE: Use prepared statements placeholders
    String query = "SELECT * FROM accounts WHERE owner = ?";
    return db.query(query, new Object[]{ inputName }, new UserRowMapper());
}`,
    explanation: "Parameterization ensures database values are parsed strictly as literals rather than structural operators, completely choking SQL injection strings."
  },
  {
    name: "CWE-78: Command Injection",
    code: `public void generateReport(String filename) throws Exception {
    // Vulnerable process command invocation
    String scriptPath = "/opt/bin/report.sh " + filename;
    Runtime.getRuntime().exec(scriptPath);
}`,
    remediation: `public void generateReport(String filename) throws Exception {
    // SECURE: Sanitize, normalize and isolate commands
    if (!filename.matches("^[a-zA-Z0-9_-]+$")) {
        throw new IllegalArgumentException("Invalid filename characters");
    }
    ProcessBuilder pb = new ProcessBuilder("/opt/bin/report.sh", filename);
    pb.start();
}`,
    explanation: "Explicit array structures inside ProcessBuilder completely isolate variables, halting variable interpolation. Rigid regex allowlists safeguard filenames."
  },
  {
    name: "CWE-798: Hardcoded Token",
    code: `public class AuthProvider {
    // Private database API entry key credentials
    private static final String AWS_SECRET_TOKEN = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY";
}`,
    remediation: `public class AuthProvider {
    // SECURE: Bind token dynamically to system environments
    private static final String AWS_SECRET_TOKEN = System.getenv("AWS_SECRET_KEY");
}`,
    explanation: "Enviroments bindings guarantee secrets never leak into public Git repositories. Key rotating frameworks verify keys securely without recompilation."
  }
];

export function ThreatSandbox() {
  const [selectedPreset, setSelectedPreset] = useState(PLAYGROUND_PRESETS[0]);
  const [rawCode, setRawCode] = useState(PLAYGROUND_PRESETS[0].code);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [lastResults, setLastResults] = useState<ScanResult | null>(null);
  const [activeRemediation, setActiveRemediation] = useState<string | null>(PLAYGROUND_PRESETS[0].remediation);
  const [activeExplanation, setActiveExplanation] = useState<string | null>(PLAYGROUND_PRESETS[0].explanation);
  const [showSecurePreview, setShowSecurePreview] = useState(false);

  // Trigger scanning check
  const handleAnalyze = async () => {
    setIsAnalyzing(true);
    setLastResults(null);

    try {
      const response = await fetch("/api/scan/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: rawCode, fileName: "Sandbox_Code.java" }),
      });
      if (response.ok) {
        const result: ScanResult = await response.json();
        setLastResults(result);
        
        // If findings are retrieved, load remediation parameters from the first finding if applicable
        if (result.findings.length > 0) {
          const first = result.findings[0];
          setActiveRemediation(first.remediation);
          setActiveExplanation(first.description + " Remediation: Use parameters bind structures.");
        } else {
          setActiveRemediation("// Strong work! Code represents static safety protocols.");
          setActiveExplanation("No security flags found. The code adheres to clean parameterization or isolated executions.");
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSelectPreset = (p: typeof PLAYGROUND_PRESETS[0]) => {
    setSelectedPreset(p);
    setRawCode(p.code);
    setActiveRemediation(p.remediation);
    setActiveExplanation(p.explanation);
    setLastResults(null);
    setShowSecurePreview(false);
  };

  return (
    <div id="threat_sandbox_wrapper" className="space-y-6">
      {/* Description block */}
      <div>
        <h2 className="text-2xl font-extrabold text-zinc-100 tracking-tight flex items-center gap-2">
          <Terminal size={24} className="text-blue-400" /> Threat Sandbox & Playground
        </h2>
        <p className="text-zinc-400 text-xs mt-1">
          An interactive playground. Select dynamic vulnerability vectors, view real-time analysis logs, and experience immediate secure code refactoring directly on the viewport canvas.
        </p>
      </div>

      {/* Preset Pickers selection */}
      <div className="flex flex-wrap gap-2">
        {PLAYGROUND_PRESETS.map((p) => {
          const isSelected = p.name === selectedPreset.name;
          return (
            <button
              key={p.name}
              onClick={() => handleSelectPreset(p)}
              disabled={isAnalyzing}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all cursor-pointer ${
                isSelected
                  ? "bg-zinc-100 border-zinc-100 text-zinc-950 font-bold"
                  : "bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-250"
              }`}
            >
              {p.name}
            </button>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Side: Vulnerable Code canvas */}
        <div className="space-y-3 text-left">
          <div className="flex items-center justify-between">
            <span className="text-xs font-extrabold text-zinc-400 uppercase tracking-widest font-mono flex items-center gap-1.5">
              <FileCode size={14} /> Interactive Code Canvas
            </span>
            <button
              onClick={() => {
                setRawCode(selectedPreset.code);
                setLastResults(null);
              }}
              disabled={isAnalyzing}
              className="text-[10px] font-bold text-zinc-500 hover:text-zinc-300 font-mono flex items-center gap-1 cursor-pointer"
            >
              <RotateCcw size={10} /> Reset Canvas
            </button>
          </div>

          <div className="relative border border-zinc-850 rounded-xl overflow-hidden bg-zinc-950">
            <textarea
              value={rawCode}
              onChange={(e) => {
                setRawCode(e.target.value);
                if (lastResults) setLastResults(null);
              }}
              disabled={isAnalyzing}
              className="w-full bg-zinc-950 text-rose-300/90 font-mono text-[11px] p-4 h-[240px] focus:outline-none leading-relaxed resize-none border-0"
              placeholder="Inject, modify, or paste computer scripts to see on-the-fly SAST parsing results..."
            />

            {/* Float Run indicator */}
            <button
              onClick={handleAnalyze}
              disabled={isAnalyzing || !rawCode}
              className="absolute bottom-3 right-3 px-4 py-2 bg-zinc-100 hover:bg-zinc-200 text-zinc-950 font-bold rounded-lg text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-md disabled:opacity-40"
            >
              <Play size={10} fill="currentColor" /> Analyze Target Code
            </button>
          </div>
        </div>

        {/* Right Side: Annotations and suggestions */}
        <div className="space-y-3.5 text-left">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowSecurePreview(false)}
              className={`px-3 py-1 font-bold text-xs rounded transition-all cursor-pointer ${
                !showSecurePreview 
                  ? "bg-zinc-850 text-zinc-100" 
                  : "text-zinc-500 hover:text-zinc-350"
              }`}
            >
              Vulnerability Audits
            </button>
            <button
              onClick={() => setShowSecurePreview(true)}
              className={`px-3 py-1 font-bold text-xs rounded transition-all cursor-pointer ${
                showSecurePreview 
                  ? "bg-zinc-850 text-zinc-100" 
                  : "text-zinc-500 hover:text-zinc-350"
              }`}
            >
              Secure Solution Proposal
            </button>
          </div>

          {!showSecurePreview ? (
            /* Vulnerabilities annotations */
            <div className="bg-zinc-900/60 border border-zinc-800 p-5 rounded-xl block min-h-[240px] flex flex-col justify-between space-y-4">
              {isAnalyzing ? (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-2 font-mono">
                  <span className="w-6 h-6 border-2 border-zinc-500 border-t-zinc-200 rounded-full animate-spin" />
                  <span className="text-[11px] text-zinc-500">Evaluating dynamic code triggers...</span>
                </div>
              ) : lastResults ? (
                <div className="space-y-4 flex-1">
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert size={16} />
                      <span className="text-xs font-bold font-mono">
                        Security Index: {lastResults.securityScore}/100
                      </span>
                    </div>
                    <span className="text-[10px] bg-rose-500/20 text-rose-300 font-bold px-1.5 py-0.5 rounded font-mono">
                      {lastResults.findings.length} FINDINGS
                    </span>
                  </div>

                  {lastResults.findings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-6 text-center text-emerald-400 space-y-2">
                      <ShieldCheck size={36} />
                      <p className="text-xs font-bold">Dynamic Evaluation Passed Successfully!</p>
                      <span className="text-[10px] text-zinc-500 font-mono">No known security flags or injection anchors triggered references.</span>
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-[140px] overflow-y-auto">
                      {lastResults.findings.map((f, i) => (
                        <div key={i} className="p-3 bg-zinc-950 border-l-2 border-rose-500 rounded-lg space-y-1">
                          <span className="text-[10px] font-mono text-rose-400 font-bold block">{f.name}</span>
                          <span className="text-[10px] text-zinc-400 block font-normal leading-relaxed">{f.description}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-zinc-600 font-mono space-y-2">
                  <AlertCircle size={32} className="text-zinc-700" />
                  <p className="text-xs">No scan evaluated.</p>
                  <span className="text-[10px] text-zinc-550 max-w-xs block leading-relaxed">
                    Click "Analyze Target Code" to run the SAST pattern engines or switch directly to "Secure Solution Proposal" to review pre-compiled remediations.
                  </span>
                </div>
              )}

              {lastResults && lastResults.findings.length > 0 && (
                <button
                  onClick={() => setShowSecurePreview(true)}
                  className="w-full py-2 bg-zinc-800 hover:bg-zinc-750 text-zinc-200 border border-zinc-700 text-xs font-bold rounded-lg transition-all cursor-pointer flex items-center justify-center gap-1"
                >
                  <Sparkles size={12} className="text-blue-400" /> Learn Secure Refactoring
                </button>
              )}
            </div>
          ) : (
            /* Secure Solution block */
            <div className="space-y-4">
              <div className="border border-emerald-950/30 rounded-xl overflow-hidden bg-emerald-950/5">
                <div className="px-4 py-2 bg-emerald-950/20 border-b border-emerald-900/30 flex items-center justify-between">
                  <span className="text-xs font-extrabold text-emerald-400 font-mono tracking-wider flex items-center gap-1.5">
                    <ShieldCheck size={14} /> SECURE COMPLIANT REMEDIATION
                  </span>
                  <button
                    onClick={() => {
                      if (activeRemediation) setRawCode(activeRemediation);
                      setShowSecurePreview(false);
                      setLastResults(null);
                    }}
                    className="text-[10px] px-2 py-0.5 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/30 text-emerald-300 font-bold font-mono rounded cursor-pointer transition-all flex items-center gap-0.5"
                  >
                    <CheckCircle2 size={10} /> Apply Fix to Canvas
                  </button>
                </div>
                <pre className="p-4 font-mono text-[10px] text-emerald-300/80 overflow-x-auto whitespace-pre leading-relaxed bg-zinc-950 h-[190px]">
                  {activeRemediation}
                </pre>
              </div>

              {activeExplanation && (
                <div className="p-4 bg-zinc-950/50 border border-zinc-850 rounded-xl space-y-1.5 text-xs text-zinc-350">
                  <span className="font-bold text-zinc-200 block uppercase tracking-wider text-[10px] font-mono">Security Advice:</span>
                  <p className="leading-relaxed font-sans">{activeExplanation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
