/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface VulnerabilityDef {
  cweId: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  commonCVEs: string[];
  vulnerableExample: string;
  secureExample: string;
  remediationExplanation: string;
}

export interface Finding {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  cweId?: string;
  context?: string; // Location or context of locating (e.g. file name, line reference, URL element)
  line?: number;    // Line number if code scan
  evidence?: string; // Code snippet or network response detail
  remediation: string;
}

export interface ScanResult {
  id: string;
  name: string; // Title of the scan
  target: string; // Executable snippet preview, file name, dependency file name, or URL
  type: "code" | "dependencies" | "web";
  createdAt: string;
  status: "scanning" | "completed" | "failed";
  securityScore: number; // 0 to 100 where higher is better
  findings: Finding[];
  summary: string;
  metrics: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export interface SecurityStats {
  totalScans: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  averageScore: number;
  mostFrequentThreat: string;
}
