import type { ServerConfig } from './config.js';
import type { ToolManifest } from './manifest.js';

/**
 * Everything a Rule needs to inspect a single server. Populated by discover/
 * (+ optionally resolve/ and probe/ in later weeks) before rules/ ever runs.
 *
 * `workspace` holds the manifests of *every* server in the same scan, so
 * cross-server rules (e.g. tool-name shadowing, A3) can reason about
 * contamination between servers sharing one model context window. Most rules
 * only touch `server` and `manifest`.
 */
export interface ScanContext {
  server: ServerConfig;
  manifest: ToolManifest;
  workspace: ToolManifest[];
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'certain' | 'likely' | 'possible';
export type RuleCategory = 'prompt' | 'capability' | 'source' | 'supply-chain';

export interface Finding {
  ruleId: string;
  server: string;
  location?: {
    tool?: string;
    file?: string;
    line?: number;
  };
  message: string;
  evidence: string;
  rationale: string;
  remediation: string;
}

export interface Rule {
  id: string; // e.g. "MCP-P001"
  severity: Severity;
  confidence: Confidence;
  category: RuleCategory;
  check(ctx: ScanContext): Promise<Finding[]>;
}
