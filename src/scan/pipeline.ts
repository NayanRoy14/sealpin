import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import type { Finding, ScanContext, Severity } from '../types/rule.js';
import { runRules, meetsSeverity, severityOf, severityRank } from '../rules/index.js';
import { analyzeWorkspace } from '../capabilities/index.js';
import type { ReportSummary } from '../report/index.js';
import type { ServerSource, SourceResolver } from '../resolve/index.js';
import { emptyManifestSource, type ManifestSource } from './manifest-source.js';

export interface ScanOptions {
  manifestSource?: ManifestSource;
  /** When set, each server's source is resolved and made available to source-AST rules. */
  sourceResolver?: SourceResolver;
  /** Drop findings below this severity from the report. */
  minSeverity?: Severity;
}

/**
 * The full scan: for each discovered server, load its manifest (empty if
 * unavailable — capability rules still apply to the config alone), build a
 * ScanContext with the whole workspace visible, run every rule, and collect
 * severity-sorted findings.
 */
export async function scanServers(servers: ServerConfig[], options: ScanOptions = {}): Promise<ReportSummary> {
  const source = options.manifestSource ?? emptyManifestSource;

  const manifests = new Map<string, ToolManifest>();
  let serversWithManifest = 0;
  for (const server of servers) {
    const manifest = await source.load(server);
    if (manifest) {
      manifests.set(server.name, manifest);
      serversWithManifest += 1;
    }
  }

  const workspace = [...manifests.values()];

  const sources = new Map<string, ServerSource>();
  if (options.sourceResolver) {
    for (const server of servers) {
      try {
        const resolved = await options.sourceResolver.resolve(server);
        if (resolved) sources.set(server.name, resolved);
      } catch {
        // a source that can't be read must not abort the scan
      }
    }
  }

  const contexts: ScanContext[] = servers.map((server) => {
    const source = sources.get(server.name);
    return {
      server,
      manifest: manifests.get(server.name) ?? { server: server.name, tools: [] },
      workspace,
      ...(source ? { source } : {}),
    };
  });

  const perServer = await runRules(contexts);
  // Cross-server (composition-level) analysis runs after per-server rules and
  // reuses their findings to reinforce capability inference.
  const crossServer = analyzeWorkspace(contexts, perServer);

  let findings: Finding[] = [...perServer, ...crossServer].sort((a, b) => {
    const bySeverity = severityRank(severityOf(a.ruleId)) - severityRank(severityOf(b.ruleId));
    return bySeverity !== 0 ? bySeverity : a.ruleId.localeCompare(b.ruleId);
  });

  if (options.minSeverity) {
    const min = options.minSeverity;
    findings = findings.filter((f) => meetsSeverity(severityOf(f.ruleId), min));
  }

  return {
    serversScanned: servers.length,
    serversWithManifest,
    findings,
  };
}

/** True if any finding is at or above `failOn` — drives exit code 1. */
export function hasFindingAtOrAbove(findings: Finding[], failOn: Severity): boolean {
  return findings.some((f) => meetsSeverity(severityOf(f.ruleId), failOn));
}
