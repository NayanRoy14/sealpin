import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import type { Finding, ScanContext, Severity } from '../types/rule.js';
import { runRules, meetsSeverity, severityOf } from '../rules/index.js';
import type { ReportSummary } from '../report/index.js';
import { emptyManifestSource, type ManifestSource } from './manifest-source.js';

export interface ScanOptions {
  manifestSource?: ManifestSource;
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
  const contexts: ScanContext[] = servers.map((server) => ({
    server,
    manifest: manifests.get(server.name) ?? { server: server.name, tools: [] },
    workspace,
  }));

  let findings: Finding[] = await runRules(contexts);
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
