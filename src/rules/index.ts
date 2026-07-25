import type { Finding, ScanContext, Severity } from '../types/rule.js';
import { ALL_RULES } from './registry.js';
import { WORKSPACE_RULES } from '../capabilities/workspace.js';

const WORKSPACE_SEVERITY = new Map<string, Severity>(WORKSPACE_RULES.map((r) => [r.id, r.severity]));

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityRank(sev: Severity): number {
  return SEVERITY_ORDER.indexOf(sev);
}

/** True when `sev` is at least as severe as `min`. */
export function meetsSeverity(sev: Severity, min: Severity): boolean {
  return severityRank(sev) <= severityRank(min);
}

/**
 * Runs every rule against every scan context. A rule throwing must not abort
 * the whole scan of a hostile server set — a thrown rule is downgraded to an
 * info finding so the failure is visible but non-fatal.
 */
export async function runRules(contexts: ScanContext[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const ruleSeverity = new Map(ALL_RULES.map((r) => [r.id, r.severity]));

  for (const ctx of contexts) {
    for (const rule of ALL_RULES) {
      try {
        findings.push(...(await rule.check(ctx)));
      } catch (err) {
        findings.push({
          ruleId: rule.id,
          server: ctx.server.name,
          message: `Rule ${rule.id} threw while scanning "${ctx.server.name}".`,
          evidence: err instanceof Error ? err.message : String(err),
          rationale: 'A rule crashing is itself worth surfacing — it usually means malformed or hostile manifest input.',
          remediation: 'Report this to the sealpin maintainers with the offending manifest.',
        });
      }
    }
  }

  // Stable sort: most severe first, then by rule id for determinism.
  return findings.sort((a, b) => {
    const sa = ruleSeverity.get(a.ruleId) ?? 'info';
    const sb = ruleSeverity.get(b.ruleId) ?? 'info';
    const bySeverity = severityRank(sa) - severityRank(sb);
    if (bySeverity !== 0) return bySeverity;
    return a.ruleId.localeCompare(b.ruleId);
  });
}

export function severityOf(ruleId: string): Severity {
  return ALL_RULES.find((r) => r.id === ruleId)?.severity ?? WORKSPACE_SEVERITY.get(ruleId) ?? 'info';
}

export { ALL_RULES, getRule } from './registry.js';
export { RULE_DOCS, type RuleDoc } from './docs.js';
