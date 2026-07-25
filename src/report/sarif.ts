import type { Finding, Severity } from '../types/rule.js';
import { ALL_RULES, RULE_DOCS, severityOf } from '../rules/index.js';
import type { ReportSummary } from './text.js';

/** SARIF result level. GitHub renders error/warning/note distinctly. */
function sarifLevel(sev: Severity): 'error' | 'warning' | 'note' {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

/** GitHub uses `security-severity` (0.0–10.0) to bucket security alerts. */
function securitySeverity(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return '9.5';
    case 'high':
      return '8.0';
    case 'medium':
      return '5.5';
    case 'low':
      return '3.0';
    case 'info':
      return '0.0';
  }
}

const VERSION = '0.1.0';

/**
 * Emits SARIF 2.1.0. Hand-rolled (no dependency) so it stays ~one file and we
 * control exactly what GitHub code scanning ingests.
 */
export function renderSarif(summary: ReportSummary): string {
  const ruleIndex = new Map(ALL_RULES.map((r, i) => [r.id, i]));

  const driverRules = ALL_RULES.map((rule) => {
    const doc = RULE_DOCS[rule.id];
    return {
      id: rule.id,
      name: doc?.title ?? rule.id,
      shortDescription: { text: doc?.title ?? rule.id },
      fullDescription: { text: doc?.summary ?? '' },
      defaultConfiguration: { level: sarifLevel(rule.severity) },
      properties: {
        category: rule.category,
        confidence: rule.confidence,
        attack: doc?.attack ?? '',
        'security-severity': securitySeverity(rule.severity),
      },
    };
  });

  const results = summary.findings.map((f: Finding) => {
    const sev = severityOf(f.ruleId);
    const uri = artifactUri(f);
    const region = f.location?.line !== undefined ? { region: { startLine: f.location.line } } : {};
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? -1,
      level: sarifLevel(sev),
      message: { text: `${f.message}\n\n${f.rationale}\n\nEvidence: ${f.evidence}\n\nRemediation: ${f.remediation}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            ...region,
          },
          logicalLocations: [
            {
              name: f.location?.tool ?? f.server,
              fullyQualifiedName: f.location?.tool ? `${f.server}.${f.location.tool}` : f.server,
              kind: f.location?.tool ? 'member' : 'namespace',
            },
          ],
        },
      ],
      properties: { server: f.server, evidence: f.evidence },
    };
  });

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'sealpin',
            informationUri: 'https://github.com/NayanRoy14/sealpin',
            version: VERSION,
            rules: driverRules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * SARIF requires every result to carry a location. Config-based findings point
 * at the real config file; manifest-based findings (a poisoned tool
 * description) have no source line in the user's tree, so we synthesize a
 * stable logical uri instead of inventing a fake file path.
 */
function artifactUri(f: Finding): string {
  if (f.location?.file) {
    return f.location.file.replace(/\\/g, '/');
  }
  const tool = f.location?.tool ? `/${f.location.tool}` : '';
  return `mcp://${f.server}${tool}`;
}
