import type { Finding, Rule } from '../../types/rule.js';
import type { SourceFile } from '../../resolve/types.js';
import { makeFinding } from '../util.js';
import { isNode, loc, parseFile, sourceOf, walk, type AstNode } from './ast.js';

// A network sink somewhere in the same file raises the stakes of an env capture.
const NETWORK_SINK =
  /\bfetch\s*\(|https?\.request\s*\(|\baxios\b|require\(\s*['"](?:https?|net|dgram|node-fetch|got|undici|axios)['"]\s*\)|from\s+['"](?:node-fetch|got|undici|axios)['"]/;

/** Is this node the `process.env` member expression? */
function isProcessEnv(node: AstNode): boolean {
  if (node.type !== 'MemberExpression') return false;
  const obj = node['object'];
  const prop = node['property'];
  return (
    isNode(obj) && obj.type === 'Identifier' && obj['name'] === 'process' &&
    isNode(prop) && prop.type === 'Identifier' && prop['name'] === 'env'
  );
}

/**
 * A6 — secret exfiltration. Reading `process.env.SPECIFIC_KEY` is normal;
 * capturing the *whole* environment object (to serialize, enumerate, spread,
 * or pass it somewhere) is how a server scoops up every secret at once.
 */
export const envExfiltrationRule: Rule = {
  id: 'MCP-S004',
  severity: 'high',
  confidence: 'possible',
  category: 'source',
  async check(ctx) {
    if (!ctx.source) return [];
    const findings: Finding[] = [];

    for (const file of ctx.source.files) {
      const ast = parseFile(file);
      if (!ast) continue;
      const hasNetworkSink = NETWORK_SINK.test(file.content);

      walk(ast, (node, ancestors) => {
        if (!isProcessEnv(node)) return;
        const parent = ancestors[ancestors.length - 1];
        // Skip specific access: process.env.FOO (parent member whose object is this node).
        if (parent && parent.type === 'MemberExpression' && parent['object'] === node) return;

        findings.push(
          makeFinding('MCP-S004', ctx.server.name, {
            location: loc(file, node),
            message: `The entire process environment is captured${hasNetworkSink ? ' in a file that also makes network calls' : ''}.`,
            evidence: evidenceFor(file, node, ancestors),
            rationale:
              'Serializing, enumerating, or passing the whole `process.env` object (rather than reading a specific known key) collects every environment variable at once — including credentials the server was never meant to see.' +
              (hasNetworkSink ? ' This file also contains a network call, a direct exfiltration path.' : ''),
            remediation: 'Read only the specific environment variables the server needs by name. Treat whole-environment capture next to a network call as an exfiltration attempt.',
          }),
        );
      });
    }
    return findings;
  },
};

/** Prefer showing the enclosing statement/call for context over the bare `process.env`. */
function evidenceFor(file: SourceFile, node: AstNode, ancestors: AstNode[]): string {
  const parent = ancestors[ancestors.length - 1];
  const target = parent && (parent.type === 'CallExpression' || parent.type === 'SpreadElement' || parent.type === 'VariableDeclarator') ? parent : node;
  return sourceOf(file, target);
}
