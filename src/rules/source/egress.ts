import type { Finding, Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';
import { calleeName, isNode, loc, parseFile, walk, type AstNode } from './ast.js';

const URL_RE = /(https?|wss?):\/\/([^/\s'"`${}]+)/i;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);

// Callees that actually perform a network request. A URL passed to anything
// else (a logger, a deprecation-warning message, a test helper, `new URL()` used
// only for parsing) is not egress and must not be flagged — that was the
// dominant false-positive class when scanning real packages.
const NETWORK_SINKS = new Set([
  'fetch', 'request', 'get', 'post', 'put', 'patch', 'delete', 'del', 'head', 'options',
  'connect', 'send', 'sendBeacon', 'axios', 'got', 'ky', 'superagent', 'undici', 'openUrl',
]);
const NETWORK_CONSTRUCTORS = new Set(['WebSocket', 'EventSource']);

function newExpressionName(node: AstNode): string | null {
  const callee = node['callee'];
  if (isNode(callee) && callee.type === 'Identifier' && typeof callee['name'] === 'string') return callee['name'];
  return null;
}

/** The literal URL string a node carries, if any (plain string or template head). */
function literalUrl(node: unknown): string | null {
  if (!isNode(node)) return null;
  if (node.type === 'StringLiteral' && typeof node['value'] === 'string') return node['value'];
  if (node.type === 'TemplateLiteral') {
    const quasis = node['quasis'];
    if (Array.isArray(quasis) && quasis.length > 0) {
      const first = quasis[0];
      const cooked = isNode(first) ? (first['value'] as { cooked?: unknown } | undefined)?.cooked : undefined;
      if (typeof cooked === 'string') return cooked;
    }
  }
  return null;
}

function externalHost(url: string): string | null {
  const m = URL_RE.exec(url);
  if (!m) return null;
  const host = (m[2] ?? '').split(':')[0]?.toLowerCase() ?? '';
  if (!host || LOCAL_HOSTS.has(host) || host.endsWith('.local')) return null;
  return host;
}

/**
 * A6 — hardcoded egress. An external http/https/websocket URL passed straight
 * into a call (fetch, request, new URL, new WebSocket, ...) is a fixed
 * outbound destination. Combined with env/secret access, it's the "phone home"
 * half of an exfiltration channel.
 */
export const hardcodedEgressRule: Rule = {
  id: 'MCP-S005',
  severity: 'medium',
  confidence: 'possible',
  category: 'source',
  async check(ctx) {
    if (!ctx.source) return [];
    const findings: Finding[] = [];

    for (const file of ctx.source.files) {
      const ast = parseFile(file);
      if (!ast) continue;
      walk(ast, (node) => {
        // Only URLs handed to an actual network sink count as egress.
        if (node.type === 'CallExpression') {
          const name = calleeName(node);
          if (!name || !NETWORK_SINKS.has(name)) return;
        } else if (node.type === 'NewExpression') {
          const name = newExpressionName(node);
          if (!name || !NETWORK_CONSTRUCTORS.has(name)) return;
        } else {
          return;
        }
        const args = node['arguments'];
        if (!Array.isArray(args)) return;
        for (const arg of args) {
          const url = literalUrl(arg);
          if (!url) continue;
          const host = externalHost(url);
          if (!host) continue;
          findings.push(
            makeFinding('MCP-S005', ctx.server.name, {
              location: loc(file, node),
              message: `Hardcoded outbound request to external host "${host}".`,
              evidence: snippet(url),
              rationale:
                'A fixed external URL passed into a network call is a hardcoded egress destination. It is worth confirming the server is meant to talk to this host at all — a hardcoded host alongside secret or environment access is the shape of a data-exfiltration channel.',
              remediation: `Confirm outbound requests to "${host}" are expected for this server's stated purpose. Be especially wary if the request body includes environment values or file contents.`,
            }),
          );
          break; // one finding per call is enough
        }
      });
    }
    return findings;
  },
};
