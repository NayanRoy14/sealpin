import type { Finding, Rule } from '../../types/rule.js';
import { makeFinding } from '../util.js';
import { calleeName, isNode, loc, parseFile, sourceOf, walk } from './ast.js';

const EXEC_METHODS = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync']);

/** A string built from runtime values: a template with holes, or a `+` concat touching a non-literal. */
function isDynamicString(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === 'TemplateLiteral') {
    return Array.isArray(node['expressions']) && node['expressions'].length > 0;
  }
  if (node.type === 'BinaryExpression' && node['operator'] === '+') {
    return containsNonLiteral(node['left']) || containsNonLiteral(node['right']);
  }
  return false;
}

function containsNonLiteral(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral') return false;
  if (node.type === 'BinaryExpression' && node['operator'] === '+') {
    return containsNonLiteral(node['left']) || containsNonLiteral(node['right']);
  }
  return true; // Identifier, MemberExpression, CallExpression, etc.
}

/**
 * A7 — command injection. A child_process exec/spawn call whose command string
 * is assembled from runtime values (template interpolation or string concat)
 * lets whatever flows into that value run as a shell command.
 */
export const commandInjectionRule: Rule = {
  id: 'MCP-S003',
  severity: 'critical',
  confidence: 'likely',
  category: 'source',
  async check(ctx) {
    if (!ctx.source) return [];
    const findings: Finding[] = [];

    for (const file of ctx.source.files) {
      const ast = parseFile(file);
      if (!ast) continue;
      walk(ast, (node) => {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (!name || !EXEC_METHODS.has(name)) return;
        const args = node['arguments'];
        const first = Array.isArray(args) ? args[0] : undefined;
        if (!isDynamicString(first)) return;

        findings.push(
          makeFinding('MCP-S003', ctx.server.name, {
            location: loc(file, node),
            message: `child_process.${name}() is called with a dynamically-built command string.`,
            evidence: sourceOf(file, node),
            rationale:
              'A command string assembled from runtime values and passed to a shell-executing child_process call is the classic command-injection sink. If any part of that value is influenced by tool arguments or model output, the server will run attacker-chosen shell commands.',
            remediation:
              'Pass arguments as an array to execFile/spawn without a shell, and never interpolate untrusted input into a command string. Validate/allowlist any value that reaches the command.',
          }),
        );
      });
    }
    return findings;
  },
};
