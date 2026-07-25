import type { Finding, Rule } from '../../types/rule.js';
import { makeFinding } from '../util.js';
import { isNode, loc, parseFile, sourceOf, walk, type AstNode } from './ast.js';

// Distinctive child_process methods — safe to match on any object.
const UNAMBIGUOUS = new Set(['execSync', 'spawnSync', 'execFile', 'execFileSync']);
// Ambiguous names that collide with unrelated APIs (db.exec, regexp.exec,
// stream.spawn). Matched only as a bare global call or on a child_process-like
// receiver, never on an arbitrary object.
const AMBIGUOUS = new Set(['exec', 'spawn']);
const CHILDPROC_OBJ = /^(cp|proc|child_?process|childProcess|shell)$/i;

/**
 * The child_process exec/spawn method being called, or null. This deliberately
 * does NOT match `db.exec(sql)` or `regexp.exec(str)` — only genuine
 * child_process calls (a bare global from `const {exec} = require(...)`, or a
 * member on a child_process-like object such as `cp.exec`).
 */
function execMethod(node: AstNode): string | null {
  const callee = node['callee'];
  if (!isNode(callee)) return null;

  if (callee.type === 'Identifier') {
    const name = callee['name'];
    return typeof name === 'string' && (UNAMBIGUOUS.has(name) || AMBIGUOUS.has(name)) ? name : null;
  }

  if (callee.type === 'MemberExpression') {
    const prop = callee['property'];
    const name = isNode(prop) && prop.type === 'Identifier' && typeof prop['name'] === 'string' ? prop['name'] : null;
    if (!name) return null;
    if (UNAMBIGUOUS.has(name)) return name;
    if (!AMBIGUOUS.has(name)) return null;
    const obj = callee['object'];
    const objName = isNode(obj) && obj.type === 'Identifier' && typeof obj['name'] === 'string' ? obj['name'] : '';
    return CHILDPROC_OBJ.test(objName) ? name : null;
  }

  return null;
}

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
        const name = execMethod(node);
        if (!name) return;
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
