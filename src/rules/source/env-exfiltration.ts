import type { Finding, Rule } from '../../types/rule.js';
import type { SourceFile } from '../../resolve/types.js';
import { makeFinding, snippet } from '../util.js';
import { calleeName, isNode, loc, parseFile, sourceOf, walk, type AstNode } from './ast.js';

// Calls that send data off the process. Combined with the requirement that the
// whole environment reaches one, this is the exfiltration shape — as opposed to
// env passed to a subprocess or a dotenv loader, which are not sinks.
const NETWORK_SINKS = new Set([
  'fetch', 'request', 'get', 'post', 'put', 'patch', 'delete', 'del', 'head',
  'send', 'sendBeacon', 'write', 'end', 'axios', 'got', 'ky', 'superagent',
]);

const FUNCTION_NODES = new Set([
  'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod',
]);
const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'comments', 'tokens', 'errors', 'extra']);

/**
 * Walk a value expression WITHOUT descending into nested function bodies. Code
 * inside a callback (e.g. an Express route handler passed to `app.post`) runs
 * later — it is not a value flowing into the enclosing call — so it must not
 * count as reaching the sink.
 */
function boundedWalk(root: AstNode, visit: (n: AstNode, parent: AstNode | undefined) => void): void {
  const rec = (n: AstNode, parent: AstNode | undefined): void => {
    // Skip function nodes entirely (even as the root): a function value's body
    // runs later and is not data flowing into the enclosing call.
    if (FUNCTION_NODES.has(n.type)) return;
    visit(n, parent);
    for (const key of Object.keys(n)) {
      if (SKIP_KEYS.has(key)) continue;
      const v = n[key];
      if (Array.isArray(v)) {
        for (const c of v) if (isNode(c)) rec(c, n);
      } else if (isNode(v)) {
        rec(v, n);
      }
    }
  };
  rec(root, undefined);
}

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

/** Does this expression reference the WHOLE process.env (not process.env.KEY), not counting nested functions? */
function containsWholeEnv(root: AstNode): boolean {
  let found = false;
  boundedWalk(root, (n, parent) => {
    if (found || !isProcessEnv(n)) return;
    // Exclude specific access process.env.KEY (parent member whose object is this node).
    if (parent && parent.type === 'MemberExpression' && parent['object'] === n) return;
    found = true;
  });
  return found;
}

/** Identifiers assigned a whole-env capture, so a later `sink(theVar)` still counts. */
function collectEnvTaint(ast: AstNode): Set<string> {
  const tainted = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'VariableDeclarator') {
      const id = node['id'];
      const init = node['init'];
      if (isNode(id) && id.type === 'Identifier' && typeof id['name'] === 'string' && isNode(init) && containsWholeEnv(init)) {
        tainted.add(id['name']);
      }
    } else if (node.type === 'AssignmentExpression') {
      const left = node['left'];
      const right = node['right'];
      if (isNode(left) && left.type === 'Identifier' && typeof left['name'] === 'string' && isNode(right) && containsWholeEnv(right)) {
        tainted.add(left['name']);
      }
    }
  });
  return tainted;
}

function subtreeHasTaintedId(root: AstNode, tainted: Set<string>): boolean {
  if (tainted.size === 0) return false;
  let found = false;
  boundedWalk(root, (n) => {
    if (found) return;
    if (n.type === 'Identifier' && typeof n['name'] === 'string' && tainted.has(n['name'])) found = true;
  });
  return found;
}

/**
 * A6 — secret exfiltration. Reading `process.env.SPECIFIC_KEY` is normal;
 * capturing the *whole* environment and passing it into a network call is how a
 * server ships every secret at once. This uses light intraprocedural taint: it
 * flags a network sink whose arguments contain the whole `process.env` (directly
 * or via a variable that was assigned it), and does NOT flag env merely passed
 * to a subprocess, a dotenv parser, or a config object.
 */
export const envExfiltrationRule: Rule = {
  id: 'MCP-S004',
  severity: 'high',
  confidence: 'likely',
  category: 'source',
  async check(ctx) {
    if (!ctx.source) return [];
    const findings: Finding[] = [];

    for (const file of ctx.source.files) {
      const ast = parseFile(file);
      if (!ast) continue;
      const tainted = collectEnvTaint(ast);
      const reported = new Set<AstNode>();

      walk(ast, (node) => {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (!name || !NETWORK_SINKS.has(name)) return;
        const args = node['arguments'];
        if (!Array.isArray(args)) return;

        const leaks = args.some((arg) => isNode(arg) && (containsWholeEnv(arg) || subtreeHasTaintedId(arg, tainted)));
        if (!leaks || reported.has(node)) return;
        reported.add(node);

        findings.push(
          makeFinding('MCP-S004', ctx.server.name, {
            location: loc(file, node),
            message: 'The whole process environment flows into an outbound call (possible exfiltration).',
            evidence: evidenceFor(file, node),
            rationale:
              'The entire `process.env` object — every secret the server was handed — is passed into a network/outbound call rather than a specific known variable being read. That is the shape of credential exfiltration, not ordinary configuration use.',
            remediation: 'Send only the specific values the request needs, never the whole environment. Confirm this outbound call is expected and audit what it transmits.',
          }),
        );
      });
    }
    return findings;
  },
};

function evidenceFor(file: SourceFile, node: AstNode): string {
  return snippet(sourceOf(file, node));
}
