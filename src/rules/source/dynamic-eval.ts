import type { Finding, Rule } from '../../types/rule.js';
import { makeFinding } from '../util.js';
import { calleeName, isNode, loc, parseFile, sourceOf, walk, type AstNode } from './ast.js';

function isNonLiteral(node: unknown): boolean {
  return isNode(node) && node.type !== 'StringLiteral';
}

/**
 * A7 — dynamic code execution. `eval(...)`, `new Function(...)`, and
 * `require(...)` / `import(...)` with a non-literal argument turn runtime data
 * into executed code or a dynamically-chosen module. In an MCP server, values
 * derived from tool arguments or model output can reach these sinks.
 */
export const dynamicEvalRule: Rule = {
  id: 'MCP-S006',
  severity: 'high',
  confidence: 'likely',
  category: 'source',
  async check(ctx) {
    if (!ctx.source) return [];
    const findings: Finding[] = [];

    for (const file of ctx.source.files) {
      const ast = parseFile(file);
      if (!ast) continue;
      walk(ast, (node) => {
        const hit = classify(node);
        if (!hit) return;
        findings.push(
          makeFinding('MCP-S006', ctx.server.name, {
            location: loc(file, node),
            message: hit.message,
            evidence: sourceOf(file, node),
            rationale:
              'Turning runtime data into executed code (eval / new Function) or into a dynamically-selected module (require/import with a computed argument) is a code-execution sink. If any input to it is influenced by tool calls or model output, it is arbitrary code execution.',
            remediation: 'Remove dynamic code execution. Replace computed require()/import() with a fixed set of statically-imported modules, and never eval untrusted input.',
          }),
        );
      });
    }
    return findings;
  },
};

function classify(node: AstNode): { message: string } | null {
  if (node.type === 'CallExpression') {
    const name = calleeName(node);
    const args = node['arguments'];
    const first = Array.isArray(args) ? args[0] : undefined;
    if (name === 'eval') return { message: 'Use of eval().' };
    if ((name === 'require' || name === 'import') && isNonLiteral(first)) {
      return { message: `Dynamic ${name}() with a non-literal argument.` };
    }
  }
  if (node.type === 'NewExpression') {
    const callee = node['callee'];
    if (isNode(callee) && callee.type === 'Identifier' && callee['name'] === 'Function') {
      return { message: 'Use of new Function() to build code at runtime.' };
    }
  }
  // import(...) is often parsed as an Import callee inside a CallExpression;
  // handle the Import node form too.
  if (node.type === 'CallExpression') {
    const callee = node['callee'];
    if (isNode(callee) && callee.type === 'Import') {
      const args = node['arguments'];
      const first = Array.isArray(args) ? args[0] : undefined;
      if (isNonLiteral(first)) return { message: 'Dynamic import() with a non-literal argument.' };
    }
  }
  return null;
}
