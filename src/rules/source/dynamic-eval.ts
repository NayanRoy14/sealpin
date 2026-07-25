import type { Finding, Rule } from '../../types/rule.js';
import { makeFinding } from '../util.js';
import { calleeName, isNode, loc, parseFile, sourceOf, walk, type AstNode } from './ast.js';

function isNonLiteral(node: unknown): boolean {
  return isNode(node) && node.type !== 'StringLiteral';
}

// Identifiers that denote a base directory, not attacker-controlled data.
const DIRNAME_LIKE = /^(?:__dirname|__filename|here|cwd|dir|dirname|root|rootdir|base|basedir|appdir|moduledir|currentdir|scriptdir)$/i;
// Path-building functions whose all-literal/all-internal calls stay internal.
const PATH_FNS = new Set(['join', 'resolve', 'normalize', 'dirname', 'fileURLToPath', 'pathToFileURL']);

/**
 * True when a module specifier is a *fixed internal path* — built only from
 * string literals, dirname-like identifiers, `import.meta.*`, and path helpers.
 * `import(join(__dirname, "../dist/x.js"))` is internal; `require(userInput)` or
 * `import("plugins/" + name)` is not. This is the provenance check that keeps
 * bin-wrappers and relative-import shims from being flagged.
 */
function isInternalPath(node: unknown): boolean {
  if (!isNode(node)) return false;
  switch (node.type) {
    case 'StringLiteral':
      return true;
    case 'Identifier':
      return typeof node['name'] === 'string' && DIRNAME_LIKE.test(node['name']);
    case 'MemberExpression': {
      const obj = node['object'];
      return isNode(obj) && obj.type === 'MetaProperty'; // import.meta.url / import.meta.dirname
    }
    case 'TemplateLiteral': {
      const exprs = node['expressions'];
      return Array.isArray(exprs) && exprs.every(isInternalPath);
    }
    case 'BinaryExpression':
      return node['operator'] === '+' && isInternalPath(node['left']) && isInternalPath(node['right']);
    case 'CallExpression': {
      const name = calleeName(node);
      if (!name || !PATH_FNS.has(name)) return false;
      const args = node['arguments'];
      return Array.isArray(args) && args.every(isInternalPath);
    }
    default:
      return false;
  }
}

/**
 * The name of a callee ONLY when it is a bare global identifier (e.g. `eval(x)`,
 * `require(x)`), not a member call (`fn.eval(x)`, `sap.ui.require([...])`). The
 * dangerous sinks are the JS globals; a namesake method on some object is not
 * `eval`/CommonJS-require and must not be flagged.
 */
function globalCalleeName(node: AstNode): string | null {
  const callee = node['callee'];
  if (isNode(callee) && callee.type === 'Identifier' && typeof callee['name'] === 'string') {
    return callee['name'];
  }
  return null;
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
    const args = node['arguments'];
    const first = Array.isArray(args) ? args[0] : undefined;

    // Only bare-global eval/require/import — never a namesake method call.
    const name = globalCalleeName(node);
    if (name === 'eval') return { message: 'Use of eval().' };
    if ((name === 'require' || name === 'import') && isDataDerivedModuleArg(first)) {
      return { message: `Dynamic ${name}() with a data-derived argument.` };
    }

    // import(...) with the dedicated Import callee node.
    const callee = node['callee'];
    if (isNode(callee) && callee.type === 'Import' && isDataDerivedModuleArg(first)) {
      return { message: 'Dynamic import() with a data-derived argument.' };
    }
  }
  if (node.type === 'NewExpression') {
    const callee = node['callee'];
    if (isNode(callee) && callee.type === 'Identifier' && callee['name'] === 'Function') {
      return { message: 'Use of new Function() to build code at runtime.' };
    }
  }
  return null;
}

/**
 * A require()/import() argument that computes the module path from *data* rather
 * than a fixed internal location. Excludes string/array/object literals (static
 * or plugin-list loads) and internal path expressions (`join(__dirname, "…")`,
 * relative-import shims), leaving genuinely data-derived specifiers.
 */
function isDataDerivedModuleArg(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === 'StringLiteral' || node.type === 'ArrayExpression' || node.type === 'ObjectExpression') return false;
  if (isInternalPath(node)) return false;
  return true; // Identifier, concat, template, member, call — derived from runtime values
}
