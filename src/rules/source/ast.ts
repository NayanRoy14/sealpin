import { parse } from '@babel/parser';
import type { SourceFile } from '../../resolve/types.js';

/**
 * A loosely-typed Babel AST node. We deliberately avoid @babel/types at
 * runtime (and @babel/traverse entirely) to keep the dependency tree minimal —
 * @babel/parser has zero runtime dependencies. Node shape is checked by the
 * `type` string plus explicit property access.
 */
export interface AstNode {
  type: string;
  start?: number;
  end?: number;
  loc?: { start: { line: number; column: number } };
  [key: string]: unknown;
}

type ParseResult = { ok: true; ast: AstNode } | { ok: false };

// Parse each source file at most once, even across multiple rules.
const cache = new WeakMap<SourceFile, ParseResult>();

export function parseFile(file: SourceFile): AstNode | null {
  const cached = cache.get(file);
  if (cached) return cached.ok ? cached.ast : null;

  try {
    const ast = parse(file.content, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      errorRecovery: true,
      plugins: ['typescript', 'jsx', 'decorators-legacy', 'importAttributes'],
    }) as unknown as AstNode;
    cache.set(file, { ok: true, ast });
    return ast;
  } catch {
    cache.set(file, { ok: false });
    return null;
  }
}

const SKIP_KEYS = new Set(['loc', 'start', 'end', 'range', 'leadingComments', 'trailingComments', 'innerComments', 'comments', 'tokens', 'errors', 'extra']);

/** Depth-first walk. The visitor receives each node and its ancestor chain (root-first). */
export function walk(node: AstNode, visit: (node: AstNode, ancestors: AstNode[]) => void, ancestors: AstNode[] = []): void {
  visit(node, ancestors);
  const childAncestors = [...ancestors, node];
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) walk(item, visit, childAncestors);
      }
    } else if (isNode(value)) {
      walk(value, visit, childAncestors);
    }
  }
}

export function isNode(value: unknown): value is AstNode {
  return typeof value === 'object' && value !== null && typeof (value as { type?: unknown }).type === 'string';
}

export function lineOf(node: AstNode): number | undefined {
  return node.loc?.start.line;
}

/** Builds a Finding.location for a source node, omitting `line` when unknown (exactOptionalPropertyTypes). */
export function loc(file: SourceFile, node: AstNode): { file: string; line?: number } {
  const line = lineOf(node);
  return line === undefined ? { file: file.relPath } : { file: file.relPath, line };
}

/** Original source text for a node, truncated for use as finding evidence. */
export function sourceOf(file: SourceFile, node: AstNode, max = 160): string {
  if (node.start === undefined || node.end === undefined) return node.type;
  const raw = file.content.slice(node.start, node.end).replace(/\s+/g, ' ').trim();
  return raw.length <= max ? raw : raw.slice(0, max - 1) + '…';
}

/** The property name of a member/identifier callee, e.g. `cp.exec(...)` → "exec". */
export function calleeName(node: AstNode): string | null {
  const callee = node['callee'];
  if (!isNode(callee)) return null;
  if (callee.type === 'Identifier') return typeof callee['name'] === 'string' ? callee['name'] : null;
  if (callee.type === 'MemberExpression') {
    const prop = callee['property'];
    if (isNode(prop) && prop.type === 'Identifier' && typeof prop['name'] === 'string') return prop['name'];
  }
  return null;
}

/** The object part of a member callee as a name, e.g. `child_process.exec` → "child_process". */
export function calleeObjectName(node: AstNode): string | null {
  const callee = node['callee'];
  if (!isNode(callee) || callee.type !== 'MemberExpression') return null;
  const obj = callee['object'];
  if (isNode(obj) && obj.type === 'Identifier' && typeof obj['name'] === 'string') return obj['name'];
  return null;
}
