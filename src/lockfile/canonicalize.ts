import type { Tool, ToolManifest } from '../types/manifest.js';

function normalizeWhitespace(s: string): string {
  return s.trim().replace(/\s+/g, ' ');
}

/**
 * Locale-independent, code-unit string ordering. `String.localeCompare` is NOT
 * stable across machines or locales, so it must never influence the canonical
 * hash — otherwise a lockfile written on one machine could report false drift
 * when verified on another. This ordering depends only on UTF-16 code units.
 */
function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => compareStrings(a, b))
      .map(([k, v]) => [k, sortObjectKeys(v)] as const);
    return Object.fromEntries(entries);
  }
  return value;
}

/** Canonical value (keys sorted, description whitespace-normalized) for one tool. */
function canonicalToolValue(tool: Tool): unknown {
  return sortObjectKeys({
    name: tool.name,
    description: tool.description ? normalizeWhitespace(tool.description) : undefined,
    inputSchema: tool.inputSchema,
    annotations: tool.annotations,
  });
}

/**
 * Deterministic, order-independent, whitespace-normalized JSON for a single
 * tool. Used both to build a manifest's canonical form and, on its own, to
 * detect which individual tools changed between two manifests.
 */
export function canonicalizeTool(tool: Tool): string {
  return JSON.stringify(canonicalToolValue(tool));
}

/**
 * Canonical form of a full manifest: tools sorted by name (so reordering the
 * server's tools/list response doesn't register as drift), each tool
 * canonicalized individually. This string is what gets SHA-256 hashed.
 */
export function canonicalize(manifest: ToolManifest): string {
  const canonicalTools = [...manifest.tools]
    .sort((a, b) => compareStrings(a.name, b.name))
    .map(canonicalToolValue);
  return JSON.stringify({ server: manifest.server, tools: canonicalTools });
}
