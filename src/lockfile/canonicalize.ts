import type { Tool, ToolManifest } from '../types/manifest.js';

function normalizeWhitespace(s: string): string {
  return s.trim().replace(/\s+/g, ' ');
}

function sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, sortObjectKeys(v)] as const);
    return Object.fromEntries(entries);
  }
  return value;
}

/**
 * Deterministic, order-independent, whitespace-normalized JSON for a single
 * tool. Used both to build a manifest's canonical form and, on its own, to
 * detect which individual tools changed between two manifests.
 */
export function canonicalizeTool(tool: Tool): string {
  return JSON.stringify(
    sortObjectKeys({
      name: tool.name,
      description: tool.description ? normalizeWhitespace(tool.description) : undefined,
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
    }),
  );
}

/**
 * Canonical form of a full manifest: tools sorted by name (so reordering the
 * server's tools/list response doesn't register as drift), each tool
 * canonicalized individually. This string is what gets SHA-256 hashed.
 */
export function canonicalize(manifest: ToolManifest): string {
  const sortedTools = [...manifest.tools].sort((a, b) => a.name.localeCompare(b.name));
  const canonicalTools = sortedTools.map((t) => JSON.parse(canonicalizeTool(t)));
  return JSON.stringify({ server: manifest.server, tools: canonicalTools });
}
