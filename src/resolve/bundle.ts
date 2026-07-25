/**
 * Dependency-aware handling of published bundles.
 *
 * Most MCP servers ship a compiled, bundled `dist/` that inlines their
 * dependencies. Running source rules over the whole bundle measures Ajv,
 * `debug`, ONNX, etc. — not the server. esbuild delimits each inlined module
 * with a `// <path>` comment at column 0; modules under `node_modules/` are
 * vendored, everything else is first-party. This module keeps only the
 * first-party regions (line-preserving, so finding line numbers stay accurate)
 * and drops the vendored ones.
 *
 * Bundles we cannot split confidently (minified single-line output, or bundlers
 * that emit no path markers) are reported as opaque rather than mis-analysed.
 */

/** esbuild module-delimiter comment, e.g. `// node_modules/foo/index.js` or `// src/index.ts`. */
const MODULE_MARKER = /^\/\/ (\S.*\.(?:c?js|mjs|jsx?|tsx?))\s*$/;

/** Average line length far above hand-written source indicates minified/one-line output. */
export function isMinified(content: string): boolean {
  const newlines = (content.match(/\n/g)?.length ?? 0) + 1;
  const avg = content.length / newlines;
  return content.length < 50_000 ? avg > 2000 : avg > 300;
}

/** Heuristic: the file inlines dependency code (esbuild path markers into node_modules). */
export function looksBundled(content: string): boolean {
  return (content.match(/\/\/ node_modules\//g)?.length ?? 0) >= 3;
}

/**
 * Returns the bundle's first-party code with vendored regions blanked out
 * (preserving line numbers), or null if no first-party region can be recovered.
 */
export function devendorBundle(content: string): string | null {
  let firstParty = false; // the esbuild helper preamble (before any marker) is not first-party
  let keptAny = false;
  const out = content.split('\n').map((line) => {
    const m = MODULE_MARKER.exec(line);
    if (m) firstParty = !(m[1] ?? '').includes('node_modules/');
    if (firstParty) {
      keptAny = true;
      return line;
    }
    return ''; // blank preamble/vendored lines but keep the line count
  });
  return keptAny ? out.join('\n') : null;
}

export type SourceKind = 'source' | 'devendored-bundle';

/**
 * Classifies a source file and returns the analysable first-party content, or
 * null when the file is an opaque bundle (minified, or bundled with no
 * recoverable first-party code) that cannot be audited at source level.
 */
export function analyzableSource(content: string): { content: string; kind: SourceKind } | null {
  if (looksBundled(content)) {
    if (isMinified(content)) return null; // minified bundle: unsplittable
    const devendored = devendorBundle(content);
    return devendored ? { content: devendored, kind: 'devendored-bundle' } : null;
  }
  if (isMinified(content)) return null; // opaque minified artifact
  return { content, kind: 'source' };
}
