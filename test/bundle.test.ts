import { describe, expect, it } from 'vitest';
import { analyzableSource, devendorBundle, isMinified, looksBundled } from '../src/resolve/bundle.js';

// A synthetic esbuild-style bundle: helper preamble, two vendored modules, then
// the first-party entry — mirroring real published bundles (figma-mcp etc.).
const BUNDLE = `"use strict";
var __commonJS = (cb) => {};

// node_modules/debug/index.js
var require_debug = __commonJS(() => {
  Object.keys(process.env);
  new Function("return 1");
});

// node_modules/ajv/dist/ajv.js
var require_ajv = __commonJS(() => {
  new Function("self", "return self");
});

// node_modules/chalk/index.js
var require_chalk = __commonJS(() => {
  const x = process.env.FORCE_COLOR;
});

// src/index.ts
var debug = require_debug();
fetch("https://api.example.com/telemetry");
`;

describe('bundle detection', () => {
  it('recognises an esbuild bundle by its node_modules markers', () => {
    expect(looksBundled(BUNDLE)).toBe(true);
    expect(looksBundled('const x = 1;\nfetch("https://api.example.com");')).toBe(false);
  });

  it('recognises minified/one-line output', () => {
    expect(isMinified('a'.repeat(60000))).toBe(true);
    expect(isMinified('const a = 1;\nconst b = 2;\nconsole.log(a + b);')).toBe(false);
  });
});

describe('devendorBundle', () => {
  it('keeps first-party regions and blanks vendored ones, preserving line numbers', () => {
    const out = devendorBundle(BUNDLE);
    expect(out).not.toBeNull();
    const lines = out.split('\n');
    // same line count (line numbers preserved)
    expect(lines.length).toBe(BUNDLE.split('\n').length);
    // vendored dependency code is gone...
    expect(out).not.toContain('require_debug = __commonJS');
    expect(out).not.toContain('require_ajv');
    expect(out).not.toContain('require_chalk');
    // ...but the first-party entry survives, on its original line
    expect(out).toContain('fetch("https://api.example.com/telemetry")');
    expect(out).toContain('// src/index.ts');
  });

  it('returns null when there is no first-party region', () => {
    const vendoredOnly = `// node_modules/a/index.js\nvar a = 1;\n// node_modules/b/index.js\nvar b = 2;\n`;
    expect(devendorBundle(vendoredOnly)).toBeNull();
  });
});

describe('analyzableSource', () => {
  it('passes ordinary source through unchanged', () => {
    const src = 'export function f() { return 1; }';
    expect(analyzableSource(src)).toEqual({ content: src, kind: 'source' });
  });

  it('de-vendors an esbuild bundle', () => {
    const r = analyzableSource(BUNDLE);
    expect(r?.kind).toBe('devendored-bundle');
    expect(r?.content).toContain('/telemetry');
    expect(r?.content).not.toContain('require_ajv');
  });

  it('treats a minified bundle as opaque (null)', () => {
    const minifiedBundle = '// node_modules/x/i.js\n' + 'var a=' + '1;'.repeat(40000);
    expect(analyzableSource(minifiedBundle)).toBeNull();
  });
});
