import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ServerConfig } from '../src/types/config.js';
import { probeServer, ProbeManifestSource, ProbeError } from '../src/probe/index.js';
import { buildProbeEnv, wrapWithSandbox } from '../src/probe/sandbox.js';
import { server } from './helpers.js';

const MOCK = join(__dirname, 'fixtures', 'mock-servers', 'server.mjs');

function mock(mode: string, extra: Partial<ServerConfig> = {}): ServerConfig {
  return server({ name: `mock-${mode}`, command: process.execPath, args: [MOCK, mode], ...extra });
}

describe('probeServer handshake', () => {
  it('extracts a tool manifest from a well-behaved server', async () => {
    const manifest = await probeServer(mock('normal'), { timeoutMs: 5000 });
    expect(manifest.server).toBe('mock-normal');
    expect(manifest.tools.map((t) => t.name)).toEqual(['echo']);
  });

  it('follows pagination via nextCursor', async () => {
    const manifest = await probeServer(mock('paged'), { timeoutMs: 5000 });
    expect(manifest.tools.map((t) => t.name)).toEqual(['echo', 'echo2']);
  });

  it('returns a poisoned tool as-is so the rule engine can flag it', async () => {
    const manifest = await probeServer(mock('poison'), { timeoutMs: 5000 });
    const poisoned = manifest.tools.find((t) => t.name === 'read_notes');
    expect(poisoned?.description).toContain('.ssh/id_rsa');
  });

  it('names the server from the config, not the server-reported name', async () => {
    const manifest = await probeServer(mock('normal', { name: 'my-alias' }), { timeoutMs: 5000 });
    expect(manifest.server).toBe('my-alias');
  });
});

describe('probeServer safety limits', () => {
  it('times out on a server that never responds', async () => {
    await expect(probeServer(mock('slow'), { timeoutMs: 400 })).rejects.toBeInstanceOf(ProbeError);
  }, 5000);

  it('aborts a server that floods stdout past the byte cap', async () => {
    await expect(
      probeServer(mock('flood'), { timeoutMs: 5000, maxOutputBytes: 200_000 }),
    ).rejects.toThrow(/output cap/);
  }, 10000);

  it('rejects a manifest with a schema-invalid tool (hostile input)', async () => {
    await expect(probeServer(mock('badtool'), { timeoutMs: 5000 })).rejects.toBeInstanceOf(ProbeError);
  });

  it('fails cleanly when the launch command does not exist', async () => {
    const bad = server({ name: 'nope', command: 'sealpin-no-such-binary-xyz', args: [] });
    await expect(probeServer(bad, { timeoutMs: 3000 })).rejects.toBeInstanceOf(ProbeError);
  });
});

describe('environment scrubbing', () => {
  it('drops ambient secrets but keeps PATH and the server-declared env', () => {
    const original = process.env['SEALPIN_TEST_SECRET'];
    process.env['SEALPIN_TEST_SECRET'] = 'ghp_shouldnotleak';
    try {
      const env = buildProbeEnv({ MY_SERVER_VAR: 'ok' });
      expect(env['SEALPIN_TEST_SECRET']).toBeUndefined();
      expect(env['MY_SERVER_VAR']).toBe('ok');
      // PATH (any case) survives so the launcher can be found
      const hasPath = Object.keys(env).some((k) => k.toLowerCase() === 'path');
      expect(hasPath).toBe(true);
    } finally {
      if (original === undefined) delete process.env['SEALPIN_TEST_SECRET'];
      else process.env['SEALPIN_TEST_SECRET'] = original;
    }
  });

  it("lets a server's declared env override an ambient allowlisted var", () => {
    const env = buildProbeEnv({ LANG: 'custom-lang' });
    expect(env['LANG']).toBe('custom-lang');
  });
});

describe('sandbox wrapping', () => {
  it('reports the isolation actually applied and preserves the command when unsandboxed', () => {
    const wrapped = wrapWithSandbox('node', ['server.js'], '/tmp/x');
    expect(['bubblewrap', 'firejail', 'sandbox-exec', 'process-only']).toContain(wrapped.isolation.mechanism);
    if (wrapped.isolation.mechanism === 'process-only') {
      expect(wrapped.command).toBe('node');
      expect(wrapped.args).toEqual(['server.js']);
      expect(wrapped.isolation.network).toBe(false);
    } else {
      // a real sandbox wraps the original command as an argument
      expect(wrapped.args.join(' ')).toContain('node');
    }
  });
});

describe('ProbeManifestSource', () => {
  it('loads a manifest for a healthy server', async () => {
    const src = new ProbeManifestSource({ timeoutMs: 5000 });
    const manifest = await src.load(mock('normal'));
    expect(manifest?.tools[0]?.name).toBe('echo');
  });

  it('reports an error and returns null for a failing server instead of throwing', async () => {
    const errors: string[] = [];
    const src = new ProbeManifestSource({ timeoutMs: 400, onError: (s, m) => errors.push(`${s}: ${m}`) });
    const manifest = await src.load(mock('slow'));
    expect(manifest).toBeNull();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('mock-slow');
  }, 5000);

  it('invokes the isolation callback', async () => {
    const seen: string[] = [];
    const src = new ProbeManifestSource({ timeoutMs: 5000, onIsolation: (iso) => seen.push(iso.mechanism) });
    await src.load(mock('normal'));
    expect(seen.length).toBe(1);
  });
});
