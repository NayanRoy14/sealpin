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

// Command construction is verified for every platform via injected probes, so
// the exact sandbox invocations are checked even off that platform.
describe('wrapWithSandbox arg construction (per platform)', () => {
  const only = (bin: string) => (n: string) => n === bin;
  const CWD = '/tmp/probe-cwd';

  it('bubblewrap: blocks network, and binds the cwd back AFTER the tmpfs so --chdir works', () => {
    const w = wrapWithSandbox('node', ['s.js'], CWD, { platform: 'linux', hasBinary: only('bwrap') });
    expect(w.command).toBe('bwrap');
    expect(w.isolation).toEqual({ mechanism: 'bubblewrap', network: true, filesystem: true });
    expect(w.args).toContain('--unshare-net');

    const tmpfsIdx = w.args.indexOf('--tmpfs');
    const bindIdx = w.args.indexOf('--bind');
    expect(tmpfsIdx).toBeGreaterThanOrEqual(0);
    expect(bindIdx).toBeGreaterThan(tmpfsIdx); // the fix: bind must come after the tmpfs
    expect(w.args.slice(bindIdx, bindIdx + 3)).toEqual(['--bind', CWD, CWD]);

    const chdirIdx = w.args.indexOf('--chdir');
    expect(w.args[chdirIdx + 1]).toBe(CWD);

    const sep = w.args.indexOf('--');
    expect(w.args.slice(sep + 1)).toEqual(['node', 's.js']); // command runs after the separator
  });

  it('firejail: used when bwrap is absent, with --net=none', () => {
    const w = wrapWithSandbox('node', ['s.js'], CWD, { platform: 'linux', hasBinary: only('firejail') });
    expect(w.command).toBe('firejail');
    expect(w.args).toContain('--net=none');
    expect(w.isolation.network).toBe(true);
    expect(w.args.slice(-2)).toEqual(['node', 's.js']);
  });

  it('sandbox-exec: used on macOS with a network-deny profile', () => {
    const w = wrapWithSandbox('node', ['s.js'], CWD, { platform: 'darwin', hasBinary: () => true });
    expect(w.command).toBe('sandbox-exec');
    expect(w.args.join(' ')).toContain('deny network');
    expect(w.args.slice(-2)).toEqual(['node', 's.js']);
  });

  it('process-only with NO network isolation on Windows', () => {
    const w = wrapWithSandbox('node', ['s.js'], CWD, { platform: 'win32', hasBinary: () => true });
    expect(w).toEqual({ command: 'node', args: ['s.js'], isolation: { mechanism: 'process-only', network: false, filesystem: false } });
  });

  it('process-only on Linux when no sandbox binary is installed', () => {
    const w = wrapWithSandbox('node', ['s.js'], CWD, { platform: 'linux', hasBinary: () => false });
    expect(w.isolation.mechanism).toBe('process-only');
    expect(w.isolation.network).toBe(false);
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
