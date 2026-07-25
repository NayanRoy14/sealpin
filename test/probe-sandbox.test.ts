import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ServerConfig } from '../src/types/config.js';
import { probeServer } from '../src/probe/index.js';
import { server } from './helpers.js';

const MOCK = join(__dirname, 'fixtures', 'mock-servers', 'server.mjs');

function mock(mode: string): ServerConfig {
  return server({ name: `mock-${mode}`, command: process.execPath, args: [MOCK, mode] });
}

function has(bin: string): boolean {
  return spawnSync('command', ['-v', bin], { shell: true }).status === 0;
}

// Which OS sandbox, if any, is available here. Present on Linux CI (bubblewrap)
// and macOS (sandbox-exec); absent on Windows and on a bare local box, where
// these integration tests are skipped rather than failing.
const sandboxAvailable =
  (process.platform === 'linux' && (has('bwrap') || has('firejail'))) ||
  (process.platform === 'darwin' && has('sandbox-exec'));

const describeSandbox = sandboxAvailable ? describe : describe.skip;

describeSandbox('probe under a real OS sandbox', () => {
  it('completes the MCP handshake inside the sandbox', async () => {
    const manifest = await probeServer(mock('normal'), { timeoutMs: 20000, requireSandbox: true });
    expect(manifest.tools.map((t) => t.name)).toEqual(['echo']);
  }, 30000);

  it('blocks the probed server from reaching the network', async () => {
    // The netprobe mock tries to open an outbound TCP connection and reports the
    // result in its tool description. Under network isolation it must be blocked.
    const manifest = await probeServer(mock('netprobe'), { timeoutMs: 20000, requireSandbox: true });
    const net = manifest.tools.find((t) => t.name === 'net');
    expect(net?.description).toBe('blocked');
  }, 30000);

  it('reports network isolation is in effect', async () => {
    let networkBlocked = false;
    await probeServer(mock('normal'), {
      timeoutMs: 20000,
      requireSandbox: true,
      onIsolation: (iso) => {
        networkBlocked = iso.network;
      },
    });
    expect(networkBlocked).toBe(true);
  }, 30000);
});
