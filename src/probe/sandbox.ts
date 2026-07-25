import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Operational environment variables that a launcher (node/npx/uvx/python) may
 * legitimately need to *start* a process. Deliberately excludes anything that
 * carries a credential. The user's ambient shell environment — which may hold
 * unrelated secrets (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, ...) — is never
 * inherited by a probed server. Only these keys plus the server's own declared
 * env are passed through.
 */
const ENV_ALLOWLIST = new Set(
  [
    // cross-platform
    'PATH',
    'LANG',
    'LC_ALL',
    'TZ',
    // POSIX
    'HOME',
    'USER',
    'LOGNAME',
    'SHELL',
    'TMPDIR',
    // Windows launcher essentials (paths, not secrets)
    'Path',
    'PATHEXT',
    'SYSTEMROOT',
    'SystemRoot',
    'WINDIR',
    'windir',
    'COMSPEC',
    'ComSpec',
    'TEMP',
    'TMP',
    'NUMBER_OF_PROCESSORS',
    'PROCESSOR_ARCHITECTURE',
    'OS',
    'APPDATA',
    'LOCALAPPDATA',
    'PROGRAMFILES',
    'ProgramFiles',
    'PROGRAMDATA',
    'ProgramData',
    'USERPROFILE',
    'HOMEDRIVE',
    'HOMEPATH',
  ].map((k) => k.toLowerCase()),
);

/**
 * Builds the environment for a probed server: allowlisted ambient vars, then
 * the server's explicitly-configured env overlaid on top (the user chose those
 * for this server). Nothing else from process.env leaks in.
 */
export function buildProbeEnv(serverEnv: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && ENV_ALLOWLIST.has(key.toLowerCase())) {
      env[key] = value;
    }
  }
  return { ...env, ...serverEnv };
}

export interface TempCwd {
  path: string;
  cleanup(): Promise<void>;
}

/**
 * A fresh, empty working directory for the probed process — separate from the
 * user's project, containing nothing of value. Made read-only on POSIX as a
 * speed bump (same-uid children can undo it, but there is nothing here to
 * protect; the point is isolation from the real cwd).
 */
export async function makeTempCwd(): Promise<TempCwd> {
  const path = await mkdtemp(join(tmpdir(), 'sealpin-probe-'));
  try {
    await chmod(path, 0o500);
  } catch {
    // chmod is best-effort (and a no-op on Windows)
  }
  return {
    path,
    async cleanup() {
      try {
        await chmod(path, 0o700);
      } catch {
        /* ignore */
      }
      // On Windows the just-killed child can briefly keep this dir (its cwd)
      // locked, so rm needs retries; and cleanup must never throw, or it would
      // mask the probe's real result/error in the caller's finally block.
      try {
        await rm(path, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
      } catch {
        /* a leftover temp dir is harmless; never fail the probe over it */
      }
    },
  };
}

export interface Isolation {
  /** Human label for the isolation mechanism in effect. */
  mechanism: 'bubblewrap' | 'firejail' | 'sandbox-exec' | 'process-only';
  network: boolean; // true = network access is blocked
  filesystem: boolean; // true = filesystem is confined
}

export interface WrappedCommand {
  command: string;
  args: string[];
  isolation: Isolation;
}

function hasBinary(name: string): boolean {
  const probe = process.platform === 'win32' ? spawnSync('where', [name]) : spawnSync('command', ['-v', name], { shell: true });
  return probe.status === 0;
}

/**
 * Overridable environment probes, so the pure command-construction logic can be
 * unit-tested for every platform without actually being on it.
 */
export interface SandboxEnv {
  platform?: NodeJS.Platform;
  hasBinary?: (name: string) => boolean;
}

/**
 * Wraps the server's launch command in an OS sandbox when one is available on
 * this platform, giving network and filesystem isolation. When none is
 * available (notably on Windows), returns the command unwrapped with
 * `process-only` isolation — the caller decides whether that is acceptable
 * (see --require-sandbox).
 */
export function wrapWithSandbox(command: string, args: string[], cwd: string, env: SandboxEnv = {}): WrappedCommand {
  const platform = env.platform ?? process.platform;
  const has = env.hasBinary ?? hasBinary;
  if (platform === 'linux') {
    if (has('bwrap')) {
      return {
        command: 'bwrap',
        args: [
          '--unshare-net',
          '--unshare-pid',
          '--die-with-parent',
          '--ro-bind', '/', '/',
          '--tmpfs', '/tmp',
          '--proc', '/proc',
          '--dev', '/dev',
          // The temp cwd lives under /tmp, which the tmpfs above just masked.
          // Bind the real cwd back in (writable) so --chdir into it works.
          '--bind', cwd, cwd,
          '--chdir', cwd,
          '--',
          command,
          ...args,
        ],
        isolation: { mechanism: 'bubblewrap', network: true, filesystem: true },
      };
    }
    if (has('firejail')) {
      return {
        command: 'firejail',
        args: ['--quiet', '--net=none', `--private=${cwd}`, '--', command, ...args],
        isolation: { mechanism: 'firejail', network: true, filesystem: true },
      };
    }
  }

  if (platform === 'darwin' && has('sandbox-exec')) {
    // Deny-by-default profile that still allows process execution and file
    // reads (needed to launch node/npx) but blocks all network access.
    const profile = [
      '(version 1)',
      '(allow default)',
      '(deny network*)',
      '(allow network-bind (local ip))',
    ].join(' ');
    return {
      command: 'sandbox-exec',
      args: ['-p', profile, command, ...args],
      isolation: { mechanism: 'sandbox-exec', network: true, filesystem: false },
    };
  }

  return {
    command,
    args,
    isolation: { mechanism: 'process-only', network: false, filesystem: false },
  };
}
