import type { ManifestSource } from '../scan/index.js';
import { FileManifestSource } from '../scan/index.js';
import { ProbeManifestSource, type Isolation } from '../probe/index.js';
import { color } from '../report/color.js';

export interface SourceOpts {
  probe?: boolean;
  manifestDir?: string;
  probeTimeout?: string;
  requireSandbox?: boolean;
}

export class SourceError extends Error {}

/**
 * Resolves the manifest source from CLI flags. --probe takes precedence over
 * --manifest-dir; with neither, returns undefined (config-only rules still run
 * on `scan`; lock/verify/diff treat undefined as an error). Probe warnings and
 * a one-time isolation banner are written to stderr so they don't pollute
 * --json / --sarif output on stdout.
 */
export function resolveManifestSource(opts: SourceOpts): ManifestSource | undefined {
  if (opts.probe) {
    let bannerShown = false;
    return new ProbeManifestSource({
      ...(opts.probeTimeout ? { timeoutMs: parseTimeout(opts.probeTimeout) } : {}),
      ...(opts.requireSandbox ? { requireSandbox: true } : {}),
      onIsolation: (iso) => {
        if (bannerShown) return;
        bannerShown = true;
        printIsolationBanner(iso);
      },
      onError: (server, message) => {
        console.error(color.yellow(`  ! could not probe ${server}: `) + message);
      },
    });
  }
  if (opts.manifestDir) {
    return new FileManifestSource(opts.manifestDir, {
      onError: (server, message) => console.error(color.yellow(`  ! skipped manifest for ${server}: `) + message),
    });
  }
  return undefined;
}

function parseTimeout(raw: string): number {
  const ms = Number(raw);
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new SourceError(`invalid --probe-timeout: ${raw} (expected a positive number of milliseconds)`);
  }
  return ms;
}

function printIsolationBanner(iso: Isolation): void {
  if (iso.network) {
    console.error(
      color.dim(`  probe isolation: ${iso.mechanism} (network blocked${iso.filesystem ? ', filesystem confined' : ''})`),
    );
  } else {
    console.error(
      color.yellow('  ⚠ probe isolation: process-only — network is NOT blocked on this platform. ') +
        color.dim('Only probe servers you already trust, or use --require-sandbox on a supported OS.'),
    );
  }
}
