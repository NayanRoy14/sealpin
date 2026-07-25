import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ServerConfig } from '../types/config.js';
import { ToolManifestSchema, type ToolManifest } from '../types/manifest.js';

/**
 * Where tool manifests come from. v1 only ships a file-backed source: a
 * directory of `<serverName>.json` files, each a ToolManifest. This is what
 * `--manifest-dir` points at.
 *
 * The live-handshake source (probe/) lands in a later build session; it will
 * implement this same interface so nothing downstream changes. Keeping the
 * boundary here is what lets the whole rule/report pipeline be built and
 * tested now without ever executing third-party code.
 */
export interface ManifestSource {
  load(server: ServerConfig): Promise<ToolManifest | null>;
}

export interface FileManifestSourceOptions {
  /** Called when a manifest file exists but is unreadable or invalid; that server is skipped. */
  onError?: (server: string, message: string) => void;
}

export class FileManifestSource implements ManifestSource {
  constructor(
    private readonly dir: string,
    private readonly options: FileManifestSourceOptions = {},
  ) {}

  async load(server: ServerConfig): Promise<ToolManifest | null> {
    const path = join(this.dir, `${server.name}.json`);
    let raw: string;
    try {
      raw = await readFile(path, 'utf-8');
    } catch (err) {
      if (isNodeError(err) && err.code === 'ENOENT') return null; // no manifest for this server
      this.options.onError?.(server.name, err instanceof Error ? err.message : String(err));
      return null;
    }
    // Hostile input: validate the whole shape through zod before any rule
    // touches it. Force the manifest's server name to match the config so a
    // mislabeled file can't smuggle findings under the wrong server. A malformed
    // file skips that one server rather than aborting the whole scan.
    try {
      const parsed = ToolManifestSchema.parse(JSON.parse(raw));
      return { ...parsed, server: server.name };
    } catch (err) {
      this.options.onError?.(server.name, `invalid manifest at ${path}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }
}

/** A source that always returns null — used when no manifests are available. */
export const emptyManifestSource: ManifestSource = {
  async load() {
    return null;
  },
};

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}
