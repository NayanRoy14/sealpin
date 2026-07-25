import { readFile } from 'node:fs/promises';

/**
 * Reads and JSON-parses a config file if it exists. Returns null on missing
 * file, throws on anything else (permission errors, malformed JSON) so
 * callers can surface a real error instead of silently skipping a server.
 */
export async function readJsonIfExists(path: string): Promise<unknown | null> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (isNodeError(err) && err.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
  return JSON.parse(raw);
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}
