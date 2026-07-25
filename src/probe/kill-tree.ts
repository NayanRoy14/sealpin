import { spawn, type ChildProcess } from 'node:child_process';

/**
 * Kills a child and its descendants. Node's `child.kill()` does not reap a
 * process tree on Windows, and a launcher like npx spawns a real server as a
 * grandchild — so a hostile or hung server must be killed by tree, not by the
 * launcher pid alone.
 */
export function killTree(child: ChildProcess): void {
  if (child.pid === undefined || child.killed) return;
  if (process.platform === 'win32') {
    // /T = tree, /F = force. Detached + ignored stdio so it can't hang us.
    spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', detached: true }).unref();
    return;
  }
  try {
    // Negative pid targets the whole process group (child spawned detached).
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    try {
      child.kill('SIGKILL');
    } catch {
      /* already gone */
    }
  }
}
