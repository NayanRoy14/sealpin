export { discoverServers, discoverClaudeDesktop, discoverClaudeCode, discoverCursor } from './discover/index.js';
export {
  lock,
  verify,
  readLockfile,
  writeLockfile,
  hashManifest,
  canonicalize,
  canonicalizeTool,
  diffManifests,
  isEmptyDiff,
  DEFAULT_LOCKFILE_NAME,
  type VerifyResult,
  type VerifyStatus,
  type ManifestDiff,
  type ChangedTool,
  type LockFile,
  type LockEntry,
} from './lockfile/index.js';
export type { ServerConfig, McpClient } from './types/config.js';
export type { ToolManifest, Tool } from './types/manifest.js';
export type { Rule, Finding, ScanContext, Severity, Confidence, RuleCategory } from './types/rule.js';
