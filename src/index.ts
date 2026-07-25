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
export { discoverFromFile } from './discover/index.js';
export type { ServerConfig, McpClient } from './types/config.js';
export type { ToolManifest, Tool } from './types/manifest.js';
export type { Rule, Finding, ScanContext, Severity, Confidence, RuleCategory } from './types/rule.js';

// rules
export { ALL_RULES, getRule, runRules, meetsSeverity, severityOf, RULE_DOCS, type RuleDoc } from './rules/index.js';

// scan pipeline
export {
  scanServers,
  hasFindingAtOrAbove,
  FileManifestSource,
  emptyManifestSource,
  type ScanOptions,
  type ManifestSource,
} from './scan/index.js';

// reporting
export { renderText, renderJson, renderSarif, setColorEnabled, type ReportSummary } from './report/index.js';

// resolve (source-code access for source/supply-chain rules)
export {
  LocalSourceResolver,
  analyzableSource,
  devendorBundle,
  looksBundled,
  isMinified,
  type ServerSource,
  type SourceFile,
  type SourceResolver,
  type SourceKind,
} from './resolve/index.js';

// probe (live, sandboxed manifest extraction)
export {
  probeServer,
  ProbeManifestSource,
  ProbeError,
  buildProbeEnv,
  wrapWithSandbox,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  type ProbeOptions,
  type Isolation,
} from './probe/index.js';
