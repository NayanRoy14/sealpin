import { homedir } from 'node:os';
import type { ServerConfig } from '../types/config.js';
import type { ToolManifest } from '../types/manifest.js';
import type { Finding } from '../types/rule.js';
import type { Capability, CapabilityEvidence, CapabilitySet } from './types.js';

const SECRET_ENV_KEY = /token|secret|password|passwd|api[_-]?key|access[_-]?key|credential|private[_-]?key|\bauth\b/i;
const SECRET_ENV_VALUE = /\bgh[pousr]_[A-Za-z0-9]{16,}|\bsk-[A-Za-z0-9_-]{16,}|\bAKIA[0-9A-Z]{16}|\bAIza[0-9A-Za-z_-]{35}|-----BEGIN/;

interface CapRule {
  re: RegExp;
  caps: Capability[];
  reason: string;
}

// Matched against `${name} ${command} ${args}` — server-level identity.
const NAME_RULES: CapRule[] = [
  { re: /filesystem|server-filesystem|file-?system|\bfs\b/i, caps: ['data.filesystem', 'sink.filesystem'], reason: 'filesystem server' },
  { re: /\b(shell|terminal|bash|zsh|powershell|pwsh|cmd)\b/i, caps: ['exec'], reason: 'shell/command server' },
  {
    re: /notion|gmail|\bmail\b|email|calendar|contacts|github|gitlab|bitbucket|postgres|mysql|mongo|sqlite|database|\bdb\b|slack|discord|telegram|jira|linear|confluence|\bdrive\b|dropbox|\bnotes?\b|obsidian|metabase/i,
    caps: ['data.private'],
    reason: 'accesses a private data store',
  },
  {
    // Messaging/notification servers are an outbound channel by their nature —
    // their purpose is to send content somewhere the recipient (or an attacker)
    // can read it.
    re: /slack|discord|telegram|gmail|\bemail\b|\bmail\b|twilio|\bsms\b|sendgrid|mailgun|postmark|nodemailer|webhook/i,
    caps: ['sink.messaging', 'sink.egress'],
    reason: 'messaging/notification server (outbound channel)',
  },
  {
    re: /fetch|\bsearch\b|brave|duckduckgo|perplexity|tavily|puppeteer|playwright|firecrawl|crawl|scrape|browser|\bweb\b|context7|\bhttp\b/i,
    caps: ['content.untrusted', 'sink.egress'],
    reason: 'web/content-fetching server',
  },
];

// Matched against `${toolName} ${toolDescription}` — per-tool behaviour.
const TOOL_RULES: CapRule[] = [
  { re: /\b(read_file|read_text_file|read_multiple_files|get_file|open_file|list_dir|list_directory|read_dir|directory_tree|cat)\b/i, caps: ['data.filesystem'], reason: 'reads local files' },
  { re: /\b(write_file|create_file|edit_file|delete_file|move_file|append|make_directory|put_file|patch_file)\b/i, caps: ['sink.filesystem'], reason: 'writes local files' },
  { re: /\b(fetch|browse|navigate|scrape|crawl|get_url|read_url|open_url|download|screenshot|web_search|search_web|http_request)\b/i, caps: ['content.untrusted', 'sink.egress'], reason: 'fetches external web content' },
  { re: /\b(send_email|send_message|post_message|send_mail|notify|webhook|publish|slack|create_issue|create_comment|reply|dispatch|sms)\b/i, caps: ['sink.messaging', 'sink.egress'], reason: 'sends outbound messages' },
  { re: /\b(exec|execute|run_command|run_shell|shell|spawn|eval|run_script|system)\b/i, caps: ['exec'], reason: 'executes commands' },
  { re: /\b(list_notes?|get_notes?|search_notes?|list_emails?|read_email|get_messages?|list_issues?|query_database|run_query|execute_sql)\b/i, caps: ['data.private'], reason: 'reads private user data' },
];

// Per-server findings that imply a capability.
const FINDING_CAPS: Record<string, { cap: Capability; reason: string }[]> = {
  'MCP-C001': [{ cap: 'data.filesystem', reason: 'over-broad filesystem root' }, { cap: 'data.secrets', reason: 'filesystem root can read credential files' }],
  'MCP-C002': [{ cap: 'exec', reason: 'unrestricted command execution' }],
  'MCP-C003': [{ cap: 'data.secrets', reason: 'plaintext secret in config' }],
  'MCP-S003': [{ cap: 'exec', reason: 'command injection sink' }],
  'MCP-S004': [{ cap: 'data.secrets', reason: 'reads the whole environment' }, { cap: 'sink.egress', reason: 'sends environment to the network' }],
  'MCP-S005': [{ cap: 'sink.egress', reason: 'hardcoded outbound request' }],
  'MCP-S006': [{ cap: 'exec', reason: 'dynamic code execution' }],
};

function isBroadRoot(arg: string): boolean {
  const p = arg.trim();
  return p === '/' || /^[A-Za-z]:[\\/]?$/.test(p) || p === '~' || p === homedir();
}

/**
 * Infers a server's capabilities from its config, manifest, and (optionally)
 * its per-server findings. Pure and deterministic; every tag carries evidence.
 */
export function inferCapabilities(server: ServerConfig, manifest: ToolManifest, findings: Finding[] = []): CapabilitySet {
  const evidence: CapabilityEvidence[] = [];
  const seen = new Set<string>();
  const add = (capability: Capability, via: CapabilityEvidence['via'], reason: string, detail?: string): void => {
    const key = `${capability}|${via}|${detail ?? ''}|${reason}`;
    if (seen.has(key)) return;
    seen.add(key);
    evidence.push({ capability, via, reason, ...(detail !== undefined ? { detail } : {}) });
  };

  // Server identity (name / command / package spec).
  const identity = `${server.name} ${server.command} ${server.args.join(' ')}`;
  for (const rule of NAME_RULES) {
    if (rule.re.test(identity)) for (const cap of rule.caps) add(cap, 'config', rule.reason);
  }

  // A filesystem server rooted broadly can read credential files.
  const looksFs = evidence.some((e) => e.capability === 'data.filesystem');
  if (looksFs && server.args.some(isBroadRoot)) {
    add('data.secrets', 'config', 'filesystem root can read credential files (~/.ssh, ~/.aws)');
  }

  // Secrets in the environment block.
  for (const [key, value] of Object.entries(server.env)) {
    if (SECRET_ENV_KEY.test(key) || SECRET_ENV_VALUE.test(value)) {
      add('data.secrets', 'env', `credential in env var ${key}`, key);
    }
  }

  // Per-tool behaviour + MCP annotations.
  for (const tool of manifest.tools) {
    const hay = `${tool.name} ${tool.description ?? ''}`;
    for (const rule of TOOL_RULES) {
      if (rule.re.test(hay)) for (const cap of rule.caps) add(cap, 'tool', rule.reason, tool.name);
    }
    const ann = tool.annotations;
    if (ann?.openWorldHint) {
      add('content.untrusted', 'tool', 'open-world tool (interacts with external entities)', tool.name);
      add('sink.egress', 'tool', 'open-world tool (interacts with external entities)', tool.name);
    }
  }

  // Reinforce from per-server findings.
  for (const f of findings) {
    for (const { cap, reason } of FINDING_CAPS[f.ruleId] ?? []) {
      add(cap, 'finding', reason, f.ruleId);
    }
  }

  return { server: server.name, capabilities: new Set(evidence.map((e) => e.capability)), evidence };
}
