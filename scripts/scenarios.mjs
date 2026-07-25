// Cross-server composition study: run sealpin's workspace analysis over a set of
// REALISTIC multi-server MCP setups — the combinations people actually configure,
// built from real published server packages. Measures how often the lethal
// trifecta and related composition risks appear in typical agent configs.
//
// These are representative scenarios (real servers, plausible combos), not a
// sample of real users' private configs (which are not public). Nothing is run;
// this is pure config-level capability analysis.
//
// Usage: node scripts/scenarios.mjs

import { inferCapabilities, analyzeWorkspace } from '../dist/index.js';

const npx = (pkg, ...rest) => ({ command: 'npx', args: ['-y', pkg, ...rest] });
const withEnv = (spec, env) => ({ ...spec, env });

// Each scenario is a named MCP config (a set of co-loaded servers).
const SCENARIOS = [
  { name: 'Coding assistant', servers: {
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/home/me/project'),
    github: withEnv(npx('mcp-server-github'), { GITHUB_TOKEN: 'ghp_x' }),
    'brave-search': npx('@brave/brave-search-mcp-server'),
    shell: npx('mcp-server-shell'),
  } },
  { name: 'Research assistant', servers: {
    'brave-search': npx('@brave/brave-search-mcp-server'),
    fetch: npx('mcp-fetch'),
    notion: npx('@notionhq/notion-mcp-server'),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/home/me/notes'),
  } },
  { name: 'Web automation', servers: {
    puppeteer: npx('puppeteer-mcp-server'),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/downloads'),
    slack: withEnv(npx('mcp-server-slack'), { SLACK_TOKEN: 'xoxb-x' }),
  } },
  { name: 'DevOps / SRE', servers: {
    kubernetes: npx('kubernetes-mcp-server'),
    shell: npx('mcp-server-shell'),
    github: withEnv(npx('mcp-server-github'), { GITHUB_TOKEN: 'ghp_x' }),
    slack: withEnv(npx('mcp-server-slack'), { SLACK_TOKEN: 'xoxb-x' }),
  } },
  { name: 'Knowledge base', servers: {
    notion: npx('@notionhq/notion-mcp-server'),
    obsidian: npx('obsidian-mcp-server'),
    'brave-search': npx('@brave/brave-search-mcp-server'),
    fetch: npx('mcp-fetch'),
  } },
  { name: 'Data analyst', servers: {
    postgres: withEnv(npx('enhanced-postgres-mcp-server'), { DATABASE_URL: 'postgres://x' }),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/data'),
    fetch: npx('mcp-fetch'),
  } },
  { name: 'Support agent', servers: {
    slack: withEnv(npx('mcp-server-slack'), { SLACK_TOKEN: 'xoxb-x' }),
    gmail: npx('@gongrzhe/server-gmail-autoauth-mcp'),
    'brave-search': npx('@brave/brave-search-mcp-server'),
  } },
  { name: 'CI helper', servers: {
    github: withEnv(npx('mcp-server-github'), { GITHUB_TOKEN: 'ghp_x' }),
    shell: npx('mcp-server-shell'),
    fetch: npx('mcp-fetch'),
  } },
  { name: 'Browser + notes', servers: {
    'chrome-devtools': npx('chrome-devtools-mcp'),
    obsidian: npx('obsidian-mcp-server'),
    fetch: npx('mcp-fetch'),
  } },
  { name: 'Docs writer', servers: {
    fetch: npx('mcp-fetch'),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/home/me/docs'),
    confluence: npx('mcp-jira-confluence'),
  } },
  { name: 'Payments agent', servers: {
    stripe: withEnv(npx('@stripe/mcp'), { STRIPE_SECRET_KEY: 'sk_live_x' }),
    fetch: npx('mcp-fetch'),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/home/me/finance'),
  } },
  // Deliberately conservative setups (should stay clean):
  { name: 'Local scratchpad (safe)', servers: {
    memory: npx('@modelcontextprotocol/server-memory'),
    thinking: npx('@modelcontextprotocol/server-sequential-thinking'),
    filesystem: npx('@modelcontextprotocol/server-filesystem', '/home/me/scratch'),
  } },
  { name: 'Read-only DB (safe)', servers: {
    sqlite: npx('mcp-server-sqlite', '--db', '/home/me/app.db'),
    memory: npx('@modelcontextprotocol/server-memory'),
  } },
  { name: 'Web browse only (safe)', servers: {
    'brave-search': npx('@brave/brave-search-mcp-server'),
    fetch: npx('mcp-fetch'),
  } },
];

function contextsFor(scenario) {
  return Object.entries(scenario.servers).map(([name, s]) => ({
    server: { name, command: s.command, args: s.args ?? [], env: s.env ?? {}, client: 'claude-desktop', configPath: scenario.name },
    manifest: { server: name, tools: [] },
    workspace: [],
  }));
}

const counts = { 'MCP-X001': 0, 'MCP-X002': 0, 'MCP-X003': 0, any: 0 };
console.log(`Cross-server composition study — ${SCENARIOS.length} realistic MCP setups (config-level analysis; nothing executed)\n`);

for (const scenario of SCENARIOS) {
  const ctxs = contextsFor(scenario);
  const findings = analyzeWorkspace(ctxs);
  const xids = [...new Set(findings.map((f) => f.ruleId))].sort();
  for (const id of ['MCP-X001', 'MCP-X002', 'MCP-X003']) if (xids.includes(id)) counts[id]++;
  if (xids.length) counts.any++;

  console.log(`■ ${scenario.name}`);
  for (const c of ctxs) {
    const tags = [...inferCapabilities(c.server, c.manifest).capabilities].join(', ') || '—';
    console.log(`    ${c.server.name.padEnd(16)} ${tags}`);
  }
  console.log(`    → ${xids.length ? xids.join(', ') : 'clean'}\n`);
}

const n = SCENARIOS.length;
const pct = (x) => `${Math.round((x / n) * 100)}%`;
console.log('='.repeat(60));
console.log('AGGREGATE');
console.log('='.repeat(60));
console.log(`Scenarios:                       ${n}`);
console.log(`With any composition finding:    ${counts.any} (${pct(counts.any)})`);
console.log(`Lethal trifecta (MCP-X001):      ${counts['MCP-X001']} (${pct(counts['MCP-X001'])})`);
console.log(`Untrusted -> exec (MCP-X002):    ${counts['MCP-X002']} (${pct(counts['MCP-X002'])})`);
console.log(`Confused deputy (MCP-X003):      ${counts['MCP-X003']} (${pct(counts['MCP-X003'])})`);
