import type { Rule } from '../../types/rule.js';
import { makeFinding, snippet } from '../util.js';
import { editDistance, extractPackageName } from './pkg-name.js';

/**
 * A8 — typosquatting. A small curated set of widely-installed MCP servers and
 * ubiquitous npm packages. A configured package that is edit-distance 1 from
 * one of these, but not itself on the list, is a likely typosquat: the user
 * meant to install the popular package and a lookalike name resolves to
 * attacker-controlled code that runs via `npx -y` before any tool is called.
 */
const POPULAR = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/sdk',
  'express',
  'lodash',
  'axios',
  'chalk',
  'commander',
  'zod',
];

const POPULAR_SET = new Set(POPULAR);

/** Distance threshold scales a little with name length, but stays tight to avoid noise. */
function threshold(name: string): number {
  return name.length >= 16 ? 2 : 1;
}

export const typosquatRule: Rule = {
  id: 'MCP-S001',
  severity: 'high',
  confidence: 'likely',
  category: 'supply-chain',
  async check(ctx) {
    const pkg = extractPackageName(ctx.server);
    if (!pkg || POPULAR_SET.has(pkg)) return [];

    let best: { name: string; distance: number } | null = null;
    for (const popular of POPULAR) {
      const d = editDistance(pkg, popular);
      if (d === 0) return []; // exact match (shouldn't happen given the set check)
      if (d <= threshold(popular) && (!best || d < best.distance)) {
        best = { name: popular, distance: d };
      }
    }
    if (!best) return [];

    return [
      makeFinding('MCP-S001', ctx.server.name, {
        location: { file: ctx.server.configPath },
        message: `Package "${pkg}" is edit-distance ${best.distance} from the popular package "${best.name}" — a likely typosquat.`,
        evidence: snippet(`${ctx.server.command} ${ctx.server.args.join(' ')}`),
        rationale:
          'Installing a lookalike package name runs attacker-controlled code on your machine, typically via `npx -y` before any tool is ever called (a postinstall script or the module top level executes immediately). Typosquats of popular packages are a common delivery vector.',
        remediation: `Confirm you intended "${pkg}" and not "${best.name}". Check the package on npm (author, download count, repository) before running it.`,
      }),
    ];
  },
};
