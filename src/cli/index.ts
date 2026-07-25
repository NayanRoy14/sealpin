#!/usr/bin/env node
import { Command, Option } from 'commander';
import { discoverServers, discoverFromFile } from '../discover/index.js';
import type { ServerConfig } from '../types/config.js';
import type { Severity } from '../types/rule.js';
import { ALL_RULES, RULE_DOCS, getRule } from '../rules/index.js';
import { FileManifestSource, scanServers, hasFindingAtOrAbove } from '../scan/index.js';
import {
  lock,
  verify,
  readLockfile,
  writeLockfile,
  diffManifests,
  isEmptyDiff,
  DEFAULT_LOCKFILE_NAME,
} from '../lockfile/index.js';
import { renderText, renderJson, renderSarif, setColorEnabled } from '../report/index.js';
import { color } from '../report/color.js';
import { loadManifests } from './load-manifests.js';
import { ExitCode } from './exit-codes.js';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface CommonOpts {
  config?: string;
  color?: boolean;
}

async function discover(opts: CommonOpts): Promise<ServerConfig[]> {
  if (opts.config) return discoverFromFile(opts.config);
  return discoverServers();
}

function applyColor(opts: CommonOpts): void {
  if (opts.color === false) setColorEnabled(false);
}

const program = new Command();

program
  .name('sealpin')
  .description('A supply-chain and prompt-injection scanner for MCP servers.')
  .version('0.1.0');

const configOption = new Option('-c, --config <path>', 'scan an explicit MCP config file instead of auto-discovering');
const manifestDirOption = new Option(
  '-m, --manifest-dir <dir>',
  'directory of <server>.json tool manifests (until sandboxed probing lands, manifests are supplied here)',
);

// ---------------------------------------------------------------- scan
program
  .command('scan')
  .description('Scan discovered MCP servers for prompt-injection and capability risks')
  .addOption(configOption)
  .addOption(manifestDirOption)
  .option('--json', 'output findings as JSON')
  .option('--sarif', 'output findings as SARIF 2.1.0 (for GitHub code scanning)')
  .addOption(new Option('--severity <min>', 'hide findings below this severity').choices(SEVERITIES))
  .addOption(new Option('--fail-on <severity>', 'exit 1 if any finding is at/above this severity').choices(SEVERITIES).default('high'))
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const servers = await discover(opts);
      const summary = await scanServers(servers, {
        ...(opts.manifestDir ? { manifestSource: new FileManifestSource(opts.manifestDir) } : {}),
        ...(opts.severity ? { minSeverity: opts.severity as Severity } : {}),
      });

      if (opts.json) console.log(renderJson(summary));
      else if (opts.sarif) console.log(renderSarif(summary));
      else console.log(renderText(summary));

      process.exitCode = hasFindingAtOrAbove(summary.findings, opts.failOn as Severity)
        ? ExitCode.Findings
        : ExitCode.Clean;
    } catch (err) {
      fail(err);
    }
  });

// ---------------------------------------------------------------- lock
program
  .command('lock')
  .description(`Write ${DEFAULT_LOCKFILE_NAME}, pinning the current tool manifest for every server`)
  .addOption(configOption)
  .addOption(manifestDirOption)
  .option('-o, --out <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const dir = requireManifestDir(opts);
      const servers = await discover(opts);
      const { manifests, missing } = await loadManifests(servers, dir);
      if (manifests.length === 0) {
        console.error(color.red('No manifests found in ') + dir + color.red('. Nothing to lock.'));
        process.exitCode = ExitCode.Error;
        return;
      }
      const lockfile = lock(manifests);
      await writeLockfile(opts.out, lockfile);
      console.log(color.green('✓ locked ') + `${manifests.length} server(s) → ${opts.out}`);
      warnMissing(missing);
      process.exitCode = ExitCode.Clean;
    } catch (err) {
      fail(err);
    }
  });

// ---------------------------------------------------------------- verify
program
  .command('verify')
  .description(`Re-hash current manifests and compare against ${DEFAULT_LOCKFILE_NAME}`)
  .addOption(configOption)
  .addOption(manifestDirOption)
  .option('-l, --lockfile <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const dir = requireManifestDir(opts);
      const lockfile = await readLockfile(opts.lockfile);
      if (!lockfile) {
        console.error(color.red(`No lockfile at ${opts.lockfile}. Run 'sealpin lock' first.`));
        process.exitCode = ExitCode.Error;
        return;
      }
      const servers = await discover(opts);
      const { manifests } = await loadManifests(servers, dir);
      const results = verify(manifests, lockfile);

      let drift = false;
      for (const r of results) {
        switch (r.status) {
          case 'match':
            console.log(`${color.green('✓ match')}   ${r.server}`);
            break;
          case 'drift':
            drift = true;
            console.log(`${color.red('✗ DRIFT')}   ${r.server}  ${color.dim(`${short(r.lockedHash)} → ${short(r.currentHash)}`)}`);
            break;
          case 'missing':
            drift = true;
            console.log(`${color.yellow('✗ MISSING')} ${r.server}  ${color.dim('was locked, no current manifest')}`);
            break;
          case 'new':
            console.log(`${color.yellow('• new')}     ${r.server}  ${color.dim("not in lockfile — run 'sealpin lock' to pin")}`);
            break;
        }
      }

      if (drift) {
        console.log('\n' + color.red('Drift detected. ') + "Review changes with 'sealpin diff' before trusting these servers.");
        process.exitCode = ExitCode.Drift;
      } else {
        console.log('\n' + color.green('All locked manifests match.'));
        process.exitCode = ExitCode.Clean;
      }
    } catch (err) {
      fail(err);
    }
  });

// ---------------------------------------------------------------- diff
program
  .command('diff')
  .description('Show a human-readable changeset between locked and current manifests')
  .addOption(configOption)
  .addOption(manifestDirOption)
  .option('-l, --lockfile <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const dir = requireManifestDir(opts);
      const lockfile = await readLockfile(opts.lockfile);
      if (!lockfile) {
        console.error(color.red(`No lockfile at ${opts.lockfile}. Run 'sealpin lock' first.`));
        process.exitCode = ExitCode.Error;
        return;
      }
      const servers = await discover(opts);
      const { manifests } = await loadManifests(servers, dir);
      const currentByServer = new Map(manifests.map((m) => [m.server, m]));

      let anyChange = false;
      for (const entry of lockfile.entries) {
        const current = currentByServer.get(entry.server);
        if (!current) {
          anyChange = true;
          console.log(color.yellow(`~ ${entry.server}: locked but no current manifest`));
          continue;
        }
        const d = diffManifests(entry.manifest, current);
        if (isEmptyDiff(d)) continue;
        anyChange = true;
        console.log(color.bold(`\n${entry.server}`));
        for (const t of d.addedTools) console.log(color.green(`  + tool ${t.name}`));
        for (const t of d.removedTools) console.log(color.red(`  - tool ${t.name}`));
        for (const c of d.changedTools) {
          console.log(color.yellow(`  ~ tool ${c.name}`));
          if (c.before.description !== c.after.description) {
            console.log(color.dim(`      was: ${truncate(c.before.description ?? '')}`));
            console.log(color.dim(`      now: ${truncate(c.after.description ?? '')}`));
          }
        }
      }

      if (!anyChange) {
        console.log(color.green('No manifest changes since lock.'));
        process.exitCode = ExitCode.Clean;
      } else {
        process.exitCode = ExitCode.Drift;
      }
    } catch (err) {
      fail(err);
    }
  });

// ---------------------------------------------------------------- rules / explain
program
  .command('rules')
  .description('List all rules')
  .action(() => {
    for (const rule of ALL_RULES) {
      const doc = RULE_DOCS[rule.id];
      console.log(`${color.bold(rule.id)}  ${color.dim(`[${rule.severity}/${rule.confidence}]`)}  ${doc?.title ?? ''}`);
    }
  });

program
  .command('explain')
  .argument('<ruleId>', 'rule id, e.g. MCP-P001')
  .description('Explain what a rule detects and why it matters')
  .action((ruleId: string) => {
    const rule = getRule(ruleId);
    const doc = RULE_DOCS[rule?.id ?? ruleId.toUpperCase()];
    if (!rule || !doc) {
      console.error(color.red(`Unknown rule: ${ruleId}. Run 'sealpin rules' to list them.`));
      process.exitCode = ExitCode.Error;
      return;
    }
    console.log(color.bold(`${rule.id} — ${doc.title}`));
    console.log(color.dim(`severity: ${rule.severity} · confidence: ${rule.confidence} · category: ${rule.category} · ${doc.attack}`));
    console.log('');
    console.log(doc.summary);
  });

// ---------------------------------------------------------------- helpers
function requireManifestDir(opts: { manifestDir?: string }): string {
  if (!opts.manifestDir) {
    throw new UsageError(
      "this command needs tool manifests. Pass --manifest-dir <dir> (a directory of <server>.json manifests). " +
        'Live sandboxed extraction (--probe) lands in a later build session.',
    );
  }
  return opts.manifestDir;
}

function warnMissing(missing: string[]): void {
  if (missing.length > 0) {
    console.log(color.dim(`  (no manifest for: ${missing.join(', ')})`));
  }
}

function short(hash?: string): string {
  return hash ? hash.slice(0, 12) : '—';
}

function truncate(s: string, max = 120): string {
  const one = s.replace(/\r?\n/g, ' ');
  return one.length <= max ? one : one.slice(0, max - 1) + '…';
}

class UsageError extends Error {}

function fail(err: unknown): void {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(color.red(err instanceof UsageError ? 'error: ' : 'scan failed: ') + msg);
  process.exitCode = ExitCode.Error;
}

await program.parseAsync(process.argv);
