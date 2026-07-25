#!/usr/bin/env node
import { Command, Option } from 'commander';
import { discoverServers, discoverFromFile } from '../discover/index.js';
import type { ServerConfig } from '../types/config.js';
import type { Severity } from '../types/rule.js';
import { ALL_RULES, RULE_DOCS, getRule, meetsSeverity, severityOf } from '../rules/index.js';
import { scanServers, hasFindingAtOrAbove, type ManifestSource } from '../scan/index.js';
import type { Finding } from '../types/rule.js';
import { LocalSourceResolver } from '../resolve/index.js';
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
import { resolveManifestSource, SourceError, type SourceOpts } from './manifest-source.js';
import { ExitCode } from './exit-codes.js';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface CommonOpts {
  config?: string;
  color?: boolean;
}

async function discover(opts: CommonOpts): Promise<ServerConfig[]> {
  if (opts.config) return discoverFromFile(opts.config);
  return discoverServers({
    onWarn: (client, message) => console.error(color.yellow(`  ! skipped ${client} config: `) + message),
  });
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
  'directory of <server>.json tool manifests (static source; alternative to --probe)',
);

/** Options shared by every command that needs live tool manifests. */
function withManifestSource(cmd: Command): Command {
  return cmd
    .addOption(manifestDirOption)
    .option('--probe', 'extract manifests live by running each server in a sandbox (opt-in; executes third-party code)')
    .addOption(new Option('--probe-timeout <ms>', 'per-server probe timeout in milliseconds').default('10000'))
    .option('--require-sandbox', 'refuse to probe unless an OS network sandbox is available');
}

// ---------------------------------------------------------------- scan
withManifestSource(
  program
    .command('scan')
    .description('Scan discovered MCP servers for prompt-injection and capability risks')
    .addOption(configOption),
)
  .option('-s, --source-dir <dir>', 'analyze server source at this local path (enables source/supply-chain AST rules)')
  .option('--json', 'output findings as JSON')
  .option('--sarif', 'output findings as SARIF 2.1.0 (for GitHub code scanning)')
  .addOption(new Option('--severity <min>', 'hide findings below this severity').choices(SEVERITIES))
  .addOption(new Option('--fail-on <severity>', 'exit 1 if any finding is at/above this severity').choices(SEVERITIES).default('high'))
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const servers = await discover(opts);
      const source = resolveManifestSource(opts as SourceOpts);
      const sourceResolver = new LocalSourceResolver(opts.sourceDir ? { dir: opts.sourceDir } : {});
      // Scan without the display filter so the --fail-on gate always sees every
      // finding; --severity only affects what is rendered.
      const summary = await scanServers(servers, {
        ...(source ? { manifestSource: source } : {}),
        sourceResolver,
      });

      // The CI gate is evaluated on the complete finding set, independent of --severity.
      const gated = hasFindingAtOrAbove(summary.findings, opts.failOn as Severity);

      const displayed = opts.severity
        ? { ...summary, findings: filterBySeverity(summary.findings, opts.severity as Severity) }
        : summary;

      if (opts.json) console.log(renderJson(displayed));
      else if (opts.sarif) console.log(renderSarif(displayed));
      else console.log(renderText(displayed));

      process.exitCode = gated ? ExitCode.Findings : ExitCode.Clean;
    } catch (err) {
      fail(err);
    }
  });

// ---------------------------------------------------------------- lock
withManifestSource(
  program
    .command('lock')
    .description(`Write ${DEFAULT_LOCKFILE_NAME}, pinning the current tool manifest for every server`)
    .addOption(configOption),
)
  .option('-o, --out <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const source = requireManifestSource(opts);
      const servers = await discover(opts);
      const { manifests, missing } = await loadManifests(servers, source);
      if (manifests.length === 0) {
        console.error(color.red('No manifests obtained. Nothing to lock.'));
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
withManifestSource(
  program
    .command('verify')
    .description(`Re-hash current manifests and compare against ${DEFAULT_LOCKFILE_NAME}`)
    .addOption(configOption),
)
  .option('-l, --lockfile <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const source = requireManifestSource(opts);
      const lockfile = await readLockfile(opts.lockfile);
      if (!lockfile) {
        console.error(color.red(`No lockfile at ${opts.lockfile}. Run 'sealpin lock' first.`));
        process.exitCode = ExitCode.Error;
        return;
      }
      const servers = await discover(opts);
      const { manifests } = await loadManifests(servers, source);
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
withManifestSource(
  program
    .command('diff')
    .description('Show a human-readable changeset between locked and current manifests')
    .addOption(configOption),
)
  .option('-l, --lockfile <path>', 'lockfile path', DEFAULT_LOCKFILE_NAME)
  .option('--no-color', 'disable ANSI colors')
  .action(async (opts) => {
    applyColor(opts);
    try {
      const source = requireManifestSource(opts);
      const lockfile = await readLockfile(opts.lockfile);
      if (!lockfile) {
        console.error(color.red(`No lockfile at ${opts.lockfile}. Run 'sealpin lock' first.`));
        process.exitCode = ExitCode.Error;
        return;
      }
      const servers = await discover(opts);
      const { manifests } = await loadManifests(servers, source);
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
function requireManifestSource(opts: SourceOpts): ManifestSource {
  const source = resolveManifestSource(opts);
  if (!source) {
    throw new UsageError(
      'this command needs tool manifests. Either pass --probe (run each server in a sandbox to extract ' +
        'its manifest) or --manifest-dir <dir> (a directory of <server>.json manifests).',
    );
  }
  return source;
}

function warnMissing(missing: string[]): void {
  if (missing.length > 0) {
    console.log(color.dim(`  (no manifest for: ${missing.join(', ')})`));
  }
}

function filterBySeverity(findings: Finding[], min: Severity): Finding[] {
  return findings.filter((f) => meetsSeverity(severityOf(f.ruleId), min));
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
  const isUsage = err instanceof UsageError || err instanceof SourceError;
  console.error(color.red(isUsage ? 'error: ' : 'scan failed: ') + msg);
  process.exitCode = ExitCode.Error;
}

await program.parseAsync(process.argv);
