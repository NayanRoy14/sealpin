#!/usr/bin/env node
import { Command } from 'commander';
import { discoverServers } from '../discover/index.js';
import { ExitCode } from './exit-codes.js';

const program = new Command();

program
  .name('sealpin')
  .description('A supply-chain and prompt-injection scanner for MCP servers.')
  .version('0.1.0');

program
  .command('scan')
  .description('Discover MCP servers configured in Claude Desktop, Claude Code, and Cursor')
  .option('--json', 'output as JSON')
  .action(async (opts: { json?: boolean }) => {
    try {
      const servers = await discoverServers();
      if (servers.length === 0) {
        console.log('No MCP servers found in Claude Desktop, Claude Code, or Cursor configs.');
        process.exitCode = ExitCode.Clean;
        return;
      }
      if (opts.json) {
        console.log(JSON.stringify(servers, null, 2));
      } else {
        for (const s of servers) {
          console.log(`${s.name}  [${s.client}]`);
          console.log(`  command: ${s.command} ${s.args.join(' ')}`);
          console.log(`  config:  ${s.configPath}`);
        }
      }
      process.exitCode = ExitCode.Clean;
    } catch (err) {
      console.error('scan failed:', err instanceof Error ? err.message : err);
      process.exitCode = ExitCode.Error;
    }
  });

// lock/verify/diff all need live tool manifests, which requires resolve/ and
// probe/ — not built in this session (see project scaffolding scope). Wired
// as real subcommands now so the CLI surface matches the target shape, but
// they fail loudly instead of pretending to work.
function notImplemented(name: string) {
  return () => {
    console.error(
      `'${name}' requires live tool-manifest extraction, which isn't implemented yet ` +
        "(resolve/ and probe/ land in a later build session). For now, use 'sealpin scan' " +
        'to see discovered servers.',
    );
    process.exitCode = ExitCode.Error;
  };
}

program
  .command('lock')
  .description('Write sealpin.json, pinning the current tool manifest for every server')
  .action(notImplemented('lock'));

program
  .command('verify')
  .description('Re-hash current tool manifests and compare against sealpin.json')
  .action(notImplemented('verify'));

program
  .command('diff')
  .description('Show a human-readable changeset between locked and current manifests')
  .action(notImplemented('diff'));

await program.parseAsync(process.argv);
