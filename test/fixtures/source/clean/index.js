// A benign MCP server source fixture — should produce no source findings.
const { execFile } = require('child_process');

function listDir(args) {
  // Safe: fixed command, arguments passed as an array (no shell).
  execFile('ls', ['-la', args.path], (err, stdout) => {
    console.log(stdout);
  });
}

function getConfig() {
  // Safe: reads a specific known env var, not the whole environment.
  return { logLevel: process.env.LOG_LEVEL ?? 'info' };
}

async function health() {
  // Safe: talks only to localhost.
  const res = await fetch('http://localhost:8080/health');
  return res.ok;
}

module.exports = { listDir, getConfig, health };
