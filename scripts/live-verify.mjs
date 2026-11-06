#!/usr/bin/env node
import { cp, mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startHeaderFixture } from '../test/helpers/php-header-server.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = path.resolve(projectRoot, '../..');
const node24 = process.execPath;
const usage = 'Usage: node scripts/live-verify.mjs --config ABSOLUTE_CONFIG --out NEW_ABSOLUTE_SCAN_DIR';

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    if (!['--config', '--out'].includes(flag) || result[flag] || !argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(usage);
    result[flag] = argv[i + 1];
  }
  if (!result['--config'] || !result['--out']) throw new Error(usage);
  if (!path.isAbsolute(result['--config']) || !path.isAbsolute(result['--out'])) throw new Error('--config and --out must be absolute paths');
  return { config: result['--config'], out: result['--out'] };
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd ?? projectRoot, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', code => resolve({ command, args, code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

function assertOk(result, accepted = [0]) {
  if (!accepted.includes(result.code)) throw new Error(`${path.basename(result.command)} exited ${result.code}: ${result.stderr || result.stdout}`);
}

async function requireAbsent(destination) {
  try {
    await stat(destination);
    throw new Error(`Path already exists; choose a new path: ${destination}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

async function main() {
  const { config, out } = parseArgs(process.argv.slice(2));
  if (process.versions.node !== '24.22.1') throw new Error(`Expected Node v24.22.1, found ${process.version}`);
  await requireAbsent(out);
  await stat(config);

  const logsPath = path.join(out, 'verification-commands.json');

  let fixtureRoot = path.join(workspaceRoot, 'work/live-target');
  try { await stat(fixtureRoot); fixtureRoot = path.join(workspaceRoot, 'work', `live-target-${path.basename(out)}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await requireAbsent(fixtureRoot);
  await mkdir(path.dirname(fixtureRoot), { recursive: true });
  await cp(path.join(projectRoot, 'test/fixtures/live-project'), fixtureRoot, { recursive: true });
  await cp(path.join(projectRoot, 'test/fixtures/live-skill/SKILL.md'), path.join(fixtureRoot, 'SKILL.md'));

  const fixture = await startHeaderFixture();
  const commands = [];
  const capture = async (name, command, args, accepted = [0]) => {
    const result = await run(command, args);
    commands.push({ name, ...result });
    assertOk(result, accepted);
    return result;
  };

  try {
    const hub = path.join(projectRoot, 'bin/sec-hub.mjs');
    const doctorResult = await capture('doctor-all-tools', node24, [hub, 'doctor', fixtureRoot, '--json', '--ai', '--config', config]);
    const doctor = JSON.parse(doctorResult.stdout);
    if (doctor.tools.length !== 7) throw new Error(`Doctor listed ${doctor.tools.length} tools, expected 7`);

    const scan = await capture('live-cli-scan', node24, [hub, 'scan', fixtureRoot, '--tools', 'osv,skillspector,php2shell', '--url', fixture.url, '--config', config, '--out', out, '--timeout', '120'], [1]);
    const scanSummary = JSON.parse(scan.stdout);
    const runRecord = JSON.parse(await readFile(path.join(out, 'run.json'), 'utf8'));
    const expected = new Set(['osv', 'skillspector', 'php2shell']);
    const actual = runRecord.tools.filter(tool => expected.has(tool.id));
    if (actual.length !== 3 || actual.some(tool => tool.status !== 'completed')) {
      throw new Error(`Selected tool executions did not all complete; statuses: ${actual.map(tool => `${tool.id}=${tool.status}${tool.reason ? ` (${tool.reason})` : ''}`).join(', ')}`);
    }
    for (const id of expected) {
      const tool = actual.find(item => item.id === id);
      const artifact = id === 'php2shell' ? path.join(out, 'raw', id, 'stdout.txt') : path.join(out, 'raw', id, 'native.json');
      const content = await readFile(artifact, 'utf8');
      if (id === 'osv' && !Array.isArray(JSON.parse(content).results)) throw new Error('OSV native JSON has no results array');
      if (id === 'skillspector') {
        const native = JSON.parse(content);
        if (!Array.isArray(native.issues) || native.execution_successful !== true || native.analysis_completeness?.is_complete === false) throw new Error('SkillSpector native output was incomplete or unsupported');
      }
      if (id === 'php2shell') {
        const native = JSON.parse(content);
        if (native.patch_status !== 'potentially_vulnerable' || native.php_version !== '8.1.2') throw new Error('PHP checker did not observe the inert fixture header as expected');
      }
      if (tool.findings.length < 1) throw new Error(`${id} completed without normalized findings`);
    }
    if (!Array.isArray(runRecord.findings) || runRecord.findings.length < 3) throw new Error('Combined scan did not retain findings from all three tools');
    const regenerated = await capture('regenerate-report', node24, [hub, 'report', out], [1]);
    const reportSummary = JSON.parse(regenerated.stdout);

    const imported = [];
    for (const provider of ['cloudflare', 'anthropic']) {
      const bridgeOut = path.join(out, 'bridges', provider);
      const bridge = await capture(`bridge-${provider}`, node24, [hub, 'bridge', provider, '--out', bridgeOut]);
      const bridgeSummary = JSON.parse(bridge.stdout);
      const example = bridgeSummary.example;
      const importOut = path.join(out, 'imports', provider);
      const result = await capture(`import-${provider}-example`, node24, [hub, 'import', provider, example, '--target', fixtureRoot, '--out', importOut], [1]);
      const importedRun = JSON.parse(await readFile(path.join(importOut, 'run.json'), 'utf8'));
      if (importedRun.tools[0]?.status !== 'imported' || !importedRun.findings.length) throw new Error(`${provider} bridge example did not import a finding`);
      const regeneratedImport = await capture(`regenerate-import-${provider}`, node24, [hub, 'report', importOut], [1]);
      imported.push({ provider, bridge: bridgeSummary, import: JSON.parse(result.stdout), report: JSON.parse(regeneratedImport.stdout) });
    }

    await writeFile(logsPath, JSON.stringify({ node: process.version, fixtureUrl: fixture.url, fixturePath: fixtureRoot, config, doctor: doctor.tools.map(tool => ({ id: tool.id, available: tool.available, reason: tool.reason, version: tool.version })), scanSummary, reportSummary, imported, commands }, null, 2) + '\n', { mode: 0o600 });
    await writeFile(path.join(out, 'LIVE-VERIFICATION.md'), `# Live verification run\n\n- Runtime: ${process.version}\n- Target: controlled fixture at \`${fixtureRoot}\` (locked lodash 4.17.20 metadata, inert SKILL.md, localhost PHP/8.1.2 response header).\n- Tools executed: OSV-Scanner 2.7.0, NVIDIA SkillSpector 2.12.0 in static-only mode, official PHP checker 1.0.0.\n- Hub scan status: ${runRecord.status}; normalized findings: ${runRecord.findings.length}.\n- OSV-Scanner: ${actual.find(tool => tool.id === 'osv').findings.length} finding(s), status completed.\n- SkillSpector: ${actual.find(tool => tool.id === 'skillspector').findings.length} finding(s), status completed.\n- PHP header checker: ${actual.find(tool => tool.id === 'php2shell').findings.length} finding(s), status completed.\n- Authenticated AI services: not invoked.\n- Command stdout/stderr and exit codes: [${path.basename(logsPath)}](${path.basename(logsPath)}).\n- Reports: \`run.json\`, \`report.html\`, and \`results.sarif\` in this directory.\n`, { mode: 0o600 });
    return 0;
  } finally {
    await fixture.close();
  }
}

main().then(code => { process.exitCode = code; }).catch(error => { console.error(error.stack ?? String(error)); process.exitCode = 2; });
