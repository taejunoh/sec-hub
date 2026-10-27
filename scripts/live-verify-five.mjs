#!/usr/bin/env node
// Invokes real configured adapters; controlled-CLI tests are not live scan evidence.
import { cp, mkdir, mkdtemp, readFile, lstat, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadConfig } from '../src/config.mjs';
import { runProcess } from '../src/processes.mjs';
import { cleanVerificationLog as clean } from './live-verify-redaction.mjs';
import { ensureSafeDirectory, atomicWriteFile } from '../src/safe-io.mjs';
import { startHeaderFixture } from '../test/helpers/php-header-server.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = path.resolve(projectRoot, '../..');
const selected = ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell'];
const usage = 'Usage: node scripts/live-verify-five.mjs --config ABS_CONFIG --out NEW_ABS_DIR [--runtime ABS_NODE_22_OR_NEWER]';

function options(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--config', '--out', '--runtime'].includes(argv[i]) || result[argv[i]] || !argv[i + 1] || !path.isAbsolute(argv[i + 1])) throw new Error(usage);
    result[argv[i]] = path.resolve(argv[i + 1]);
  }
  if (!result['--config'] || !result['--out']) throw new Error(usage);
  return { config: result['--config'], out: result['--out'], runtime: result['--runtime'] ?? process.execPath };
}
async function absent(destination) {
  try { await lstat(destination); throw new Error(`Choose a new output path: ${destination}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function hashes(directory, prefix = '') {
  const result = {};
  for (const entry of (await readdir(path.join(directory, prefix), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === '.git') continue;
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) Object.assign(result, await hashes(directory, relative));
    else if (entry.isFile()) result[relative] = createHash('sha256').update(await readFile(path.join(directory, relative))).digest('hex');
    else result[relative] = entry.isSymbolicLink() ? 'symbolic-link' : 'non-regular-file';
  }
  return result;
}
function changes(before, after) {
  return { added: Object.keys(after).filter(key => !Object.hasOwn(before, key)), removed: Object.keys(before).filter(key => !Object.hasOwn(after, key)), changed: Object.keys(before).filter(key => Object.hasOwn(after, key) && before[key] !== after[key]) };
}

export async function runFiveToolVerification({
  argv = process.argv.slice(2), processRef = process, loadConfigImpl = loadConfig,
  runProcessImpl = runProcess, startFixtureImpl = startHeaderFixture,
  ensureSafeDirectoryImpl = ensureSafeDirectory, atomicWriteFileImpl = atomicWriteFile,
} = {}) {
  const { config, out, runtime } = options(argv);
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node.js 22 or newer is required');
  await absent(out);
  const configured = await loadConfigImpl(config);
  const cs = configured.tools['codex-security']?.scanOptions;
  const ocr = configured.tools['open-code-review']?.scanOptions;
  if (!cs?.auth || !cs?.model || !cs?.effort || !cs?.maxCost || !cs?.maxTimeMinutes || !ocr?.provider || !ocr?.model || !ocr?.maxTokensBudget || !ocr?.concurrency || !ocr?.timeoutMinutes) throw new Error('Explicit bounded scanOptions are required for both AI tools');
  await ensureSafeDirectoryImpl(out);
  const controller = new AbortController(), cancel = () => controller.abort();
  processRef.once('SIGINT', cancel); processRef.once('SIGTERM', cancel);
  const commands = [], evidence = { verificationPassed: false, startedAt: new Date().toISOString(), config, scanOptions: { 'codex-security': cs, 'open-code-review': ocr }, commands };
  const capture = async (name, command, args, accepted = [0], extra = {}) => {
    const result = await runProcessImpl({ command, args, successCodes: accepted }, { cwd: projectRoot, timeoutMs: 3_100_000, maxOutputBytes: 2 * 1024 * 1024, signal: controller.signal, ...extra });
    const record = { name, command, args, ...result, stdout: clean(result.stdout), stderr: clean(result.stderr) };
    commands.push(record);
    return record;
  };
  let fixture, target, before;
  try {
    const version = await capture('runtime-version', runtime, ['--version']);
    if (version.status !== 'completed' || !/^v(?:2[2-9]|[3-9]\d)\./.test(version.stdout.trim())) throw new Error('Selected runtime must be Node.js 22 or newer');
    evidence.runtime = version.stdout.trim();
    await mkdir(path.join(workspaceRoot, 'work'), { recursive: true });
    target = await mkdtemp(path.join(workspaceRoot, 'work/live-five-target-'));
    evidence.fixturePath = target;
    await cp(path.join(projectRoot, 'test/fixtures/live-five'), target, { recursive: true });
    for (const args of [['init', '--quiet', target], ['-C', target, 'add', '.'], ['-C', target, '-c', 'user.name=SecHub Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Controlled synthetic scan fixture']]) {
      if ((await capture('initialize-controlled-git', 'git', args)).status !== 'completed') throw new Error('Controlled Git fixture initialization failed');
    }
    before = await hashes(target);
    evidence.targetHashes = { before };
    fixture = await startFixtureImpl();
    evidence.fixtureUrl = fixture.url;
    const hub = path.join(projectRoot, 'bin/sec-hub.mjs');
    const doctor = await capture('doctor-all-tools', runtime, [hub, 'doctor', target, '--json', '--ai', '--config', config]);
    if (doctor.status !== 'completed') throw new Error('Doctor failed');
    evidence.doctor = JSON.parse(doctor.stdout).tools.map(({ id, available, version, reason }) => ({ id, available, version, reason }));
    await capture('five-tool-scan', runtime, [hub, 'scan', target, '--tools', selected.join(','), '--url', fixture.url, '--ai', '--config', config, '--timeout', '600', '--out', out], [0, 1, 2]);
    const run = JSON.parse(await readFile(path.join(out, 'run.json'), 'utf8'));
    evidence.runStatus = run.status;
    evidence.tools = run.tools.filter(tool => selected.includes(tool.id)).map(({ id, selected, status, reason, version, exitCode, findings }) => ({ id, selected, status, reason, version, exitCode, findings: findings.length }));
    evidence.findings = run.findings.length;
    const report = await capture('regenerate-report', runtime, [hub, 'report', out], [0, 1, 2]);
    if (report.status !== 'completed' || report.exitCode === 2) throw new Error('Report regeneration retained incomplete coverage or failed');
    const sarif = JSON.parse(await readFile(path.join(out, 'results.sarif'), 'utf8'));
    const html = await readFile(path.join(out, 'report.html'), 'utf8');
    if (sarif.version !== '2.1.0' || !Array.isArray(sarif.runs) || !sarif.runs.length || !html.includes(run.id)) throw new Error('Generated reports are missing or invalid');
    if (evidence.tools.length !== 5 || evidence.tools.some(tool => tool.selected !== true || tool.status !== 'completed') || run.status !== 'completed') throw new Error('All five selected adapters must complete for verification to pass');
    evidence.verificationPassed = true;
  } catch (error) {
    evidence.error = clean(error.message);
  } finally {
    const noteFailure = (label, error) => {
      evidence.verificationPassed = false;
      const message = clean(error?.message ?? String(error));
      evidence.error ??= `${label}: ${message}`;
      (evidence.finalizationErrors ??= []).push(`${label}: ${message}`);
    };
    const attempt = async (label, action) => {
      try { await action(); }
      catch (error) { noteFailure(label, error); }
    };
    try {
      if (target && before) await attempt('Target hash collection failed', async () => {
        const after = await hashes(target);
        evidence.targetHashes.after = after;
        evidence.targetChanges = changes(before, after);
        if (evidence.targetChanges.changed.length || evidence.targetChanges.removed.length) {
          evidence.verificationPassed = false;
          evidence.error ??= 'Target source files changed during the scan';
        }
      });
      await attempt('Fixture shutdown failed', async () => { await fixture?.close(); });
      await attempt('Output directory preparation failed', async () => { await ensureSafeDirectoryImpl(out); });
      await attempt('Output artifact hashing failed', async () => { evidence.artifactHashes = await hashes(out); });
      evidence.endedAt = new Date().toISOString();
      await attempt('Verification evidence write failed', async () => {
        await atomicWriteFileImpl(path.join(out, 'verification-commands.json'), clean(JSON.stringify(evidence, null, 2)) + '\n', { mode: 0o600 });
      });
      await attempt('Verification summary write failed', async () => {
        await atomicWriteFileImpl(path.join(out, 'LIVE-VERIFICATION.md'), `# Five-tool execution verification\n\n- Verification passed: ${evidence.verificationPassed}.\n- Runtime: ${evidence.runtime ?? 'not verified'}.\n- Controlled target: \`${target ?? 'not prepared'}\`. Source was never installed or executed.\n- Coverage: ${(evidence.tools ?? []).map(tool => `${tool.id}=${tool.status}`).join(', ') || 'scan not completed'}.\n- Native provider authentication remains in upstream login storage.\n- Target byte hashes exclude Git metadata; new native metadata is listed separately.\n- Target changes: ${JSON.stringify(evidence.targetChanges ?? {})}.\n- Native output and reports are retained, including on partial/failing runs.\n- Command results, scan options, versions, hashes and failures: [verification-commands.json](verification-commands.json).\n${evidence.error ? `- Failure: ${evidence.error}\n` : ''}${evidence.finalizationErrors?.length ? `- Finalization errors: ${evidence.finalizationErrors.join('; ')}\n` : ''}`, { mode: 0o600 });
      });
      if (evidence.finalizationErrors?.some(error => error.startsWith('Verification summary write failed:'))) {
        // Refresh machine evidence after a summary-only failure when the output path still accepts writes.
        await attempt('Verification evidence refresh failed', async () => {
          await atomicWriteFileImpl(path.join(out, 'verification-commands.json'), clean(JSON.stringify(evidence, null, 2)) + '\n', { mode: 0o600 });
        });
      }
    } finally {
      processRef.removeListener('SIGINT', cancel);
      processRef.removeListener('SIGTERM', cancel);
    }
  }
  console.log(JSON.stringify({ verificationPassed: evidence.verificationPassed, out, fixturePath: target, status: evidence.runStatus, tools: evidence.tools, error: evidence.error }, null, 2));
  return evidence.verificationPassed ? 0 : 2;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runFiveToolVerification().then(code => { process.exitCode = code; }).catch(error => { console.error(clean(error.message)); process.exitCode = 2; });
}
