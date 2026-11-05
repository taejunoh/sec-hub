import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { link, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { writeReports } from '../src/reports.mjs';
import { runScan } from '../src/runner.mjs';
import { assertSafeDirectory, atomicWriteFile, ensureSafeDirectory } from '../src/safe-io.mjs';
import { atomicWriteWindowsFile } from '../src/safe-io-windows.mjs';

const execute = promisify(execFile);
const native = { skip: process.platform !== 'win32' };
const windowsDirectory = process.env.SystemRoot ?? 'C:\\Windows';

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'sec-hub-windows-io-')));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  return root;
}

test('Windows path grammar rejects device aliases, streams and remote paths before launching a helper', () => {
  for (const path of [
    'C:\\out\\NUL.txt', 'C:\\out\\LPT¹.txt', 'C:\\out\\report:stream',
    'C:\\out\\report. ', 'C:report', '\\\\server\\share\\report',
    '\\\\?\\C:\\out\\report', '\\\\.\\C:\\out\\report', 'C:\\out\\\ud800',
  ]) {
    assert.throws(() => atomicWriteWindowsFile(path, 'secret'), /Unsafe Windows path/i);
  }
});

test('Windows native: scan saves private raw artifacts and all report formats', native, async t => {
  const root = await fixture(t);
  const target = join(root, 'fixture');
  const directory = join(root, 'Run 한글');
  await mkdir(target);
  const adapter = {
    id: 'fixture', name: 'Fixture scanner', source: 'fixture',
    check: async () => ({ available: true }),
    build: async () => ({ command: process.execPath, args: ['-e', 'process.stdout.write("fixture output")'], cwd: target }),
    parse: async () => [],
  };
  const run = await runScan({ target, out: directory, tools: [adapter.id], adapters: [adapter] });
  assert.equal(run.status, 'completed', run.tools[0]?.reason);
  const saved = await writeReports(run, directory);
  assert.equal(await assertSafeDirectory(join(root, 'rUN 한글')), await realpath(directory));
  assert.equal(JSON.parse(await readFile(saved.json, 'utf8')).id, run.id);
  assert.match(await readFile(saved.html, 'utf8'), /<!doctype html>/i);
  assert.equal(JSON.parse(await readFile(saved.sarif, 'utf8')).version, '2.1.0');
  assert.equal(await readFile(join(directory, 'raw', adapter.id, 'stdout.txt'), 'utf8'), 'fixture output');
  const shell = join(windowsDirectory, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const check = "$acl = Get-Acl -LiteralPath $env:SEC_HUB_TEST_ACL_PATH; [PSCustomObject]@{Protected = $acl.AreAccessRulesProtected; Sids = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]).IdentityReference.Value); Current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value} | ConvertTo-Json -Compress";
  for (const path of [directory, saved.json]) {
    const { stdout } = await execute(shell, ['-NoProfile', '-NonInteractive', '-Command', check], { env: { ...process.env, SEC_HUB_TEST_ACL_PATH: path } });
    const acl = JSON.parse(stdout);
    assert.equal(acl.Protected, true);
    assert.deepEqual(new Set(acl.Sids), new Set(['S-1-5-18', 'S-1-5-32-544', acl.Current]));
  }
});

test('Windows native: untrusted ACL, junction and unsafe file names fail before mutation', native, async t => {
  const root = await fixture(t);
  const outside = join(root, 'outside');
  const exposed = join(root, 'exposed');
  const junction = join(root, 'junction');
  const inherits = join(root, 'inherits');
  await Promise.all([mkdir(outside), mkdir(exposed), mkdir(inherits)]);
  const victim = join(outside, 'victim.txt');
  await writeFile(victim, 'unchanged');
  await symlink(outside, junction, 'junction');
  await assert.rejects(ensureSafeDirectory(join(junction, 'missing')), /reparse|junction/i);
  await assert.rejects(atomicWriteFile(join(junction, 'victim.txt'), 'modified'), /reparse|junction/i);
  const icacls = join(windowsDirectory, 'System32', 'icacls.exe');
  await execute(icacls, [exposed, '/grant', '*S-1-5-11:(DC)']);
  await assert.rejects(ensureSafeDirectory(join(exposed, 'missing')), /ACL/i);
  await assert.rejects(atomicWriteFile(join(exposed, 'report.txt'), 'secret'), /ACL/i);
  assert.deepEqual(await readdir(exposed), []);
  await execute(icacls, [inherits, '/grant', '*S-1-5-11:(OI)(CI)(IO)(M)']);
  await assert.rejects(assertSafeDirectory(inherits), /ACL/i);
  assert.deepEqual(await readdir(inherits), []);
  for (const name of ['victim.txt:secret', 'NUL.txt', 'LPT¹.txt', 'report.txt.', 'report.txt ']) {
    await assert.rejects(atomicWriteFile(join(outside, name), 'secret'), /unsupported|unsafe/i);
  }
  assert.deepEqual(await readdir(outside), ['victim.txt']);
  assert.equal(await readFile(victim, 'utf8'), 'unchanged');
});

test('Windows native: atomic replacement preserves hard-link targets and rolls back stream failure', native, async t => {
  const root = await fixture(t);
  const output = join(root, 'output');
  await ensureSafeDirectory(output);
  const victim = join(root, 'victim.txt');
  const report = join(output, 'report.txt');
  await writeFile(victim, 'unchanged');
  await link(victim, report);
  await atomicWriteFile(report, Uint8Array.from([0, 13, 10, 255]));
  assert.deepEqual(await readFile(report), Buffer.from([0, 13, 10, 255]));
  assert.equal(await readFile(victim, 'utf8'), 'unchanged');
  async function* broken() { yield 'partial'; throw new Error('broken stream'); }
  await assert.rejects(atomicWriteFile(report, broken()), /broken stream/);
  assert.deepEqual(await readFile(report), Buffer.from([0, 13, 10, 255]));
  assert.deepEqual(await readdir(output), ['report.txt']);
});
