import test from 'node:test';
import assert from 'node:assert/strict';
import fsPromises, { mkdtemp, mkdir, writeFile, readFile, rm, readdir, unlink } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { compareRuns } from '../src/compare.mjs';
import { loadCatalog } from '../src/dashboard/catalog.mjs';
import { writeComparisonReports } from '../src/comparison-io.mjs';

const finding = (severity = 'critical') => ({ toolId: 'osv', ruleId: 'CVE-test', title: 'Fixture', severity, location: { path: 'a.lock', package: 'npm:a', version: '1' } });
const run = (id, findings = [], extra = {}) => ({ schemaVersion: 1, id, startedAt: '2026-10-27T00:00:00Z', endedAt: '2026-10-27T00:01:00Z', target: { path: '/repo' }, status: 'completed', tools: [{ id: 'osv', selected: true, status: 'completed', findings }], findings, ...extra });
const sandbox = async (fn) => { const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-r022-c-')); try { return await fn(root); } finally { await rm(root, { recursive: true, force: true }); } };

test('#19 global incompleteness prevents resolution and explains unobserved entries on either side', () => {
  for (const extra of [{ status: 'partial' }, { status: 'failed' }, { verificationPassed: false }, { verification: { passed: false } }, { pendingIntegrations: ['deferred-fixture'] }]) {
    for (const side of ['baseline', 'current']) {
      const base = run('base', [finding()], side === 'baseline' ? extra : {});
      const current = run('current', [], side === 'current' ? extra : {});
      const comparison = compareRuns(base, current);
      assert.equal(comparison.counts.resolved, 0, `${side} ${JSON.stringify(extra)}`);
      assert.equal(comparison.counts.unobserved, 1);
      assert.ok(comparison.entries[0].reasons.some((reason) => reason.startsWith(`${side}:run-`)), JSON.stringify(comparison.entries[0].reasons));
      assert.equal(comparison.gate.exitCode, 2);
    }
  }
  assert.equal(compareRuns(run('base', [finding()]), run('current')).counts.resolved, 1);
});

test('#25 catalog derives exact gate sets from new/regressed findings and canonical thresholds', async () => sandbox(async (root) => {
  const cases = [];
  for (const severity of ['critical', 'high', 'medium', 'low', 'info', 'unknown']) for (const failOn of ['critical', 'high', 'medium', 'low', 'info', 'any', 'none']) {
    const valid = compareRuns(run('base'), run('current', [finding(severity)]), { failOn });
    cases.push({ payload: valid, ready: true });
    const forged = structuredClone(valid);
    if (valid.gate.violations.length || valid.gate.unknown.length) {
      forged.gate = { failOn, violations: [], unknown: [], exitCode: 0 };
    } else {
      forged.gate = { failOn, violations: [valid.entries[0].id], unknown: [], exitCode: 1 };
    }
    cases.push({ payload: forged, ready: false });
  }
  for (const [index, item] of cases.entries()) {
    const dir = path.join(root, String(index).padStart(3, '0')); await mkdir(dir);
    await writeFile(path.join(dir, 'comparison.json'), JSON.stringify(item.payload));
  }
  const { catalog } = await loadCatalog(root);
  for (const [index, item] of cases.entries()) {
    const entry = catalog.artifacts.find((entry) => entry.label === `${String(index).padStart(3, '0')}/comparison.json`);
    assert.equal(entry.state, item.ready ? 'ready' : 'error', `${item.payload.entries[0].after.severity}/${item.payload.gate.failOn} forged=${!item.ready}`);
    if (!item.ready) assert.equal(entry.error.code, 'invalid_artifact');
  }
  const regression = compareRuns(run('base', [finding('low')]), run('current', [finding('critical')]));
  regression.gate = { failOn: 'high', violations: [], unknown: [], exitCode: 0 };
  await writeFile(path.join(root, 'comparison.json'), JSON.stringify(regression));
  assert.equal((await loadCatalog(root)).catalog.artifacts.find((item) => item.label === 'comparison.json').state, 'error');
  const uppercase = compareRuns(run('base'), run('current', [finding('critical')]));
  uppercase.entries[0].after.severity = 'CRITICAL';
  await writeFile(path.join(root, 'comparison.json'), JSON.stringify(uppercase));
  assert.equal((await loadCatalog(root)).catalog.artifacts.find((item) => item.label === 'comparison.json').state, 'ready');
  uppercase.gate = { failOn: 'high', violations: [], unknown: [], exitCode: 0 };
  await writeFile(path.join(root, 'comparison.json'), JSON.stringify(uppercase));
  assert.equal((await loadCatalog(root)).catalog.artifacts.find((item) => item.label === 'comparison.json').state, 'error');
}));

test('#26 saved comparisons require equal normalized target paths', async () => sandbox(async (root) => {
  const saved = compareRuns(run('base'), run('current'));
  saved.current.target.path = '/elsewhere';
  await writeFile(path.join(root, 'comparison.json'), JSON.stringify(saved));
  assert.equal((await loadCatalog(root)).catalog.artifacts[0].state, 'error');
  saved.current.target.path = '/repo/child/..';
  await writeFile(path.join(root, 'comparison.json'), JSON.stringify(saved));
  assert.equal((await loadCatalog(root)).catalog.artifacts[0].state, 'ready');
}));

for (const existing of [false, true]) test(`#21 simultaneous processes reserve one ${existing ? 'empty' : 'absent'} output and publish a matching JSON/HTML pair`, async () => sandbox(async (root) => {
  const output = path.join(root, 'shared'); if (existing) await mkdir(output);
  const source = `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    import { writeComparisonReports } from ${JSON.stringify(new URL('../src/comparison-io.mjs', import.meta.url).href)};
    import { compareRuns } from ${JSON.stringify(new URL('../src/compare.mjs', import.meta.url).href)};
    const original = fs.readdir;
    fs.readdir = async (...args) => { const entries = await original(...args); process.send({ checked: true }); await new Promise(resolve => process.once('message', resolve)); return entries; };
    syncBuiltinESMExports();
    await new Promise(resolve => process.once('message', resolve));
    const id = process.argv[2];
    const run = id => ({schemaVersion:1,id,startedAt:'2026-10-27T00:00:00Z',endedAt:'2026-10-27T00:01:00Z',target:{path:'/repo'},status:'completed',tools:[],findings:[]});
    try { await writeComparisonReports(compareRuns(run('base-'+id),run('current-'+id)),process.argv[1]); process.send({ success:true,id }); }
    catch(error) { process.send({ success:false,id,error:error.message }); }
    process.disconnect();
  `;
  const children = ['FIRST', 'SECOND'].map((id) => spawn(process.execPath, ['--input-type=module', '-e', source, output, id], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }));
  const checked = new Set(); let releaseTimer;
  const results = children.map((child) => new Promise((resolve, reject) => {
    let stderr = ''; child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('message', (message) => {
      if (message.checked) { checked.add(child); if (!releaseTimer) releaseTimer = setTimeout(() => { for (const writer of checked) writer.send('release'); }, 150); }
      if (message.success !== undefined) resolve(message);
    });
    child.on('exit', (code) => { if (code) reject(new Error(stderr)); });
  }));
  for (const child of children) child.send('start');
  const settled = await Promise.all(results);
  assert.equal(settled.filter((result) => result.success).length, 1, JSON.stringify(settled));
  const winner = settled.find((result) => result.success).id;
  const json = JSON.parse(await readFile(path.join(output, 'comparison.json'), 'utf8'));
  const html = await readFile(path.join(output, 'comparison.html'), 'utf8');
  assert.equal(json.current.id, `current-${winner}`); assert.ok(html.includes(`current-${winner}`));
  assert.deepEqual((await readdir(output)).sort(), ['comparison.html', 'comparison.json']);
}));

test('#21 stale reservations fail actionably and remain owned by their creator', async () => sandbox(async (root) => {
  const lock = path.join(root, '.comparison.lock'); await writeFile(lock, 'stale fixture');
  await assert.rejects(writeComparisonReports(compareRuns(run('base'), run('current')), root), /reservation|lock/i);
  assert.equal(await readFile(lock, 'utf8'), 'stale fixture');
  assert.deepEqual(await readdir(root), ['.comparison.lock']);
}));

test('#21 a failed write keeps the reservation until the other writer settles, then cleans up', async () => sandbox(async (root) => {
  const original = fsPromises.open;
  let release;
  let reached;
  const held = new Promise((resolve) => { release = resolve; });
  const waiting = new Promise((resolve) => { reached = resolve; });
  fsPromises.open = async (filename, ...args) => {
    if (path.basename(filename).startsWith('.comparison.json.') && filename.endsWith('.tmp')) throw new Error('fixture-json-write-failure');
    if (path.basename(filename).startsWith('.comparison.html.') && filename.endsWith('.tmp')) { reached(); await held; }
    return original(filename, ...args);
  };
  syncBuiltinESMExports();
  let first;
  try {
    first = writeComparisonReports(compareRuns(run('base'), run('current')), root);
    // Register rejection immediately so a broken implementation is observable.
    const rejected = assert.rejects(first, /fixture-json-write-failure/);
    await waiting;
    assert.ok((await readdir(root)).includes('.comparison.lock'));
    await assert.rejects(writeComparisonReports(compareRuns(run('other'), run('current')), root), /reservation exists/);
    release(); await rejected;
    assert.equal((await readdir(root)).includes('.comparison.lock'), false);
  } finally { release(); await first?.catch(() => {}); fsPromises.open = original; syncBuiltinESMExports(); }
}));

test('#21 cleanup never removes a replacement reservation owned by another writer', async () => sandbox(async (root) => {
  const original = fsPromises.readdir;
  const lock = path.join(root, '.comparison.lock');
  let replaced = false;
  fsPromises.readdir = async (...args) => {
    if (!replaced) { replaced = true; await unlink(lock); await writeFile(lock, 'replacement-owner'); }
    return original(...args);
  };
  syncBuiltinESMExports();
  try { await writeComparisonReports(compareRuns(run('base'), run('current')), root); }
  finally { fsPromises.readdir = original; syncBuiltinESMExports(); }
  assert.equal(await readFile(lock, 'utf8'), 'replacement-owner');
}));
