import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { loadCatalog } from '../src/dashboard/catalog.mjs';
import { compareRuns } from '../src/compare.mjs';

const finding = { toolId: 'osv', ruleId: 'SYNTHETIC', title: '<img onerror=alert(1)>', severity: 'high', location: { path: 'package-lock.json', package: 'npm:demo', version: '1.0.0' }, verification: 'candidate' };
const run = (id, findings = [], overrides = {}) => ({ schemaVersion: 1, id, startedAt: '2026-10-27T00:00:00Z', endedAt: '2026-10-27T00:01:00Z', target: { path: '/synthetic/target' }, status: 'completed', tools: [{ id: 'osv', status: 'completed', selected: true, findings }], findings, ...overrides });
const bytes = (value) => Buffer.from(JSON.stringify(value));
const hash = (value) => createHash('sha256').update(value).digest('hex');
async function sandbox(fn) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-catalog-'));
  try { return await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test('discovers only root and immediate-child artifacts with location-derived opaque IDs', async () => sandbox(async (root) => {
  const child = path.join(root, 'a-child');
  const deep = path.join(child, 'grandchild');
  await mkdir(deep, { recursive: true });
  await mkdir(path.join(root, 'raw'));
  const rootBytes = bytes(run('../../outside', [finding]));
  const childBytes = bytes(run('../../outside'));
  const base = run('baseline');
  const current = run('current', [finding]);
  const saved = compareRuns(base, current);
  const comparisonBytes = bytes(saved);
  await writeFile(path.join(root, 'run.json'), rootBytes);
  await writeFile(path.join(child, 'run.json'), childBytes);
  await writeFile(path.join(child, 'comparison.json'), comparisonBytes);
  await writeFile(path.join(deep, 'run.json'), bytes(run('deep')));
  await writeFile(path.join(root, 'raw', 'run.json'), bytes(run('raw')));
  await writeFile(path.join(root, 'other.json'), bytes(run('unknown')));

  const { catalog, records } = await loadCatalog(root);
  assert.deepEqual(catalog.artifacts.map((entry) => [entry.kind, entry.label, entry.state]), [
    ['run', 'run.json', 'ready'],
    ['run', 'a-child/run.json', 'ready'],
    ['comparison', 'a-child/comparison.json', 'ready'],
  ]);
  assert.notEqual(catalog.artifacts[0].id, catalog.artifacts[1].id);
  assert.match(catalog.artifacts[0].id, /^[a-f0-9]{64}$/);
  assert.equal(records.get(catalog.artifacts[0].id).sha256, hash(rootBytes));
  assert.equal(records.get(catalog.artifacts[2].id).sha256, hash(comparisonBytes));
  assert.deepEqual(await readFile(path.join(root, 'run.json')), rootBytes);
  assert.deepEqual(await readFile(path.join(child, 'run.json')), childBytes);
  assert.deepEqual(await readFile(path.join(child, 'comparison.json')), comparisonBytes);
  assert.equal(catalog.artifacts.some((entry) => entry.label.includes('grandchild')), false);
}));

test('malformed and unsafe artifacts become payload-free fixed errors', async () => sandbox(async (root) => {
  await mkdir(path.join(root, 'child'));
  await writeFile(path.join(root, 'run.json'), '{"token":"synthetic-secret-123"');
  const outside = path.join(root, 'outside.json');
  await writeFile(outside, bytes(run('outside')));
  await symlink(outside, path.join(root, 'child', 'run.json'));
  await symlink(path.dirname(outside), path.join(root, 'linked-child'));
  const { catalog, records } = await loadCatalog(root);
  const errors = catalog.artifacts.filter((entry) => entry.state === 'error');
  assert.ok(errors.length >= 2);
  assert.ok(errors.every((entry) => !('payload' in entry) && !records.has(entry.id)));
  assert.equal(JSON.stringify(catalog).includes('synthetic-secret-123'), false);
  assert.ok(errors.some((entry) => entry.error.code === 'invalid_artifact'));
  assert.ok(errors.some((entry) => ['unsafe_artifact', 'artifact_unreadable'].includes(entry.error.code)));
}));

test('applies lowerable production limits and reports truncation', async () => sandbox(async (root) => {
  for (const name of ['a', 'b', 'c']) {
    const directory = path.join(root, name);
    await mkdir(directory);
    await writeFile(path.join(directory, 'run.json'), bytes(run(name)));
  }
  const { catalog } = await loadCatalog(root, { limits: { directoryEntries: 2, artifacts: 1, artifactBytes: 4096, totalBytes: 4096, findingLeavesPerRun: 10, findingLeavesTotal: 10 } });
  assert.equal(catalog.snapshot.truncated, true);
  assert.ok(catalog.snapshot.notices.some((notice) => notice.code === 'catalog_limit'));
  await assert.rejects(loadCatalog(root, { limits: { artifacts: 129 } }), /limit/i);
}));

test('rejects depth, node, per-run finding and shared-byte overages with fixed error entries', async () => sandbox(async (root) => {
  const child = path.join(root, 'child');
  await mkdir(child);
  await writeFile(path.join(root, 'run.json'), bytes(run('too-many', [finding, { ...finding, ruleId: 'SECOND' }])));
  await writeFile(path.join(child, 'run.json'), bytes(run('deep')));
  const deep = JSON.parse(await readFile(path.join(child, 'run.json'), 'utf8'));
  let nested = {};
  for (let index = 0; index < 66; index += 1) nested = { nested };
  deep.metadata = nested;
  await writeFile(path.join(child, 'run.json'), bytes(deep));
  const byFindings = await loadCatalog(root, { limits: { findingLeavesPerRun: 1 } });
  assert.equal(byFindings.catalog.artifacts.find((entry) => entry.label === 'run.json').error.code, 'artifact_too_large');
  const byDepth = await loadCatalog(root);
  assert.equal(byDepth.catalog.artifacts.find((entry) => entry.label === 'child/run.json').error.code, 'artifact_too_large');
  const nodes = Array.from({ length: 100001 }, () => null);
  await writeFile(path.join(child, 'run.json'), JSON.stringify(nodes));
  const byNodes = await loadCatalog(root);
  assert.equal(byNodes.catalog.artifacts.find((entry) => entry.label === 'child/run.json').error.code, 'artifact_too_large');

  await writeFile(path.join(root, 'run.json'), '{}');
  await writeFile(path.join(child, 'run.json'), 'abcdef');
  const fsPromises = fs.promises;
  const originalOpen = fsPromises.open;
  let bytesRead = 0;
  fsPromises.open = async (...args) => {
    const handle = await originalOpen(...args);
    const read = handle.read.bind(handle);
    handle.read = async (...readArgs) => { const result = await read(...readArgs); bytesRead += result.bytesRead; return result; };
    return handle;
  };
  syncBuiltinESMExports();
  let byBytes;
  try { byBytes = await loadCatalog(root, { limits: { artifactBytes: 10, totalBytes: 5 } }); }
  finally { fsPromises.open = originalOpen; syncBuiltinESMExports(); }
  assert.equal(byBytes.catalog.artifacts.find((entry) => entry.label === 'run.json').error.code, 'invalid_artifact');
  assert.equal(byBytes.catalog.artifacts.find((entry) => entry.label === 'child/run.json').error.code, 'artifact_too_large');
  assert.equal(byBytes.catalog.snapshot.truncated, true);
  assert.ok(bytesRead <= 5, `reader consumed ${bytesRead} bytes beyond the 5-byte shared budget`);
}));

test('validates saved comparison counts, enums and gate references without hiding ready runs', async () => sandbox(async (root) => {
  const childNames = ['wrong-kind', 'bad-count', 'bad-gate', 'bad-enum', 'duplicate-entry'];
  const base = run('base');
  const current = run('current', [finding, { ...finding, title: 'Second', location: { path: 'other.lock', package: 'npm:other', version: '2' } }]);
  const saved = compareRuns(base, current);
  await writeFile(path.join(root, 'run.json'), bytes(base));
  for (const [index, name] of childNames.entries()) {
    const directory = path.join(root, name);
    await mkdir(directory);
    const payload = structuredClone(saved);
    if (name === 'wrong-kind') payload.kind = 'other';
    if (name === 'bad-count') payload.counts.new += 1;
    if (name === 'bad-gate') payload.gate.violations = ['dangling'];
    if (name === 'bad-enum') payload.gate.failOn = 'never';
    if (name === 'duplicate-entry') payload.entries[1].id = payload.entries[0].id;
    await writeFile(path.join(directory, 'comparison.json'), bytes(payload));
  }
  const { catalog } = await loadCatalog(root);
  assert.equal(catalog.artifacts.find((entry) => entry.kind === 'run').state, 'ready');
  assert.ok(catalog.artifacts.filter((entry) => entry.kind === 'comparison').every((entry) => entry.state === 'error' && entry.error.code === 'invalid_artifact'));
}));

test('shares the retained leaf/entry capacity across artifact kinds and commits it only after validation', async () => sandbox(async (root) => {
  const base = run('base');
  const current = run('current', [finding]);
  const saved = compareRuns(base, current);
  await writeFile(path.join(root, 'comparison.json'), bytes(saved));
  const child = path.join(root, 'run-child');
  await mkdir(child);
  await writeFile(path.join(child, 'run.json'), bytes(run('child', [finding])));
  const limited = await loadCatalog(root, { limits: { findingLeavesTotal: 1 } });
  assert.equal(limited.catalog.artifacts.find((entry) => entry.kind === 'comparison').state, 'ready');
  assert.equal(limited.catalog.artifacts.find((entry) => entry.kind === 'run').error.code, 'artifact_too_large');

  const corrupt = structuredClone(saved);
  corrupt.counts.new += 1;
  await writeFile(path.join(root, 'comparison.json'), bytes(corrupt));
  const invalidDoesNotConsume = await loadCatalog(root, { limits: { findingLeavesTotal: 1 } });
  assert.equal(invalidDoesNotConsume.catalog.artifacts.find((entry) => entry.kind === 'comparison').error.code, 'invalid_artifact');
  assert.equal(invalidDoesNotConsume.catalog.artifacts.find((entry) => entry.kind === 'run').state, 'ready');
}));

test('rejects a child directory replaced by a symlink at the descriptor-open boundary', async () => sandbox(async (root) => {
  const child = path.join(root, 'child');
  const parked = path.join(root, 'child-before-swap');
  const outside = `${root}-outside`;
  await mkdir(child);
  await mkdir(outside);
  await writeFile(path.join(child, 'run.json'), bytes(run('inside')));
  await writeFile(path.join(outside, 'run.json'), bytes(run('outside', [], { provenance: { token: 'outside-content-must-not-escape' } })));
  const fsPromises = fs.promises;
  const originalOpen = fsPromises.open;
  const canonicalChildFile = path.join(await realpath(child), 'run.json');
  let swapped = false;
  fsPromises.open = async (filename, ...args) => {
    if (!swapped && filename === canonicalChildFile) {
      swapped = true;
      await rename(child, parked);
      await symlink(outside, child);
    }
    return originalOpen(filename, ...args);
  };
  syncBuiltinESMExports();
  try {
    const { catalog, records } = await loadCatalog(root);
    const result = catalog.artifacts.find((entry) => entry.label === 'child/run.json');
    assert.equal(swapped, true, JSON.stringify(catalog.artifacts));
    assert.equal(result.state, 'error');
    assert.ok(['artifact_changed', 'unsafe_artifact'].includes(result.error.code));
    assert.equal(records.has(result.id), false);
    assert.equal(JSON.stringify(catalog).includes('outside-content-must-not-escape'), false);
  } finally {
    fsPromises.open = originalOpen;
    syncBuiltinESMExports();
    await unlink(child).catch(() => {});
    await rename(parked, child).catch(() => {});
    await rm(outside, { recursive: true, force: true });
  }
}));

test('rejects FIFOs without opening or waiting on them', { skip: process.platform === 'win32' }, async () => sandbox(async (root) => {
  const fifo = path.join(root, 'run.json');
  execFileSync('mkfifo', [fifo]);
  const { catalog, records } = await loadCatalog(root);
  const entry = catalog.artifacts[0];
  assert.equal(entry.state, 'error');
  assert.equal(entry.error.code, 'unsafe_artifact');
  assert.equal(records.has(entry.id), false);
}));

test('does not block if a regular artifact becomes a FIFO at open time', { skip: process.platform === 'win32' }, async () => sandbox(async (root) => {
  await writeFile(path.join(root, 'run.json'), bytes(run('swapped')));
  const script = `
    import fsp from 'node:fs/promises';
    import { execFileSync } from 'node:child_process';
    import path from 'node:path';
    import { loadCatalog } from ${JSON.stringify(new URL('../src/dashboard/catalog.mjs', import.meta.url).href)};
    const root = await fsp.realpath(process.argv[1]);
    const file = path.join(root, 'run.json');
    const originalOpen = fsp.open;
    let swapped = false;
    fsp.open = async (filename, flags, ...rest) => {
      if (!swapped && filename === file) { swapped = true; await fsp.unlink(file); execFileSync('mkfifo', [file]); }
      return originalOpen(filename, flags, ...rest);
    };
    const result = await loadCatalog(root);
    process.stdout.write(JSON.stringify({ swapped, entry: result.catalog.artifacts[0] }));
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, root], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const result = await new Promise((resolve) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); resolve({ timedOut: true }); }, 1500);
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ timedOut: false, code, signal }); });
  });
  assert.equal(result.timedOut, false, `catalog blocked opening a FIFO: ${stderr}`);
  assert.equal(result.code, 0, stderr);
  const output = JSON.parse(stdout);
  assert.equal(output.swapped, true);
  assert.equal(output.entry.state, 'error');
  assert.equal(output.entry.error.code, 'unsafe_artifact');
}));

test('keeps permission failures visible instead of treating them as absent artifacts', async () => sandbox(async (root) => {
  const child = path.join(root, 'child');
  await mkdir(child);
  await writeFile(path.join(child, 'run.json'), bytes(run('unreadable')));
  const fsPromises = fs.promises;
  const originalLstat = fsPromises.lstat;
  const canonicalFile = path.join(await realpath(child), 'run.json');
  fsPromises.lstat = async (filename, ...args) => {
    if (filename === canonicalFile) throw Object.assign(new Error('denied'), { code: 'EACCES' });
    return originalLstat(filename, ...args);
  };
  syncBuiltinESMExports();
  try {
    const { catalog } = await loadCatalog(root);
    const entry = catalog.artifacts.find((item) => item.label === 'child/run.json');
    assert.equal(entry.state, 'error');
    assert.equal(entry.error.code, 'artifact_unreadable');
  } finally { fsPromises.lstat = originalLstat; syncBuiltinESMExports(); }
}));

test('native Windows target paths in saved runs and comparisons are valid on any host', async () => sandbox(async (root) => {
  const baseline = run('windows-baseline', [], { target: { path: 'c:\\Users\\Developer\\repo' } });
  const current = run('windows-current', [finding], { target: { path: 'C:/Users/Developer/repo/' } });
  await writeFile(path.join(root, 'run.json'), bytes(current));
  const initial = await loadCatalog(root);
  assert.equal(initial.catalog.artifacts[0].state, 'ready');
  assert.equal(initial.catalog.artifacts[0].summary.runId, 'windows-current');
  const comparison = compareRuns(baseline, current);
  await writeFile(path.join(root, 'comparison.json'), bytes(comparison));
  const { catalog } = await loadCatalog(root);
  assert.equal(catalog.artifacts.find((entry) => entry.kind === 'comparison').state, 'ready');
}));
