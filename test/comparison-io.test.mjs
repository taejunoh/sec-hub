import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile, lstat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { readComparisonRun, writeComparisonReports } from '../src/comparison-io.mjs';

const digest = (value) => createHash('sha256').update(value).digest('hex');
const runBytes = (extra = {}) => Buffer.from(JSON.stringify({ schemaVersion: 1, id: 'run-a', ...extra }));
const comparison = (inputs = {}) => ({
  schemaVersion: 1,
  kind: 'sec-hub.comparison',
  identityVersion: 1,
  baseline: { id: '<base>', target: { path: '/private/base' }, status: 'completed' },
  current: { id: 'current', target: { path: '/private/current' }, status: 'completed' },
  status: 'complete',
  coverage: [{ toolId: '<script>', baseline: 'completed', current: 'failed', reasons: ['<img src=x onerror=alert(1)>'] }],
  entries: [{
    id: 'cmp-v1-0123456789abcdef', identity: '0123abcdef'.repeat(6), identityMethod: 'rule-location',
    category: 'regressed', before: { severity: 'low', verification: 'reported', location: { path: 'src/<x>.js', line: 9 }, evidence: '<script>alert(1)</script>' },
    after: { title: '<svg/onload=alert(1)>', severity: 'high', verification: 'candidate', location: { url: 'javascript:alert(1)' }, evidence: '</pre><script>alert(2)</script>' }, reasons: ['<a href="javascript:alert(3)">bad</a>'],
  }],
  counts: { new: 0, regressed: 1, existing: 0, resolved: 0, unobserved: 0 },
  notices: ['Resolved means absent from this completed check; it does not confirm a fix.'],
  gate: { failOn: 'high', violations: ['finding-1'], unknown: [], exitCode: 1 },
  inputs,
});

async function sandbox(fn) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-comparison-io-'));
  try { return await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test('reads a file or run directory and hashes the exact original bytes', async () => sandbox(async (root) => {
  const dir = path.join(root, 'run');
  await mkdir(dir);
  const bytes = runBytes({ title: ' baseline ' });
  const file = path.join(dir, 'run.json');
  await writeFile(file, bytes);
  const fromFile = await readComparisonRun(file);
  const fromDirectory = await readComparisonRun(dir);
  assert.deepEqual(fromFile.run, JSON.parse(bytes));
  assert.equal(fromFile.sha256, digest(bytes));
  assert.equal(fromDirectory.sha256, digest(bytes));
  assert.equal(fromDirectory.artifactRoot, await realpath(dir));
  assert.equal(fromFile.artifactRoot, await realpath(dir));
  const directoryAlias = path.join(root, 'run-directory-alias');
  await symlink(dir, directoryAlias);
  assert.equal((await readComparisonRun(directoryAlias)).file, await realpath(file));
  const arbitrary = path.join(root, 'renamed-baseline.json');
  await writeFile(arbitrary, bytes);
  assert.equal((await readComparisonRun(arbitrary)).artifactRoot, undefined);
}));

test('rejects malformed, missing, unreadable, and oversized run inputs without echoing contents', async () => sandbox(async (root) => {
  const malformed = path.join(root, 'malformed.json');
  await writeFile(malformed, '{"secret":"never echo this"');
  await assert.rejects(readComparisonRun(malformed), (error) => !error.message.includes('never echo this'));
  const missingDir = path.join(root, 'missing');
  await mkdir(missingDir);
  await assert.rejects(readComparisonRun(missingDir), (error) => !error.message.includes(root));
  const huge = path.join(root, 'huge.json');
  const handle = await import('node:fs/promises').then(({ open }) => open(huge, 'w'));
  await handle.truncate(20 * 1024 * 1024 + 1);
  await handle.close();
  await assert.rejects(readComparisonRun(huge), (error) => /20 MiB/.test(error.message));
}));

test('rejects non-regular run files and final symlinks', async () => sandbox(async (root) => {
  const target = path.join(root, 'real.json');
  await writeFile(target, runBytes());
  const link = path.join(root, 'alias.json');
  await symlink(target, link);
  await assert.rejects(readComparisonRun(link));
  await assert.rejects(readComparisonRun(root));
}));

test('refuses occupied output directories without replacing existing files', async () => sandbox(async (root) => {
  const out = path.join(root, 'out');
  await mkdir(out);
  const sentinel = path.join(out, 'keep.txt');
  await writeFile(sentinel, 'keep');
  await assert.rejects(writeComparisonReports(comparison(), out, { inputs: [] }));
  assert.equal(await readFile(sentinel, 'utf8'), 'keep');
}));

test('rejects output aliases and overlaps with run artifact roots before mutating either tree', async () => sandbox(async (root) => {
  const inputDir = path.join(root, 'input');
  await mkdir(inputDir);
  const inputFile = path.join(inputDir, 'run.json');
  const bytes = runBytes();
  await writeFile(inputFile, bytes);
  const input = { file: inputFile, sha256: digest(bytes) };
  const alias = path.join(root, 'input-alias');
  await symlink(inputDir, alias);
  for (const out of [inputDir, path.join(inputDir, 'nested'), path.join(alias, 'out')]) {
    await assert.rejects(writeComparisonReports(comparison(), out, { inputs: [input] }));
  }
  await assert.rejects(lstat(path.join(inputDir, 'nested')));
  assert.equal(await readFile(inputFile, 'utf8'), bytes.toString());
  const outAlias = path.join(root, 'output-alias');
  await symlink(inputDir, outAlias);
  await assert.rejects(writeComparisonReports(comparison(), outAlias, { inputs: [input] }));
}));

test('rejects POSIX output backslashes before mutating a source tree', async () => sandbox(async (root) => {
  if (path.sep !== '/') return;
  const inputDir = path.join(root, 'input');
  await mkdir(inputDir);
  const inputFile = path.join(inputDir, 'run.json');
  const bytes = runBytes();
  await writeFile(inputFile, bytes);
  const beforeNames = await (await import('node:fs/promises')).readdir(inputDir);
  const out = `${inputDir}\\unexpected-child`;
  await assert.rejects(writeComparisonReports(comparison(), out, { inputs: [{ file: inputFile, sha256: digest(bytes) }] }));
  assert.deepEqual(await (await import('node:fs/promises')).readdir(inputDir), beforeNames);
  assert.deepEqual(await readFile(inputFile), bytes);
  assert.equal(digest(await readFile(inputFile)), digest(bytes));
}));

test('allows renamed baseline and current files while writing only the two comparison reports', async () => sandbox(async (root) => {
  const base = path.join(root, 'baseline.json');
  const current = path.join(root, 'current.json');
  const baseBytes = runBytes({ id: 'base' });
  const currentBytes = runBytes({ id: 'current' });
  await writeFile(base, baseBytes);
  await writeFile(current, currentBytes);
  const out = path.join(root, 'comparison');
  const result = await writeComparisonReports(comparison(), out, { inputs: [{ file: base }, { file: current }] });
  assert.deepEqual(Object.keys(result).sort(), ['html', 'json']);
  assert.deepEqual((await (await import('node:fs/promises')).readdir(out)).sort(), ['comparison.html', 'comparison.json']);
}));

test('renders a standalone escaped offline dossier and omits unsafe active links', async () => sandbox(async (root) => {
  const out = path.join(root, 'out');
  const { html } = await writeComparisonReports(comparison(), out, { inputs: [] });
  const body = await readFile(html, 'utf8');
  assert.match(body, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(body, /&lt;svg\/onload=alert\(1\)&gt;/);
  assert.doesNotMatch(body, /<(?:script|img)\b|<[^>]+\son\w+\s*=|href=["']javascript:/i);
  assert.doesNotMatch(body, /<link\b|@import|https?:\/\//i);
  assert.match(body, /regressed/i);
  assert.match(body, /not confirm a fix/i);
  assert.match(body, /<h3>&lt;svg\/onload=alert\(1\)&gt;<\/h3>/);
  assert.doesNotMatch(body, /<h3>cmp-v1-|<h3>0123abcdef/);
  assert.match(body, /오프라인 비교 · 완료/);
  assert.doesNotMatch(body, /identity schema/);
  assert.match(body, /심각도.*unknown/);
}));

test('renders escaped provenance details and explicit unknown revision and dirty states', async () => sandbox(async (root) => {
  const model = comparison();
  model.baseline.provenance = { kind: 'aggregate', sourceRuns: [{ id: '<source>', link: 'javascript:alert(9)' }] };
  model.baseline.target = { path: '/baseline', dirty: true };
  model.current.target = { path: '/current', dirty: false };
  const { html } = await writeComparisonReports(model, path.join(root, 'out'), { inputs: [] });
  const body = await readFile(html, 'utf8');
  assert.match(body, /&lt;source&gt;/);
  assert.match(body, /javascript:alert\(9\)/);
  assert.match(body, /Source provenance|Provenance/);
  assert.match(body, /revision · 미기록/);
  assert.match(body, /working tree · 변경됨/);
  assert.match(body, /working tree · 깨끗함/);
  assert.match(body, /revision · 미기록 \/ unknown/);
  assert.doesNotMatch(body, /href=["']javascript:/i);
  delete model.current.target.dirty;
  const unknownTree = await writeComparisonReports(model, path.join(root, 'unknown-tree'), { inputs: [] });
  assert.match(await readFile(unknownTree.html, 'utf8'), /working tree · 알 수 없음/);
}));

test('redacts inherited secrets and repeated same-context writes are byte-identical', async () => sandbox(async (root) => {
  const key = 'COMPARISON_TEST_API_KEY';
  const original = process.env[key];
  process.env[key] = 'secret-value-12345';
  try {
    const model = comparison({ baseline: { file: `/tmp/${process.env[key]}/base`, sha256: 'a'.repeat(64) } });
    const first = await writeComparisonReports(model, path.join(root, 'first'), { inputs: [] });
    const second = await writeComparisonReports(model, path.join(root, 'second'), { inputs: [] });
    assert.doesNotMatch(await readFile(first.json, 'utf8'), /secret-value-12345/);
    assert.doesNotMatch(await readFile(first.html, 'utf8'), /secret-value-12345/);
    assert.deepEqual(await readFile(first.json), await readFile(second.json));
    assert.deepEqual(await readFile(first.html), await readFile(second.html));
  } finally {
    if (original === undefined) delete process.env[key]; else process.env[key] = original;
  }
}));
