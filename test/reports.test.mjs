import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { normalizeFindings, writeReports } from '../src/reports.mjs';

const finding = (overrides = {}) => ({
  toolId: 'osv', ruleId: 'GHSA-1234', title: 'Vulnerable package', severity: 'high',
  description: 'Unsafe <script>alert(1)</script>',
  location: { package: 'left-pad', version: '1.0.0', path: 'package-lock.json' },
  vulnerabilityId: 'CVE-2025-0001', aliases: ['GHSA-1234'],
  references: ['javascript:alert(1)'], evidence: { note: '<img src=x onerror=alert(1)>' },
  verification: 'reported', ...overrides,
});

const run = (findings = [finding()], tools = [{ id: 'osv', name: 'OSV', source: 'local', status: 'completed', findings: findings }]) => ({
  schemaVersion: 1, id: 'run-1', startedAt: '2026-10-27T00:00:00.000Z', endedAt: '2026-10-27T00:01:00.000Z',
  target: { path: '/repo', revision: 'abc123', dirty: false }, status: 'completed', tools, findings,
});

test('normalizeFindings groups dependency aliases while retaining every source record', () => {
  const a = finding({ toolId: 'osv' });
  const b = finding({ toolId: 'skillspector', vulnerabilityId: 'GHSA-1234', aliases: ['CVE-2025-0001'] });
  const result = normalizeFindings([a, b]);
  assert.equal(result.length, 1);
  assert.deepEqual(result[0].sources, ['osv', 'skillspector']);
  assert.equal(result[0].sourceRecords.length, 2);
  assert.equal(normalizeFindings(result)[0].sourceRecords.length, 2);
  assert.deepEqual(new Set(result[0].aliases), new Set(['GHSA-1234', 'CVE-2025-0001']));
});

test('normalizeFindings does not merge code findings by similar title', () => {
  const a = finding({ location: { path: 'src/a.js', line: 4 }, vulnerabilityId: undefined, aliases: [] });
  const b = finding({ toolId: 'other', location: { path: 'src/b.js', line: 8 }, vulnerabilityId: undefined, aliases: [] });
  assert.equal(normalizeFindings([a, b]).length, 2);
});

test('normalizeFindings preserves unknown severity and malformed records are rejected', () => {
  assert.equal(normalizeFindings([finding({ severity: 'urgent' })])[0].severity, 'unknown');
  assert.throws(() => normalizeFindings([null]), /finding/i);
  assert.throws(() => normalizeFindings([finding({ aliases: 'CVE-1' })]), /aliases/i);
  const numeric = normalizeFindings([finding({ severity: 9 })])[0];
  assert.equal(numeric.severity, 'unknown');
  assert.equal(numeric.evidence.nativeSeverity, 9);
});

test('writeReports emits escaped self-contained HTML and SARIF with source locations', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-report-'));
  try {
    const paths = await writeReports(run(), directory);
    assert.ok(path.isAbsolute(paths.json) && path.isAbsolute(paths.html) && path.isAbsolute(paths.sarif));
    const html = await readFile(paths.html, 'utf8');
    assert.match(html, /&lt;script&gt;/);
    assert.doesNotMatch(html, /<script>alert/);
    assert.doesNotMatch(html, /href="javascript:/i);
    assert.match(html, /Coverage limitations/);
    const sarif = JSON.parse(await readFile(paths.sarif, 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('writeReports shows skipped and failed coverage plus empty findings', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-empty-'));
  try {
    const paths = await writeReports(run([], [
      { id: 'osv', name: 'OSV', source: 'local', status: 'completed', findings: [] },
      { id: 'codex', name: 'Codex Security', source: 'remote', status: 'skipped', reason: 'AI disabled', findings: [] },
      { id: 'php', name: 'PHP checker', source: 'local', status: 'failed', reason: 'not configured', findings: [] },
    ]), directory);
    const html = await readFile(paths.html, 'utf8');
    assert.match(html, /0 findings/);
    assert.match(html, /skipped/i);
    assert.match(html, /failed/i);
    assert.match(html, /coverage/i);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('selected count includes selected integrations skipped for missing prerequisites', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-selected-'));
  try {
    const paths = await writeReports(run([], [
      { id: 'osv', name: 'OSV', source: 'local', selected: true, status: 'skipped', reason: 'Not installed', findings: [] },
      { id: 'codex', name: 'Codex Security', source: 'remote', selected: false, status: 'skipped', reason: 'Not selected', findings: [] },
    ]), directory);
    const html = await readFile(paths.html, 'utf8');
    assert.match(html, /<b>1<\/b>selected/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('report generation replaces a report symlink without modifying its target', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-report-symlink-'));
  const outside = path.join(directory, 'outside.txt');
  const html = path.join(directory, 'report.html');
  try {
    await writeFile(outside, 'sentinel');
    await symlink(outside, html);
    await writeReports(run(), directory);
    assert.equal(await readFile(outside, 'utf8'), 'sentinel');
    assert.match(await readFile(html, 'utf8'), /Security scan report/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('report generation refuses a symlinked output ancestor before creating child directories', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-report-ancestor-'));
  const outside = path.join(directory, 'outside');
  const linked = path.join(directory, 'linked');
  const output = path.join(linked, 'new-run');
  try {
    await mkdir(outside);
    await symlink(outside, linked);
    await assert.rejects(writeReports(run(), output), /symbolic link/i);
    await assert.rejects(access(path.join(outside, 'new-run')));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('imported SARIF does not claim a local scan and includes imported coverage states', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-imported-sarif-'));
  try {
    const imported = run([finding({ toolId: 'cloudflare' })], [{ id: 'cloudflare', name: 'Cloudflare', source: 'external import', status: 'imported', findings: [finding({ toolId: 'cloudflare' })] }]);
    const paths = await writeReports(imported, directory);
    const sarif = JSON.parse(await readFile(paths.sarif, 'utf8'));
    assert.equal(sarif.runs[0].invocations, undefined);
    assert.equal(sarif.runs[0].properties.provenance, 'imported');
    assert.equal(sarif.runs[0].properties.toolStates[0].status, 'imported');
    assert.doesNotMatch(JSON.stringify(sarif), /local run/);
    const html = await readFile(paths.html, 'utf8');
    assert.match(html, /Imported results are external reports/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
