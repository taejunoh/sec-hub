import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { normalizeFindings, writeReports } from '../src/reports.mjs';
const finding = (toolId, aliases, extra = {}) => ({ toolId, ruleId: aliases[0] ?? 'fixture-rule', title: toolId, severity: 'low', aliases, references: [`https://example.test/${toolId}`], location: { package: 'npm:demo', version: '1' }, ...extra });

test('#35 bridge aliases merge every intersecting advisory group in all six input orders', () => {
  const records = [finding('scanner-a', ['CVE-X']), finding('scanner-b', ['GHSA-Y'], { severity: 'critical' }), finding('bridge', ['CVE-X', 'GHSA-Y'])];
  const orders = [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]];
  for (const order of orders) {
    const merged = normalizeFindings(order.map((index) => records[index]));
    assert.equal(merged.length, 1, JSON.stringify(order));
    assert.equal(merged[0].severity, 'critical');
    assert.deepEqual(new Set(merged[0].aliases), new Set(['CVE-X', 'GHSA-Y']));
    assert.deepEqual(new Set(merged[0].sources), new Set(records.map((item) => item.toolId)));
    assert.deepEqual(new Set(merged[0].references), new Set(records.flatMap((item) => item.references)));
    assert.deepEqual(new Set(merged[0].sourceRecords.map((item) => item.toolId)), new Set(records.map((item) => item.toolId)));
    assert.deepEqual(normalizeFindings(order.map((index) => records[index])), merged);
  }
  assert.equal(normalizeFindings([records[0], { ...records[1], location: { package: 'npm:demo', version: '2' } }, records[2]]).length, 2);
});

test('#36 merging preconsolidated inputs retains every source ID and source record', () => {
  const first = finding('scanner-first', ['CVE-X']);
  const consolidated = normalizeFindings([finding('scanner-a', ['CVE-X']), finding('scanner-b', ['CVE-X'])])[0];
  const merged = normalizeFindings([first, consolidated])[0];
  assert.deepEqual(new Set(merged.sources), new Set(['scanner-first', 'scanner-a', 'scanner-b']));
  assert.deepEqual(new Set(merged.sourceRecords.map((item) => item.toolId)), new Set(merged.sources));
});

test('#37 SARIF preserves safe HTTP URL query/percent escapes and separately encodes filesystem segments', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-r022-sarif-'));
  try {
    const urls = ['https://example.test/item?id=1&view=a%2Fb#part', 'https://example.test/a%20b?q=%252F'];
    const findings = urls.map((url, index) => finding(`url-${index}`, [], { location: { url } }));
    findings.push(finding('filesystem', [], { location: { path: 'dir with space/a?b%20.txt' } }));
    const run = { schemaVersion: 1, id: 'urls', startedAt: '2026-10-27T00:00:00Z', endedAt: '2026-10-27T00:01:00Z', target: { path: '/repo' }, status: 'completed', tools: [], findings };
    const outputs = await writeReports(run, root);
    const sarif = JSON.parse(await readFile(outputs.sarif, 'utf8'));
    const uris = sarif.runs[0].results.map((result) => result.locations[0].physicalLocation.artifactLocation.uri);
    assert.deepEqual(uris, [...urls, 'dir%20with%20space/a%3Fb%2520.txt']);
  } finally { await rm(root, { recursive: true, force: true }); }
});
