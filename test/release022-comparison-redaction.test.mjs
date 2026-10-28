import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { redactValue } from '../src/redaction.mjs';

// Exercise private helpers from the actual source without a production test hook.
const serverUrl = new URL('../src/dashboard/server.mjs', import.meta.url);
const source = (await readFile(serverUrl, 'utf8')).replace(/from '([^']+)'/g, (match, specifier) => specifier.startsWith('.') ? `from '${new URL(specifier, serverUrl).href}'` : match);
const { redactRun, redactComparison } = await import(`data:text/javascript;base64,${Buffer.from(`${source}\nexport { redactRun, redactComparison };`).toString('base64')}`);
const nodes = (value) => 1 + (value && typeof value === 'object' ? Object.values(value).reduce((sum, child) => sum + nodes(child), 0) : 0);
const env = { API_TOKEN: 'fixture-secret-value', API_KEY: 'completed', SECOND_SECRET: 'candidate', THIRD_SECRET: 'location' };
const leaf = () => ({ toolId: 'osv', ruleId: 'fixture-secret-value', title: 'fixture-secret-value', severity: 'high', verification: 'candidate', location: { path: 'fixture-secret-value', line: 1 }, rawRef: { path: 'raw/fixture-secret-value' }, evidence: { payload: Array.from({ length: 64 }, () => 'fixture-secret-value') }, sources: ['osv'] });

test('#28 run redaction traverses nested source records once while preserving privacy and schema fields', (t) => {
  let finding = leaf();
  for (let depth = 0; depth < 12; depth++) finding = { ...leaf(), evidence: {}, sourceRecords: [finding] };
  const run = { schemaVersion: 1, id: 'fixture-secret-value', status: 'completed', target: { path: '/fixture-secret-value', dirty: false }, tools: [{ id: 'osv', status: 'completed', selected: true, findings: [finding], execution: { mode: 'fixture-secret-value' } }], findings: [finding], metadata: { key: 'fixture-secret-value' } };
  const original = structuredClone(run);
  let traversed = 0;
  const safe = redactRun(run, (value) => { traversed += nodes(value); return redactValue(value, env); });
  t.diagnostic(`${traversed} redacted node visits for ${nodes(run)} input nodes`);
  assert.ok(traversed <= nodes(run) + 20, `${traversed} redacted node visits for ${nodes(run)} input nodes`);
  assert.equal(safe.status, 'completed'); assert.equal(safe.schemaVersion, 1); assert.equal(safe.tools[0].status, 'completed');
  let current = safe.findings[0];
  for (let depth = 0; depth < 12; depth++) { assert.equal(current.verification, 'candidate'); assert.equal(current.location.path, '[REDACTED]'); assert.equal(current.rawRef.path, 'raw/[REDACTED]'); current = current.sourceRecords[0]; }
  assert.equal(current.evidence.payload[0], '[REDACTED]');
  assert.equal(JSON.stringify(safe).includes('fixture-secret-value'), false);
  assert.deepEqual(run, original);
});

test('#28 comparison redaction preserves generated IDs, safe enums, source records and raw references', (t) => {
  const finding = { ...leaf(), sourceRecords: [leaf()] };
  const comparison = { schemaVersion: 1, kind: 'sec-hub.comparison', identityVersion: 1, baseline: { id: 'fixture-secret-value', target: { path: '/repo', dirty: true }, status: 'completed' }, current: { id: 'fixture-secret-value', target: { path: '/repo' }, status: 'completed' }, status: 'complete', coverage: [{ toolId: 'osv', baseline: null, current: { status: 'completed', selected: true, execution: { mode: 'fixture-secret-value' } }, reasons: [] }], entries: [{ id: 'fixture-secret-value', identity: 'fixture-secret-value', identityMethod: 'location', category: 'new', after: finding, reasons: ['fixture-secret-value'] }], counts: { new: 1 }, notices: [], gate: { failOn: 'high', violations: ['fixture-secret-value'], unknown: [], exitCode: 1 } };
  let traversed = 0;
  const safe = redactComparison(comparison, (value) => { traversed += nodes(value); return redactValue(value, env); }, true);
  t.diagnostic(`${traversed} redacted node visits for ${nodes(comparison)} input nodes`);
  assert.ok(traversed <= nodes(comparison) + 20, `${traversed} redacted node visits for ${nodes(comparison)} input nodes`);
  assert.equal(safe.entries[0].id, 'fixture-secret-value'); assert.equal(safe.entries[0].identityMethod, 'location'); assert.equal(safe.entries[0].after.verification, 'candidate');
  assert.equal(safe.entries[0].after.sourceRecords[0].rawRef.path, 'raw/[REDACTED]');
  assert.equal(safe.current.status, 'completed'); assert.equal(safe.coverage[0].current.status, 'completed');
  assert.equal(safe.entries[0].after.ruleId, '[REDACTED]');
  const saved = redactComparison(comparison, (value) => redactValue(value, env), false);
  assert.equal(saved.entries[0].id, '[REDACTED]'); assert.equal(saved.gate.violations[0], '[REDACTED]');
});
