import test from 'node:test';
import assert from 'node:assert/strict';
import { categoryLabel, comparisonControlState, filterArtifacts, filterFindings, gateLabel, pageItems, runStatusLabel, toolStatusLabel, verificationLabel } from '../src/web/view-model.mjs';

const artifacts = [
  { id: 'a'.repeat(64), kind: 'run', state: 'ready', label: 'runs/one/run.json', summary: { runId: 'same', status: 'partial', target: { path: '/alpha' }, tools: [{ id: 'osv', status: 'imported' }] } },
  { id: 'b'.repeat(64), kind: 'run', state: 'ready', label: 'runs/two/run.json', summary: { runId: 'same', status: 'completed', target: { path: '/beta' }, tools: [{ id: 'semgrep', status: 'completed' }] } },
  { id: 'c'.repeat(64), kind: 'comparison', state: 'ready', label: 'comparison.json', summary: { baselineId: 'same', currentId: 'same', status: 'incomplete', target: { path: '/alpha' } } },
  { id: 'd'.repeat(64), kind: 'unknown', state: 'error', label: 'bad/run.json', error: { code: 'invalid_artifact' } },
];

test('filters intersect and search displayed text case-insensitively', () => {
  assert.deepEqual(filterArtifacts(artifacts, { query: 'ALPHA', kind: 'run', status: 'partial', tool: 'osv' }).map(x => x.id), ['a'.repeat(64)]);
  assert.deepEqual(filterArtifacts(artifacts, { query: 'same', kind: 'run', status: 'completed' }).map(x => x.id), ['b'.repeat(64)]);
  assert.deepEqual(filterArtifacts(artifacts, { kind: 'unknown', status: 'error' }).map(x => x.id), ['d'.repeat(64)]);
  assert.deepEqual(filterArtifacts(artifacts, { query: 'absent' }), []);
});

test('finding filtering intersects query, severity and tool', () => {
  const findings = [
    { severity: 'high', ruleId: 'RULE-A', toolId: 'osv', title: 'Package alpha', location: { path: 'lock.json' } },
    { severity: 'low', ruleId: 'RULE-B', toolId: 'osv', title: 'Package beta', location: { path: 'other.json' } },
    { severity: 'high', ruleId: 'RULE-C', toolId: 'semgrep', title: 'Code gamma', location: 'src/app.js' },
  ];
  assert.deepEqual(filterFindings(findings, { query: 'ALPHA', severity: 'high', tool: 'osv' }), [findings[0]]);
  assert.deepEqual(filterFindings(findings, { severity: 'high', tool: 'osv' }), [findings[0]]);
});

test('pagination clamps and caps the page size at 100', () => {
  const all = Array.from({ length: 245 }, (_, i) => i);
  assert.deepEqual(pageItems(all, 2, 50), { items: all.slice(50, 100), page: 2, pages: 5, total: 245 });
  assert.deepEqual(pageItems(all, 99), { items: all.slice(200), page: 3, pages: 3, total: 245 });
  assert.equal(pageItems(all, 1, 500).items.length, 100);
  assert.deepEqual(pageItems([], -1), { items: [], page: 1, pages: 1, total: 0 });
});

test('status, gate, category and verification labels preserve source semantics', () => {
  assert.equal(gateLabel(0), '비교 완료 · 기준 통과');
  assert.equal(gateLabel(1), '비교 완료 · 기준 위반');
  assert.equal(gateLabel(2), '범위 불충분 · 판단 불가');
  assert.equal(categoryLabel('new'), '새로 관측');
  assert.equal(categoryLabel('unobserved'), '범위 부족 · 미관측');
  assert.equal(runStatusLabel('completed'), '실행 완료');
  assert.equal(runStatusLabel('partial'), '부분 완료');
  assert.equal(toolStatusLabel('imported'), '가져온 결과 · 로컬 실행 아님');
  assert.equal(verificationLabel('candidate'), '후보');
  assert.equal(verificationLabel(undefined), '보고됨 · 검증 수준 미기록');
});

test('comparison controls stay frozen while a request is pending', () => {
  assert.deepEqual(comparisonControlState(true, true), { inputsDisabled: true, compareDisabled: true });
  assert.deepEqual(comparisonControlState(true, false), { inputsDisabled: true, compareDisabled: true });
  assert.deepEqual(comparisonControlState(false, true), { inputsDisabled: false, compareDisabled: false });
  assert.deepEqual(comparisonControlState(false, false), { inputsDisabled: false, compareDisabled: true });
});
