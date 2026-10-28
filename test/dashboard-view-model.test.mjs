import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { categoryLabel, compactPath, comparisonControlState, filterArtifacts, filterFindings, gateLabel, pageItems, runStatusLabel, toolStatusLabel, verificationLabel } from '../src/web/view-model.mjs';

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

test('compact path presentation retains exact Windows, POSIX, Unicode and HTML-like source strings', () => {
  const paths = [
    String.raw`C:\workspace\deep-parent-directory\saved-result-folder\nested-package\package-lock.json`,
    '/workspace/deep-parent-directory/saved-result-folder/nested-package/package-lock.json',
    '/사용자/아주-긴-부모-경로/보존해야-하는-검사-폴더/유니코드-경로/📄-원본-결과.json',
    '/workspace/<img src=x onerror=alert(1)>/long-parent-directory/another-folder/report.json',
  ];
  for (const full of paths) {
    const result = compactPath(full);
    assert.equal(result.full, full, 'full text must not normalize separators or escape source characters');
    assert.ok(result.summary.length < full.length, 'long path has a compact presentation');
    assert.ok(result.summary.includes(full.split(/[\\/]/).at(-1)), 'summary retains the filename');
  }
  assert.deepEqual(compactPath('src/app.js'), { summary: 'src/app.js', full: 'src/app.js' });
});

test('full parent paths remain searchable independently of compact presentation', () => {
  const full = '/workspace/searchable-parent-directory/another-long-directory/nested-package/package-lock.json';
  const finding = { severity: 'high', toolId: 'osv', title: 'Package', location: { path: full, line: 8 } };
  const original = structuredClone(finding);
  const result = compactPath(full);
  assert.equal(result.summary.includes('searchable-parent-directory'), false);
  assert.deepEqual(filterFindings([finding], { query: 'SEARCHABLE-PARENT-DIRECTORY', severity: 'high', tool: 'osv' }), [finding]);
  assert.deepEqual(filterFindings([finding], { query: 'searchable-parent-directory', severity: 'low', tool: 'osv' }), []);
  assert.deepEqual(filterFindings([finding], { query: 'absent' }), []);
  assert.deepEqual(finding, original, 'presentation and search leave saved data unchanged');
});

test('finding page clamps after filtering shrinks or removes all matches', () => {
  const findings = Array.from({ length: 125 }, (_, id) => ({ severity: id < 3 ? 'high' : 'low', toolId: 'osv', title: `Item ${id}` }));
  assert.equal(pageItems(findings, 2).items.length, 25);
  assert.deepEqual(pageItems(filterFindings(findings, { severity: 'high', tool: 'osv' }), 2), {
    items: findings.slice(0, 3), page: 1, pages: 1, total: 3,
  });
  assert.deepEqual(pageItems(filterFindings(findings, { query: 'absent', severity: 'high', tool: 'osv' }), 2), {
    items: [], page: 1, pages: 1, total: 0,
  });
});


test('compact labels stay shorter for a long single filename and keep Unicode characters whole', () => {
  const full = '📄'.repeat(49);
  const result = compactPath(full);
  assert.equal(result.full, full);
  assert.ok(Array.from(result.summary).length < Array.from(full).length);
  assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(result.summary));
});


test('raw Windows parent path search matches object locations without JSON escape artifacts', () => {
  const full = String.raw`C:\workspace\parent-directory\nested-package\package-lock.json`;
  const finding = { severity: 'high', toolId: 'osv', location: { path: full, line: 8 } };
  assert.deepEqual(filterFindings([finding], { query: String.raw`C:\workspace\parent-directory`, severity: 'high', tool: 'osv' }), [finding]);
  assert.deepEqual(filterFindings([finding], { query: full }), [finding]);
  assert.deepEqual(filterFindings([finding], { query: 'parent-directory', severity: 'high', tool: 'semgrep' }), []);
});


test('adversarial long path tokens finish within an isolated deadline and retain bounded summaries', () => {
  const moduleUrl = new URL('../src/web/view-model.mjs', import.meta.url).href;
  const script = `
    import assert from 'node:assert/strict';
    import { compactPath } from ${JSON.stringify(moduleUrl)};
    const paths = [
      'x'.repeat(300_000),
      '/workspace/' + '📄'.repeat(150_000) + '/report.json',
      '/workspace/' + 'parent'.repeat(50_000) + '/' + 'file'.repeat(75_000),
    ];
    for (const full of paths) {
      const result = compactPath(full);
      assert.equal(result.full, full);
      assert.ok(Array.from(result.summary).length <= 72, 'collapsed summary stays bounded');
    }
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { timeout: 2000, encoding: 'utf8' });
  assert.equal(result.error?.code, undefined, 'long source tokens must not exhaust the isolated deadline');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(compactPath('/workspace/long-parent-directory/saved-result-folder/nested-package/package-lock.json').summary, '…/nested-package/package-lock.json');
});
