import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { categoryLabel, compactPath, comparisonControlState, filterArtifacts, filterFindings, findingPackage, gateLabel, pageItems, runStatusLabel, sortFindingsBySeverity, toolStatusLabel, verificationLabel, transitionFindingView } from '../src/web/view-model.mjs';

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

// Catches stale evidence when filters exclude a selected source row, including duplicate IDs.
test('finding selection is scoped to matching source rows and filtering resets the page', () => {
  const findings = [{ id: 'same', title: '<img src=x>', severity: 'high', toolId: 'osv', location: String.raw`C:\원본\file.json` }, { id: 'same', title: 'Other', severity: 'low', toolId: 'semgrep' }];
  const state = { query: '', severity: 'all', tool: 'all', page: 2, selectedIndex: 0, locale: 'ko' };
  assert.deepEqual(transitionFindingView(findings, state, { severity: 'low' }), { ...state, severity: 'low', page: 1, selectedIndex: null });
  assert.equal(transitionFindingView(findings, state, { query: '원본' }).selectedIndex, 0);
  assert.equal(findings[0].title, '<img src=x>');
});

// Catches language changes clearing filters, selection or the current bounded page.
test('locale changes preserve finding view state and page changes keep selection', () => {
  const findings = Array.from({ length: 140 }, (_, i) => ({ title: `Item ${i}`, severity: 'high', toolId: 'osv' }));
  const state = { query: 'Item', severity: 'high', tool: 'osv', page: 2, selectedIndex: 125, locale: 'ko' };
  assert.deepEqual(transitionFindingView(findings, state, { locale: 'en' }), { ...state, locale: 'en' });
  assert.deepEqual(transitionFindingView(findings, state, { page: 99 }), { ...state, page: 2 });
});

// Catches accidental translation of unknown stored status/verification identifiers.
test('localized labels translate known semantics and retain unknown stored identifiers', () => {
  assert.equal(toolStatusLabel('imported', 'en'), 'Imported results · not a local execution');
  assert.equal(verificationLabel('candidate', 'en'), 'Candidate');
  assert.equal(toolStatusLabel('증거', 'en'), '증거');
  assert.equal(verificationLabel('증거', 'en'), '증거');
});

test('OSV display uses matched package evidence and a single version fix', () => {
  const finding = {
    toolId: 'osv',
    vulnerabilityId: 'GHSA-29mw-wpgm-hmr9',
    location: { package: 'npm:lodash', version: '4.17.20' },
    evidence: {
      package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
      affected: [
        { package: { name: 'lodash-es', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '5.0.0' }] }] },
        { package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] }] },
      ],
    },
  };
  assert.deepEqual(findingPackage(finding), {
    name: 'lodash', version: '4.17.20', fixedVersion: '4.17.21',
    advisoryUrl: 'https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9',
  });
  assert.deepEqual(filterFindings([finding], { query: '4.17.21' }), [finding]);
});

test('OSV display falls back to saved locations and omits ambiguous or absent fixes', () => {
  const location = { package: 'npm:@scope/package', version: '1.0.0' };
  const finding = { toolId: 'osv', location, description: 'Upgrade to 2.0.0' };
  assert.deepEqual(findingPackage(finding), { name: '@scope/package', version: '1.0.0' });
  for (const range of [
    { type: 'GIT', events: [{ introduced: '0' }, { fixed: 'e91d01c' }] },
    { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }, { introduced: '3.0.0' }] },
    { type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '2.0.0' }] },
  ]) {
    const evidence = { affected: [{ package: { name: '@scope/package', ecosystem: 'npm' }, ranges: [range] }] };
    assert.deepEqual(findingPackage({ ...finding, evidence }), { name: '@scope/package', version: '1.0.0' });
  }
  assert.deepEqual(findingPackage({ ...finding, toolId: 'semgrep' }), {});
});

test('OSV advisory links are canonical and use saved IDs, known legacy rule IDs, or canonical references', () => {
  assert.deepEqual(findingPackage({
    toolId: 'osv', references: ['javascript:alert(1)', 'https://example.com/advisory', 'https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9'],
  }), { advisoryUrl: 'https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9' });
  assert.deepEqual(findingPackage({
    toolId: 'osv', ruleId: 'GHSA-29mw-wpgm-hmr9',
  }), { advisoryUrl: 'https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9' });
  assert.deepEqual(findingPackage({
    toolId: 'osv', ruleId: 'UI-000', vulnerabilityId: '../other',
    references: ['https://example.com/advisory', 'https://osv.dev/vulnerability/foo?redirect=x'],
  }), {});
});

test('finding severity sort preserves original order and row identity for equal ranks', () => {
  const findings = Object.freeze([
    { severity: 'high' }, { severity: 'low' }, { severity: 'custom' }, { severity: 'critical' },
    { severity: 'high' }, { severity: 'info' }, { severity: 'medium' }, { severity: 'unknown' },
  ]);
  const sorted = sortFindingsBySeverity(findings);
  [3, 0, 4, 6, 1, 5, 2, 7].forEach((index, i) => assert.equal(sorted[i], findings[index]));
});
