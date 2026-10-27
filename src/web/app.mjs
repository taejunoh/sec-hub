import { categoryLabel, comparisonControlState, filterArtifacts, filterFindings, gateLabel, pageItems, runStatusLabel, toolStatusLabel, verificationLabel } from './view-model.mjs';

const $ = (id) => document.getElementById(id);
const el = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
};
const field = (label, value, className = '') => {
  const cell = el('div', 'summary-cell');
  cell.append(el('dt', '', label), el('dd', className, value ?? '기록 없음'));
  return cell;
};
const jsonText = (value) => {
  try { return JSON.stringify(value, null, 2); } catch { return '표시할 수 없는 자료'; }
};
const labelFor = (artifact) => artifact.kind === 'run' ? '검사 실행' : artifact.kind === 'comparison' ? '저장된 비교' : '자료 오류';
const statusFor = (artifact) => artifact.state === 'error' ? '자료 오류' : artifact.summary?.status === 'partial' ? '부분 완료' : artifact.summary?.status === 'failed' ? '실패' : artifact.summary?.status === 'completed' ? '실행 완료' : artifact.summary?.status === 'incomplete' ? '불완전' : '준비됨';

let catalog;
let selectedId = null;
let detailController;
let compareController;
let catalogController;
let detailRequest = 0;
let compareRequest = 0;
let findingPage = 1;
let comparisonPage = 1;
let comparisonPending = false;
let allFindings = [];
let activeRun;
let activeComparison;
let filteredFindings = [];

function announce(message) { $('live-status').textContent = message; }
function setCatalogState(message, visible = true) {
  const node = $('catalog-state');
  node.textContent = message;
  node.hidden = !visible;
}
function safeStatusStamp(status) {
  const stamp = el('span', `status-stamp ${status ?? 'unknown'}`, runStatusLabel(status));
  return stamp;
}
function readyRuns() {
  return (catalog?.artifacts ?? []).filter((item) => item.state === 'ready' && item.kind === 'run');
}
function setOptions(select, runs, selected = '') {
  while (select.options.length > 1) select.remove(1);
  for (const run of runs) {
    const option = document.createElement('option');
    option.value = run.id;
    option.textContent = `${run.summary.runId} · ${run.label}`;
    select.append(option);
  }
  if (selected && runs.some((run) => run.id === selected)) select.value = selected;
}
function updateComparisonControls() {
  const hasInputs = Boolean($('baseline-select').value && $('current-select').value);
  const state = comparisonControlState(comparisonPending, hasInputs);
  $('baseline-select').disabled = state.inputsDisabled;
  $('current-select').disabled = state.inputsDisabled;
  $('fail-on').disabled = state.inputsDisabled;
  $('compare-button').disabled = state.compareDisabled;
}
function refreshRunOptions() {
  const runs = readyRuns();
  const b = $('baseline-select').value;
  const c = $('current-select').value;
  setOptions($('baseline-select'), runs, b);
  setOptions($('current-select'), runs, c);
  updateComparisonControls();
}
function updateToolOptions() {
  const tools = new Set();
  for (const item of catalog?.artifacts ?? []) {
    for (const tool of item.summary?.tools ?? []) if (tool?.id) tools.add(tool.id);
  }
  const select = $('tool-filter');
  const selected = select.value;
  while (select.options.length > 1) select.remove(1);
  for (const id of [...tools].sort()) {
    const option = document.createElement('option');
    option.value = id;
    option.textContent = id;
    select.append(option);
  }
  if (tools.has(selected)) select.value = selected;
}
function updateCounts(visible) {
  const items = catalog?.artifacts ?? [];
  const runs = items.filter((x) => x.kind === 'run' && x.state === 'ready').length;
  const comparisons = items.filter((x) => x.kind === 'comparison' && x.state === 'ready').length;
  const invalid = items.filter((x) => x.state === 'error').length;
  $('catalog-counts').textContent = `검사 ${runs} · 저장 비교 ${comparisons} · 오류 ${invalid} / 전체 ${items.length} · 현재 표시 ${visible}`;
}
function drawCatalog() {
  const list = $('artifact-list');
  list.replaceChildren();
  if (!catalog) return;
  const filtered = filterArtifacts(catalog.artifacts, {
    query: $('catalog-search').value,
    kind: $('kind-filter').value,
    status: $('status-filter').value,
    tool: $('tool-filter').value,
  });
  updateCounts(filtered.length);
  const total = catalog.artifacts.length;
  const errorCount = catalog.artifacts.filter((x) => x.state === 'error').length;
  if (catalog.snapshot.truncated || catalog.snapshot.notices?.length) {
    $('truncation').hidden = false;
    $('truncation').textContent = catalog.snapshot.notices?.map((x) => x.message).filter(Boolean).join(' ') || '자료 수집 한도에 도달했습니다. 표시되지 않은 자료가 있을 수 있습니다.';
  } else {
    $('truncation').hidden = true;
    $('truncation').textContent = '';
  }
  if (total === 0) setCatalogState('저장된 자료가 없습니다. 지정된 시작 디렉터리에 run.json 또는 comparison.json을 확인하세요.');
  else if (filtered.length === 0) setCatalogState('현재 검색 및 필터에 맞는 자료가 없습니다.');
  else setCatalogState('', false);
  for (const artifact of filtered) {
    const li = el('li');
    const button = el('button', 'artifact-button');
    button.type = 'button';
    button.setAttribute('aria-current', artifact.id === selectedId ? 'true' : 'false');
    button.addEventListener('click', () => selectArtifact(artifact.id));
    const name = el('span', 'artifact-name', artifact.label);
    const meta = el('span', 'artifact-meta');
    const kind = el('span', 'tag', labelFor(artifact));
    const state = el('span', artifact.state === 'error' ? 'tag alert' : 'tag', statusFor(artifact));
    meta.append(kind, state);
    button.append(name, meta);
    if (artifact.state === 'error') {
      const reason = el('span', 'artifact-meta', artifact.error?.message ?? '자료를 읽을 수 없습니다.');
      button.append(reason);
    } else if (artifact.kind === 'run') {
      button.append(el('span', 'artifact-meta', `${artifact.summary.runId} · ${artifact.summary.target.path}`));
    } else if (artifact.kind === 'comparison') {
      button.append(el('span', 'artifact-meta', `${artifact.summary.baselineId} → ${artifact.summary.currentId}`));
    }
    li.append(button);
    list.append(li);
  }
  if (errorCount) $('catalog-state').setAttribute('aria-label', `${errorCount}개의 오류 자료가 목록에 표시됩니다.`);
  refreshRunOptions();
}
async function apiJson(url, signal) {
  const response = await fetch(url, { headers: { Accept: 'application/json' }, signal });
  let body;
  try { body = await response.json(); } catch { throw new Error('서버 응답을 읽을 수 없습니다.'); }
  if (!response.ok) throw new Error(body?.error?.message ?? '요청을 처리할 수 없습니다.');
  return body;
}
async function loadCatalog() {
  catalogController?.abort();
  catalogController = new AbortController();
  setCatalogState('시작 스냅샷을 불러오는 중…');
  announce('저장된 자료 목록을 불러오는 중입니다.');
  try {
    const value = await apiJson('/api/catalog', catalogController.signal);
    catalog = value;
    $('snapshot-state').textContent = `시작 스냅샷 · ${value.snapshot.createdAt} · 새 파일은 서버 재시작 후 반영`;
    updateToolOptions();
    drawCatalog();
    announce(`저장된 자료 ${value.artifacts.length}개를 불러왔습니다.`);
    if (selectedId && !catalog.artifacts.some((item) => item.id === selectedId)) clearDetail('선택한 자료가 스냅샷에 없습니다.');
  } catch (error) {
    if (error.name === 'AbortError') return;
    catalog = undefined;
    $('snapshot-state').textContent = '스냅샷을 불러오지 못함';
    $('catalog-counts').textContent = '목록을 불러오지 못했습니다.';
    $('artifact-list').replaceChildren();
    $('truncation').hidden = true;
    setCatalogState(`${error.message} 다시 시도할 수 있습니다.`);
    announce('목록 요청에 실패했습니다.');
    refreshRunOptions();
  }
}
function clearDetail(message = '목록에서 저장된 검사 또는 비교를 선택하세요.') {
  detailController?.abort();
  selectedId = null;
  activeRun = null;
  allFindings = [];
  $('selection-mark').textContent = '선택 없음';
  $('detail-content').replaceChildren();
  $('detail-state').hidden = false;
  $('detail-state').textContent = message;
  drawCatalog();
}
function detailHeading(title, note) {
  const heading = el('div', 'block-heading');
  heading.append(el('h3', '', title), el('small', '', note));
  return heading;
}
function appendDefinitionGrid(parent, pairs) {
  const dl = el('dl', 'record-summary');
  for (const [label, value, klass] of pairs) dl.append(field(label, value, klass));
  parent.append(dl);
}
function provenanceBlock(parent, value, title = '출처 및 실행 기록') {
  const block = el('section', 'block');
  block.append(detailHeading(title, '저장된 기록'));
  if (value === undefined) block.append(el('p', 'muted', '출처 기록이 없습니다.'));
  else {
    const details = el('details');
    details.append(el('summary', '', '기록 펼치기'));
    details.append(el('pre', 'mono', jsonText(value)));
    block.append(details);
  }
  parent.append(block);
}
function drawTools(parent, run) {
  const section = el('section', 'block');
  const tools = Array.isArray(run.tools) ? run.tools : [];
  section.append(detailHeading('도구 실행 범위', `${tools.length}개 도구 · 상태는 저장된 주장`));
  const ul = el('ul', 'tool-list');
  for (const tool of tools) {
    const li = el('li');
    const heading = el('div', 'tool-row-heading');
    heading.append(el('span', 'mono', tool.id), el('span', '', toolStatusLabel(tool.status)));
    if (tool.selected === false) heading.append(el('span', 'muted', '선택 안 됨'));
    const details = el('details', 'tool-record');
    details.append(el('summary', '', '저장된 실행 정보 펼치기'));
    details.append(el('pre', 'mono', jsonText(tool)));
    li.append(heading, details);
    ul.append(li);
  }
  section.append(ul);
  parent.append(section);
}
function findingContent(finding) {
  const article = el('div', 'finding-title');
  article.append(el('strong', '', finding.title ?? '제목 미기록'));
  const pieces = [
    ['설명', finding.description],
    ['별칭', finding.aliases],
    ['원본 레코드', finding.sourceRecords],
    ['증거', finding.evidence],
    ['실행 메타데이터', finding.execution],
    ['출처', finding.provenance ?? finding.source],
    ['참고 자료', finding.references],
  ];
  for (const [label, value] of pieces) {
    if (value === undefined || value === null) continue;
    const details = el('details');
    details.append(el('summary', '', label));
    details.append(el('pre', 'mono', typeof value === 'string' ? value : jsonText(value)));
    article.append(details);
  }
  return article;
}
function drawPager(parent, info, onPage) {
  const pager = el('div', 'pager');
  pager.append(el('span', '', `${info.total}개 결과 · ${info.page} / ${info.pages}쪽 · 한 번에 최대 100개`));
  const actions = el('div', 'pager-actions');
  const previous = el('button', 'page-button', '이전');
  previous.type = 'button';
  previous.disabled = info.page <= 1;
  previous.addEventListener('click', () => onPage(info.page - 1));
  const next = el('button', 'page-button', '다음');
  next.type = 'button';
  next.disabled = info.page >= info.pages;
  next.addEventListener('click', () => onPage(info.page + 1));
  actions.append(previous, next);
  pager.append(actions);
  parent.append(pager);
}
function drawFindingRows() {
  const section = $('finding-section');
  if (!section) return;
  const info = pageItems(filteredFindings, findingPage, 100);
  findingPage = info.page;
  const tbody = section.querySelector('tbody');
  tbody.replaceChildren();
  for (const finding of info.items) {
    const row = el('tr');
    row.append(el('td', 'mono', finding.severity ?? 'unknown'), el('td', 'mono', finding.ruleId ?? '규칙 미기록'), el('td', 'mono', finding.toolId ?? '도구 미기록'));
    const location = typeof finding.location === 'string' ? finding.location : finding.location?.path ?? jsonText(finding.location ?? {});
    row.append(el('td', 'mono', location));
    row.append(el('td', '', verificationLabel(finding.verification)));
    const content = el('td');
    content.append(findingContent(finding));
    row.append(content);
    tbody.append(row);
  }
  const pager = section.querySelector('.pager');
  if (pager) pager.remove();
  drawPager(section, info, (page) => { findingPage = page; drawFindingRows(); });
  const count = section.querySelector('.block-heading small');
  if (count) count.textContent = `${info.total}개 표시 · 전체 ${allFindings.length}개 저장 행`;
}
function drawFindings(parent, run) {
  const section = el('section', 'block');
  section.id = 'finding-section';
  const tools = [...new Set((run.findings ?? []).map((x) => x.toolId).filter(Boolean))].sort();
  const controls = el('div', 'finding-controls');
  const searchLabel = el('label', 'filters-label', '검색');
  const search = document.createElement('input');
  search.type = 'search'; search.placeholder = '규칙, 제목, 위치'; search.setAttribute('aria-label', '검사 결과 검색');
  searchLabel.append(search);
  const severityLabel = el('label', 'filters-label', '심각도');
  const severity = document.createElement('select');
  severity.setAttribute('aria-label', '심각도 필터');
  for (const [value, title] of [['all', '전체'], ['critical', 'critical'], ['high', 'high'], ['medium', 'medium'], ['low', 'low'], ['info', 'info'], ['unknown', 'unknown']]) {
    const option = document.createElement('option'); option.value = value; option.textContent = title; severity.append(option);
  }
  severityLabel.append(severity);
  const toolLabel = el('label', 'filters-label', '도구 ID');
  const toolSelect = document.createElement('select'); toolSelect.setAttribute('aria-label', '도구 ID 필터');
  const all = document.createElement('option'); all.value = 'all'; all.textContent = '전체'; toolSelect.append(all);
  for (const id of tools) { const option = document.createElement('option'); option.value = id; option.textContent = id; toolSelect.append(option); }
  toolLabel.append(toolSelect);
  controls.append(searchLabel, severityLabel, toolLabel);
  section.append(detailHeading('저장된 발견 항목', `${run.findings?.length ?? 0}개 저장 행`), controls);
  const scroll = el('div', 'table-scroll');
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const tr = document.createElement('tr');
  for (const heading of ['심각도', '규칙 ID', '도구', '위치', '검증', '항목 / 근거']) tr.append(el('th', '', heading));
  thead.append(tr);
  const tbody = document.createElement('tbody');
  table.append(thead, tbody); scroll.append(table); section.append(scroll);
  parent.append(section);
  allFindings = Array.isArray(run.findings) ? run.findings : [];
  const apply = () => {
    filteredFindings = filterFindings(allFindings, { query: search.value, severity: severity.value, tool: toolSelect.value });
    findingPage = 1; drawFindingRows();
  };
  search.addEventListener('input', apply);
  severity.addEventListener('change', apply);
  toolSelect.addEventListener('change', apply);
  filteredFindings = allFindings;
  drawFindingRows();
}
function drawRun(parent, run, artifact) {
  const top = el('div');
  const title = el('div', 'section-heading');
  title.append(el('div', '', ''));
  const titleText = title.firstChild;
  titleText.append(el('p', 'eyebrow', 'SAVED RUN · 원본 검사 재실행 안 함'), el('h3', '', artifact.label));
  title.append(safeStatusStamp(run.status));
  top.append(title);
  const pairs = [
    ['실행 ID', run.id], ['대상 경로', run.target?.path], ['리비전', run.target?.revision ?? '기록 없음'],
    ['작업 트리', run.target?.dirty === true ? '변경 있음' : run.target?.dirty === false ? '변경 없음' : '상태 미기록'],
    ['시작', run.startedAt], ['종료', run.endedAt],
    ['저장된 발견 행', run.findings?.length ?? 0], ['결과 의미', run.status === 'completed' ? '실행 완료 · 안전 확인이 아님' : run.status === 'partial' ? '부분 완료 · 범위가 제한됨' : '실패 · 결과 범위 제한'],
  ];
  appendDefinitionGrid(top, pairs);
  drawTools(top, run);
  const imported = (run.tools ?? []).some((item) => item.status === 'imported');
  if (imported) top.append(el('p', 'notice', '가져온 결과 · 로컬 실행 아님'));
  if (run.status === 'partial') top.append(el('p', 'notice', '부분 실행입니다. 누락되거나 제한된 검사 범위를 확인하세요.'));
  if (run.verification === undefined && run.verificationPassed === undefined) top.append(el('p', 'muted', '보고됨 · 검증 수준 미기록'));
  provenanceBlock(top, run.provenance ?? run.source);
  parent.append(top);
  drawFindings(top, run);
}
function comparisonTable(parent, entries, page, onPage) {
  const info = pageItems(entries ?? [], page, 100);
  const scroll = el('div', 'table-scroll');
  const table = document.createElement('table');
  const head = document.createElement('thead');
  const hr = document.createElement('tr');
  for (const title of ['범주', 'ID / 정체성', '전', '후', '이유']) hr.append(el('th', '', title));
  head.append(hr);
  const body = document.createElement('tbody');
  for (const entry of info.items) {
    const row = el('tr');
    row.append(el('td', '', categoryLabel(entry.category)));
    const identity = el('td');
    identity.append(el('span', 'mono', entry.id), el('br'), el('span', 'muted', `${entry.identityMethod ?? '방법 미기록'} · ${entry.identity ?? ''}`));
    row.append(identity);
    row.append(snapshotCell(entry.before), snapshotCell(entry.after));
    row.append(el('td', 'mono', (entry.reasons ?? []).join(', ') || '이유 기록 없음'));
    body.append(row);
  }
  table.append(head, body); scroll.append(table); parent.append(scroll);
  drawPager(parent, info, onPage);
}
function snapshotCell(value) {
  const td = el('td');
  if (!value) { td.textContent = '—'; return td; }
  td.append(el('span', 'mono', `${value.severity ?? 'unknown'} · ${value.ruleId ?? '규칙 미기록'} · ${verificationLabel(value.verification)}`));
  const details = el('details'); details.append(el('summary', '', value.title ?? '상세 기록'));
  details.append(el('pre', 'mono', jsonText(value)));
  td.append(details);
  return td;
}
function drawComparison(parent, comparison, originLabel, inputs = undefined) {
  const c = comparison;
  const section = el('section', 'block');
  section.append(detailHeading('비교 판독', originLabel));
  const gate = c.gate ?? {};
  const banner = el('div', `gate-banner ${gate.exitCode === 1 ? 'fail' : gate.exitCode === 2 ? 'unknown' : ''}`);
  banner.append(el('strong', '', gateLabel(gate.exitCode)), el('span', 'mono', `failOn ${gate.failOn ?? '기록 없음'} · 종료 코드 ${gate.exitCode ?? '—'}`));
  section.append(banner);
  if (inputs) {
    const hashes = el('p', 'muted mono', `기준 자료 SHA-256 ${inputs.baseline?.sha256 ?? '기록 없음'} · 현재 자료 SHA-256 ${inputs.current?.sha256 ?? '기록 없음'}`);
    section.append(hashes);
  }
  const baseline = c.baseline ?? {};
  const current = c.current ?? {};
  appendDefinitionGrid(section, [
    ['기준 실행', baseline.id], ['기준 대상', baseline.target?.path], ['기준 리비전', baseline.target?.revision ?? '기록 없음'],
    ['기준 작업 트리', baseline.target?.dirty === true ? '변경 있음' : baseline.target?.dirty === false ? '변경 없음' : '상태 미기록'],
    ['현재 실행', current.id], ['현재 대상', current.target?.path], ['현재 리비전', current.target?.revision ?? '기록 없음'],
    ['현재 작업 트리', current.target?.dirty === true ? '변경 있음' : current.target?.dirty === false ? '변경 없음' : '상태 미기록'],
    ['기준 상태', runStatusLabel(baseline.status)], ['현재 상태', runStatusLabel(current.status)],
    ['게이트 위반', gate.violations?.length ?? 0], ['판단 불명', gate.unknown?.length ?? 0], ['비교 범위', c.status === 'complete' ? '완료' : '불완전 · 범위 부족'],
  ]);
  if (baseline.provenance !== undefined || current.provenance !== undefined) {
    provenanceBlock(section, { baseline: baseline.provenance, current: current.provenance }, '기준 및 현재 출처');
  }
  const counts = el('div', 'category-grid');
  for (const category of ['new', 'regressed', 'existing', 'resolved', 'unobserved']) {
    const item = el('div', 'category-count');
    item.append(el('strong', '', c.counts?.[category] ?? 0), el('span', '', categoryLabel(category)));
    counts.append(item);
  }
  section.append(counts);
  section.append(el('p', 'muted', '새로 관측은 도입 증명이 아닙니다. 완료 검사에서 더 이상 보이지 않는 항목도 수정 증명이 아닙니다. 후보 항목은 비교 게이트에 포함될 수 있으며 계속 후보로 표시됩니다.'));
  if (Array.isArray(c.coverage)) {
    const cov = el('section', 'block');
    cov.append(detailHeading('도구 범위', `${c.coverage.length}개 기록`));
    const ul = el('ul', 'tool-list');
    for (const entry of c.coverage) {
      const li = el('li');
      const heading = el('div', 'tool-row-heading');
      heading.append(el('span', 'mono', entry.toolId), el('span', '', entry.reasons?.length ? entry.reasons.join(', ') : '제한 사유 기록 없음'));
      const details = el('details', 'tool-record');
      details.append(el('summary', '', '기준·현재 도구 메타데이터 펼치기'));
      details.append(el('pre', 'mono', jsonText({ baseline: entry.baseline, current: entry.current })));
      li.append(heading, details);
      ul.append(li);
    }
    cov.append(ul); section.append(cov);
  }
  if (Array.isArray(c.notices) && c.notices.length) {
    const notice = el('ul', 'muted');
    for (const item of c.notices) notice.append(el('li', '', item));
    section.append(notice);
  }
  const entriesBlock = el('section', 'block');
  entriesBlock.append(detailHeading('비교 항목', `${c.entries?.length ?? 0}개 저장 결과`));
  section.append(entriesBlock);
  comparisonPage = 1;
  const renderEntries = (page) => {
    entriesBlock.replaceChildren(detailHeading('비교 항목', `${c.entries?.length ?? 0}개 저장 결과`));
    comparisonPage = page;
    comparisonTable(entriesBlock, c.entries, page, (next) => renderEntries(next));
  };
  renderEntries(1);
  parent.append(section);
}
function drawComparisonSummary(parent, comparison) {
  const section = el('section', 'block');
  section.append(detailHeading('저장된 비교', '저장된 비교 · 원본 검사 재검증 안 함'));
  appendDefinitionGrid(section, [
    ['기준 실행 ID', comparison.baseline?.id], ['기준 대상', comparison.baseline?.target?.path], ['기준 상태', runStatusLabel(comparison.baseline?.status)],
    ['현재 실행 ID', comparison.current?.id], ['현재 대상', comparison.current?.target?.path], ['현재 상태', runStatusLabel(comparison.current?.status)],
  ]);
  drawComparison(section, comparison, '저장된 비교 · 원본 검사 재검증 안 함');
  parent.append(section);
}
async function selectArtifact(id) {
  detailController?.abort();
  detailController = new AbortController();
  const request = ++detailRequest;
  selectedId = id;
  activeRun = null;
  $('detail-content').replaceChildren();
  $('detail-state').hidden = false;
  $('detail-state').textContent = '저장 자료를 여는 중…';
  $('selection-mark').textContent = id;
  drawCatalog();
  announce('선택한 저장 자료를 여는 중입니다.');
  try {
    const value = await apiJson(`/api/artifacts/${id}`, detailController.signal);
    if (request !== detailRequest) return;
    $('detail-state').hidden = true;
    const parent = $('detail-content');
    parent.replaceChildren();
    const artifact = value.artifact;
    if (artifact.kind === 'run' && value.run) {
      activeRun = value.run;
      $('workspace-title').textContent = '검사 기록';
      drawRun(parent, value.run, artifact);
      announce(`${value.run.id} 검사 기록을 표시했습니다.`);
    } else if (artifact.kind === 'comparison' && value.comparison) {
      $('workspace-title').textContent = '저장 비교';
      drawComparisonSummary(parent, value.comparison);
      announce('저장된 비교를 표시했습니다. 원본 검사를 재검증하지 않았습니다.');
    } else {
      $('detail-state').hidden = false;
      $('detail-state').textContent = artifact.error?.message ?? '자료를 표시할 수 없습니다.';
    }
  } catch (error) {
    if (error.name === 'AbortError' || request !== detailRequest) return;
    $('detail-state').hidden = false;
    $('detail-state').textContent = `${error.message} 다시 목록에서 선택해 재시도하세요.`;
    announce('저장 자료를 열지 못했습니다.');
  }
}
function appendComparisonResult(parent, result, label) {
  parent.replaceChildren();
  drawComparison(parent, result, label);
}
async function compareSelected() {
  const baseline = $('baseline-select').value;
  const current = $('current-select').value;
  if (!baseline || !current) return;
  compareController?.abort();
  compareController = new AbortController();
  const request = ++compareRequest;
  comparisonPending = true;
  updateComparisonControls();
  $('comparison-state').textContent = '비교 중…';
  $('comparison-content').replaceChildren();
  announce('저장된 두 실행을 비교하고 있습니다.');
  try {
    const params = new URLSearchParams({ baseline, current, failOn: $('fail-on').value });
    const value = await apiJson(`/api/compare?${params}`, compareController.signal);
    if (request !== compareRequest) return;
    $('comparison-content').replaceChildren();
    drawComparison($('comparison-content'), value.comparison, '메모리 비교 · 저장되지 않음', value.inputs);
    $('comparison-state').textContent = `대상 ${value.comparison.baseline?.target?.path ?? '기록 없음'} · 입력 자료 해시를 함께 표시`;
    announce(gateLabel(value.comparison.gate.exitCode));
  } catch (error) {
    if (error.name === 'AbortError' || request !== compareRequest) return;
    $('comparison-state').textContent = `${error.message} 실행을 다시 선택하고 재시도하세요.`;
    announce('비교 요청에 실패했습니다.');
  } finally {
    if (request === compareRequest) {
      comparisonPending = false;
      updateComparisonControls();
    }
  }
}

$('reload').addEventListener('click', loadCatalog);
$('catalog-filters').addEventListener('submit', (event) => event.preventDefault());
for (const id of ['catalog-search', 'kind-filter', 'status-filter', 'tool-filter']) $(id).addEventListener(id === 'catalog-search' ? 'input' : 'change', drawCatalog);
$('compare-button').addEventListener('click', compareSelected);
for (const id of ['baseline-select', 'current-select']) $(id).addEventListener('change', updateComparisonControls);
loadCatalog();
