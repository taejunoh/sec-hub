import { desktopToolName, initializeExecutionView } from './execution-view.mjs';
import { translate } from './i18n.mjs';
import { categoryLabel, compactPath, comparisonControlState, filterArtifacts, filterFindings, findingPackage, findingSeverity, gateLabel, pageItems, runStatusLabel, sortFindingsBySeverity, toolStatusLabel, verificationLabel, transitionFindingView } from './view-model.mjs';

const $ = (id) => document.getElementById(id);
const desk = () => document.querySelector('.desk');
const el = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
};
function advisoryText(node, value) {
  for (const [index, text] of String(value).split(/\x60([^\x60\n]+)\x60/).entries()) {
    node.append(index % 2 ? el('code', '', text) : text);
  }
  return node;
}
const field = (label, value, className = '', isPath = false) => {
  const cell = el('div', 'summary-cell');
  const content = el('dd', className);
  if (isPath && typeof value === 'string') content.append(pathDetails(value));
  else content.textContent = value ?? t('기록 없음');
  cell.append(el('dt', '', label), content);
  return cell;
};
const jsonText = (value) => {
  try { return JSON.stringify(value, null, 2); } catch { return t('표시할 수 없는 자료'); }
};
const labelFor = (artifact) => artifact.kind === 'run' ? t('검사 실행') : artifact.kind === 'comparison' ? t('저장된 비교') : t('자료 오류');
const statusFor = (artifact) => artifact.state === 'error' ? t('자료 오류') : artifact.summary?.status === 'partial' ? t('부분 완료') : artifact.summary?.status === 'failed' ? t('실패') : artifact.summary?.status === 'completed' ? t('실행 완료') : artifact.summary?.status === 'incomplete' ? t('불완전') : t('준비됨');

let locale = 'ko';
const t = (key, values) => translate(locale, key, values);
let findingView = { query: '', severity: 'all', tool: 'all', page: 1, selectedIndex: null, locale };
let selectedArtifact;
let savedComparison;
let localComparison;
let listScroll = 0;
let listFocusIndex = null;
let catalog;
let catalogGeneration = 0;
let catalogRequest = 0;
let executionView;
let executionMode = { enabled: false, expired: false, lastRefresh: null };
let selectedId = null;
let detailController;
let compareController;
let catalogController;
let detailRequest = 0;
let compareRequest = 0;
let findingPage = 1;
let comparisonPending = false;
let allFindings = [];
let activeRun;
let filteredFindings = [];

const severityKeys = { critical: '치명적', high: '높음', medium: '보통', low: '낮음', info: '정보', unknown: '알 수 없음' };
const severityName = (severity) => t(severityKeys[severity]);
const packageLabel = ({ name, version }) => name && (version ? `${name} ${version}` : name);
const toolName = desktopToolName;
const projectName = (path) => typeof path === 'string' && path.split(/[\\/]/).filter(Boolean).at(-1) || t('프로젝트 검사 결과');
function severityBadge(finding) {
  const severity = findingSeverity(finding);
  return el('span', `severity-badge severity-${severity}`, severityName(severity));
}

const chromeMessages = new Map();
function chromeMessage(id, key, values) {
  chromeMessages.set(id, { key, values });
  $(id).textContent = t(key, typeof values === 'function' ? values() : values);
}
function setCatalogState(key, visible = true, values) {
  const node = $('catalog-state');
  chromeMessage('catalog-state', key, values);
  node.hidden = !visible;
}
function safeStatusStamp(status) {
  const stamp = el('span', `status-stamp ${status ?? 'unknown'}`, t(runStatusLabel(status)));
  return stamp;
}
function focusResults() {
  const heading = $('workspace-title');
  heading.focus({ preventScroll: true });
  heading.scrollIntoView({ block: 'start', behavior: 'instant' });
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
  chromeMessage('catalog-counts', '검사 {v0} · 저장 비교 {v1} · 오류 {v2} / 전체 {v3} · 현재 표시 {v4}', { v0: runs, v1: comparisons, v2: invalid, v3: items.length, v4: visible });
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
    $('truncation').textContent = catalog.snapshot.notices?.map((x) => t(x.message)).filter(Boolean).join(' ') || t('자료 수집 한도에 도달했습니다. 표시되지 않은 자료가 있을 수 있습니다.');
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
    button.addEventListener('click', async () => {
      await selectArtifact(artifact.id);
      if (selectedId === artifact.id && $('detail-state').hidden) focusResults();
    });
    const name = el('span', 'artifact-name', artifact.kind === 'run' && artifact.summary ? projectName(artifact.summary.target?.path) : artifact.label);
    const meta = el('span', 'artifact-meta');
    const kind = el('span', 'tag', labelFor(artifact));
    const state = el('span', artifact.state === 'error' ? 'tag alert' : 'tag', statusFor(artifact));
    meta.append(kind, state);
    button.append(name, meta);
    if (artifact.state === 'error') {
      const reason = el('span', 'artifact-meta', t(artifact.error?.message ?? '자료를 읽을 수 없습니다.'));
      button.append(reason);
    } else if (artifact.kind === 'run' && artifact.summary?.startedAt) {
      const date = new Date(artifact.summary.startedAt);
      if (!Number.isNaN(date.valueOf())) button.append(el('span', 'artifact-meta', date.toLocaleString(locale, { dateStyle: 'medium', timeStyle: 'short' })));
    } else if (artifact.kind === 'comparison') {
      button.append(el('span', 'artifact-meta', `${artifact.summary.baselineId} → ${artifact.summary.currentId}`));
    }
    li.append(button);
    list.append(li);
  }
  if (errorCount) $('catalog-state').setAttribute('aria-label', t('{v0}개의 오류 자료가 목록에 표시됩니다.', { v0: errorCount }));
  refreshRunOptions();
}
async function apiJson(url, signal) {
  const response = await fetch(url, { headers: { Accept: 'application/json' }, signal });
  let body;
  try { body = await response.json(); } catch { throw new Error('서버 응답을 읽을 수 없습니다.'); }
  if (!response.ok) throw new Error(body?.error?.message ?? '요청을 처리할 수 없습니다.');
  return body;
}
function updateSnapshotChrome() {
  if (!catalog) return;
  if (executionMode.enabled) {
    chromeMessage('snapshot-state', executionMode.lastRefresh || executionMode.generation > 0 ? '마지막 결과 반영 · {v0}' : '마지막 결과 반영 없음 · 시작 스냅샷 {v0}', { v0: executionMode.lastRefresh ?? catalog.snapshot.createdAt });
  } else chromeMessage('snapshot-state', '시작 스냅샷 · {v0} · 새 파일은 서버 재시작 후 반영', { v0: catalog.snapshot.createdAt });
}
function updateExecutionMode(mode) {
  executionMode = mode;
  $('execution-seal').dataset.i18n = mode.desktop ? '데스크톱 검사' : mode.enabled ? '로컬 실행 가능' : '읽기 전용';
  $('refresh-note').dataset.i18n = mode.desktop ? '검사 보고서가 준비되면 자동으로 엽니다.' : mode.enabled ? '검사 후 결과 반영을 누르면 새 파일을 읽습니다.' : '새 파일을 반영하려면 서버를 다시 시작하세요.';
  $('snapshot-note').dataset.i18n = mode.desktop ? '자동 결과 반영 / 저장된 결과는 안전 판정이 아닙니다' : mode.enabled ? '명시적 결과 반영 / 저장된 결과는 안전 판정이 아닙니다' : '고정 스냅샷 / 브라우저 새로고침은 디스크를 다시 읽지 않습니다';
  for (const id of ['execution-seal', 'refresh-note', 'snapshot-note']) $(id).textContent = t($(id).dataset.i18n);
  updateSnapshotChrome();
}
async function applyExecutionCatalog(value, artifactId) {
  catalogController?.abort();
  detailController?.abort();
  compareController?.abort();
  ++catalogRequest;
  ++catalogGeneration;
  ++detailRequest;
  ++compareRequest;
  comparisonPending = false;
  localComparison = null;
  savedComparison = null;
  $('comparison-content').replaceChildren();
  delete $('comparison-content').dataset.comparisonPage;
  chromeMessage('comparison-state', '');
  catalog = value;
  clearDetail();
  updateToolOptions();
  drawCatalog();
  updateSnapshotChrome();
  if (artifactId && catalog.artifacts.some((item) => item.id === artifactId)) {
    await selectArtifact(artifactId);
    if (executionMode.desktop && selectedId === artifactId) focusResults();
  }
}
async function loadCatalog() {
  const request = ++catalogRequest;
  const generation = catalogGeneration;
  catalogController?.abort();
  catalogController = new AbortController();
  setCatalogState('시작 스냅샷을 불러오는 중…');
  chromeMessage('live-status', '저장된 자료 목록을 불러오는 중입니다.');
  try {
    const value = await apiJson('/api/catalog', catalogController.signal);
    if (request !== catalogRequest || generation !== catalogGeneration) return;
    if (catalog && catalog.snapshot.createdAt !== value.snapshot.createdAt) await applyExecutionCatalog(value, null);
    else catalog = value;
    updateSnapshotChrome();
    updateToolOptions();
    drawCatalog();
    chromeMessage('live-status', '저장된 자료 {v0}개를 불러왔습니다.', { v0: value.artifacts.length });
    if (selectedId && !catalog.artifacts.some((item) => item.id === selectedId)) clearDetail('선택한 자료가 스냅샷에 없습니다.');
  } catch (error) {
    if (error.name === 'AbortError' || request !== catalogRequest || generation !== catalogGeneration) return;
    catalog = undefined;
    chromeMessage('snapshot-state', '스냅샷을 불러오지 못함');
    chromeMessage('catalog-counts', '목록을 불러오지 못했습니다.');
    $('artifact-list').replaceChildren();
    $('truncation').hidden = true;
    setCatalogState('{v0} 다시 시도할 수 있습니다.', true, () => ({ v0: t(error.message) }));
    chromeMessage('live-status', '목록 요청에 실패했습니다.');
    refreshRunOptions();
  }
}
function clearDetail(message = '목록에서 저장된 검사 또는 비교를 선택하세요.') {
  detailController?.abort();
  ++detailRequest;
  selectedId = null;
  activeRun = null;
  selectedArtifact = null;
  savedComparison = null;
  allFindings = [];
  delete desk().dataset.artifact;
  $('catalog-disclosure').open = true;
  chromeMessage('workspace-title', '검사 기록');
  resetFindingView();
  $('detail-content').replaceChildren();
  delete $('detail-content').dataset.comparisonPage;
  $('detail-state').hidden = false;
  chromeMessage('detail-state', message);
  drawCatalog();
}
function detailHeading(title, note) {
  const heading = el('div', 'block-heading');
  heading.append(el('h3', '', title), el('small', '', note));
  return heading;
}
function appendDefinitionGrid(parent, pairs) {
  const dl = el('dl', 'record-summary');
  for (const [label, value, klass, isPath] of pairs) dl.append(field(label, value, klass, isPath));
  parent.append(dl);
}
function provenanceBlock(parent, value, title = t('출처 및 실행 기록')) {
  const block = el('section', 'block');
  block.append(detailHeading(title, t('저장된 기록')));
  if (value === undefined) block.append(el('p', 'muted', t('출처 기록이 없습니다.')));
  else {
    const details = el('details');
    details.append(el('summary', '', t('기록 펼치기')));
    details.append(el('pre', 'mono', jsonText(value)));
    block.append(details);
  }
  parent.append(block);
}
function drawTools(parent, run) {
  const section = el('section', 'block');
  const tools = Array.isArray(run.tools) ? run.tools : [];
  section.append(detailHeading(t('도구 실행 범위'), t('{v0}개 도구 · 상태는 저장된 주장', { v0: tools.length })));
  const ul = el('ul', 'tool-list');
  for (const tool of tools) {
    const li = el('li');
    const heading = el('div', 'tool-row-heading');
    heading.append(el('span', 'mono', tool.id), el('span', '', toolStatusLabel(tool.status, locale)));
    if (tool.selected === false) heading.append(el('span', 'muted', t('선택 안 됨')));
    const details = el('details', 'tool-record');
    details.append(el('summary', '', t('저장된 실행 정보 펼치기')));
    details.append(el('pre', 'mono', jsonText(tool)));
    li.append(heading, details);
    ul.append(li);
  }
  section.append(ul);
  parent.append(section);
}
function pathDetails(value) {
  const path = compactPath(value);
  const details = el('details', 'path-details');
  details.append(el('summary', 'path-summary mono', path.summary || t('빈 경로')));
  details.append(el('pre', 'path-full mono', path.full));
  return details;
}
function findingLocation(location) {
  const content = el('div', 'finding-location');
  if (typeof location === 'string') content.append(pathDetails(location));
  else if (typeof location?.path === 'string') {
    content.append(pathDetails(location.path));
    if (Object.keys(location).some((key) => key !== 'path')) {
      const metadata = el('details');
      metadata.append(el('summary', '', t('위치 메타데이터')), el('pre', 'path-full mono', jsonText(location)));
      content.append(metadata);
    }
  } else {
    const details = el('details', 'path-details');
    details.append(el('summary', 'path-summary', t('위치 기록 펼치기')), el('pre', 'path-full mono', jsonText(location ?? {})));
    content.append(details);
  }
  return content;
}
function findingCell(label, className = '') {
  const cell = el('td', className);
  cell.setAttribute('role', 'cell');
  const name = el('span', 'finding-cell-label', label);
  name.setAttribute('aria-hidden', 'true');
  cell.append(name);
  return cell;
}
function resetFindingView() {
  findingView = { query: '', severity: 'all', tool: 'all', page: 1, selectedIndex: null, locale };
  findingPage = 1;
  document.querySelector('.desk').dataset.reading = 'list';
  drawEvidence();
}
function drawEvidence() {
  const parent = $('evidence-content');
  parent.replaceChildren();
  const finding = allFindings[findingView.selectedIndex];
  if (!finding) {
    parent.append(el('p', 'evidence-empty empty-state', t('목록에서 항목을 선택하면 저장된 근거를 확인할 수 있습니다.')));
    return;
  }
  const article = el('article', 'evidence-record');
  const dependency = findingPackage(finding);
  const lead = el('div', 'evidence-lead');
  const label = packageLabel(dependency);
  if (finding.ruleId) lead.append(el('p', 'evidence-id mono', finding.ruleId));
  if (label) lead.append(el('p', 'evidence-package', label));
  lead.append(severityBadge(finding), advisoryText(el('h3'), finding.title ?? t('제목 미기록')));
  article.append(lead);

  const summary = [finding.description, finding.message]
    .filter((value) => typeof value === 'string')
    .map((value) => value.trim().split(/\r?\n\s*\r?\n|(?:```|~~~)/, 1)[0].trim())
    .find((value) => value);
  if (summary) {
    const description = el('section', 'evidence-field evidence-description');
    const excerpt = summary.length > 480 ? `${summary.slice(0, 480).replace(/\s+\S*$/, '').trimEnd()}…` : summary;
    description.append(el('h4', '', t('문제 설명')), advisoryText(el('p'), excerpt));
    article.append(description);
  }
  if (dependency.fixedVersion || dependency.advisoryUrl) {
    const advisory = el('section', 'evidence-field evidence-advisory');
    advisory.append(el('h4', '', t('다음 조치')));
    if (dependency.fixedVersion) advisory.append(el('p', '', t('권고문에 기록된 수정 버전: {v0}', { v0: dependency.fixedVersion })));
    if (dependency.advisoryUrl) {
      const link = el('a', '', t('보안 권고문 보기'));
      link.href = dependency.advisoryUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      advisory.append(link);
    }
    article.append(advisory);
  }
  const locations = el('section', 'evidence-field');
  locations.append(el('h4', '', t('위치')), findingLocation(finding.location));
  article.append(locations);
  const raw = el('details', 'evidence-raw');
  raw.append(el('summary', '', t('원본 근거 및 메타데이터')));
  appendDefinitionGrid(raw, [
    [t('규칙 ID'), finding.ruleId ?? t('규칙 미기록')],
    [t('도구'), toolName(finding.toolId) ?? t('도구 미기록')], [t('검증'), verificationLabel(finding.verification, locale)],
  ]);
  const pieces = [
    [t('메시지'), finding.message], [t('설명'), finding.description], [t('추가 위치'), finding.locations],
    [t('별칭'), finding.aliases], [t('원본 레코드'), finding.sourceRecords], [t('증거'), finding.evidence],
    [t('조치'), finding.remediation], [t('실행 메타데이터'), finding.execution],
    [t('출처'), finding.provenance ?? finding.source], [t('참고 자료'), finding.references],
  ];
  for (const [label, value] of pieces) {
    if (value === undefined || value === null) continue;
    const block = el('section', 'evidence-field');
    block.append(el('h4', '', label), el('pre', 'mono', typeof value === 'string' ? value : jsonText(value)));
    raw.append(block);
  }
  article.append(raw);
  parent.append(article);
}
function selectFinding(index, keyboard) {
  listScroll = window.scrollY;
  listFocusIndex = index;
  findingView = transitionFindingView(allFindings, findingView, { selectedIndex: index });
  drawFindingRows();
  drawEvidence();
  document.querySelector('.desk').dataset.reading = 'evidence';
  if (window.matchMedia('(max-width: 1120px)').matches) {
    $('evidence-panel').scrollIntoView({ block: 'start', behavior: 'instant' });
    $('evidence-back').focus({ preventScroll: true });
  } else if (keyboard) {
    document.querySelector(`.finding-select[data-finding-index="${index}"]`)?.focus({ preventScroll: true });
  }
}
function drawPager(parent, info, onPage) {
  const pager = el('div', 'pager');
  pager.append(el('span', '', t('{v0}개 결과 · {v1} / {v2}쪽 · 한 번에 최대 100개', { v0: info.total, v1: info.page, v2: info.pages })));
  const actions = el('div', 'pager-actions');
  const previous = el('button', 'page-button', t('이전'));
  previous.type = 'button';
  previous.disabled = info.page <= 1;
  previous.addEventListener('click', () => {
    onPage(info.page - 1);
    const buttons = parent.querySelectorAll('.pager .page-button');
    (buttons[0]?.disabled ? buttons[1] : buttons[0])?.focus();
  });
  const next = el('button', 'page-button', t('다음'));
  next.type = 'button';
  next.disabled = info.page >= info.pages;
  next.addEventListener('click', () => {
    onPage(info.page + 1);
    const buttons = parent.querySelectorAll('.pager .page-button');
    (buttons[1]?.disabled ? buttons[0] : buttons[1])?.focus();
  });
  actions.append(previous, next);
  pager.append(actions);
  parent.append(pager);
}
function drawFindingRows() {
  const section = $('finding-section');
  if (!section) return;
  const info = pageItems(filteredFindings, findingPage, 100);
  findingPage = info.page;
  findingView.page = info.page;
  const tbody = section.querySelector('tbody');
  tbody.replaceChildren();
  for (const finding of info.items) {
    const row = el('tr');
    row.setAttribute('role', 'row');
    const content = findingCell(t('항목 / 근거'), 'finding-cell--primary');
    const index = allFindings.indexOf(finding);
    row.dataset.selected = String(index === findingView.selectedIndex);
    const select = el('button', 'finding-select');
    const label = packageLabel(findingPackage(finding));
    if (label) select.append(el('span', 'finding-package', label));
    select.append(advisoryText(el('span', 'finding-title'), finding.title ?? t('제목 미기록')));
    select.type = 'button';
    select.dataset.findingIndex = String(index);
    select.setAttribute('aria-pressed', String(index === findingView.selectedIndex));
    select.addEventListener('click', (event) => selectFinding(index, event.detail === 0));
    content.append(select);
    const severity = findingCell(t('심각도'));
    severity.append(severityBadge(finding));
    row.append(content, severity);
    tbody.append(row);
  }
  const empty = section.querySelector('.finding-empty');
  empty.hidden = info.total > 0;
  empty.textContent = allFindings.length === 0
    ? t('이 실행에는 저장된 발견 항목이 없습니다.')
    : t('현재 검색·필터와 일치하는 항목이 없습니다. 조건을 변경하거나 결과 필터를 초기화하세요.');
  const pager = section.querySelector('.pager');
  if (pager) pager.remove();
  if (info.pages > 1) drawPager(section, info, (page) => { findingView = transitionFindingView(allFindings, findingView, { page }); findingPage = findingView.page; drawFindingRows(); });
  const count = section.querySelector('.block-heading small');
  if (count) count.textContent = info.total === allFindings.length ? '' : t('{v1}건 중 {v0}건 표시', { v0: info.total, v1: allFindings.length });
}
function drawFindings(parent, run) {
  const section = el('section', 'block');
  section.id = 'finding-section';
  const findingTools = (run.findings ?? []).map((finding) => finding.toolId);
  const selectedTools = executionMode.desktop ? (run.tools ?? []).filter((tool) => tool.selected !== false).map((tool) => tool.id) : [];
  const tools = [...new Set([...findingTools, ...selectedTools].filter(Boolean))].sort();
  const controls = el('div', 'finding-controls');
  const searchLabel = el('label', 'filters-label', t('검색'));
  const search = document.createElement('input');
  search.type = 'search'; search.placeholder = t('패키지, 제목, 권고문 ID'); search.setAttribute('aria-label', t('검사 결과 검색'));
  search.value = findingView.query; search.id = 'finding-search';
  searchLabel.append(search);
  const severityLabel = el('label', 'filters-label', t('심각도'));
  const severity = document.createElement('select');
  severity.setAttribute('aria-label', t('심각도 필터'));
  for (const [value, title] of [['all', t('전체')], ...Object.keys(severityKeys).map((key) => [key, severityName(key)])]) {
    const option = document.createElement('option'); option.value = value; option.textContent = title; severity.append(option);
  }
  severity.value = findingView.severity; severity.id = 'finding-severity';
  severityLabel.append(severity);
  const toolLabel = el('label', 'filters-label', t('도구 ID'));
  const toolSelect = document.createElement('select'); toolSelect.setAttribute('aria-label', t('도구 ID 필터'));
  const all = document.createElement('option'); all.value = 'all'; all.textContent = t('전체'); toolSelect.append(all);
  for (const id of tools) { const option = document.createElement('option'); option.value = id; option.textContent = toolName(id); toolSelect.append(option); }
  toolSelect.value = findingView.tool; toolSelect.id = 'finding-tool';
  toolLabel.append(toolSelect);
  const reset = el('button', 'quiet-button filters-reset', t('결과 필터 초기화'));
  reset.type = 'button';
  controls.append(searchLabel, severityLabel);
  if (tools.length > 1) {
    controls.classList.add('has-tool-filter');
    controls.append(toolLabel);
  }
  controls.append(reset);
  const active = el('div', 'active-filters');
  active.setAttribute('aria-label', t('적용 중인 결과 필터'));
  section.append(detailHeading(t('발견 항목'), ''), controls, active);
  const scroll = el('div', 'table-scroll');
  const table = el('table', 'finding-table');
  table.setAttribute('role', 'table');
  table.setAttribute('aria-label', t('저장된 발견 항목'));
  const thead = document.createElement('thead');
  thead.setAttribute('role', 'rowgroup');
  const tr = document.createElement('tr');
  tr.setAttribute('role', 'row');
  for (const heading of [t('발견 항목'), t('심각도')]) {
    const th = el('th', '', heading);
    th.scope = 'col';
    th.setAttribute('role', 'columnheader');
    tr.append(th);
  }
  thead.append(tr);
  const tbody = document.createElement('tbody');
  tbody.setAttribute('role', 'rowgroup');
  table.append(thead, tbody); scroll.append(table); section.append(scroll);
  const empty = el('p', 'finding-empty notice');
  empty.hidden = true;
  section.append(empty);
  parent.append(section);
  allFindings = sortFindingsBySeverity(run.findings);
  const apply = () => {
    active.replaceChildren();
    const conditions = [
      [t('검색'), search.value.trim()], [t('심각도'), severity.value === 'all' ? '' : severityName(severity.value)], [t('도구'), toolSelect.value === 'all' ? '' : toolName(toolSelect.value)],
    ].filter(([, value]) => value);
    for (const [label, value] of conditions) active.append(el('span', 'filter-chip', `${label}: ${value}`));
    active.hidden = reset.hidden = !conditions.length;
    findingView = transitionFindingView(allFindings, findingView, { query: search.value, severity: severity.value, tool: toolSelect.value });
    filteredFindings = filterFindings(allFindings, findingView);
    findingPage = findingView.page;
    drawFindingRows();
    drawEvidence();
    if (findingView.selectedIndex === null) document.querySelector('.desk').dataset.reading = 'list';
  };
  search.addEventListener('input', apply);
  severity.addEventListener('change', apply);
  toolSelect.addEventListener('change', apply);
  reset.addEventListener('click', () => {
    search.value = ''; severity.value = 'all'; toolSelect.value = 'all';
    apply();
    search.focus();
  });
  apply();
}
function drawRun(parent, run, artifact) {
  const top = el('div');
  const overview = el('div', 'run-overview');
  const runSummary = el('div', 'run-summary');
  const heading = el('div', 'section-heading');
  heading.append(el('h3', '', projectName(run.target?.path)), safeStatusStamp(run.status));
  const selectedTools = (run.tools ?? []).filter((tool) => tool.selected !== false);
  const usedTools = selectedTools.filter((tool) => tool.status !== 'skipped');
  const findings = Array.isArray(run.findings) ? run.findings : [];
  const total = t('발견 항목 {v0}건', { v0: findings.length });
  const names = usedTools.map((tool) => toolName(tool.id)).filter(Boolean).join(', ');
  runSummary.append(heading, el('p', '', names && !executionMode.desktop ? `${names} · ${total}` : total));
  overview.append(runSummary);
  const counts = new Map();
  for (const finding of findings) {
    const severity = findingSeverity(finding);
    counts.set(severity, (counts.get(severity) ?? 0) + 1);
  }
  const severitySummary = el('ul', 'severity-summary');
  for (const severity of Object.keys(severityKeys)) {
    if (!counts.has(severity)) continue;
    const item = el('li', 'severity-summary-item');
    item.dataset.severity = severity;
    item.append(el('span', '', severityName(severity)), el('strong', '', counts.get(severity)));
    severitySummary.append(item);
  }
  if (counts.size) overview.append(severitySummary);
  top.append(overview);
  if (executionMode.desktop && selectedTools.length) {
    const coverage = el('ul', 'run-tool-coverage');
    coverage.setAttribute('aria-label', t('도구 실행 범위'));
    for (const tool of selectedTools) {
      const item = el('li', 'tag', `${toolName(tool.id)} · ${toolStatusLabel(tool.status, locale)}`);
      if (['failed', 'missing', 'skipped'].includes(tool.status)) item.classList.add('alert');
      coverage.append(item);
    }
    top.append(coverage);
  }
  const metadata = el('details', 'run-metadata');
  metadata.append(el('summary', '', t('검사 세부 정보')));
  const pairs = [
    [t('실행 ID'), run.id], [t('자료 ID'), artifact.id], [t('자료 SHA-256'), artifact.sha256], [t('대상 경로'), run.target?.path, '', true], [t('리비전'), run.target?.revision ?? t('기록 없음')],
    [t('작업 트리'), run.target?.dirty === true ? t('변경 있음') : run.target?.dirty === false ? t('변경 없음') : t('상태 미기록')],
    [t('시작'), run.startedAt], [t('종료'), run.endedAt],
    [t('저장된 발견 행'), run.findings?.length ?? 0], [t('결과 의미'), run.status === 'completed' ? t('실행 완료 · 안전 확인이 아님') : run.status === 'partial' ? t('부분 완료 · 범위가 제한됨') : t('실패 · 결과 범위 제한')],
  ];
  appendDefinitionGrid(metadata, pairs);
  drawTools(metadata, run);
  const imported = (run.tools ?? []).some((item) => item.status === 'imported');
  if (imported) top.append(el('p', 'notice', t('가져온 결과 · 로컬 실행 아님')));
  if (run.status === 'partial') top.append(el('p', 'notice', t('부분 실행입니다. 누락되거나 제한된 검사 범위를 확인하세요.')));
  if (run.verification === undefined && run.verificationPassed === undefined) metadata.append(el('p', 'muted', t('보고됨 · 검증 수준 미기록')));
  metadata.append(el('p', 'muted', t('SAVED RUN · 원본 검사 재실행 안 함')));
  provenanceBlock(metadata, run.provenance ?? run.source);
  top.append(metadata);
  parent.append(top);
  drawFindings(top, run);
}
function comparisonTable(parent, entries, page, onPage) {
  const info = pageItems(entries ?? [], page, 100);
  const scroll = el('div', 'table-scroll');
  scroll.tabIndex = 0;
  scroll.setAttribute('role', 'region');
  scroll.setAttribute('aria-label', t('비교 항목 표 · 가로로 스크롤할 수 있습니다'));
  const table = el('table', 'comparison-table');
  const head = document.createElement('thead');
  const hr = document.createElement('tr');
  for (const title of [t('범주'), t('ID / 정체성'), t('전'), t('후'), t('이유')]) {
    const th = el('th', '', title);
    th.scope = 'col';
    hr.append(th);
  }
  head.append(hr);
  const body = document.createElement('tbody');
  for (const entry of info.items) {
    const row = el('tr');
    row.append(el('td', '', t(categoryLabel(entry.category))));
    const identity = el('td');
    identity.append(el('span', 'mono', entry.id), el('br'), el('span', 'muted', t('{v0} · {v1}', { v0: entry.identityMethod ?? t('방법 미기록'), v1: entry.identity ?? '' })));
    row.append(identity);
    row.append(snapshotCell(entry.before), snapshotCell(entry.after));
    row.append(el('td', 'mono', (entry.reasons ?? []).join(', ') || t('이유 기록 없음')));
    body.append(row);
  }
  table.append(head, body); scroll.append(table); parent.append(scroll);
  drawPager(parent, info, onPage);
}
function snapshotCell(value) {
  const td = el('td');
  if (!value) { td.textContent = '—'; return td; }
  td.append(el('span', 'mono', t('{v0} · {v1} · {v2}', { v0: value.severity ?? 'unknown', v1: value.ruleId ?? t('규칙 미기록'), v2: verificationLabel(value.verification, locale) })));
  const details = el('details'); details.append(el('summary', '', value.title ?? t('상세 기록')));
  details.append(el('pre', 'mono', jsonText(value)));
  td.append(details);
  return td;
}
function drawComparison(parent, comparison, originLabel, inputs = undefined) {
  const c = comparison;
  const section = el('section', 'block');
  section.append(detailHeading(t('비교 판독'), originLabel));
  const gate = c.gate ?? {};
  const banner = el('div', `gate-banner ${gate.exitCode === 1 ? 'fail' : gate.exitCode === 2 ? 'unknown' : ''}`);
  banner.append(el('strong', '', t(gateLabel(gate.exitCode))), el('span', 'mono', t('failOn {v0} · 종료 코드 {v1}', { v0: gate.failOn ?? t('기록 없음'), v1: gate.exitCode ?? '—' })));
  section.append(banner);
  if (inputs) {
    const hashes = el('p', 'muted mono', t('기준 자료 SHA-256 {v0} · 현재 자료 SHA-256 {v1}', { v0: inputs.baseline?.sha256 ?? t('기록 없음'), v1: inputs.current?.sha256 ?? t('기록 없음') }));
    section.append(hashes);
  }
  const baseline = c.baseline ?? {};
  const current = c.current ?? {};
  appendDefinitionGrid(section, [
    [t('기준 실행'), baseline.id], [t('기준 대상'), baseline.target?.path, '', true], [t('기준 리비전'), baseline.target?.revision ?? t('기록 없음')],
    [t('기준 작업 트리'), baseline.target?.dirty === true ? t('변경 있음') : baseline.target?.dirty === false ? t('변경 없음') : t('상태 미기록')],
    [t('현재 실행'), current.id], [t('현재 대상'), current.target?.path, '', true], [t('현재 리비전'), current.target?.revision ?? t('기록 없음')],
    [t('현재 작업 트리'), current.target?.dirty === true ? t('변경 있음') : current.target?.dirty === false ? t('변경 없음') : t('상태 미기록')],
    [t('기준 상태'), t(runStatusLabel(baseline.status))], [t('현재 상태'), t(runStatusLabel(current.status))],
    [t('게이트 위반'), gate.violations?.length ?? 0], [t('판단 불명'), gate.unknown?.length ?? 0], [t('비교 범위'), c.status === 'complete' ? t('완료') : t('불완전 · 범위 부족')],
  ]);
  if (baseline.provenance !== undefined || current.provenance !== undefined) {
    provenanceBlock(section, { baseline: baseline.provenance, current: current.provenance }, t('기준 및 현재 출처'));
  }
  const counts = el('div', 'category-grid');
  for (const category of ['new', 'regressed', 'existing', 'resolved', 'unobserved']) {
    const item = el('div', 'category-count');
    item.append(el('strong', '', c.counts?.[category] ?? 0), el('span', '', t(categoryLabel(category))));
    counts.append(item);
  }
  section.append(counts);
  section.append(el('p', 'muted', t('새로 관측은 도입 증명이 아닙니다. 완료 검사에서 더 이상 보이지 않는 항목도 수정 증명이 아닙니다. 후보 항목은 비교 게이트에 포함될 수 있으며 계속 후보로 표시됩니다.')));
  if (Array.isArray(c.coverage)) {
    const cov = el('section', 'block');
    cov.append(detailHeading(t('도구 범위'), t('{v0}개 기록', { v0: c.coverage.length })));
    const ul = el('ul', 'tool-list');
    for (const entry of c.coverage) {
      const li = el('li');
      const heading = el('div', 'tool-row-heading');
      heading.append(el('span', 'mono', entry.toolId), el('span', '', entry.reasons?.length ? entry.reasons.join(', ') : t('제한 사유 기록 없음')));
      const details = el('details', 'tool-record');
      details.append(el('summary', '', t('기준·현재 도구 메타데이터 펼치기')));
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
  entriesBlock.append(detailHeading(t('비교 항목'), t('{v0}개 저장 결과', { v0: c.entries?.length ?? 0 })));
  section.append(entriesBlock);
  const pageOwner = parent.closest('#detail-content, #comparison-content') ?? parent;
  const entryPage = Number(pageOwner.dataset.comparisonPage || 1);
  const renderEntries = (page) => {
    entriesBlock.replaceChildren(detailHeading(t('비교 항목'), t('{v0}개 저장 결과', { v0: c.entries?.length ?? 0 })));
    pageOwner.dataset.comparisonPage = String(pageItems(c.entries, page).page);
    comparisonTable(entriesBlock, c.entries, page, (next) => renderEntries(next));
  };
  renderEntries(entryPage);
  parent.append(section);
}
function drawComparisonSummary(parent, comparison) {
  const section = el('section', 'block');
  section.append(detailHeading(t('저장된 비교'), t('저장된 비교 · 원본 검사 재검증 안 함')));
  appendDefinitionGrid(section, [
    [t('기준 실행 ID'), comparison.baseline?.id], [t('기준 대상'), comparison.baseline?.target?.path, '', true], [t('기준 상태'), t(runStatusLabel(comparison.baseline?.status))],
    [t('현재 실행 ID'), comparison.current?.id], [t('현재 대상'), comparison.current?.target?.path, '', true], [t('현재 상태'), t(runStatusLabel(comparison.current?.status))],
  ]);
  parent.append(section);
  drawComparison(section, comparison, t('저장된 비교 · 원본 검사 재검증 안 함'));
}
async function selectArtifact(id) {
  detailController?.abort();
  detailController = new AbortController();
  const request = ++detailRequest;
  const generation = catalogGeneration;
  selectedId = id;
  activeRun = null;
  savedComparison = null;
  selectedArtifact = null;
  allFindings = [];
  resetFindingView();
  $('detail-content').replaceChildren();
  delete $('detail-content').dataset.comparisonPage;
  $('detail-state').hidden = false;
  chromeMessage('detail-state', '저장 자료를 여는 중…');
  drawCatalog();
  chromeMessage('live-status', '선택한 저장 자료를 여는 중입니다.');
  try {
    const value = await apiJson(`/api/artifacts/${id}`, detailController.signal);
    if (request !== detailRequest || generation !== catalogGeneration) return;
    $('detail-state').hidden = true;
    const parent = $('detail-content');
    parent.replaceChildren();
    const artifact = value.artifact;
    selectedArtifact = artifact;
    if (artifact.kind === 'run' && value.run) {
      activeRun = value.run;
      desk().dataset.artifact = 'run';
      $('catalog-disclosure').open = false;
      chromeMessage('workspace-title', '보안 받은편지함');
      drawRun(parent, value.run, artifact);
      if (allFindings.length && window.matchMedia('(min-width: 1121px)').matches) {
        findingView = transitionFindingView(allFindings, findingView, { selectedIndex: 0 });
        drawFindingRows();
        drawEvidence();
      }
      chromeMessage('live-status', '{v0} 검사 결과를 표시했습니다.', () => ({ v0: projectName(value.run.target?.path) }));
    } else if (artifact.kind === 'comparison' && value.comparison) {
      savedComparison = value.comparison;
      desk().dataset.artifact = 'comparison';
      $('catalog-disclosure').open = true;
      chromeMessage('workspace-title', '저장 비교');
      drawComparisonSummary(parent, value.comparison);
      chromeMessage('live-status', '저장된 비교를 표시했습니다. 원본 검사를 재검증하지 않았습니다.');
    } else {
      $('detail-state').hidden = false;
      chromeMessage('detail-state', artifact.error?.message ?? '자료를 표시할 수 없습니다.');
    }
  } catch (error) {
    if (error.name === 'AbortError' || request !== detailRequest || generation !== catalogGeneration) return;
    $('detail-state').hidden = false;
    chromeMessage('detail-state', '{v0} 다시 목록에서 선택해 재시도하세요.', () => ({ v0: t(error.message) }));
    chromeMessage('live-status', '저장 자료를 열지 못했습니다.');
  }
}
async function compareSelected() {
  const baseline = $('baseline-select').value;
  const current = $('current-select').value;
  if (!baseline || !current) return;
  compareController?.abort();
  compareController = new AbortController();
  const request = ++compareRequest;
  const generation = catalogGeneration;
  comparisonPending = true;
  updateComparisonControls();
  chromeMessage('comparison-state', '비교 중…');
  $('comparison-content').replaceChildren();
  localComparison = null;
  delete $('comparison-content').dataset.comparisonPage;
  chromeMessage('live-status', '저장된 두 실행을 비교하고 있습니다.');
  try {
    const params = new URLSearchParams({ baseline, current, failOn: $('fail-on').value });
    const value = await apiJson(`/api/compare?${params}`, compareController.signal);
    if (request !== compareRequest || generation !== catalogGeneration) return;
    $('comparison-content').replaceChildren();
    localComparison = value;
    drawComparison($('comparison-content'), value.comparison, t('메모리 비교 · 저장되지 않음'), value.inputs);
    chromeMessage('comparison-state', '대상 {v0} · 입력 자료 해시를 함께 표시', { v0: value.comparison.baseline?.target?.path ?? t('기록 없음') });
    chromeMessage('live-status', gateLabel(value.comparison.gate.exitCode));
  } catch (error) {
    if (error.name === 'AbortError' || request !== compareRequest || generation !== catalogGeneration) return;
    chromeMessage('comparison-state', '{v0} 실행을 다시 선택하고 재시도하세요.', () => ({ v0: t(error.message) }));
    chromeMessage('live-status', '비교 요청에 실패했습니다.');
  } finally {
    if (request === compareRequest && generation === catalogGeneration) {
      comparisonPending = false;
      updateComparisonControls();
    }
  }
}

function applyLanguage() {
  document.documentElement.lang = locale;
  document.title = t('Security Scan Hub / 개발자 워크벤치');
  for (const [id, { key, values }] of chromeMessages) $(id).textContent = t(key, typeof values === 'function' ? values() : values);
  for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = t(node.dataset.i18n);
  for (const node of document.querySelectorAll('[data-i18n-placeholder]')) node.placeholder = t(node.dataset.i18nPlaceholder);
  for (const node of document.querySelectorAll('[data-i18n-aria]')) node.setAttribute('aria-label', t(node.dataset.i18nAria));
}
$('language-select').addEventListener('change', () => {
  locale = $('language-select').value === 'en' ? 'en' : 'ko';
  findingView = transitionFindingView(allFindings, findingView, { locale });
  const reading = document.querySelector('.desk').dataset.reading;
  const scroll = window.scrollY;
  const savedPage = $('detail-content').dataset.comparisonPage;
  applyLanguage();
  if (catalog) {
    updateSnapshotChrome();
    drawCatalog();
  }
  if (activeRun) {
    $('detail-content').replaceChildren();
    chromeMessage('workspace-title', '보안 받은편지함');
    drawRun($('detail-content'), activeRun, selectedArtifact);
  } else if (savedComparison) {
    $('detail-content').replaceChildren();
    $('detail-content').dataset.comparisonPage = savedPage || '1';
    chromeMessage('workspace-title', '저장 비교');
    drawComparisonSummary($('detail-content'), savedComparison);
  }
  if (localComparison) {
    $('comparison-content').replaceChildren();
    drawComparison($('comparison-content'), localComparison.comparison, t('메모리 비교 · 저장되지 않음'), localComparison.inputs);
    chromeMessage('comparison-state', '대상 {v0} · 입력 자료 해시를 함께 표시', { v0: localComparison.comparison.baseline?.target?.path ?? t('기록 없음') });
  }
  drawEvidence();
  executionView?.render();
  document.querySelector('.desk').dataset.reading = reading;
  window.scrollTo({ top: scroll, behavior: 'instant' });
});
$('evidence-back').addEventListener('click', () => {
  document.querySelector('.desk').dataset.reading = 'list';
  const button = document.querySelector(`.finding-select[data-finding-index="${listFocusIndex}"]`);
  button?.focus({ preventScroll: true });
  window.scrollTo({ top: listScroll, behavior: 'instant' });
});

$('reload').addEventListener('click', loadCatalog);
$('catalog-filters').addEventListener('submit', (event) => event.preventDefault());
for (const id of ['catalog-search', 'kind-filter', 'status-filter', 'tool-filter']) $(id).addEventListener(id === 'catalog-search' ? 'input' : 'change', drawCatalog);
$('catalog-reset').addEventListener('click', () => {
  $('catalog-search').value = '';
  for (const id of ['kind-filter', 'status-filter', 'tool-filter']) $(id).value = 'all';
  drawCatalog();
  $('catalog-search').focus();
});
$('compare-button').addEventListener('click', compareSelected);
for (const id of ['baseline-select', 'current-select']) $(id).addEventListener('change', updateComparisonControls);
chromeMessage('detail-state', '목록에서 저장된 검사 또는 비교를 선택하세요.');
chromeMessage('workspace-title', '검사 기록');
executionView = initializeExecutionView({ document, window, getLocale: () => locale, applyCatalog: applyExecutionCatalog, onModeChange: updateExecutionMode });
applyLanguage();
drawEvidence();
loadCatalog();
