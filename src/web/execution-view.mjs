import { translate } from './i18n.mjs';
import { runStatusLabel, toolStatusLabel } from './view-model.mjs';

const sessionKey = 'sec-hub.execution.session';
const active = (job) => job?.state === 'running' || job?.state === 'cancelling';
const terminal = (job) => ['completed', 'cancelled', 'failed'].includes(job?.state);
const desktopMethods = ['getState', 'chooseFolder', 'startScan', 'getJob', 'cancelScan', 'refreshResults', 'openSetup'];
const setupLabels = { install: '설치 안내', sign_in: '로그인 안내' };
const installationLabels = { installed: '설치 감지됨', missing: '설치를 감지하지 못함', unknown: '설치 상태 미확인' };
const authenticationLabels = { unknown: '로그인 미확인', not_required: '로그인 필요 없음' };
const desktopToolNames = { osv: 'OSV Scanner', skillspector: 'SkillSpector', 'codex-security': 'Codex Security', 'open-code-review': 'Open Code Review', cloudflare: 'Cloudflare Security Audit', anthropic: 'Anthropic Defending Code', php2shell: 'PHP2Shell Checker' };
const desktopToolGuides = {
  osv: 'OSV Scanner를 설치한 뒤 도구 상태를 다시 확인하세요.',
  skillspector: 'SkillSpector를 설치하고 루트에 SKILL.md가 있는 폴더를 선택하세요. 정적 분석 모드로 실행합니다.',
  'codex-security': 'Codex Security CLI를 설치하고 사용할 계정으로 인증한 뒤 CLI 설정을 확인하세요.',
  'open-code-review': 'Open Code Review CLI를 설치하고 사용할 모델 제공업체의 인증과 모델을 설정하세요.',
  php2shell: 'Node.js와 공식 검사 스크립트를 설치하고 설정 파일에 절대 경로를 지정하세요.',
  cloudflare: 'Codex CLI에 로그인하고 공식 감사 스킬과 작업 디렉터리를 설정 파일에 지정하세요.',
  anthropic: 'Claude Code에 로그인하고 공식 하네스와 작업 디렉터리를 설정 파일에 지정하세요.',
};
const unavailableLabels = {
  platform_unsupported: '이 플랫폼에서 사용할 수 없습니다.',
  config_required: '신뢰할 수 있는 도구 설정 파일이 필요합니다.',
  executable_missing: '설정한 실행 파일을 찾을 수 없습니다.',
  configuration_invalid: '도구 설정을 확인하세요.',
  node_required: '이 도구를 실행하려면 Node.js 22 이상이 필요합니다.',
};
export const desktopToolName = (id) => Object.hasOwn(desktopToolNames, id) ? desktopToolNames[id] : id;

export function consumeExecutionSession({ location, history, storage }) {
  const hash = location.hash;
  if (hash.startsWith('#session=')) {
    history.replaceState(history.state, '', `${location.pathname}${location.search}`);
    const token = /^#session=([a-f0-9]{64})$/.exec(hash)?.[1] ?? null;
    try { if (token) storage?.setItem(sessionKey, token); else storage?.removeItem(sessionKey); } catch {}
    return token;
  }
  try {
    const token = storage?.getItem(sessionKey);
    return /^[a-f0-9]{64}$/.test(token ?? '') ? token : null;
  } catch { return null; }
}

export function executionSelection(targets, selection = {}) {
  const target = targets.find((item) => item.id === selection.targetId) ?? targets[0];
  if (!target) return { targetId: '', toolIds: [] };
  const requested = target.id === selection.targetId && Array.isArray(selection.toolIds) ? selection.toolIds : target.toolIds;
  return { targetId: target.id, toolIds: [...new Set(requested.filter((id) => target.toolIds.includes(id) && id !== 'anthropic'))] };
}

export function executionControls({ authenticated, enabled, selection, job, pending = false, quotaReached = false }) {
  const unavailable = !authenticated || !enabled;
  const busy = active(job) || pending;
  return {
    inputsDisabled: unavailable || busy,
    startDisabled: unavailable || busy || quotaReached || job?.errorCode === 'cleanup_unconfirmed' || !selection?.targetId || !selection.toolIds?.length,
    cancelDisabled: unavailable || pending || job?.state !== 'running',
    refreshDisabled: unavailable || busy || !terminal(job) || !job.reportsReady,
  };
}

const errors = {
  job_busy: '다른 작업이 진행 중입니다. 완료 후 다시 시도하세요.',
  execution_busy: '다른 작업이 진행 중입니다. 완료 후 다시 시도하세요.',
  job_limit: '이 세션의 검사 한도에 도달했습니다. 운영자가 서버를 다시 시작해야 합니다.',
  job_limit_reached: '이 세션의 검사 한도에 도달했습니다. 운영자가 서버를 다시 시작해야 합니다.',
  cleanup_unconfirmed: '프로세스 정리를 확인하지 못했습니다. 운영자가 서버 상태를 확인해야 합니다.',
  job_timeout: '전체 검사 시간이 초과되었습니다.',
  server_shutdown: '서버 종료로 검사가 중단되었습니다.',
  execution_path_changed: '대상 또는 출력 디렉터리가 변경되었습니다. 운영자가 확인해야 합니다.',
  report_failed: '보고서 저장에 실패했습니다. 결과를 반영할 수 없습니다.',
  report_write_failed: '보고서 저장에 실패했습니다. 결과를 반영할 수 없습니다.',
  reports_failed: '보고서 저장에 실패했습니다. 결과를 반영할 수 없습니다.',
};
const desktopErrors = {
  target_not_found: '검사할 폴더를 먼저 선택하세요.',
  target_unavailable: '이 폴더를 열 수 없습니다. 접근할 수 있는 프로젝트 폴더를 선택하세요.',
  tool_unavailable: '선택한 도구를 실행할 수 없습니다. 도구 상태를 다시 확인하세요.',
  config_unavailable: '도구 설정 파일을 읽을 수 없습니다. 신뢰할 수 있는 유효한 JSON 파일을 선택하세요.',
  node_unavailable: 'Node.js를 실행할 수 없습니다. 신뢰할 수 있는 Node.js 22 이상 실행 파일을 선택하세요.',
  php_url_required: 'PHP2Shell Checker에 검사할 URL을 입력하세요.',
  invalid_php_url: 'PHP2Shell Checker에 올바른 HTTP 또는 HTTPS URL을 입력하세요.',
  ai_consent_required: 'AI 도구를 실행하려면 이번 검사의 전송 및 비용에 동의하세요.',
};
export function executionStatus(job, locale = 'ko') {
  const t = (key) => translate(locale, key);
  if (!job) return t('허용된 대상과 도구를 선택해 검사를 시작하세요.');
  if (job.state === 'failed') return t(errors[job.errorCode] ?? '검사 작업이 실패했습니다.');
  if (job.state === 'cancelled') return t('취소 완료 · 프로세스 정리 확인됨');
  if (job.state === 'cancelling') return t('취소 중 · 프로세스 정리를 기다립니다.');
  if (job.state === 'completed') return `${t('검사 작업 완료 · 안전 판정이 아님')} · ${t(runStatusLabel(job.runStatus))}`;
  return t('검사 실행 중');
}

export function executionResultMapping(response, jobId, generation) {
  if (!Number.isSafeInteger(response?.generation) || response.generation <= generation) return { accepted: false, artifactId: null };
  return { accepted: true, artifactId: response.results?.find((entry) => entry.jobId === jobId)?.artifactId ?? null };
}

const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const strings = (value) => Array.isArray(value) && value.every((entry) => typeof entry === 'string');
const validJob = (job) => record(job)
  && typeof job.id === 'string' && job.id.length > 0
  && typeof job.targetId === 'string' && typeof job.targetLabel === 'string'
  && strings(job.toolIds) && (active(job) || terminal(job))
  && ['preparing', 'checking', 'scanning', 'reporting', 'ready'].includes(job.phase)
  && typeof job.startedAt === 'string' && (job.completedAt === null || typeof job.completedAt === 'string')
  && typeof job.reportsReady === 'boolean' && (job.runStatus === null || ['completed', 'partial', 'failed'].includes(job.runStatus))
  && record(job.progress) && Number.isSafeInteger(job.progress.completedCount) && job.progress.completedCount >= 0
  && Number.isSafeInteger(job.progress.totalCount) && job.progress.totalCount >= 0
  && Array.isArray(job.progress.tools) && job.progress.tools.every((tool) => record(tool) && typeof tool.id === 'string' && typeof tool.status === 'string');
const validDesktopState = (state) => record(state)
  && (state.folderLabel === null || (typeof state.folderLabel === 'string' && state.folderLabel.length > 0))
  && (state.nodeConfigured === undefined || typeof state.nodeConfigured === 'boolean')
  && (state.configLabel == null || typeof state.configLabel === 'string')
  && Number.isSafeInteger(state.generation) && state.generation >= 0
  && (state.job === null || validJob(state.job))
  && Array.isArray(state.tools) && state.tools.every((tool) => record(tool) && typeof tool.id === 'string'
    && Object.hasOwn(installationLabels, tool.installation) && Object.hasOwn(authenticationLabels, tool.authentication)
    && typeof tool.selectable === 'boolean' && typeof tool.ai === 'boolean'
    && (tool.setupActions === undefined || (strings(tool.setupActions) && tool.setupActions.every((action) => Object.hasOwn(setupLabels, action)))));
function validResponse(path, payload) {
  if (!record(payload)) return false;
  if (path === '') return payload.enabled === true && /^[a-f0-9]{64}$/.test(payload.csrfToken ?? '')
    && Number.isSafeInteger(payload.generation) && payload.generation >= 0 && record(payload.limits)
    && Array.isArray(payload.targets) && payload.targets.every((target) => record(target) && typeof target.id === 'string' && typeof target.label === 'string' && strings(target.toolIds))
    && Array.isArray(payload.jobs) && payload.jobs.every(validJob) && (payload.currentJob === null || validJob(payload.currentJob));
  if (path === '/catalog/refresh') return record(payload.catalog) && Array.isArray(payload.catalog.artifacts)
    && record(payload.catalog.snapshot) && typeof payload.catalog.snapshot.createdAt === 'string'
    && Number.isSafeInteger(payload.generation) && payload.generation >= 0
    && Array.isArray(payload.results) && payload.results.every((result) => record(result) && typeof result.jobId === 'string' && typeof result.runId === 'string' && (result.artifactId === null || typeof result.artifactId === 'string'));
  return validJob(payload.job);
}

export function initializeExecutionView({ document, window, getLocale, applyCatalog, onModeChange }) {
  const $ = (id) => document.getElementById(id);
  const t = (key, values) => translate(getLocale(), key, values);
  const desktop = desktopMethods.every((name) => typeof window.secHubDesktop?.[name] === 'function') ? window.secHubDesktop : null;
  let storage;
  try { storage = window.sessionStorage; } catch {}
  let bearer = desktop ? null : consumeExecutionSession({ location: window.location, history: window.history, storage });
  let enabled = false;
  let csrfToken;
  let targets = [];
  let selection = { targetId: '', toolIds: [] };
  let job = null;
  let generation = -1;
  let pending = false;
  let quotaReached = false;
  let timer;
  let polling = false;
  let revision = 0;
  let message = '';
  let lastRefresh = null;
  let openedJobId = null;
  let autoRefreshJobId = null;
  let toolSignature = '';
  const toolNodes = new Map();
  let folderLabel = null;
  let configLabel = null;
  let nodeConfigured = false;
  let readiness = [];
  let readinessSignature = '';
  const readinessNodes = new Map();
  const phaseKeys = { preparing: '검사 준비', checking: '도구 확인', scanning: '도구 검사', reporting: '보고서 저장', ready: '결과 준비됨' };
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const clearSession = () => {
    bearer = null;
    csrfToken = null;
    enabled = false;
    window.clearTimeout(timer);
    try { storage?.removeItem(sessionKey); } catch {}
    message = '실행 세션이 만료되었습니다. 운영자가 제공한 새 실행 URL을 이 탭에서 여세요.';
    onModeChange({ enabled: false, expired: true, lastRefresh });
  };
  function unavailableResponse() {
    enabled = false;
    window.clearTimeout(timer);
    onModeChange({ enabled: false, expired: !desktop, desktop: Boolean(desktop), lastRefresh });
    return new Error('connection_failed');
  }
  async function nativeRequest(method, args, validate) {
    let value;
    try { value = await desktop[method](...args); } catch { throw new Error('connection_failed'); }
    if (record(value?.error) && typeof value.error.code === 'string') {
      const { code } = value.error;
      if (code === 'job_limit' || code === 'job_limit_reached') quotaReached = true;
      throw new Error(Object.hasOwn(errors, code) || Object.hasOwn(desktopErrors, code) ? code : 'request_failed');
    }
    if (!validate(value)) throw new Error('connection_failed');
    return value;
  }
  async function request(path, body) {
    const headers = { Accept: 'application/json', Authorization: `Bearer ${bearer}` };
    const options = { headers, credentials: 'omit', cache: 'no-store' };
    if (body !== undefined) {
      options.method = 'POST';
      headers['Content-Type'] = 'application/json';
      headers['X-Sec-Hub-CSRF'] = csrfToken;
      options.body = JSON.stringify(body);
    }
    let response;
    try { response = await window.fetch(`/api/execution${path}`, options); } catch { throw unavailableResponse(); }
    if (response.status === 401) { clearSession(); throw new Error('session_expired'); }
    let payload;
    try { payload = await response.json(); } catch { throw unavailableResponse(); }
    if (!response.ok) {
      if (!record(payload?.error) || typeof payload.error.code !== 'string') throw unavailableResponse();
      const code = payload?.error?.code;
      if (response.status === 429) quotaReached = true;
      throw new Error(Object.hasOwn(errors, code) ? code : response.status === 409 ? 'job_busy' : 'request_failed');
    }
    if (!validResponse(path, payload)) throw unavailableResponse();
    return payload;
  }
  function errorMessage(error, fallback) {
    if (error.message === 'session_expired') return message;
    if (error.message === 'connection_failed') {
      if (!desktop) return '실행 서버 연결이 끊겼습니다. 운영자가 제공한 실행 URL을 이 탭에서 다시 여세요.';
      unavailableResponse();
      return '앱의 검사 상태를 확인할 수 없습니다. 도구 상태를 다시 확인하세요.';
    }
    return desktopErrors[error.message] ?? errors[error.message] ?? fallback;
  }
  const readyTool = (tool) => tool.selectable && tool.installation === 'installed';
  const usesAI = () => readiness.some((tool) => tool.ai && selection.toolIds.includes(tool.id));
  const usesPHP = () => selection.toolIds.includes('php2shell');
  const phpURL = () => usesPHP() ? $('desktop-php-url').value?.trim() ?? '' : '';
  function validPHPSelection() {
    if (!usesPHP()) return true;
    const value = phpURL();
    if (value.length > 2048 || !/^https?:\/\//i.test(value) || /[\x00-\x20\x7f\\?#]/.test(value)) return false;
    try {
      const url = new URL(value);
      return !url.username && !url.password;
    } catch { return false; }
  }
  function chooseTools(toolIds) {
    selection.toolIds = toolIds;
    $('desktop-ai-consent').checked = false;
    draw();
  }

  function drawReadiness() {
    const busy = pending || active(job);
    const folder = $('desktop-folder');
    const folderText = folderLabel ?? t('선택한 폴더 없음');
    if (folder.textContent !== folderText) folder.textContent = folderText;
    $('desktop-choose-folder').textContent = t(folderLabel ? '폴더 변경' : '폴더 선택');
    $('desktop-choose-folder').disabled = !enabled || busy;
    $('desktop-recheck').disabled = pending || (enabled && active(job));
    $('desktop-config').hidden = typeof desktop.chooseConfig !== 'function';
    $('desktop-choose-config').disabled = !enabled || busy;
    $('desktop-config-label').textContent = configLabel ?? t('선택한 도구 설정 없음');
    $('desktop-node').hidden = typeof desktop.chooseNode !== 'function';
    $('desktop-choose-node').disabled = !enabled || busy;
    $('desktop-node-label').textContent = t(nodeConfigured ? 'Node.js 실행 파일을 선택했습니다.' : '필요한 경우 Node.js 22 이상 실행 파일을 선택하세요.');
    const readyCount = readiness.filter(readyTool).length;
    $('desktop-select-all').disabled = !enabled || busy || !folderLabel || selection.toolIds.length === readyCount;
    $('desktop-selection-count').textContent = t('선택 {selected}개 / 준비 {ready}개', { selected: selection.toolIds.length, ready: readyCount });
    const signature = JSON.stringify(readiness);
    if (signature !== readinessSignature) {
      readinessSignature = signature;
      readinessNodes.clear();
      $('desktop-tools').replaceChildren();
      $('desktop-optional-tools').replaceChildren();
      $('desktop-optional').hidden = readiness.every((tool) => tool.id === 'osv');
      for (const tool of readiness) {
        const row = make('li', 'scan-tool');
        const heading = make(readyTool(tool) ? 'label' : 'div', 'scan-tool-name');
        let checkbox;
        if (readyTool(tool)) {
          checkbox = make('input');
          checkbox.type = 'checkbox';
          checkbox.addEventListener('change', () => {
            if (checkbox.disabled) return;
            chooseTools(readiness.filter((item) => readinessNodes.get(item.id)?.checkbox?.checked).map((item) => item.id));
          });
          heading.append(checkbox);
        }
        heading.append(make('strong', '', desktopToolName(tool.id)));
        const scope = tool.id === 'osv' ? '기본 검사' : !tool.selectable ? '이 앱에서 실행할 수 없음' : '';
        const scopeBadge = scope ? make('span', 'scan-tool-scope') : null;
        if (scopeBadge) heading.append(scopeBadge);
        const installation = make('span', 'scan-tool-state');
        installation.dataset.state = tool.installation;
        const authentication = make('span', 'scan-tool-auth');
        const actions = make('div', 'scan-setup-actions');
        const buttons = (tool.setupActions ?? []).map((action) => {
          const button = make('button', 'quiet-button');
          button.type = 'button';
          button.addEventListener('click', async () => {
            if (button.disabled) return;
            pending = true; message = ''; draw();
            try { await nativeRequest('openSetup', [tool.id, action], (value) => value?.ok === true); }
            catch (error) { message = errorMessage(error, '안내를 열지 못했습니다. 다시 시도하세요.'); }
            finally { pending = false; draw(); }
          });
          actions.append(button);
          return [action, button];
        });
        const guide = make('p', 'scan-tool-guide');
        const reason = make('p', 'scan-tool-guide');
        const guideKey = Object.hasOwn(desktopToolGuides, tool.id) && (tool.id !== 'osv' || !readyTool(tool)) ? desktopToolGuides[tool.id] : '';
        const reasonKey = !readyTool(tool) && Object.hasOwn(unavailableLabels, tool.unavailableReason) ? unavailableLabels[tool.unavailableReason] : '';
        guide.hidden = !guideKey;
        reason.hidden = !reasonKey;
        row.append(heading, installation, authentication, actions, guide, reason);
        $(tool.id === 'osv' ? 'desktop-tools' : 'desktop-optional-tools').append(row);
        readinessNodes.set(tool.id, { checkbox, scope, scopeBadge, installation, authentication, buttons, guide, guideKey, reason, reasonKey });
      }
    }
    for (const tool of readiness) {
      const { checkbox, scope, scopeBadge, installation, authentication, buttons, guide, guideKey, reason, reasonKey } = readinessNodes.get(tool.id);
      if (scopeBadge) scopeBadge.textContent = t(scope);
      guide.textContent = t(guideKey);
      reason.textContent = t(reasonKey);
      installation.textContent = t(installationLabels[tool.installation]);
      authentication.textContent = t(authenticationLabels[tool.authentication]);
      if (checkbox) {
        checkbox.checked = selection.toolIds.includes(tool.id);
        checkbox.disabled = !folderLabel || !enabled || busy;
      }
      for (const [action, button] of buttons) {
        button.textContent = t(setupLabels[action]);
        button.disabled = !enabled || busy;
      }
    }
    $('desktop-php-target').hidden = !usesPHP();
    $('desktop-php-url').disabled = !usesPHP() || !enabled || busy;
    $('desktop-ai-consent-box').hidden = !usesAI();
    $('desktop-ai-consent').disabled = !enabled || busy;
  }
  function drawTools() {
    const allowed = targets.find((target) => target.id === selection.targetId)?.toolIds.filter((id) => id !== 'anthropic') ?? [];
    const signature = JSON.stringify([selection.targetId, allowed]);
    if (signature !== toolSignature) {
      toolSignature = signature;
      toolNodes.clear();
      $('execution-tools').replaceChildren();
      for (const id of allowed) {
        const label = make('label', 'execution-tool');
        const input = document.createElement('input');
        input.type = 'checkbox'; input.value = id; input.checked = selection.toolIds.includes(id);
        input.addEventListener('change', () => {
          selection = { ...selection, toolIds: allowed.filter((tool) => toolNodes.get(tool).checked) };
          draw();
        });
        label.append(input, make('span', 'mono', id));
        $('execution-tools').append(label);
        toolNodes.set(id, input);
      }
    }
  }
  function draw() {
    if (!desktop && !bearer && !message) return;
    $('execution-panel').hidden = false;
    if (desktop) drawReadiness(); else drawTools();
    const controls = executionControls({ authenticated: Boolean(desktop || bearer), enabled, selection, job, pending, quotaReached });
    $('execution-target').disabled = controls.inputsDisabled;
    $('execution-toolset').disabled = controls.inputsDisabled;
    for (const [id, node] of toolNodes) { node.disabled = controls.inputsDisabled; node.checked = selection.toolIds.includes(id); }
    $('execution-start').disabled = controls.startDisabled || Boolean(desktop && (!validPHPSelection() || (usesAI() && !$('desktop-ai-consent').checked)));
    $('execution-cancel').disabled = controls.cancelDisabled;
    $('execution-refresh').disabled = controls.refreshDisabled;
    $('execution-refresh').hidden = !terminal(job) || !job?.reportsReady || Boolean(desktop && job.id === openedJobId);
    $('execution-cancel').hidden = !active(job);
    const status = $('execution-status');
    const guidance = !folderLabel ? '검사할 폴더를 먼저 선택하세요.' : selection.toolIds.length ? '준비되었습니다. 검사를 시작할 수 있습니다.' : '사용할 도구의 설치와 준비 상태를 확인하세요.';
    const statusText = message ? t(message) : desktop && !job ? t(guidance) : executionStatus(job, getLocale());
    if (status.textContent !== statusText) status.textContent = statusText;
    status.dataset.state = job?.state ?? 'idle';
    const progress = $('execution-progress');
    progress.hidden = !job;
    if (job) {
      const started = Date.parse(job.startedAt);
      const end = Date.parse(job.completedAt) || Date.now();
      const seconds = Number.isFinite(started) ? Math.max(0, Math.floor((end - started) / 1000)) : 0;
      $('execution-job-target').textContent = job.targetLabel;
      $('execution-phase').textContent = t(phaseKeys[job.phase] ?? '검사 실행 중');
      $('execution-count').textContent = t('도구 {done}/{total} · 경과 {seconds}초', { done: job.progress?.completedCount ?? 0, total: job.progress?.totalCount ?? job.toolIds.length, seconds });
      $('execution-coverage').textContent = job.runStatus ? t('검사 범위 상태: {status}', { status: t(runStatusLabel(job.runStatus)) }) : t('검사 완료와 안전 확인은 다릅니다.');
      const badges = $('execution-tool-status');
      badges.replaceChildren();
      for (const tool of job.progress?.tools ?? []) badges.append(make('li', 'tag', `${desktop ? desktopToolName(tool.id) : tool.id} · ${(['pending', 'checking', 'scanning'].includes(tool.status) ? t({ pending: '대기 중', checking: '확인 중', scanning: '검사 중' }[tool.status]) : toolStatusLabel(tool.status, getLocale()))}`));
    }
    $('execution-quota').hidden = !quotaReached;
    $('execution-quota').textContent = t(desktop ? '이 세션의 검사 한도에 도달했습니다. Security Scan Hub를 다시 여세요.' : '이 세션의 검사 한도에 도달했습니다. 운영자가 서버를 다시 시작해야 합니다.');
  }
  function schedulePoll() {
    window.clearTimeout(timer);
    if ((desktop || bearer) && enabled && !pending && active(job)) timer = window.setTimeout(poll, 1000);
  }
  async function poll() {
    if (polling || (!desktop && !bearer) || !active(job)) return;
    polling = true;
    const requestRevision = revision;
    const jobId = job.id;
    try {
      const value = desktop ? await nativeRequest('getJob', [], (value) => validJob(value?.job) && value.job.id === jobId) : await request(`/jobs/${encodeURIComponent(jobId)}`);
      if (revision !== requestRevision || job?.id !== jobId) return;
      job = value.job;
      message = '';
    } catch (error) {
      if (revision !== requestRevision) return;
      message = errorMessage(error, '실행 상태를 불러오지 못했습니다. 연결을 확인하세요.');
    } finally {
      polling = false;
      draw();
      schedulePoll();
    }
    await openDesktopResult();
  }
  $('execution-target').addEventListener('change', () => {
    selection = executionSelection(targets, { targetId: $('execution-target').value });
    draw();
  });
  $('execution-start').addEventListener('click', async () => {
    if ($('execution-start').disabled) return;
    const toolIds = [...selection.toolIds];
    const aiConsent = Boolean(desktop && usesAI() && $('desktop-ai-consent').checked);
    const phpUrl = desktop ? phpURL() : '';
    if (desktop) $('desktop-ai-consent').checked = false;
    revision++; window.clearTimeout(timer);
    pending = true; message = '검사를 시작하는 중…'; draw();
    try {
      const value = desktop ? await nativeRequest('startScan', [{ toolIds, aiConsent, ...(phpUrl ? { phpUrl } : {}) }], (value) => validJob(value?.job)) : await request('/jobs', { targetId: selection.targetId, toolIds });
      job = value.job; message = '';
    } catch (error) { message = errorMessage(error, '검사를 시작하지 못했습니다. 다시 시도하세요.'); }
    finally { pending = false; draw(); schedulePoll(); }
    await openDesktopResult();
  });
  $('execution-cancel').addEventListener('click', async () => {
    if ($('execution-cancel').disabled) return;
    revision++; window.clearTimeout(timer);
    pending = true; draw();
    try {
      const value = desktop ? await nativeRequest('cancelScan', [], (value) => validJob(value?.job) && value.job.id === job.id) : await request(`/jobs/${encodeURIComponent(job.id)}/cancel`, {});
      job = value.job; message = '';
    } catch (error) { message = errorMessage(error, '취소 요청에 실패했습니다. 실행 상태를 확인하세요.'); }
    finally { pending = false; draw(); schedulePoll(); }
    await openDesktopResult();
  });
  async function openDesktopResult() {
    if (!desktop || !terminal(job) || !job.reportsReady || job.id === autoRefreshJobId || $('execution-refresh').disabled) return;
    autoRefreshJobId = job.id;
    await refreshResults();
  }
  async function refreshResults() {
    if ($('execution-refresh').disabled) return;
    pending = true; message = '검사 결과를 목록에 반영하는 중…'; draw();
    try {
      const result = desktop ? await nativeRequest('refreshResults', [], (value) => validResponse('/catalog/refresh', value)) : await request('/catalog/refresh', {});
      const mapping = executionResultMapping(result, job.id, generation);
      if (!mapping.accepted) throw new Error('stale_generation');
      generation = result.generation;
      lastRefresh = result.catalog.snapshot.createdAt;
      await applyCatalog(result.catalog, mapping.artifactId, generation);
      if (desktop && mapping.artifactId) openedJobId = job.id;
      message = mapping.artifactId ? (desktop ? '' : '새 스냅샷에 결과를 반영했습니다.') : '검사 결과가 현재 스냅샷에 없습니다. 목록 수집 한도를 확인하세요.';
      onModeChange({ enabled, desktop: Boolean(desktop), lastRefresh, generation });
    } catch (error) { message = errorMessage(error, '결과 반영에 실패했습니다. 기존 스냅샷을 유지합니다. 다시 시도하세요.'); }
    finally { pending = false; draw(); }
  }
  $('execution-refresh').addEventListener('click', refreshResults);
  async function discover() {
    if (!bearer) return;
    pending = true; message = '로컬 실행 권한을 확인하는 중…'; draw();
    try {
      const value = await request('');
      if (value.enabled !== true) throw new Error('request_failed');
      enabled = true; csrfToken = value.csrfToken; targets = value.targets;
      generation = value.generation;
      selection = executionSelection(targets, selection);
      job = value.currentJob ?? value.jobs?.[0] ?? null;
      quotaReached = Boolean(value.limits?.maxJobs && value.jobs?.length >= value.limits.maxJobs);
      for (const target of targets) {
        const option = make('option', '', target.label); option.value = target.id; $('execution-target').append(option);
      }
      $('execution-target').value = selection.targetId;
      message = ''; onModeChange({ enabled, lastRefresh, generation });
    } catch (error) { message = errorMessage(error, '로컬 실행에 연결하지 못했습니다. 운영자가 제공한 실행 URL을 확인하세요.'); }
    finally { pending = false; draw(); schedulePoll(); }
  }
  async function loadDesktopState(method) {
    revision++; window.clearTimeout(timer);
    pending = true;
    message = method === 'chooseFolder' ? '폴더 선택을 기다리는 중…'
      : method === 'chooseConfig' ? '도구 설정 파일 선택을 기다리는 중…'
        : method === 'chooseNode' ? 'Node.js 실행 파일 선택을 기다리는 중…'
          : '도구 준비 상태를 확인하는 중…';
    draw();
    try {
      const value = await nativeRequest(method, [], validDesktopState);
      const newFolder = method === 'chooseFolder' || value.folderLabel !== folderLabel;
      const defaultOSV = newFolder || !readyTool(readiness.find((tool) => tool.id === 'osv') ?? {});
      if (newFolder) {
        selection.toolIds = [];
        $('desktop-php-url').value = '';
        $('desktop-ai-consent').checked = false;
      }
      folderLabel = value.folderLabel;
      configLabel = value.configLabel ?? null;
      nodeConfigured = value.nodeConfigured === true;
      readiness = value.tools;
      const toolIds = readiness.filter((tool) => readyTool(tool) && ((defaultOSV && tool.id === 'osv') || selection.toolIds.includes(tool.id))).map((tool) => tool.id);
      if (method !== 'getState' || toolIds.length !== selection.toolIds.length) $('desktop-ai-consent').checked = false;
      selection = { targetId: folderLabel ? 'native-selection' : '', toolIds };
      job = value.job;
      generation = value.generation;
      enabled = true;
      message = '';
      onModeChange({ enabled, desktop: true, lastRefresh, generation });
    } catch (error) {
      const fallback = method === 'chooseFolder' ? '폴더를 선택하지 못했습니다. 다시 시도하세요.'
        : method === 'chooseConfig' ? desktopErrors.config_unavailable
          : method === 'chooseNode' ? desktopErrors.node_unavailable
            : '도구 준비 상태를 확인하지 못했습니다. 다시 시도하세요.';
      message = errorMessage(error, fallback);
    } finally { pending = false; draw(); schedulePoll(); }
    await openDesktopResult();
  }
  if (desktop) {
    $('desktop-scan').hidden = false;
    $('desktop-execution').append($('execution-panel'));
    $('execution-panel').open = true;
    for (const id of ['execution-summary', 'execution-scope', 'execution-target-label', 'execution-toolset']) $(id).hidden = true;
    $('desktop-ai-consent').addEventListener('change', draw);
    $('desktop-php-url').addEventListener('input', draw);
    $('desktop-choose-config').addEventListener('click', () => {
      if (typeof desktop.chooseConfig === 'function' && !$('desktop-choose-config').disabled) return loadDesktopState('chooseConfig');
    });
    $('desktop-choose-node').addEventListener('click', () => {
      if (typeof desktop.chooseNode === 'function' && !$('desktop-choose-node').disabled) return loadDesktopState('chooseNode');
    });
    $('desktop-select-all').addEventListener('click', () => {
      if ($('desktop-select-all').disabled) return;
      $('desktop-optional').open = true;
      chooseTools(readiness.filter(readyTool).map((tool) => tool.id));
    });
    $('desktop-choose-folder').addEventListener('click', () => {
      if (!$('desktop-choose-folder').disabled) return loadDesktopState('chooseFolder');
    });
    $('desktop-recheck').addEventListener('click', () => {
      if (!$('desktop-recheck').disabled) return loadDesktopState('getState');
    });
    void loadDesktopState('getState');
  } else void discover();
  window.addEventListener('pagehide', () => window.clearTimeout(timer));
  return { render: draw };
}
