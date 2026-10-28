import { translate } from './i18n.mjs';
import { runStatusLabel, toolStatusLabel } from './view-model.mjs';

const sessionKey = 'sec-hub.execution.session';
const active = (job) => job?.state === 'running' || job?.state === 'cancelling';
const terminal = (job) => ['completed', 'cancelled', 'failed'].includes(job?.state);

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
  let storage;
  try { storage = window.sessionStorage; } catch {}
  let bearer = consumeExecutionSession({ location: window.location, history: window.history, storage });
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
  let toolSignature = '';
  const toolNodes = new Map();
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
    onModeChange({ enabled: false, expired: true, lastRefresh });
    return new Error('connection_failed');
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
    if (error.message === 'connection_failed') return '실행 서버 연결이 끊겼습니다. 운영자가 제공한 실행 URL을 이 탭에서 다시 여세요.';
    return errors[error.message] ?? fallback;
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
    if (!bearer && !message) return;
    $('execution-panel').hidden = false;
    drawTools();
    const controls = executionControls({ authenticated: Boolean(bearer), enabled, selection, job, pending, quotaReached });
    $('execution-target').disabled = controls.inputsDisabled;
    $('execution-toolset').disabled = controls.inputsDisabled;
    for (const [id, node] of toolNodes) { node.disabled = controls.inputsDisabled; node.checked = selection.toolIds.includes(id); }
    $('execution-start').disabled = controls.startDisabled;
    $('execution-cancel').disabled = controls.cancelDisabled;
    $('execution-refresh').disabled = controls.refreshDisabled;
    $('execution-refresh').hidden = !terminal(job) || !job?.reportsReady;
    $('execution-cancel').hidden = !active(job);
    $('execution-status').textContent = message ? t(message) : executionStatus(job, getLocale());
    $('execution-status').dataset.state = job?.state ?? 'idle';
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
      for (const tool of job.progress?.tools ?? []) badges.append(make('li', 'tag', `${tool.id} · ${(['pending', 'checking', 'scanning'].includes(tool.status) ? t({ pending: '대기 중', checking: '확인 중', scanning: '검사 중' }[tool.status]) : toolStatusLabel(tool.status, getLocale()))}`));
    }
    $('execution-quota').hidden = !quotaReached;
    $('execution-quota').textContent = t('이 세션의 검사 한도에 도달했습니다. 운영자가 서버를 다시 시작해야 합니다.');
  }
  function schedulePoll() {
    window.clearTimeout(timer);
    if (bearer && enabled && !pending && active(job)) timer = window.setTimeout(poll, 1000);
  }
  async function poll() {
    if (polling || !bearer || !active(job)) return;
    polling = true;
    const requestRevision = revision;
    const jobId = job.id;
    try {
      const value = await request(`/jobs/${encodeURIComponent(jobId)}`);
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
  }
  $('execution-target').addEventListener('change', () => {
    selection = executionSelection(targets, { targetId: $('execution-target').value });
    draw();
  });
  $('execution-start').addEventListener('click', async () => {
    if ($('execution-start').disabled) return;
    revision++; window.clearTimeout(timer);
    pending = true; message = '검사를 시작하는 중…'; draw();
    try {
      const value = await request('/jobs', { targetId: selection.targetId, toolIds: [...selection.toolIds] });
      job = value.job; message = '';
    } catch (error) { message = errorMessage(error, '검사를 시작하지 못했습니다. 다시 시도하세요.'); }
    finally { pending = false; draw(); schedulePoll(); }
  });
  $('execution-cancel').addEventListener('click', async () => {
    if ($('execution-cancel').disabled) return;
    revision++; window.clearTimeout(timer);
    pending = true; draw();
    try {
      const value = await request(`/jobs/${encodeURIComponent(job.id)}/cancel`, {});
      job = value.job; message = '';
    } catch (error) { message = errorMessage(error, '취소 요청에 실패했습니다. 실행 상태를 확인하세요.'); }
    finally { pending = false; draw(); schedulePoll(); }
  });
  $('execution-refresh').addEventListener('click', async () => {
    if ($('execution-refresh').disabled) return;
    pending = true; message = '검사 결과를 목록에 반영하는 중…'; draw();
    try {
      const result = await request('/catalog/refresh', {});
      const mapping = executionResultMapping(result, job.id, generation);
      if (!mapping.accepted) throw new Error('stale_generation');
      generation = result.generation;
      lastRefresh = result.catalog.snapshot.createdAt;
      await applyCatalog(result.catalog, mapping.artifactId, generation);
      message = mapping.artifactId ? '새 스냅샷에 결과를 반영했습니다.' : '검사 결과가 현재 스냅샷에 없습니다. 목록 수집 한도를 확인하세요.';
      onModeChange({ enabled, lastRefresh, generation });
    } catch (error) { message = errorMessage(error, '결과 반영에 실패했습니다. 기존 스냅샷을 유지합니다. 다시 시도하세요.'); }
    finally { pending = false; draw(); }
  });
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
  void discover();
  window.addEventListener('pagehide', () => window.clearTimeout(timer));
  return { render: draw };
}
