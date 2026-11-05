import test from 'node:test';
import assert from 'node:assert/strict';
import * as execution from '../src/web/execution-view.mjs';

const targets = [{ id: 'target-one', label: '<local>', toolIds: ['osv', 'semgrep'] }, { id: 'target-two', label: 'Two', toolIds: ['skillspector'] }];
const terminal = { id: 'job-one', state: 'completed', phase: 'ready', reportsReady: true, runStatus: 'partial', resultRunId: 'run-one' };

// Catches allowing browser-selected tools beyond the operator's target allowlist.
test('target selection preserves a selected subset and resets to allowed tools on target change', () => {
  assert.equal(typeof execution.executionSelection, 'function');
  assert.deepEqual(execution.executionSelection(targets, { targetId: 'target-one', toolIds: ['osv'] }), { targetId: 'target-one', toolIds: ['osv'] });
  assert.deepEqual(execution.executionSelection(targets, { targetId: 'target-one', toolIds: ['osv', 'anthropic', 'osv'] }), { targetId: 'target-one', toolIds: ['osv'] });
  assert.deepEqual(execution.executionSelection(targets, { targetId: 'target-two' }), { targetId: 'target-two', toolIds: ['skillspector'] });
  assert.deepEqual(execution.executionSelection(targets, { targetId: 'unknown' }), { targetId: 'target-one', toolIds: ['osv', 'semgrep'] });
});

// Catches a second admission during cancellation/reporting and premature refresh on partial writes.
test('controls require authentication, a nonempty selection and confirmed ready terminal reports', () => {
  assert.equal(typeof execution.executionControls, 'function');
  const base = { authenticated: true, enabled: true, selection: { targetId: 'target-one', toolIds: ['osv'] }, job: terminal };
  assert.deepEqual(execution.executionControls(base), { inputsDisabled: false, startDisabled: false, cancelDisabled: true, refreshDisabled: false });
  for (const state of ['running', 'cancelling']) {
    const got = execution.executionControls({ ...base, job: { ...terminal, state, phase: 'reporting' } });
    assert.equal(got.startDisabled, true);
    assert.equal(got.inputsDisabled, true);
    assert.equal(got.refreshDisabled, true);
    assert.equal(got.cancelDisabled, state === 'cancelling');
  }
  assert.equal(execution.executionControls({ ...base, job: { ...terminal, reportsReady: false } }).refreshDisabled, true);
  assert.equal(execution.executionControls({ ...base, authenticated: false }).startDisabled, true);
  assert.equal(execution.executionControls({ ...base, selection: { targetId: 'target-one', toolIds: [] } }).startDisabled, true);
  assert.equal(execution.executionControls({ ...base, job: { ...terminal, state: 'failed', errorCode: 'cleanup_unconfirmed' } }).startDisabled, true);
  assert.equal(execution.executionControls({ ...base, quotaReached: true }).startDisabled, true);
});

// Catches treating workflow completion as full coverage or treating uncertain cleanup as success.
test('job status distinguishes workflow completion, coverage, cancellation and cleanup failure in both locales', () => {
  assert.equal(typeof execution.executionStatus, 'function');
  assert.match(execution.executionStatus(terminal, 'en'), /workflow complete/i);
  assert.match(execution.executionStatus(terminal, 'en'), /partial/i);
  assert.match(execution.executionStatus({ ...terminal, state: 'cancelling' }, 'en'), /cancelling/i);
  assert.match(execution.executionStatus({ ...terminal, state: 'failed', errorCode: 'cleanup_unconfirmed', abortReason: 'user_cancel' }, 'en'), /cleanup.*unconfirmed/i);
  assert.match(execution.executionStatus({ ...terminal, state: 'failed', errorCode: 'report_failed' }, 'ko'), /보고서/);
});

// Catches opening a same-run-id artifact guessed from the old catalog rather than the exact fresh mapping.
test('result lookup uses only the requested job mapping and requires a newer catalog generation', () => {
  assert.equal(typeof execution.executionResultMapping, 'function');
  const response = { generation: 2, results: [{ jobId: 'other', runId: 'run-one', artifactId: 'wrong' }, { jobId: 'job-one', runId: 'run-one', artifactId: null }] };
  assert.deepEqual(execution.executionResultMapping(response, 'job-one', 1), { accepted: true, artifactId: null });
  assert.deepEqual(execution.executionResultMapping(response, 'job-one', 2), { accepted: false, artifactId: null });
  assert.deepEqual(execution.executionResultMapping({ ...response, results: [{ jobId: 'job-one', artifactId: 'actual' }] }, 'job-one', 1), { accepted: true, artifactId: 'actual' });
});

// Catches credentials remaining in browser history or leaking into broader persistent storage.
test('session consumes an exact launch fragment, strips it immediately and uses per-tab storage', () => {
  assert.equal(typeof execution.consumeExecutionSession, 'function');
  const secret = 'a'.repeat(64);
  const values = new Map();
  const storage = { getItem: k => values.get(k) ?? null, setItem: (k, v) => values.set(k, v), removeItem: k => values.delete(k) };
  const history = { state: null, replaceState: (...args) => { history.args = args; } };
  assert.equal(execution.consumeExecutionSession({ location: { hash: `#session=${secret}`, pathname: '/', search: '' }, history, storage }), secret);
  assert.deepEqual(history.args, [null, '', '/']);
  assert.equal(execution.consumeExecutionSession({ location: { hash: '', pathname: '/', search: '' }, history, storage }), secret);
  assert.equal(execution.consumeExecutionSession({ location: { hash: '#session=invalid', pathname: '/', search: '' }, history, storage }), null);
  assert.equal(values.size, 0);
});

// Minimal DOM boundary, with the real execution controller owning state and requests.
function harness(respond, { token = 'b'.repeat(64), locale = 'ko', desktop } = {}) {
  class Node {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.dataset = {}; this.listeners = {}; this.textContent = ''; this.disabled = true; this.hidden = true; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    addEventListener(name, fn) { this.listeners[name] = fn; }
    async emit(name) { await this.listeners[name]?.(); }
  }
  const nodes = new Map();
  const document = { getElementById: id => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); }, createElement: tag => new Node(tag) };
  const stored = new Map();
  const requests = [];
  const timers = new Map();
  let nextTimer = 0;
  const modes = [];
  const applied = [];
  const window = {
    secHubDesktop: desktop,
    location: { hash: token ? `#session=${token}` : '', pathname: '/', search: '' },
    history: { state: null, replaceState(_state, _title, url) { this.url = url; window.location.hash = ''; } },
    sessionStorage: { getItem: k => stored.get(k), setItem: (k, v) => stored.set(k, v), removeItem: k => stored.delete(k) },
    fetch: async (url, options) => { requests.push({ url, options }); return respond(url, options); },
    setTimeout(fn, delay) { const id = ++nextTimer; timers.set(id, { fn, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    addEventListener() {},
  };
  const view = execution.initializeExecutionView({ document, window, getLocale: () => locale, applyCatalog: async (...args) => applied.push(args), onModeChange: mode => modes.push(mode) });
  return { nodes, stored, requests, timers, modes, applied, window, view, setLocale: value => { locale = value; view.render(); }, settle: () => new Promise(resolve => setImmediate(resolve)) };
}
const reply = (payload, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => payload });
const description = (job = null) => ({ enabled: true, csrfToken: 'c'.repeat(64), targets, limits: { maxActiveJobs: 1, maxJobs: 20, maxJobTimeMs: 900000, maxHistory: 20 }, currentJob: job?.state === 'running' ? job : null, jobs: job ? [job] : [], generation: 0 });
const running = { ...terminal, state: 'running', phase: 'scanning', targetId: 'target-one', targetLabel: '<local>', toolIds: ['osv'], startedAt: '2026-10-28T00:00:00Z', completedAt: null, progress: { completedCount: 0, totalCount: 1, tools: [{ id: 'osv', status: 'scanning' }] }, runStatus: null, reportsReady: false };

const localTool = { id: 'osv', installation: 'installed', authentication: 'not_required', selectable: true, ai: false, setupActions: [] };
const aiTool = { id: 'codex-security', installation: 'installed', authentication: 'unknown', selectable: true, ai: true, setupActions: ['sign_in'] };
const desktopState = (overrides = {}) => ({ folderLabel: null, tools: [localTool, aiTool], job: null, generation: 0, ...overrides });
const nativeHarness = (overrides = {}) => {
  const calls = [];
  const done = { ...running, ...terminal, completedAt: '2026-10-28T00:00:10Z' };
  const methods = {
    getState: () => desktopState(),
    chooseFolder: () => desktopState({ folderLabel: '<img src=x>' }),
    startScan: () => ({ job: running }),
    getJob: () => ({ job: done }),
    cancelScan: () => ({ job: { ...running, state: 'cancelling' } }),
    refreshResults: () => ({ generation: 1, catalog: { artifacts: [], snapshot: { createdAt: 'now' } }, results: [{ jobId: done.id, runId: 'run-one', artifactId: 'saved' }] }),
    openSetup: () => ({ ok: true }),
    ...overrides,
  };
  const desktop = Object.fromEntries(Object.entries(methods).map(([name, handler]) => [name, (...args) => { calls.push([name, ...args]); return handler(...args); }]));
  const h = harness(() => { throw new Error('desktop scans must not use browser execution'); }, { locale: 'en', desktop });
  return { ...h, calls, node: id => h.nodes.get(id) };
};

test('desktop uses native folder selection and runs only the default OSV scan without AI consent', async () => {
  const h = nativeHarness();
  await h.settle();
  assert.equal(h.node('desktop-scan').hidden, false);
  assert.equal(h.node('execution-start').disabled, true);
  await h.node('desktop-choose-folder').emit('click');
  assert.equal(h.node('desktop-folder').textContent, '<img src=x>');
  assert.equal(h.node('execution-start').disabled, false);
  await h.node('execution-start').emit('click');
  assert.deepEqual(h.calls.slice(0, 3), [['getState'], ['chooseFolder'], ['startScan', { toolIds: ['osv'], aiConsent: false }]]);
  assert.equal(h.node('desktop-choose-folder').disabled, true);
  await h.node('execution-cancel').emit('click');
  assert.deepEqual(h.calls.at(-1), ['cancelScan']);
  assert.match(h.node('execution-status').textContent, /cancelling/i);
  await [...h.timers.values()][0].fn();
  assert.match(h.node('execution-status').textContent, /partial/i);
  await h.node('execution-refresh').emit('click');
  assert.deepEqual(h.applied[0].slice(1, 3), ['saved', 1]);
  assert.equal(h.requests.length, 0);
});

test('desktop presents install and authentication separately and sends AI tools only after opt-in', async () => {
  const h = nativeHarness();
  await h.settle();
  await h.node('desktop-choose-folder').emit('click');
  const ai = h.node('desktop-optional-tools').children[0];
  assert.match(ai.children[1].textContent, /installed/i);
  assert.match(ai.children[2].textContent, /sign-in.*unverified/i);
  await ai.children[3].children[0].emit('click');
  assert.deepEqual(h.calls.at(-1), ['openSetup', 'codex-security', 'sign_in']);
  const checkbox = ai.children[0].children[0];
  assert.equal(checkbox.checked, false);
  checkbox.checked = true;
  await checkbox.emit('change');
  assert.equal(h.node('desktop-ai-consent-box').hidden, false);
  assert.equal(h.node('execution-start').disabled, true);
  await h.node('execution-start').emit('click');
  assert.equal(h.calls.some(([method]) => method === 'startScan'), false);
  const consent = h.node('desktop-ai-consent');
  consent.checked = true;
  await consent.emit('change');
  await h.node('execution-start').emit('click');
  assert.deepEqual(h.calls.at(-1), ['startScan', { toolIds: ['osv', 'codex-security'], aiConsent: true }]);
  assert.equal(consent.checked, false);
});

test('missing OSV keeps start disabled and offers setup with a readiness recheck', async () => {
  const missing = { ...localTool, installation: 'missing', selectable: false, setupActions: ['install'] };
  const h = nativeHarness({ chooseFolder: () => desktopState({ folderLabel: 'app', tools: [missing] }), getState: () => desktopState({ folderLabel: 'app', tools: [localTool] }) });
  await h.settle();
  await h.node('desktop-choose-folder').emit('click');
  assert.equal(h.node('execution-start').disabled, true);
  const osv = h.node('desktop-tools').children[0];
  assert.match(osv.children[1].textContent, /installation.*not detected/i);
  await osv.children[3].children[0].emit('click');
  assert.deepEqual(h.calls.at(-1), ['openSetup', 'osv', 'install']);
  await h.node('desktop-recheck').emit('click');
  assert.equal(h.node('execution-start').disabled, false);
});

test('an ambiguous desktop start requires a fresh native state before another admission', async () => {
  const h = nativeHarness({
    startScan: () => { throw new Error('native path /private/example'); },
    getState: () => desktopState({ folderLabel: 'project', job: running }),
  });
  await h.settle();
  // The picker is intentionally unavailable while the host reports a job. Once
  // the existing job finishes, reproduce a start whose reply never arrives.
  await [...h.timers.values()][0].fn();
  await h.node('execution-start').emit('click');
  assert.match(h.node('execution-status').textContent, /recheck tools/i);
  assert.doesNotMatch(h.node('execution-status').textContent, /private/);
  await h.node('execution-start').emit('click');
  assert.equal(h.calls.filter(([method]) => method === 'startScan').length, 1);
  await h.node('desktop-recheck').emit('click');
  assert.equal(h.node('execution-start').disabled, true);
  assert.equal(h.node('execution-cancel').disabled, false);
});

test('read-only mode never discovers execution or enables controls without a session', async () => {
  const h = harness(() => { throw new Error('must not fetch'); }, { token: null });
  await h.settle();
  assert.equal(h.requests.length, 0);
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.nodes.get('execution-panel')?.hidden ?? true, true);
});

test('locale changes retain the same checkbox nodes, selection, job and polling owner', async () => {
  const h = harness(() => reply(description(running)));
  await h.settle();
  const tools = h.nodes.get('execution-tools').children;
  const timers = [...h.timers.values()];
  h.setLocale('en');
  assert.equal(h.nodes.get('execution-tools').children, tools);
  assert.equal(h.requests.length, 1);
  assert.equal(h.timers.size, 1);
  assert.equal([...h.timers.values()][0], timers[0]);
  assert.match(h.nodes.get('execution-status').textContent, /running/i);
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.nodes.get('execution-cancel').disabled, false);
});

test('start sends only opaque target and selected tools with bearer and CSRF headers', async () => {
  const h = harness((url) => reply(url === '/api/execution' ? description() : { job: running }));
  await h.settle();
  const semgrep = h.nodes.get('execution-tools').children[1].children[0];
  semgrep.checked = false;
  await semgrep.emit('change');
  h.setLocale('en');
  await h.nodes.get('execution-start').emit('click');
  const { url, options } = h.requests[1];
  assert.equal(url, '/api/execution/jobs');
  assert.equal(options.headers.Authorization, `Bearer ${'b'.repeat(64)}`);
  assert.equal(options.headers['X-Sec-Hub-CSRF'], 'c'.repeat(64));
  assert.equal(options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(options.body), { targetId: 'target-one', toolIds: ['osv'] });
  assert.equal(options.credentials, 'omit');
  assert.equal(h.window.history.url, '/');
  assert.equal(h.nodes.get('execution-start').disabled, true);
});

test('401 clears tab storage, disables starting and gives localized operator reconnection instructions', async () => {
  const h = harness(() => reply({ error: { code: 'unauthorized' } }, 401), { locale: 'en' });
  await h.settle();
  assert.equal(h.stored.size, 0);
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.match(h.nodes.get('execution-status').textContent, /operator.*this tab/i);
  assert.equal(h.modes.at(-1).expired, true);
  h.setLocale('ko');
  assert.match(h.nodes.get('execution-status').textContent, /운영자/);
  assert.equal(h.requests.length, 1);
});

test('a poll completing after accepted cancellation cannot restore running status', async () => {
  let finishPoll;
  const h = harness((url) => {
    if (url === '/api/execution') return reply(description(running));
    if (url.endsWith('/cancel')) return reply({ job: { ...running, state: 'cancelling' } }, 202);
    return new Promise(resolve => { finishPoll = resolve; });
  }, { locale: 'en' });
  await h.settle();
  const polling = [...h.timers.values()][0].fn();
  await h.settle();
  await h.nodes.get('execution-cancel').emit('click');
  assert.match(h.nodes.get('execution-status').textContent, /cancelling/i);
  finishPoll(reply({ job: running }));
  await polling;
  assert.match(h.nodes.get('execution-status').textContent, /cancelling/i);
  assert.equal(h.nodes.get('execution-start').disabled, true);
});

test('terminal history refresh applies the exact result mapping and reports catalog omission', async () => {
  const ready = { ...running, ...terminal, completedAt: '2026-10-28T00:00:05Z' };
  const catalog = { snapshot: { createdAt: '2026-10-28T00:01:00Z' }, artifacts: [] };
  const h = harness(url => reply(url === '/api/execution' ? description(ready) : { catalog, generation: 1, results: [{ jobId: 'job-one', runId: 'run-one', artifactId: null }] }), { locale: 'en' });
  await h.settle();
  assert.equal(h.nodes.get('execution-refresh').disabled, false);
  await h.nodes.get('execution-refresh').emit('click');
  assert.deepEqual(h.applied, [[catalog, null, 1]]);
  assert.match(h.nodes.get('execution-status').textContent, /absent.*snapshot/i);
  assert.equal(h.requests[1].options.body, '{}');
  assert.equal(h.timers.size, 0);
});

test('lost server connection disables further starts without exposing raw failures or retrying admission', async () => {
  const h = harness((url) => {
    if (url === '/api/execution') return reply(description());
    throw new Error('/private/path raw diagnostic');
  }, { locale: 'en' });
  await h.settle();
  await h.nodes.get('execution-start').emit('click');
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.modes.at(-1).enabled, false);
  assert.equal(h.nodes.get('execution-status').textContent.includes('/private/path'), false);
  assert.equal(h.requests.length, 2);
});

function brokenJsonResponse(status = 200) {
  const stream = new ReadableStream({ start(controller) { controller.error(new TypeError('terminated private diagnostic')); } });
  return new Response(stream, { status, headers: { 'Content-Type': 'application/json' } });
}

test('a disconnected start response body blocks repeat admission and requires operator reconnection', async () => {
  const h = harness(url => url === '/api/execution' ? reply(description()) : brokenJsonResponse(202), { locale: 'en' });
  await h.settle();
  await h.nodes.get('execution-start').emit('click');
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.modes.at(-1).enabled, false);
  assert.equal(h.timers.size, 0);
  assert.match(h.nodes.get('execution-status').textContent, /operator.*this tab/i);
  assert.doesNotMatch(h.nodes.get('execution-status').textContent, /try again|private diagnostic/i);
  await h.nodes.get('execution-start').emit('click');
  assert.equal(h.requests.filter(request => request.url === '/api/execution/jobs').length, 1);
  h.setLocale('ko');
  assert.match(h.nodes.get('execution-status').textContent, /운영자/);
});

test('a disconnected polling response retains the last known job while stopping polling and admission', async () => {
  const h = harness(url => url === '/api/execution' ? reply(description(running)) : brokenJsonResponse(), { locale: 'en' });
  await h.settle();
  await [...h.timers.values()][0].fn();
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.nodes.get('execution-cancel').disabled, true);
  assert.equal(h.nodes.get('execution-status').dataset.state, 'running');
  assert.equal(h.nodes.get('execution-progress').hidden, false);
  assert.equal(h.nodes.get('execution-job-target').textContent, '<local>');
  assert.equal(h.modes.at(-1).enabled, false);
  assert.equal(h.timers.size, 0);
  assert.match(h.nodes.get('execution-status').textContent, /operator.*this tab/i);
});

test('a malformed successful cancellation response cannot erase the known job or enable a new scan', async () => {
  const h = harness(url => url === '/api/execution' ? reply(description(running)) : Response.json({ job: null }, { status: 202 }), { locale: 'en' });
  await h.settle();
  await h.nodes.get('execution-cancel').emit('click');
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.nodes.get('execution-status').dataset.state, 'running');
  assert.equal(h.nodes.get('execution-progress').hidden, false);
  assert.equal(h.nodes.get('execution-job-target').textContent, '<local>');
  assert.equal(h.modes.at(-1).enabled, false);
  assert.equal(h.timers.size, 0);
  assert.match(h.nodes.get('execution-status').textContent, /operator.*this tab/i);
});

test('malformed JSON after accepted start blocks repeat admission', async () => {
  const h = harness(url => url === '/api/execution' ? reply(description()) : new Response('{"job":', { status: 202, headers: { 'Content-Type': 'application/json' } }), { locale: 'en' });
  await h.settle();
  await h.nodes.get('execution-start').emit('click');
  assert.equal(h.nodes.get('execution-start').disabled, true);
  assert.equal(h.modes.at(-1).enabled, false);
  assert.match(h.nodes.get('execution-status').textContent, /operator.*this tab/i);
});
