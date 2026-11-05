import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import fsPromises from 'node:fs/promises';
import path from 'node:path';
import { compareRuns, comparisonGate, normalizeSavedTargetPath } from '../compare.mjs';
import { normalizeFindings } from '../reports.mjs';

const HARD = Object.freeze({ directoryEntries: 512, artifacts: 128, artifactBytes: 20 * 1024 * 1024, totalBytes: 64 * 1024 * 1024, findingLeavesPerRun: 5000, findingLeavesTotal: 20000 });
const TOOL_STATUSES = new Set(['completed', 'failed', 'skipped', 'timed_out', 'cancelled', 'imported']);
const CATEGORIES = ['new', 'regressed', 'existing', 'resolved', 'unobserved'];
const ARTIFACT_NAMES = ['run.json', 'comparison.json'];
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const METHODS = new Set(['native', 'dependency', 'location', 'weak']);
const LIMIT_MESSAGE = '카탈로그 용량 제한으로 일부 항목을 읽지 않았습니다.';
const ERROR_MESSAGES = Object.freeze({
  unsafe_artifact: '안전하지 않은 아티팩트 항목입니다.',
  artifact_unreadable: '아티팩트를 읽을 수 없습니다.',
  invalid_artifact: '아티팩트 형식 또는 스키마가 올바르지 않습니다.',
  artifact_too_large: '아티팩트가 대시보드 용량 제한을 초과했습니다.',
  artifact_changed: '읽는 동안 아티팩트가 변경되었습니다.',
});
const errorCodes = new Set(Object.keys(ERROR_MESSAGES));
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value) => typeof value === 'string' && value.trim().length > 0;
const binary = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const within = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

function normalizeLimits(overrides = {}) {
  if (!isObject(overrides)) throw new TypeError('limits must be an object');
  const limits = { ...HARD };
  for (const [key, value] of Object.entries(overrides)) {
    if (!(key in HARD) || !within(value, 1, HARD[key])) throw new TypeError(`invalid catalog limit: ${key}`);
    limits[key] = value;
  }
  return limits;
}

function sameIdentity(a, b) { return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode; }
function sameFileSnapshot(a, b) { return sameIdentity(a, b) && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs; }
function statSnapshot(stat) {
  return { dev: stat.dev, ino: stat.ino, mode: stat.mode, size: stat.size, mtimeNs: stat.mtimeNs, ctimeNs: stat.ctimeNs };
}
function fsErrorCode(error) {
  if (error?.dashboardCode && errorCodes.has(error.dashboardCode)) return error.dashboardCode;
  if (['ELOOP', 'ENOTDIR'].includes(error?.code)) return 'unsafe_artifact';
  return 'artifact_unreadable';
}
function coded(code) { const error = new Error(code); error.dashboardCode = code; return error; }

async function assertDirectory(directory, expected) {
  let current;
  try { current = await fsPromises.lstat(directory, { bigint: true }); } catch { throw coded('artifact_changed'); }
  if (current.isSymbolicLink() || !current.isDirectory() || !sameIdentity(expected, statSnapshot(current))) throw coded('artifact_changed');
}

async function readArtifact(file, parent, root, expectedRoot, expectedParent, byteCeiling, totalRemaining, state) {
  let handle;
  try {
    await assertDirectory(root, expectedRoot);
    await assertDirectory(parent, expectedParent);
    const before = await fsPromises.lstat(file, { bigint: true });
    if (before.isSymbolicLink() || !before.isFile()) throw coded('unsafe_artifact');
    const beforeInfo = statSnapshot(before);
    handle = await fsPromises.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const opened = await handle.stat({ bigint: true });
    const openedInfo = statSnapshot(opened);
    if (!opened.isFile()) throw coded('unsafe_artifact');
    if (!sameFileSnapshot(beforeInfo, openedInfo)) throw coded('artifact_changed');
    if (openedInfo.size > BigInt(byteCeiling) || openedInfo.size > BigInt(totalRemaining)) throw coded('artifact_too_large');
    const maximum = Math.min(byteCeiling, totalRemaining);
    const chunks = [];
    let length = 0;
    while (length < maximum) {
      const size = Math.min(64 * 1024, maximum - length);
      if (!size) break;
      const chunk = Buffer.allocUnsafe(size);
      const { bytesRead } = await handle.read(chunk, 0, size, length);
      if (!bytesRead) break;
      chunks.push(chunk.subarray(0, bytesRead));
      length += bytesRead;
      state.bytes += bytesRead;
    }
    if (openedInfo.size > BigInt(length)) throw coded('artifact_changed');
    const afterInfo = statSnapshot(await handle.stat({ bigint: true }));
    const finalInfo = statSnapshot(await fsPromises.lstat(file, { bigint: true }));
    await assertDirectory(parent, expectedParent);
    await assertDirectory(root, expectedRoot);
    if (finalInfo.mode && typeof finalInfo.mode === 'bigint' && (finalInfo.mode & 0o170000n) === 0o120000n) throw coded('artifact_changed');
    if (!sameFileSnapshot(openedInfo, afterInfo) || !sameFileSnapshot(openedInfo, finalInfo)) throw coded('artifact_changed');
    return { bytes: Buffer.concat(chunks, length) };
  } catch (error) {
    if (error.dashboardCode) throw error;
    throw coded(fsErrorCode(error));
  } finally {
    await handle?.close().catch(() => {});
  }
}

function preflightTree(value, { maxDepth = 64, maxNodes = 100000 } = {}) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const { value: current, depth } = stack.pop();
    nodes += 1;
    if (nodes > maxNodes || depth > maxDepth) throw coded('artifact_too_large');
    if (Array.isArray(current)) {
      if (nodes + stack.length + current.length > maxNodes) throw coded('artifact_too_large');
      for (const item of current) stack.push({ value: item, depth: depth + 1 });
    } else if (isObject(current)) {
      const values = Object.values(current);
      if (nodes + stack.length + values.length > maxNodes) throw coded('artifact_too_large');
      for (const item of values) stack.push({ value: item, depth: depth + 1 });
    }
  }
}

function countFindingLeaves(findings) {
  if (!Array.isArray(findings)) throw coded('invalid_artifact');
  const stack = findings.slice();
  let count = 0;
  while (stack.length) {
    const finding = stack.pop();
    if (!isObject(finding)) throw coded('invalid_artifact');
    if (finding.sourceRecords !== undefined) {
      if (!Array.isArray(finding.sourceRecords)) throw coded('invalid_artifact');
      if (finding.sourceRecords.length) { stack.push(...finding.sourceRecords); continue; }
    }
    count += 1;
  }
  return count;
}

function validateRun(payload, limits, state) {
  if (!isObject(payload) || payload.schemaVersion !== 1) throw coded('invalid_artifact');
  const leaves = countFindingLeaves(payload.findings);
  if (leaves > limits.findingLeavesPerRun || state.findings + state.comparisonEntries + leaves > limits.findingLeavesTotal) throw coded('artifact_too_large');
  try { compareRuns(payload, payload, { failOn: 'none' }); } catch { throw coded('invalid_artifact'); }
  state.findings += leaves;
  return {
    runId: payload.id,
    status: payload.status,
    target: { path: payload.target.path, ...(payload.target.revision !== undefined ? { revision: payload.target.revision } : {}), ...(typeof payload.target.dirty === 'boolean' ? { dirty: payload.target.dirty } : {}) },
    startedAt: payload.startedAt,
    endedAt: payload.endedAt,
    findingCount: payload.findings.length,
    tools: payload.tools.map(({ id, status, selected }) => ({ id, status, ...(selected !== undefined ? { selected } : {}) })),
  };
}

function validComparison(payload, limits, state) {
  if (!isObject(payload) || payload.schemaVersion !== 1 || payload.kind !== 'sec-hub.comparison' || payload.identityVersion !== 1 || !['complete', 'incomplete'].includes(payload.status)) throw coded('invalid_artifact');
  for (const side of [payload.baseline, payload.current]) {
    if (!isObject(side) || !nonempty(side.id) || !isObject(side.target) || !['completed', 'partial', 'failed'].includes(side.status)) throw coded('invalid_artifact');
  }
  const baselineTarget = normalizeSavedTargetPath(payload.baseline.target.path);
  if (!baselineTarget || baselineTarget !== normalizeSavedTargetPath(payload.current.target.path)) throw coded('invalid_artifact');
  if (!Array.isArray(payload.coverage) || !Array.isArray(payload.entries) || !Array.isArray(payload.notices) || payload.notices.some((item) => typeof item !== 'string')) throw coded('invalid_artifact');
  const toolIds = new Set();
  for (const item of payload.coverage) {
    if (!isObject(item) || !nonempty(item.toolId) || toolIds.has(item.toolId) || !Array.isArray(item.reasons) || item.reasons.some((reason) => typeof reason !== 'string')) throw coded('invalid_artifact');
    toolIds.add(item.toolId);
    for (const side of [item.baseline, item.current]) if (side !== null && (!isObject(side) || !TOOL_STATUSES.has(side.status) || typeof side.selected !== 'boolean' && side.selected !== null)) throw coded('invalid_artifact');
  }
  const counts = Object.fromEntries(CATEGORIES.map((category) => [category, 0]));
  const ids = new Set();
  const gateEntries = [];
  for (const entry of payload.entries) {
    if (!isObject(entry) || !nonempty(entry.id) || ids.has(entry.id) || !nonempty(entry.identity) || !METHODS.has(entry.identityMethod) || !CATEGORIES.includes(entry.category) || !Array.isArray(entry.reasons) || entry.reasons.some((reason) => typeof reason !== 'string')) throw coded('invalid_artifact');
    ids.add(entry.id); counts[entry.category] += 1;
    const hasBefore = entry.before !== undefined, hasAfter = entry.after !== undefined;
    if ((entry.category === 'new' && (hasBefore || !hasAfter)) || (['resolved', 'unobserved'].includes(entry.category) && (!hasBefore || hasAfter)) || (['existing', 'regressed'].includes(entry.category) && (!hasBefore || !hasAfter))) throw coded('invalid_artifact');
    for (const field of ['before', 'after']) {
      const snapshot = entry[field];
      if (snapshot === undefined) continue;
      try {
        const normalized = normalizeFindings([snapshot]);
        if (normalized.length !== 1 || !SEVERITIES.has(normalized[0].severity)) throw new Error();
        if (field === 'after' && ['new', 'regressed'].includes(entry.category)) gateEntries.push({ id: entry.id, category: entry.category, after: { severity: normalized[0].severity } });
      } catch { throw coded('invalid_artifact'); }
    }
  }
  if (payload.entries.length + state.findings + state.comparisonEntries > limits.findingLeavesTotal) throw coded('artifact_too_large');
  if (!isObject(payload.counts) || Object.keys(payload.counts).length !== CATEGORIES.length || CATEGORIES.some((category) => !Number.isSafeInteger(payload.counts[category]) || payload.counts[category] !== counts[category])) throw coded('invalid_artifact');
  const gate = payload.gate;
  if (!isObject(gate) || !['critical', 'high', 'medium', 'low', 'info', 'any', 'none'].includes(gate.failOn) || ![0, 1, 2].includes(gate.exitCode) || !Array.isArray(gate.violations) || !Array.isArray(gate.unknown)) throw coded('invalid_artifact');
  for (const values of [gate.violations, gate.unknown]) if (values.some((id) => !ids.has(id)) || new Set(values).size !== values.length) throw coded('invalid_artifact');
  const expectedGate = comparisonGate(gateEntries, payload.status, gate.failOn);
  for (const field of ['violations', 'unknown']) {
    const supplied = new Set(gate[field]);
    if (supplied.size !== expectedGate[field].length || expectedGate[field].some((id) => !supplied.has(id))) throw coded('invalid_artifact');
  }
  if (gate.exitCode !== expectedGate.exitCode) throw coded('invalid_artifact');
  if ((payload.status === 'incomplete' && gate.exitCode !== 2) || (gate.exitCode === 0 && (payload.status !== 'complete' || gate.violations.length || gate.unknown.length)) || (gate.exitCode === 1 && (payload.status !== 'complete' || !gate.violations.length || gate.unknown.length)) || (gate.exitCode === 2 && !gate.unknown.length && payload.status === 'complete')) throw coded('invalid_artifact');
  state.comparisonEntries += payload.entries.length;
  return { baselineId: payload.baseline.id, currentId: payload.current.id, target: { path: payload.baseline.target.path }, status: payload.status, counts, gate: { failOn: gate.failOn, exitCode: gate.exitCode } };
}

function parsePayload(bytes) {
  let payload;
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw coded('invalid_artifact'); }
  preflightTree(payload);
  return payload;
}

function artifactId(location) { return createHash('sha256').update(`sec-hub-artifact-v1\0${location}`).digest('hex'); }
function labelFor(root, file) { return path.relative(root, file).split(path.sep).join('/'); }
function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

/** Load a bounded, immutable startup snapshot of saved runs and comparisons. */
export async function loadCatalog(inputRoot, { limits: overrides } = {}) {
  if (typeof inputRoot !== 'string' || !path.isAbsolute(inputRoot)) throw new TypeError('runs root must be an absolute path');
  const limits = normalizeLimits(overrides);
  const root = await fsPromises.realpath(inputRoot);
  const rootStat = await fsPromises.lstat(root, { bigint: true });
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) throw new TypeError('runs root must be a real directory');
  const rootIdentity = statSnapshot(rootStat);
  const artifacts = [];
  const records = new Map();
  const state = { bytes: 0, findings: 0, comparisonEntries: 0, truncated: false, notices: new Set() };
  const addNotice = () => { state.truncated = true; state.notices.add('catalog_limit'); };
  const candidates = [];
  const rootEntries = [];
  const directory = await fsPromises.opendir(root);
  try {
    while (true) {
      const entry = await directory.read();
      if (!entry) break;
      if (rootEntries.length >= limits.directoryEntries) { addNotice(); break; }
      rootEntries.push(entry);
    }
  } finally { await directory.close().catch(() => {}); }
  rootEntries.sort((a, b) => binary(a.name, b.name));
  for (const filename of ARTIFACT_NAMES) {
    const entry = rootEntries.find((item) => item.name === filename);
    if (entry) candidates.push({ parent: root, name: filename, kind: filename === 'run.json' ? 'run' : 'comparison', child: false });
  }
  for (const entry of rootEntries) {
    if (['run.json', 'comparison.json'].includes(entry.name)) continue;
    if (entry.name === 'raw') continue;
    if (entry.isSymbolicLink()) { candidates.push({ parent: root, name: entry.name, kind: 'unknown', child: true, symlink: true }); continue; }
    if (!entry.isDirectory()) continue;
    const child = path.join(root, entry.name);
    const stat = await fsPromises.lstat(child, { bigint: true }).catch(() => null);
    if (!stat) { candidates.push({ parent: root, name: entry.name, kind: 'unknown', child: true, discoveryError: 'artifact_unreadable' }); continue; }
    if (stat.isSymbolicLink() || !stat.isDirectory()) { candidates.push({ parent: root, name: entry.name, kind: 'unknown', child: true, symlink: true }); continue; }
    for (const filename of ARTIFACT_NAMES) {
      const artifactPath = path.join(child, filename);
      try {
        await fsPromises.lstat(artifactPath, { bigint: true });
        candidates.push({ parent: child, parentInfo: statSnapshot(stat), name: filename, kind: filename === 'run.json' ? 'run' : 'comparison', child: true });
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        candidates.push({ parent: child, parentInfo: statSnapshot(stat), name: filename, kind: filename === 'run.json' ? 'run' : 'comparison', child: true, discoveryError: fsErrorCode(error) });
      }
    }
  }
  if (candidates.length > limits.artifacts) { candidates.length = limits.artifacts; addNotice(); }
  for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
    const candidate = candidates[candidateIndex];
    if (state.bytes >= limits.totalBytes && candidateIndex < candidates.length) { addNotice(); break; }
    const file = path.join(candidate.parent, candidate.name);
    const label = candidate.child && candidate.kind !== 'unknown' ? labelFor(root, file) : candidate.kind === 'unknown' ? labelFor(root, path.join(root, candidate.name)) : candidate.name;
    const absoluteLocation = candidate.kind === 'unknown' ? path.join(root, candidate.name) : file;
    const id = artifactId(absoluteLocation);
    if (candidate.symlink) {
      artifacts.push({ id, kind: 'unknown', state: 'error', label, error: { code: 'unsafe_artifact', message: ERROR_MESSAGES.unsafe_artifact } });
      continue;
    }
    if (candidate.discoveryError) {
      artifacts.push({ id, kind: candidate.kind, state: 'error', label, error: { code: candidate.discoveryError, message: ERROR_MESSAGES[candidate.discoveryError] } });
      continue;
    }
    let code;
    try {
      const parentInfo = candidate.child ? candidate.parentInfo : rootIdentity;
      const { bytes: content } = await readArtifact(file, candidate.parent, root, rootIdentity, parentInfo, limits.artifactBytes, limits.totalBytes - state.bytes, state);
      const payload = parsePayload(content);
      const summary = candidate.kind === 'run' ? validateRun(payload, limits, state) : validComparison(payload, limits, state);
      const sha256 = createHash('sha256').update(content).digest('hex');
      const artifact = { id, kind: candidate.kind, state: 'ready', label, sha256, summary };
      artifacts.push(artifact);
      records.set(id, deepFreeze({ id, kind: candidate.kind, label, sha256, payload: structuredClone(payload) }));
    } catch (error) {
      code = error.dashboardCode ? fsErrorCode(error) : 'invalid_artifact';
      if (!errorCodes.has(code)) code = 'invalid_artifact';
      artifacts.push({ id, kind: candidate.kind, state: 'error', label, error: { code, message: ERROR_MESSAGES[code] } });
      if (code === 'artifact_too_large') addNotice();
      if (state.bytes >= limits.totalBytes) { addNotice(); break; }
    }
  }
  const snapshot = { createdAt: new Date().toISOString(), refresh: 'restart', truncated: state.truncated, limits, notices: [...state.notices].map((code) => ({ code, message: LIMIT_MESSAGE })) };
  return { catalog: { schemaVersion: 1, kind: 'sec-hub.catalog', snapshot, artifacts }, records };
}
