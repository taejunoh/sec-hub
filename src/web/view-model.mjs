import { translate } from './i18n.mjs';

const text = (value) => String(value ?? '').toLocaleLowerCase();
const nonempty = (value) => typeof value === 'string' && value.trim() ? value : undefined;
const asArray = (value) => Array.isArray(value) ? value : [];
const severityOrder = ['unknown', 'info', 'low', 'medium', 'high', 'critical'];

export function findingSeverity(finding) {
  return severityOrder.includes(finding?.severity) ? finding.severity : 'unknown';
}
const severityRank = (finding) => Math.max(0, severityOrder.indexOf(finding?.severity));
const osvAdvisoryPrefix = 'https://osv.dev/vulnerability/';
const osvId = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
const legacyOsvId = /^(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|(?:CVE|GO|PYSEC|RUSTSEC|OSV)-[0-9]{4}-[0-9]+)$/;

export function sortFindingsBySeverity(findings) {
  return [...asArray(findings)].sort((a, b) => severityRank(b) - severityRank(a));
}

function fixedPackageVersion(affected, name, ecosystem) {
  if (!name || !ecosystem) return undefined;
  const matching = asArray(affected).filter((entry) => entry?.package?.name === name && entry.package.ecosystem === ecosystem);
  if (matching.length !== 1) return undefined;
  // A single bounded version range gives an unambiguous fix boundary.
  const ranges = asArray(matching[0].ranges);
  if (ranges.length !== 1 || !['SEMVER', 'ECOSYSTEM'].includes(ranges[0]?.type)) return undefined;
  const events = asArray(ranges[0].events);
  if (events.length !== 2 || !nonempty(events[0]?.introduced)) return undefined;
  return nonempty(events[1]?.fixed);
}

function osvAdvisoryUrl(finding) {
  const id = finding.vulnerabilityId;
  if (osvId(id)) return osvAdvisoryPrefix + id;
  const ruleId = finding.ruleId;
  if (typeof ruleId === 'string' && legacyOsvId.test(ruleId)) return osvAdvisoryPrefix + ruleId;
  return asArray(finding.references).find((reference) =>
    typeof reference === 'string' && reference.startsWith(osvAdvisoryPrefix)
      && osvId(reference.slice(osvAdvisoryPrefix.length)));
}

export function findingPackage(finding) {
  if (finding?.toolId !== 'osv') return {};
  const packageRecord = finding.evidence?.package;
  const locationPackage = nonempty(finding.location?.package) ?? '';
  const separator = locationPackage.indexOf(':');
  const name = nonempty(packageRecord?.name) ?? nonempty(locationPackage.slice(separator + 1));
  const version = nonempty(packageRecord?.version) ?? nonempty(finding.location?.version);
  const ecosystem = nonempty(packageRecord?.ecosystem) ?? (separator > 0 ? locationPackage.slice(0, separator) : undefined);
  const fixedVersion = fixedPackageVersion(finding.evidence?.affected, name, ecosystem);
  const advisoryUrl = osvAdvisoryUrl(finding);
  return {
    ...(name ? { name } : {}),
    ...(version ? { version } : {}),
    ...(fixedVersion ? { fixedVersion } : {}),
    ...(advisoryUrl ? { advisoryUrl } : {}),
  };
}

export function compactPath(value) {
  const full = String(value ?? '');
  const characters = Array.from(full);
  if (characters.length <= 48) return { summary: full, full };
  let end = full.length;
  while (end > 0 && (full[end - 1] === '/' || full[end - 1] === '\\')) end -= 1;
  const lastSeparator = Math.max(full.lastIndexOf('/', end - 1), full.lastIndexOf('\\', end - 1));
  const previousSeparator = lastSeparator > 0
    ? Math.max(full.lastIndexOf('/', lastSeparator - 1), full.lastIndexOf('\\', lastSeparator - 1)) : -1;
  const context = full.slice(previousSeparator + 1);
  const tail = Array.from(context).slice(-44).join('');
  const separator = full.includes('\\') && !full.includes('/') ? '\\' : '/';
  return { summary: `…${separator}${tail}`, full };
}

export function filterArtifacts(artifacts, { query = '', kind = 'all', status = 'all', tool = 'all' } = {}) {
  const q = text(query).trim();
  return (Array.isArray(artifacts) ? artifacts : []).filter((artifact) => {
    const summary = artifact?.summary ?? {};
    const runStatus = summary.status ?? 'error';
    const haystack = [artifact?.label, summary.runId, summary.baselineId, summary.currentId, summary.target?.path]
      .map(text).join(' ');
    const tools = Array.isArray(summary.tools) ? summary.tools : [];
    return (kind === 'all' || artifact?.kind === kind)
      && (status === 'all' || runStatus === status || (status === 'error' && artifact?.state === 'error'))
      && (tool === 'all' || tools.some((item) => item?.id === tool))
      && (!q || haystack.includes(q));
  });
}

export function filterFindings(findings, { query = '', severity = 'all', tool = 'all' } = {}) {
  const q = text(query).trim();
  return asArray(findings).filter((finding) => {
    if ((severity !== 'all' && findingSeverity(finding) !== severity) || (tool !== 'all' && finding?.toolId !== tool)) return false;
    if (!q) return true;
    const location = finding?.location;
    const locationText = typeof location === 'string' ? location : JSON.stringify(location ?? {});
    const { name, version, fixedVersion } = findingPackage(finding);
    const haystack = [finding?.severity, finding?.ruleId, finding?.toolId, finding?.title,
      finding?.description, location?.path, locationText, name, version, fixedVersion].map(text).join(' ');
    return haystack.includes(q);
  });
}

export function pageItems(items, page = 1, pageSize = 100) {
  const list = Array.isArray(items) ? items : [];
  const size = Math.max(1, Math.min(100, Number.isInteger(pageSize) ? pageSize : 100));
  const pages = Math.max(1, Math.ceil(list.length / size));
  const current = Math.max(1, Math.min(pages, Number.isInteger(page) ? page : 1));
  return { items: list.slice((current - 1) * size, current * size), page: current, pages, total: list.length };
}

export function gateLabel(exitCode) {
  if (exitCode === 0) return '비교 완료 · 기준 통과';
  if (exitCode === 1) return '비교 완료 · 기준 위반';
  return '범위 불충분 · 판단 불가';
}

const CATEGORY_LABELS = Object.freeze({
  new: '새로 관측',
  regressed: '심각도 변화 · 검토 필요',
  existing: '기존',
  resolved: '완료 검사에서 더 이상 보고되지 않음',
  unobserved: '범위 부족 · 미관측',
});

export function categoryLabel(category) {
  return CATEGORY_LABELS[category] ?? '알 수 없는 범주';
}

export function runStatusLabel(status) {
  return ({ completed: '실행 완료', partial: '부분 완료', failed: '실패' })[status] ?? '상태 미기록';
}

export function toolStatusLabel(status, locale = 'ko') {
  const label = ({ completed: '완료', failed: '실패', timed_out: '시간 초과', cancelled: '취소', skipped: '건너뜀', imported: '가져온 결과 · 로컬 실행 아님' })[status];
  return label ? translate(locale, label) : status == null ? translate(locale, '상태 미기록') : String(status);
}

export function verificationLabel(value, locale = 'ko') {
  if (value === 'candidate') return translate(locale, '후보');
  if (value === 'confirmed') return translate(locale, '저장된 주장 · 확인됨');
  if (value == null || value === '') return translate(locale, '보고됨 · 검증 수준 미기록');
  return String(value);
}

export function comparisonControlState(pending, hasInputs) {
  return { inputsDisabled: Boolean(pending), compareDisabled: Boolean(pending || !hasInputs) };
}

export function transitionFindingView(findings, state, patch) {
  const next = { ...state, ...patch };
  const changedFilter = ['query', 'severity', 'tool'].some((key) => key in patch && patch[key] !== state[key]);
  const matches = filterFindings(findings, next);
  next.page = pageItems(matches, changedFilter ? 1 : next.page).page;
  if (!matches.includes(findings[next.selectedIndex])) next.selectedIndex = null;
  return next;
}
