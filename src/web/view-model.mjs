const text = (value) => String(value ?? '').toLocaleLowerCase();

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
  return (Array.isArray(findings) ? findings : []).filter((finding) => {
    const location = finding?.location;
    const locationText = typeof location === 'string' ? location : JSON.stringify(location ?? {});
    const haystack = [finding?.severity, finding?.ruleId, finding?.toolId, finding?.title,
      finding?.description, location?.path, locationText].map(text).join(' ');
    return (severity === 'all' || finding?.severity === severity)
      && (tool === 'all' || finding?.toolId === tool)
      && (!q || haystack.includes(q));
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

export function toolStatusLabel(status) {
  return ({ completed: '완료', failed: '실패', timed_out: '시간 초과', cancelled: '취소', skipped: '건너뜀', imported: '가져온 결과 · 로컬 실행 아님' })[status] ?? String(status ?? '상태 미기록');
}

export function verificationLabel(value) {
  if (value === 'candidate') return '후보';
  if (value === 'confirmed') return '저장된 주장 · 확인됨';
  if (value == null || value === '') return '보고됨 · 검증 수준 미기록';
  return String(value);
}

export function comparisonControlState(pending, hasInputs) {
  return { inputsDisabled: Boolean(pending), compareDisabled: Boolean(pending || !hasInputs) };
}
