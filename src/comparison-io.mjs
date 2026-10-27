import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, lstat, realpath, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { atomicWriteFile, ensureSafeDirectory } from './safe-io.mjs';
import { redactValue } from './redaction.mjs';

const MAX_RUN_BYTES = 20 * 1024 * 1024;
const READ_ERROR = 'Unable to read comparison run.';
const SIZE_ERROR = 'Comparison run exceeds the 20 MiB limit.';

function asPath(input) {
  if (typeof input !== 'string' || !input.trim()) throw new Error(READ_ERROR);
  return path.resolve(input);
}

async function canonicalDirectory(directory) {
  return realpath(directory);
}

async function readBounded(file) {
  let handle;
  try {
    const info = await lstat(file);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error(READ_ERROR);
    handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile()) throw new Error(READ_ERROR);
    const bytes = Buffer.allocUnsafe(MAX_RUN_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(bytes, length, bytes.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > MAX_RUN_BYTES) throw new Error(SIZE_ERROR);
    return bytes.subarray(0, length);
  } catch (error) {
    if (error.message === SIZE_ERROR) throw error;
    throw new Error(READ_ERROR);
  } finally {
    await handle?.close().catch(() => {});
  }
}

/** Read one saved run from a file or a run directory without following its final file entry. */
export async function readComparisonRun(input) {
  try {
    const requested = asPath(input);
    const info = await stat(requested);
    let file;
    if (info.isDirectory()) {
      const parent = await canonicalDirectory(requested);
      file = path.join(parent, 'run.json');
    } else {
      const parent = await canonicalDirectory(path.dirname(requested));
      file = path.join(parent, path.basename(requested));
    }
    const bytes = await readBounded(file);
    let run;
    try { run = JSON.parse(bytes.toString('utf8')); } catch { throw new Error(READ_ERROR); }
    return {
      run,
      file,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      ...(path.basename(file) === 'run.json' ? { artifactRoot: path.dirname(file) } : {}),
    };
  } catch (error) {
    if (error.message === SIZE_ERROR) throw error;
    throw new Error(READ_ERROR);
  }
}

function esc(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}

function display(value) {
  if (value === undefined || value === null || value === '') return '—';
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function detailBlock(label, value) {
  if (value === undefined) return '';
  return `<details><summary>${esc(label)}</summary><pre>${esc(display(value))}</pre></details>`;
}

function targetMetadata(side) {
  const target = side?.target ?? {};
  const revision = typeof target.revision === 'string' && target.revision.trim() ? target.revision : '미기록 / unknown';
  const dirty = target.dirty === true ? '변경됨' : target.dirty === false ? '깨끗함' : '알 수 없음';
  return `<div>revision · ${esc(revision)}</div><div>working tree · ${esc(dirty)}</div>${detailBlock('Source provenance', side?.provenance)}`;
}

function findingPanel(finding, label) {
  if (finding === undefined) return `<section class="side empty"><h4>${esc(label)}</h4><p>해당 검사에서 관측되지 않음</p></section>`;
  const location = finding.location ?? {};
  const coordinate = [location.path, location.line != null ? `:${location.line}` : '', location.package ? `package ${location.package}${location.version ? `@${location.version}` : ''}` : '', location.url].filter(Boolean).join(' · ') || '위치 정보 없음';
  return `<section class="side"><h4>${esc(label)}</h4><p class="meta">${esc(finding.severity ?? 'unknown')} · ${esc(finding.verification ?? 'reported')} · ${esc(coordinate)}</p>${finding.title ? `<p class="title">${esc(finding.title)}</p>` : ''}${finding.description ? `<p>${esc(finding.description)}</p>` : ''}${detailBlock('Evidence / details', finding.evidence ?? finding.details ?? finding)}</section>`;
}

function renderHtml(comparison) {
  const counts = comparison.counts ?? {};
  const categories = ['new', 'regressed', 'existing', 'resolved', 'unobserved'];
  const stats = categories.map((category) => `<div class="count"><strong>${esc(counts[category] ?? 0)}</strong><span>${esc(category)}</span></div>`).join('');
  const entries = (comparison.entries ?? []).map((entry) => {
    const title = entry.after?.title ?? entry.before?.title ?? entry.id ?? 'Finding';
    return `<article class="entry"><header><span class="badge ${esc(entry.category)}">${esc(entry.category)}</span><span class="identity">${esc(entry.identityMethod ?? 'unknown')} · ${esc(entry.id ?? 'entry')}</span></header><h3>${esc(title)}</h3><p class="meta">${esc(entry.after?.ruleId ?? entry.before?.ruleId ?? '')}</p><div class="sides">${findingPanel(entry.before, 'Baseline · 기준')}${findingPanel(entry.after, 'Current · 현재')}</div>${(entry.reasons ?? []).length ? `<ul class="reasons">${entry.reasons.map((reason) => `<li>${esc(reason)}</li>`).join('')}</ul>` : ''}</article>`;
  }).join('') || '<p class="empty">비교 항목이 없습니다.</p>';
  const coverage = (comparison.coverage ?? []).map((tool) => `<tr><th>${esc(tool.toolId)}</th><td>${coverageCell(tool.baseline)}</td><td>${coverageCell(tool.current)}</td><td>${(tool.reasons ?? []).map(esc).join('<br>')}</td></tr>`).join('');
  const gate = comparison.gate ?? {};
  const gateText = gate.exitCode === 0 ? '기준 통과' : gate.exitCode === 1 ? '차단 기준 위반' : '판정 불가';
  const comparisonStatus = comparison.status === 'complete' ? '완료' : comparison.status === 'incomplete' ? '불완전' : '상태 미확인';
  const notices = (comparison.notices ?? []).map((notice) => `<li>${esc(notice)}</li>`).join('');
  return `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sec Hub · 비교 리포트</title>
<style>
:root{color-scheme:light;--paper:#f6f3e9;--ink:#1c2328;--muted:#5a625e;--line:#b7b9a9;--olive:#c5da5b;--oxide:#9a4d22;--red:#b83430}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 "Avenir Next","Segoe UI",sans-serif}main{max-width:1120px;margin:auto;padding:32px 22px 60px}h1,h2,h3,h4{font-family:"Iowan Old Style",Georgia,serif;line-height:1.2}h1{font-size:clamp(2rem,4vw,3.1rem);margin:.25rem 0}.eyebrow,.meta,.identity{color:var(--muted);font-size:.88rem}.hero{border-block:2px solid var(--ink);padding:20px 0}.targets{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:18px}.target{border-left:5px solid var(--olive);padding:8px 14px;background:#eeeddf;overflow-wrap:anywhere}.target.current{border-color:var(--oxide)}.counts{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border-block:1px solid var(--ink);margin:22px 0}.count{padding:12px;border-right:1px solid var(--line)}.count:last-child{border:0}.count strong{display:block;font:2rem Georgia,serif}.count span{text-transform:uppercase;font:700 .75rem ui-monospace,monospace;letter-spacing:.06em}.gate{padding:14px 18px;border:1px solid var(--ink);border-left:8px solid var(--olive);margin:20px 0}.gate.fail{border-left-color:var(--red)}.gate.unknown{border-left-color:var(--oxide)}.criteria{display:flex;gap:8px;flex-wrap:wrap}.chip,.badge{display:inline-block;border:1px solid var(--line);padding:2px 8px;font:700 .75rem ui-monospace,monospace;text-transform:uppercase}.badge.new{background:#e6efbf}.badge.regressed{background:#f3d6cd;border-color:var(--oxide)}.badge.resolved{background:#dce8d0}.badge.unobserved{background:#efe3cf}.entry{border-block-start:2px solid var(--ink);padding:16px 0 20px}.entry>header{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.entry h3{font-size:1.35rem;margin:10px 0 2px;overflow-wrap:anywhere}.sides{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.side{border:1px solid var(--line);padding:12px;min-width:0;overflow-wrap:anywhere}.side:first-child{border-top:4px solid var(--olive)}.side:last-child{border-top:4px solid var(--oxide)}.side h4{margin:0 0 8px}.title{font-weight:650}.reasons{padding-left:1.3rem}.coverage{width:100%;border-collapse:collapse}.coverage th,.coverage td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.coverage th{font-family:ui-monospace,monospace}.coverage code{font:inherit}details{margin-top:10px;border-top:1px solid var(--line);padding-top:7px}summary{cursor:pointer;font-weight:650}summary:focus-visible{outline:3px solid var(--oxide);outline-offset:3px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font: .82rem/1.5 ui-monospace,monospace;background:#ebe9dd;padding:10px;max-height:28rem;overflow:auto}.empty{padding:12px;border-left:4px solid var(--oxide)}footer{border-top:1px solid var(--ink);margin-top:30px;padding-top:12px;color:var(--muted)}@media(max-width:600px){main{padding:20px 14px 40px}.targets,.sides{grid-template-columns:1fr}.counts{grid-template-columns:repeat(2,minmax(0,1fr))}.count:nth-child(2n){border-right:0}.count:last-child{grid-column:1/-1;border-top:1px solid var(--line)}}@media print{body{background:#fff}main{max-width:none;padding:0}.entry,details,.gate,.target{break-inside:avoid}summary{display:none}}
</style></head><body><main><header class="hero"><p class="eyebrow">SEC HUB / OFFLINE COMPARISON DOSSIER</p><h1>보안 검사 비교</h1><p>오프라인 비교 · ${esc(comparisonStatus)}</p><div class="targets"><section class="target"><b>Baseline · 기준</b><div>${esc(comparison.baseline?.id)} · ${esc(comparison.baseline?.status)}</div><div>${esc(comparison.baseline?.target?.path ?? comparison.baseline?.target)}</div>${targetMetadata(comparison.baseline)}</section><section class="target current"><b>Current · 현재</b><div>${esc(comparison.current?.id)} · ${esc(comparison.current?.status)}</div><div>${esc(comparison.current?.target?.path ?? comparison.current?.target)}</div>${targetMetadata(comparison.current)}</section></div></header>
<section aria-label="Category counts" class="counts">${stats}</section><section class="gate ${gate.exitCode === 1 ? 'fail' : gate.exitCode === 2 ? 'unknown' : ''}"><h2>Gate · ${esc(gateText)}</h2><div class="criteria"><span class="chip">fail on · ${esc(gate.failOn ?? 'none')}</span><span class="chip">exit code · ${esc(gate.exitCode ?? 'unknown')}</span><span class="chip">violations · ${(gate.violations ?? []).length}</span><span class="chip">unknown · ${(gate.unknown ?? []).length}</span></div><p>unknown은 비교 항목의 심각도가 unknown이어서 차단 기준 충족 여부를 판단할 수 없음을 뜻합니다. 검사 범위 누락 사유는 Coverage에 따로 표시됩니다.</p>${detailBlock('Gate entry IDs', { violations: gate.violations ?? [], unknown: gate.unknown ?? [] })}</section>
<h2>Coverage · 검사 범위</h2><table class="coverage"><thead><tr><th>도구</th><th>Baseline</th><th>Current</th><th>범위 사유</th></tr></thead><tbody>${coverage}</tbody></table><p class="meta">resolved는 이번 완료 검사에서 보고되지 않았다는 의미이며 수정 확인이 아닙니다. unobserved는 비교 범위를 확인하지 못한 상태입니다. 후보 항목은 확정 결과로 승격되지 않습니다.</p>
<h2>Entries · 비교 항목</h2>${entries}${notices ? `<h2>Notices · 안내</h2><ul>${notices}</ul>` : ''}<footer>Sec Hub 로컬 비교 기록 · 원본 검사를 대체하지 않습니다.</footer></main></body></html>`;
}

function coverageCell(side) {
  if (side == null) return '<span>범위 없음</span>';
  return `<span>${esc(side.status ?? 'unknown')}</span>${side.selected != null ? ` · selected ${esc(side.selected)}` : ''}${side.source ? `<br>${esc(side.source)}` : ''}${side.version ? `<br>${esc(side.version)}` : ''}${side.execution !== undefined ? `<details><summary>Execution details</summary><pre>${esc(display(side.execution))}</pre></details>` : ''}`;
}

function resolvedPath(file) {
  return path.resolve(file);
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function canonicalFutureDirectory(directory) {
  const absolute = resolvedPath(directory);
  const root = path.parse(absolute).root;
  let current = root;
  const tail = absolute.slice(root.length).split(path.sep).filter(Boolean);
  let missing = [];
  for (let i = 0; i < tail.length; i += 1) {
    const next = path.join(current, tail[i]);
    if (missing.length) { missing.push(tail[i]); continue; }
    try {
      const info = await lstat(next);
      let systemAlias = false;
      if (info.isSymbolicLink()) {
        systemAlias = process.platform === 'darwin' && ['/var', '/tmp'].includes(next) && (await realpath(next)) === `/private${next}`;
        if (!systemAlias) throw new Error('unsafe output path');
      }
      if (!systemAlias && !info.isDirectory()) throw new Error('unsafe output path');
      current = await realpath(next);
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error('unsafe output path');
      missing.push(tail[i]);
    }
  }
  return path.join(current, ...missing);
}

async function inputPaths(inputs) {
  const files = [];
  const roots = [];
  for (const input of inputs ?? []) {
    if (!input || typeof input.file !== 'string') continue;
    const absolute = resolvedPath(input.file);
    const parent = await realpath(path.dirname(absolute));
    const file = path.join(parent, path.basename(absolute));
    files.push(file);
    const suppliedRoot = typeof input.artifactRoot === 'string' ? input.artifactRoot : undefined;
    if (suppliedRoot) roots.push(await realpath(suppliedRoot));
    else if (path.basename(file) === 'run.json') roots.push(parent);
    try { files.push(await realpath(file)); } catch { /* retain the canonicalized parent and name */ }
  }
  return { files: [...new Set(files)], roots: [...new Set(roots)] };
}

async function preflightOutput(directory, inputs) {
  if (path.sep === '/' && typeof directory === 'string' && directory.includes('\\')) {
    throw new Error('Invalid comparison output path.');
  }
  const out = await canonicalFutureDirectory(directory);
  const { files, roots } = await inputPaths(inputs);
  for (const source of [...files, ...roots]) {
    if (isWithin(source, out) || isWithin(out, source)) throw new Error('Output overlaps a comparison input.');
  }
  try {
    const info = await lstat(out);
    if (!info.isDirectory() || (await readdir(out)).length > 0) throw new Error('Comparison output directory is occupied.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return out;
}

/** Write deterministic JSON and offline HTML for a comparison result. */
export async function writeComparisonReports(comparison, directory, { inputs = [] } = {}) {
  const outputDirectory = await preflightOutput(directory, inputs);
  await ensureSafeDirectory(outputDirectory);
  const safe = stable(redactValue(comparison));
  const json = path.join(outputDirectory, 'comparison.json');
  const html = path.join(outputDirectory, 'comparison.html');
  await Promise.all([
    atomicWriteFile(json, `${JSON.stringify(safe, null, 2)}\n`, { mode: 0o600 }),
    atomicWriteFile(html, renderHtml(safe), { mode: 0o600 }),
  ]);
  return { json, html };
}
