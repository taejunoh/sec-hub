import path from 'node:path';
import { atomicWriteFile, ensureSafeDirectory } from './safe-io.mjs';
import { redactValue } from './redaction.mjs';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const VERIFICATIONS = new Set(['candidate', 'reported', 'confirmed']);
const text = (value, field) => {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${field} must be a non-empty string`);
  return value;
};
const uniq = (values) => [...new Set(values.filter((value) => typeof value === 'string' && value.trim()))];
const clone = (value) => structuredClone(value);

function canonicalFinding(input, index) {
  const prefix = `finding ${index}`;
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError(`${prefix} must be an object`);
  const toolId = text(input.toolId, `${prefix}.toolId`);
  const ruleId = text(input.ruleId, `${prefix}.ruleId`);
  const title = text(input.title, `${prefix}.title`);
  for (const key of ['id', 'description', 'vulnerabilityId']) if (input[key] !== undefined && typeof input[key] !== 'string') throw new TypeError(`${prefix}.${key} must be a string`);
  const location = input.location ?? {};
  if (!location || typeof location !== 'object' || Array.isArray(location)) throw new TypeError(`${prefix}.location must be an object`);
  if (location.line !== undefined && (!Number.isInteger(location.line) || location.line < 1)) throw new TypeError(`${prefix}.location.line must be a positive integer`);
  for (const key of ['path', 'package', 'version', 'url']) if (location[key] !== undefined && typeof location[key] !== 'string') throw new TypeError(`${prefix}.location.${key} must be a string`);
  for (const key of ['aliases', 'references']) {
    if (input[key] !== undefined && (!Array.isArray(input[key]) || input[key].some((value) => typeof value !== 'string'))) throw new TypeError(`${prefix}.${key} must be an array of strings`);
  }
  if (input.verification !== undefined && !VERIFICATIONS.has(input.verification)) throw new TypeError(`${prefix}.verification is unsupported`);
  const originalSeverity = input.severity ?? 'unknown';
  const severityText = typeof originalSeverity === 'string' ? originalSeverity : '';
  const severity = SEVERITIES.has(severityText.toLowerCase()) ? severityText.toLowerCase() : 'unknown';
  const aliases = uniq([...(Array.isArray(input.aliases) ? input.aliases : []), input.vulnerabilityId]);
  const references = uniq(Array.isArray(input.references) ? input.references : []);
  const result = {
    ...(input.id ? { id: input.id } : {}), toolId, ruleId, title, severity,
    ...(input.description !== undefined ? { description: input.description } : {}),
    location: clone(location), ...(input.vulnerabilityId ? { vulnerabilityId: input.vulnerabilityId } : {}),
    aliases, references,
    ...(input.evidence !== undefined ? { evidence: clone(input.evidence) } : {}),
    ...(VERIFICATIONS.has(input.verification) ? { verification: input.verification } : {}),
    ...(input.rawRef !== undefined ? { rawRef: clone(input.rawRef) } : {}),
    ...(Array.isArray(input.sources) ? { sources: uniq(input.sources) } : {}),
    ...(Array.isArray(input.sourceRecords) ? { sourceRecords: clone(input.sourceRecords) } : {}),
  };
  if (severity === 'unknown' && originalSeverity !== 'unknown') result.evidence = { ...(result.evidence && typeof result.evidence === 'object' && !Array.isArray(result.evidence) ? result.evidence : { originalEvidence: result.evidence }), nativeSeverity: originalSeverity };
  return result;
}

function dependencyKey(finding) {
  const { package: packageName, version } = finding.location;
  const aliases = new Set(finding.aliases);
  if (!packageName || !version || aliases.size === 0) return null;
  return { packageName: packageName.toLowerCase(), version, aliases };
}

/** Validate, normalize and conservatively consolidate duplicate dependency advisories. */
export function normalizeFindings(findings) {
  if (!Array.isArray(findings)) throw new TypeError('findings must be an array');
  const normalized = findings.map(canonicalFinding);
  const groups = [];
  for (const finding of normalized) {
    const key = dependencyKey(finding);
    const match = key && groups.find((group) => {
      const other = dependencyKey(group);
      return other && key.packageName === other.packageName && key.version === other.version && [...key.aliases].some((alias) => other.aliases.has(alias));
    });
    if (!match) {
      groups.push({ ...finding, sources: uniq([finding.toolId, ...(finding.sources ?? [])]), sourceRecords: finding.sourceRecords?.length ? clone(finding.sourceRecords) : [clone(finding)] });
      continue;
    }
    match.sources = uniq([...match.sources, finding.toolId]);
    match.aliases = uniq([...match.aliases, ...finding.aliases]);
    match.references = uniq([...match.references, ...finding.references]);
    match.sourceRecords.push(...(finding.sourceRecords?.length ? clone(finding.sourceRecords) : [clone(finding)]));
    if (severityRank(finding.severity) > severityRank(match.severity)) match.severity = finding.severity;
  }
  return groups;
}

function severityRank(severity) { return ({ critical: 6, high: 5, medium: 4, low: 3, info: 2, unknown: 1 })[severity] ?? 0; }
const esc = (value) => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
function safeLink(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : null; } catch { return null; }
}
function stringify(value) {
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}
function locationLabel(location = {}) {
  return [location.path, location.line && `:${location.line}`, location.package && `package ${location.package}@${location.version ?? '?'}`, location.url].filter(Boolean).join(' · ') || 'Location not supplied';
}
function validateRun(run) {
  if (!run || typeof run !== 'object' || Array.isArray(run)) throw new TypeError('run must be an object');
  if (run.schemaVersion !== 1) throw new TypeError('run.schemaVersion must be 1');
  for (const field of ['id', 'startedAt', 'endedAt', 'status']) text(run[field], `run.${field}`);
  if (!run.target || typeof run.target.path !== 'string') throw new TypeError('run.target.path must be a string');
  if (!Array.isArray(run.tools) || !Array.isArray(run.findings)) throw new TypeError('run.tools and run.findings must be arrays');
}

function aggregateNotice(run) {
  if (run.provenance?.kind !== 'aggregate') return '';
  const sources = (run.provenance.sourceRuns ?? []).map(source => {
    const link = typeof source.link === 'string' && /^\.{1,2}\//.test(source.link) && !/[\\\x00-\x1f]/.test(source.link) ? `<a href="${esc(source.link)}">${esc(source.id)}</a>` : esc(source.id);
    return `<li>${link} · ${esc(source.status)}</li>`;
  }).join('');

  const description=run.provenance.description ?? (run.provenance.retry ? 'Results from the initial run plus an OCR retry on the same unchanged target.' : 'Results combined from verified source runs on the same unchanged target.');
  const summary=run.provenance.summary ? '<p>'+esc(stringify(run.provenance.summary))+'</p>' : '';
  const workflow=run.provenance.workflow ? '<p>Workflow: '+esc(stringify(run.provenance.workflow))+(run.provenance.integrationCount ? ' · '+esc(run.provenance.integrationCount)+' integrations' : '')+'</p>' : '';
  const retry=run.provenance.retry ? '<p>Original OCR status: '+esc(run.provenance.retry.previousStatus)+' · retry reason: '+esc(run.provenance.retry.reason)+'.</p>' : '';
  return '<section class="panel"><h2>Aggregate verification</h2><p>'+esc(description)+' Source runs retain their original execution states and native artifacts.</p>'+summary+workflow+'<ul>'+sources+'</ul>'+retry+'</section>';

}

function renderHtml(run, findings) {
  const tools = run.tools;
  const selected = tools.filter((tool) => tool.selected ?? tool.status !== 'skipped');
  const completed = tools.filter((tool) => tool.status === 'completed');
  const skipped = tools.filter((tool) => tool.status === 'skipped');
  const failed = tools.filter((tool) => ['failed', 'timed_out', 'cancelled'].includes(tool.status));
  const imported = tools.filter((tool) => tool.status === 'imported');
  const limitations = tools.filter((tool) => tool.status !== 'completed' && tool.status !== 'imported');
  const findingRows = findings.length ? findings.map((finding) => {
    const refs = finding.references.map((reference) => { const href = safeLink(reference); return href ? `<a rel="noreferrer" href="${esc(href)}">${esc(reference)}</a>` : `<span>${esc(reference)}</span>`; }).join(' · ');
    return `<article class="finding"><div class="finding-head"><span class="badge ${esc(finding.severity)}">${esc(finding.severity)}</span><h3>${esc(finding.title)}</h3></div><p class="muted">${esc(locationLabel(finding.location))}</p><p>${esc(finding.description ?? 'No description supplied.')}</p><p class="meta">Provenance: ${esc(finding.verification ?? 'reported')} · Sources: ${esc(finding.sources.join(', '))}</p>${finding.aliases.length ? `<p class="meta">Advisories: ${esc(finding.aliases.join(', '))}</p>` : ''}${refs ? `<p class="meta">References: ${refs}</p>` : ''}${finding.sourceRecords.map((record) => record.evidence === undefined ? '' : `<details><summary>Evidence from ${esc(record.toolId)}</summary><pre>${esc(stringify(record.evidence))}</pre></details>`).join('')}</article>`;
  }).join('') : '<p class="empty">0 findings. This means these completed checks reported no findings; it does not prove the target is free of vulnerabilities.</p>';
  const toolRows = tools.map((tool) => `<tr><td>${esc(tool.name ?? tool.id)}</td><td>${esc(tool.status)}</td><td>${esc(tool.source ?? '')}</td><td>${esc(Array.isArray(tool.findings) ? tool.findings.length : tool.findings ?? 0)}</td><td>${esc([tool.reason, tool.provenance?.sourceRunId && `Source run: ${tool.provenance.sourceRunId}`].filter(Boolean).join(' · '))}${tool.execution ? `<details><summary>Execution mode and coverage</summary><pre>${esc(stringify(tool.execution))}</pre></details>` : ''}</td></tr>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sec Hub report · ${esc(run.id)}</title>
<style>
:root{color-scheme:light dark;--bg:#f5f7fa;--panel:#fff;--text:#182230;--muted:#596579;--line:#d9e0e8;--accent:#265d97;--red:#a32222;--orange:#8b4a00} @media(prefers-color-scheme:dark){:root{--bg:#111820;--panel:#1b2631;--text:#e8edf3;--muted:#b1becc;--line:#394958;--accent:#83baff;--red:#ff8a8a;--orange:#ffc16b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:1050px;margin:0 auto;padding:32px 20px 64px}h1{font-size:2rem;margin:0 0 5px}h2{font-size:1.3rem;margin:30px 0 12px}.muted,.meta{color:var(--muted);font-size:.92rem}.panel,.finding{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin:12px 0}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:22px 0}.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.stat b{display:block;font-size:1.55rem}.finding-head{display:flex;align-items:center;gap:10px}.finding h3{margin:0;font-size:1.08rem}.badge{border-radius:999px;padding:3px 9px;background:#e9edf2;color:#263648;font-size:.82rem;font-weight:700;text-transform:uppercase}.badge.critical,.badge.high{background:#fce3e3;color:var(--red)}.badge.medium{background:#fff0d8;color:var(--orange)}a{color:var(--accent);overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--bg);padding:12px;border-radius:8px}table{width:100%;border-collapse:collapse;background:var(--panel);font-size:.92rem}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}.empty{padding:16px;border-left:4px solid var(--accent);background:var(--panel)}
</style></head><body><main><h1>Security scan report</h1><p class="muted">Run ${esc(run.id)} · target ${esc(run.target.path)} · ${esc(run.status)}</p><p class="muted">Started ${esc(run.startedAt)} · ended ${esc(run.endedAt)}${run.target.revision ? ` · revision ${esc(run.target.revision)}` : ''}${run.target.dirty === true ? ' · working tree dirty' : ''}</p>
${aggregateNotice(run)}<div class="stats"><div class="stat"><b>${findings.length}</b>findings</div><div class="stat"><b>${selected.length}</b>selected</div><div class="stat"><b>${completed.length}</b>completed</div><div class="stat"><b>${skipped.length}</b>skipped</div><div class="stat"><b>${failed.length}</b>failed</div><div class="stat"><b>${imported.length}</b>imported</div><div class="stat"><b>${findings.filter((f) => f.verification === 'candidate').length}</b>candidates</div><div class="stat"><b>${findings.filter((f) => f.verification === 'confirmed').length}</b>confirmed</div></div>
<h2>Coverage</h2><div class="panel"><table><thead><tr><th>Integration</th><th>Status</th><th>Source</th><th>Findings</th><th>Details</th></tr></thead><tbody>${toolRows}</tbody></table>${limitations.length ? `<p class="meta">Coverage limitations: ${limitations.map((tool) => `${esc(tool.name ?? tool.id)} (${esc(tool.status)}${tool.reason ? `: ${esc(tool.reason)}` : ''})`).join('; ')}.</p>` : '<p class="meta">Coverage limitations: this report covers only the checks and scan modes listed above. A clean result does not establish absence of vulnerabilities.</p>'}<p class="meta">Imported results are external reports and were not executed locally by Sec Hub. Candidate, reported, and confirmed provenance reflects each source record.</p></div>
<h2>Findings</h2>${findingRows}<footer class="muted">Generated by Sec Hub. A clean report does not establish absence of vulnerabilities.</footer></main></body></html>`;
}

function sarifUri(value) {
  return String(value).replaceAll('\\', '/').split('/').map((part) => encodeURIComponent(part).replaceAll('%3A', ':')).join('/');
}
function toSarif(run, findings) {
  const rules = new Map();
  for (const finding of findings) {
    const key = `${finding.toolId}:${finding.ruleId}`;
    if (!rules.has(key)) rules.set(key, { id: key, name: finding.ruleId, shortDescription: { text: finding.title }, properties: { severity: finding.severity, source: finding.toolId } });
  }
  const ruleList = [...rules.values()];
  const ruleIndex = new Map(ruleList.map((rule, index) => [rule.id, index]));
  const aggregate = run.provenance?.kind === 'aggregate';
  const importedOnly = run.tools.length > 0 && run.tools.every((tool) => tool.status === 'imported');
  const toolStates = run.tools.map(({ id, status, source, selected, reason, provenance, execution }) => ({ id, status, ...(source ? { source } : {}), ...(selected !== undefined ? { selected } : {}), ...(reason ? { reason } : {}), ...(provenance ? { provenance } : {}), ...(execution ? { execution: clone(execution) } : {}) }));
  const sarifRun = {
    tool: { driver: { name: 'Sec Hub', informationUri: 'https://github.com/openai/sec-hub', rules: ruleList } },
    properties: { runId: run.id, target: run.target.path, status: run.status, provenance: aggregate ? clone(run.provenance) : importedOnly ? 'imported' : 'local', toolStates },
    results: findings.map((finding) => {
      const result = { ruleId: `${finding.toolId}:${finding.ruleId}`, ruleIndex: ruleIndex.get(`${finding.toolId}:${finding.ruleId}`), level: ({ critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note', unknown: 'none' })[finding.severity], message: { text: finding.description ?? finding.title }, properties: { severity: finding.severity, verification: finding.verification ?? 'reported', sources: finding.sources, aliases: finding.aliases } };
      if (finding.location.path || safeLink(finding.location.url ?? '')) result.locations = [{ physicalLocation: { artifactLocation: { uri: sarifUri(finding.location.path ?? safeLink(finding.location.url)), ...(safeLink(finding.location.url ?? '') ? { properties: { url: safeLink(finding.location.url) } } : {}) }, ...(finding.location.line ? { region: { startLine: finding.location.line } } : {}) } }];
      if (finding.references.length) result.relatedLocations = finding.references.map((uri, index) => ({ id: index, message: { text: 'Reference' }, physicalLocation: { artifactLocation: { uri: safeLink(uri) ? uri : `external/${index}` } } }));
      if (finding.aliases.length) result.fingerprints = { 'sec-hub/advisoryAliases': finding.aliases.slice().sort().join('|') };
      return result;
    }),
  };
  if (!importedOnly && !aggregate) sarifRun.invocations = [{ executionSuccessful: run.status === 'completed', commandLine: 'sec-hub scan', startTimeUtc: run.startedAt, endTimeUtc: run.endedAt }];
  return {
    version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [sarifRun],
  };
}

/** Write normalized JSON, a standalone HTML report, and SARIF 2.1.0. */
export async function writeReports(run, directory) {
  validateRun(run);
  const findings = normalizeFindings(run.findings);
  const outputDirectory = path.resolve(directory);
  await ensureSafeDirectory(outputDirectory);
  const json = path.join(outputDirectory, 'run.json');
  const html = path.join(outputDirectory, 'report.html');
  const sarif = path.join(outputDirectory, 'results.sarif');
  const normalizedRun = redactValue({ ...run, findings });
  const reportFindings = normalizedRun.findings;
  await Promise.all([
    atomicWriteFile(json, `${JSON.stringify(normalizedRun, null, 2)}\n`),
    atomicWriteFile(html, renderHtml(normalizedRun, reportFindings)),
    atomicWriteFile(sarif, `${JSON.stringify(toSarif(normalizedRun, reportFindings), null, 2)}\n`),
  ]);
  return { json, html, sarif };
}
