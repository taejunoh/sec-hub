import { stat, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProcess } from '../processes.mjs';

const MAX_NATIVE_BYTES = 20 * 1024 * 1024;
const wrapper = fileURLToPath(new URL('./codex-wrapper.mjs', import.meta.url));
const sources = {
  osv: 'https://github.com/google/osv-scanner',
  skillspector: 'https://github.com/NVIDIA/skillspector',
  'codex-security': 'https://github.com/openai/codex-security',
  'open-code-review': 'https://github.com/alibaba/open-code-review',
  php2shell: 'https://github.com/openai/php2shell-checker',
};
const labels = { osv: 'OSV', skillspector: 'SkillSpector', 'codex-security': 'Codex Security', 'open-code-review': 'Open Code Review', php2shell: 'PHP2Shell' };
function invalid(id, message) { throw new Error(`${labels[id]}: ${message}`); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function string(value) { return typeof value === 'string' && value.trim().length > 0; }
function line(value) { return Number.isInteger(value) && value > 0; }
function severity(value) {
  const level = typeof value === 'string' ? value.toLowerCase() : '';
  return ['critical', 'high', 'medium', 'low', 'info'].includes(level) ? level : level === 'informational' ? 'info' : 'unknown';
}
function numericSeverity(value) {
  if (typeof value !== 'string' || !/^(?:10(?:\.0+)?|[0-9](?:\.\d+)?)$/.test(value)) return severity(value);
  const score = Number(value);
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info';
}
function strings(value, id, name) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some(x => !string(x))) invalid(id, `invalid ${name}`);
  return value;
}
function executable(ctx, id, command) {
  const override = ctx.config?.tools?.[id];
  if (override !== undefined && (!object(override) || !string(override.command) || (override.args !== undefined && (!Array.isArray(override.args) || override.args.some(x => typeof x !== 'string'))))) invalid(id, 'invalid executable configuration');
  return { command: override?.command ?? command, args: override?.args ?? [] };
}
function command(ctx, id, defaultCommand, args, findingCodes = []) {
  const configured = executable(ctx, id, defaultCommand);
  return { command: configured.command, args: [...configured.args, ...args], successCodes: [0], findingCodes };
}
function exit(ctx, id, allowed) { if (!allowed.includes(ctx.exitCode)) invalid(id, `unsupported native exit code ${ctx.exitCode}`); }
async function nativeJSON(ctx, id) {
  let text;
  if (id === 'php2shell') text = ctx.stdout;
  else {
    const path = join(ctx.artifactDir, id === 'codex-security' ? 'findings.json' : 'native.json');
    // A handle prevents a path swap between metadata validation and the bounded read.
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)).catch(() => invalid(id, 'native JSON output file is missing or unsafe'));
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_NATIVE_BYTES) invalid(id, 'native JSON output exceeds limit or is not a file');
      const buffer = Buffer.alloc(MAX_NATIVE_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const result = await handle.read(buffer, length, buffer.length - length, null);
        if (!result.bytesRead) break;
        length += result.bytesRead;
      }
      if (length > MAX_NATIVE_BYTES) invalid(id, 'native JSON output exceeds limit');
      text = buffer.subarray(0, length).toString('utf8');
    } finally { await handle.close(); }
  }
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_NATIVE_BYTES) invalid(id, 'invalid native JSON output');
  let value;
  try { value = JSON.parse(text); } catch { invalid(id, 'invalid native JSON output'); }
  if (!object(value)) invalid(id, 'unsupported native JSON document');
  return value;
}
function incomplete(id, findings) {
  const error = new Error(`${labels[id]}: native scan incomplete; inspect retained native coverage output`);
  error.findings = findings;
  throw error;
}
async function probe(ctx, id, defaultCommand) {
  if (['codex-security', 'open-code-review'].includes(id) && !ctx.config?.tools?.[id]) return { available: false, reason: 'Explicit tool configuration and --ai are required; provider authentication must be configured separately.' };
  if (id === 'php2shell') {
    if (!ctx.url) return { available: false, reason: 'An explicit HTTP(S) --url is required for this header/version heuristic.' };
    if (!ctx.config?.tools?.[id]) return { available: false, reason: 'Configure node plus the absolute official phpcheck.js path in tools.php2shell.' };
  }
  if (id === 'skillspector' && ctx.target) {
    try { if (!(await stat(join(ctx.target, 'SKILL.md'))).isFile()) throw new Error(); }
    catch { return { available: false, reason: 'Not applicable: target must contain a root SKILL.md; select an individual skill directory.' }; }
  }
  try {
    const selected = executable(ctx, id, defaultCommand);
    const result = await runProcess({ command: selected.command, args: [...selected.args, '--version'], successCodes: [0] }, { timeoutMs: ctx.probeTimeoutMs ?? 10000, maxOutputBytes: 64 * 1024, signal: ctx.signal });
    if (result.status !== 'completed') {
      const reason = result.status === 'timed_out' ? 'Executable version probe timed out.' : result.status === 'cancelled' ? 'Executable version probe cancelled.' : result.reason?.includes('ENOENT') ? 'Executable not found; install the official tool or configure its executable.' : 'Executable version probe failed.';
      return { available: false, reason };
    }
    const version = (result.stdout || result.stderr).trim();
    if (!version) return { available: false, reason: 'Version probe returned no version.' };
    return { available: true, version: version.slice(0, 500) };
  } catch (error) {
    return { available: false, reason: error.code === 'ENOENT' ? 'Executable not found; install the official tool or configure its executable.' : 'Executable version probe failed or timed out.' };
  }
}

async function parseOSV(ctx) {
  const id = 'osv'; exit(ctx, id, [0, 1]);
  const data = await nativeJSON(ctx, id);
  if (!Array.isArray(data.results)) invalid(id, 'unsupported results schema');
  const findings = [];
  for (const result of data.results) {
    if (!object(result) || !object(result.source) || !string(result.source.path) || !Array.isArray(result.packages)) invalid(id, 'invalid package source');
    for (const item of result.packages) {
      if (!object(item) || !object(item.package) || !string(item.package.name) || typeof item.package.version !== 'string' || !string(item.package.ecosystem)) invalid(id, 'invalid package record');
      if (item.vulnerabilities !== undefined && !Array.isArray(item.vulnerabilities)) invalid(id, 'invalid vulnerabilities');
      if (item.groups !== undefined && !Array.isArray(item.groups)) invalid(id, 'invalid vulnerability groups');
      for (const v of item.vulnerabilities ?? []) {
        if (!object(v) || !string(v.id)) invalid(id, 'invalid vulnerability record');
        const group = item.groups?.find(g => object(g) && Array.isArray(g.ids) && g.ids.includes(v.id));
        const nativeSeverity = group?.max_severity ?? v.database_specific?.severity ?? v.ecosystem_specific?.severity ?? null;
        const aliases = strings(v.aliases, id, 'aliases');
        if (v.references !== undefined && (!Array.isArray(v.references) || v.references.some(r => !object(r) || !string(r.url)))) invalid(id, 'invalid references');
        findings.push({ toolId: id, ruleId: v.id, title: string(v.summary) ? v.summary : v.id, severity: numericSeverity(nativeSeverity), description: typeof v.details === 'string' ? v.details : '', location: { path: result.source.path, package: `${item.package.ecosystem}:${item.package.name}`, version: item.package.version }, vulnerabilityId: v.id, aliases, references: (v.references ?? []).map(r => r.url), evidence: { nativeSeverity, severity: v.severity ?? [], package: item.package, affected: v.affected ?? [], group: group ?? null, source: result.source }, verification: 'reported', rawRef: join(ctx.artifactDir, 'native.json') });
      }
    }
  }
  if (data.experimental_generic_findings?.length) incomplete(id, findings);
  return findings;
}

async function parseSkillspector(ctx) {
  const id = 'skillspector'; exit(ctx, id, [0, 1]);
  const data = await nativeJSON(ctx, id);
  if (!object(data.skill) || !object(data.risk_assessment) || !Array.isArray(data.issues) || typeof data.execution_successful !== 'boolean' || !object(data.analysis_completeness)) invalid(id, 'unsupported issues schema');
  const findings = data.issues.map(f => {
    if (!object(f) || !string(f.id) || !string(f.finding_id) || !object(f.location) || !string(f.location.file) || !line(f.location.start_line) || !string(f.explanation)) invalid(id, 'invalid issue record');
    return { id: f.finding_id, toolId: id, ruleId: f.id, title: string(f.finding) ? f.finding : f.explanation, severity: severity(f.severity), description: f.explanation, location: { path: f.location.file, line: f.location.start_line }, references: f.source_url ? [f.source_url] : [], evidence: { nativeSeverity: f.severity ?? null, confidence: f.confidence, remediation: f.remediation, codeSnippet: f.code_snippet, tags: f.tags, nativeEvidence: f.evidence, occurrences: f.occurrences, analysisCompleteness: data.analysis_completeness }, verification: 'candidate', rawRef: join(ctx.artifactDir, 'native.json') };
  });
  if (!data.execution_successful || data.analysis_completeness.is_complete === false || (data.analysis_completeness.status && data.analysis_completeness.status !== 'complete')) incomplete(id, findings);
  return findings;
}

async function parseCodex(ctx) {
  const id = 'codex-security'; exit(ctx, id, [0, 1]);
  const data = await nativeJSON(ctx, id);
  if (data.documentType !== 'codex-security.findings' || data.schemaVersion !== '1.0' || !string(data.scanId) || !Array.isArray(data.findings)) invalid(id, 'unsupported findings schema');
  return data.findings.map(f => {
    if (!object(f) || !/^csf_[a-f0-9]{24}$/.test(f.findingId) || !/^occ_[a-f0-9]{24}$/.test(f.occurrenceId) || !string(f.ruleId) || !string(f.title) || !string(f.summary) || !object(f.identity) || !string(f.identity.anchor) || !object(f.fingerprints) || f.fingerprints.algorithm !== 'codex-security/v1' || !/^codex-security\/v1:sha256:[a-f0-9]{64}$/.test(f.fingerprints.primary) || !object(f.confidence) || !string(f.confidence.level) || !string(f.confidence.rationale) || !object(f.taxonomy) || !string(f.taxonomy.category) || !Array.isArray(f.taxonomy.cwe) || !string(f.remediation) || !object(f.provenance) || !string(f.provenance.source) || !object(f.severity) || !Array.isArray(f.locations) || !f.locations.length || f.locations.some(l => !object(l) || !string(l.path) || !line(l.startLine))) invalid(id, 'invalid finding record');
    return { id: f.occurrenceId, toolId: id, ruleId: f.ruleId, title: f.title, description: f.summary, severity: severity(f.severity.level), location: { path: f.locations[0].path, line: f.locations[0].startLine }, evidence: { nativeSeverity: f.severity, findingId: f.findingId, locations: f.locations, codeEvidence: f.codeEvidence ?? f.code_evidence ?? [], rootCause: f.rootCause ?? f.root_cause, attackPath: f.attackPath, validation: f.validation, taxonomy: f.taxonomy, remediation: f.remediation, confidence: f.confidence, provenance: f.provenance }, verification: 'reported', rawRef: join(ctx.artifactDir, 'findings.json') };
  });
}

async function parseOCR(ctx) {
  const id = 'open-code-review'; exit(ctx, id, [0]);
  const data = await nativeJSON(ctx, id);
  if (!string(data.status) || !Array.isArray(data.comments)) invalid(id, 'unsupported comments schema');
  const findings = data.comments.map(f => {
    if (!object(f) || !string(f.path) || !string(f.content) || !line(f.start_line)) invalid(id, 'invalid comment record');
    return { toolId: id, ruleId: string(f.category) ? f.category : 'code-review', title: f.content.split('\n')[0], description: f.content, severity: severity(f.severity), location: { path: f.path, line: f.start_line }, evidence: { nativeSeverity: f.severity ?? null, category: f.category, existingCode: f.existing_code, suggestionCode: f.suggestion_code, thinking: f.thinking, endLine: f.end_line, nativeStatus: data.status, manifest: data.manifest ?? null, warnings: data.warnings ?? [] }, verification: 'candidate', rawRef: join(ctx.artifactDir, 'native.json') };
  });
  if (!['success', 'complete', 'completed_with_warnings'].includes(data.status) || data.summary?.budget_exceeded === true || data.warnings?.some(w => ['subtask_error', 'scan_subtask_error', 'review_limit_reached'].includes(w.type)) || (data.manifest && data.manifest.terminal_state !== 'complete')) incomplete(id, findings);
  return findings;
}

async function parsePHP(ctx) {
  const id = 'php2shell'; exit(ctx, id, [0, 1, 3]);
  const data = await nativeJSON(ctx, id);
  const expected = { ok: 0, potentially_vulnerable: 1, unknown: 3 };
  if (!Object.hasOwn(expected, data.patch_status) || !string(data.reason) || !(data.php_version === null || string(data.php_version)) || !Number.isInteger(data.exit_code)) invalid(id, 'unsupported header-check schema');
  if (expected[data.patch_status] !== ctx.exitCode || data.exit_code !== ctx.exitCode) invalid(id, 'inconsistent native status/exit code');
  if (data.patch_status === 'ok') return [];
  return [{ toolId: id, ruleId: 'php2shell-header-version', title: data.patch_status === 'unknown' ? 'PHP patch status is unknown' : 'Advertised PHP version may be vulnerable to PHP2Shell', severity: data.patch_status === 'unknown' ? 'unknown' : 'high', description: data.reason, location: { url: ctx.url, ...(data.php_version ? { version: data.php_version } : {}) }, evidence: { nativeSeverity: null, patchStatus: data.patch_status, phpVersion: data.php_version, limitation: 'HTTP header/version heuristic only; installed build and backported fixes are not verified.' }, verification: 'candidate', rawRef: join(ctx.artifactDir, 'stdout.txt') }];
}

export const adapters = [
  { id: 'osv', name: 'Google OSV Scanner', kind: 'cli', source: sources.osv, requiresAI: false, network: 'OSV vulnerability database and package metadata services', install: 'go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0', check: ctx => probe(ctx, 'osv', 'osv-scanner'), build: ctx => command(ctx, 'osv', 'osv-scanner', ['scan', 'source', '-r', '--no-resolve', '--no-call-analysis=go', '--no-call-analysis=rust', '--format', 'json', '--output-file', join(ctx.artifactDir, 'native.json'), ctx.target], [1]), parse: parseOSV },
  { id: 'skillspector', name: 'NVIDIA SkillSpector (static)', kind: 'cli', source: sources.skillspector, requiresAI: false, network: 'Static mode; advisory enrichment may access external vulnerability services', install: 'uv tool install git+https://github.com/NVIDIA/skillspector.git@a5425e594d59a14c3d3eaa39e26847613ba08696', check: ctx => probe(ctx, 'skillspector', 'skillspector'), build: ctx => command(ctx, 'skillspector', 'skillspector', ['scan', ctx.target, '--no-llm', '--format', 'json', '--output', join(ctx.artifactDir, 'native.json')], [1]), parse: parseSkillspector },
  { id: 'codex-security', name: 'OpenAI Codex Security', kind: 'cli', source: sources['codex-security'], requiresAI: true, network: 'Code and context may be uploaded to the configured model provider', install: 'npm install -g @openai/codex-security@0.7.0', check: ctx => probe(ctx, 'codex-security', 'cs'), build: ctx => ({ command: process.execPath, args: [wrapper, JSON.stringify({ ...executable(ctx, 'codex-security', 'cs'), target: ctx.target, artifactDir: ctx.artifactDir })], successCodes: [0], findingCodes: [1] }), parse: parseCodex },
  { id: 'open-code-review', name: 'Alibaba Open Code Review', kind: 'cli', source: sources['open-code-review'], requiresAI: true, network: 'Code and context may be uploaded to the configured model provider; native OCR may write session metadata', install: 'npm install -g @alibaba-group/open-code-review@1.13.3', check: ctx => probe(ctx, 'open-code-review', 'ocr'), build: ctx => command(ctx, 'open-code-review', 'ocr', ['scan', '--repo', ctx.target, '--format', 'json', '--output', join(ctx.artifactDir, 'native.json')]), parse: parseOCR },
  { id: 'php2shell', name: 'OpenAI PHP2Shell Checker (header heuristic)', kind: 'cli', source: sources.php2shell, requiresAI: false, network: 'HEAD, with GET fallback on 405/501, to the explicitly provided URL only; no redirects followed', install: 'git clone https://github.com/openai/php2shell-checker.git; configure command node and args [absolute path to phpcheck.js]', check: ctx => probe(ctx, 'php2shell', 'phpcheck.js'), build: ctx => command(ctx, 'php2shell', 'phpcheck.js', [ctx.url, '--json'], [1, 3]), parse: parsePHP },
];
export function getAdapter(id) { return adapters.find(adapter => adapter.id === id); }
