import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { normalizeFindings } from './reports.mjs';
import { atomicWriteFile, ensureSafeDirectory } from './safe-io.mjs';

const BASE = 'https://github.com';
const definitions = [
  { id: 'cloudflare', name: 'Cloudflare Security Audit Skill', source: `${BASE}/cloudflare/security-audit-skill`, upstream: 'Native report schema is supported for the documented report-schema.json shape.' },
  { id: 'anthropic', name: 'Anthropic Defending Code Reference Harness', source: `${BASE}/anthropics/defending-code-reference-harness`, upstream: 'Use the Sec Hub bridge contract; this bridge does not claim to parse an upstream native report schema.' },
];
export const bridges = definitions.map((item) => ({ ...item, kind: 'bridge' }));
const getBridge = (id) => {
  const bridge = bridges.find((item) => item.id === id);
  if (!bridge) throw new TypeError(`Unknown bridge: ${id}`);
  return bridge;
};
const schemaFor = (id) => ({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: `Sec Hub ${id} bridge import`, type: 'object', additionalProperties: false,
  required: ['schemaVersion', 'provider', 'findings'],
  properties: {
    schemaVersion: { const: 1 }, provider: { const: id }, findings: { type: 'array', minItems: 1, items: {
      type: 'object', additionalProperties: false, required: ['toolId', 'ruleId', 'title', 'severity', 'location'],
      properties: {
        id: { type: 'string', minLength: 1 }, toolId: { type: 'string', minLength: 1 }, ruleId: { type: 'string', minLength: 1 }, title: { type: 'string', minLength: 1 },
        severity: { enum: ['critical', 'high', 'medium', 'low', 'info', 'unknown'] }, description: { type: 'string', minLength: 1 },
        location: { type: 'object', additionalProperties: false, properties: { path: { type: 'string', minLength: 1 }, line: { type: 'integer', minimum: 1 }, package: { type: 'string', minLength: 1 }, version: { type: 'string', minLength: 1 }, url: { type: 'string', minLength: 1 } } },
        vulnerabilityId: { type: 'string', minLength: 1 }, aliases: { type: 'array', items: { type: 'string', minLength: 1 } }, references: { type: 'array', items: { type: 'string', minLength: 1 } },
        evidence: {}, verification: { enum: ['candidate', 'reported', 'confirmed'] }, rawRef: {},
      },
    } },
  },
});
const exampleFor = (id) => ({ schemaVersion: 1, provider: id, findings: [{
  toolId: id, ruleId: 'AUTHZ-MISSING-CHECK', title: 'Authorization check may be missing', severity: 'medium',
  description: 'A request path may reach a sensitive operation without an authorization check.',
  location: { path: 'src/routes/account.js', line: 42 }, verification: 'candidate',
  evidence: { summary: 'Describe source-backed evidence and validation limits here.' },
}] });
function guideFor(bridge) {
  return `# Sec Hub handoff: ${bridge.name}\n\n` +
    `Upstream: ${bridge.source}\n\n` +
    `This is an execution handoff. Sec Hub does not install, start, or run this integration. Follow the upstream instructions in a separate environment and review its output before importing.\n\n` +
    `## Exported files\n\n- \`${bridge.id}-bridge.schema.json\`: the supported Sec Hub import contract.\n- \`${bridge.id}-bridge.example.json\`: a minimal candidate finding example.\n\n` +
    `## Import contract\n\n` +
    `Save a JSON object with \`schemaVersion: 1\`, \`provider: "${bridge.id}"\`, and a non-empty \`findings\` array. Each finding has \`toolId\`, \`ruleId\`, \`title\`, \`severity\`, and \`location\`; see the schema and example. Use \`verification: "candidate"\` until the source's decisive validation is complete. Sec Hub rewrites the imported tool identity to \`${bridge.id}\` and marks its tool record \`imported\`; it was not locally executed.\n\n` +
    `Convert with care: preserve source evidence in \`evidence\`, include advisory identifiers in \`vulnerabilityId\` or \`aliases\`, and keep reported and confirmed states faithful to the source. Unknown input shapes and empty reports are rejected.\n\n` +
    (bridge.id === 'cloudflare'
      ? `## Cloudflare native reports\n\nSec Hub also accepts the official \`skills/security-audit/report-schema.json\` native format: a non-empty top-level array with supported \`confirmed\`, \`needs_validation\`, or \`rejected\` records. Confirmed issues import as confirmed, needs-validation issues as candidates, and rejected records are retained in the imported tool's rejected count but excluded from vulnerability findings. Fields are validated before conversion.\n\n`
      : `## Upstream status\n\nThe Anthropic repository describes itself as not maintained. Its pinned revision d3bea6b5793b5f3d59a75ebe69a58efa88383145 includes an Apache-2.0 LICENSE. Sec Hub does not bundle its implementation. Its upstream native output shape is not claimed as a supported import format; convert reviewed results to the explicit Sec Hub contract above.\n\n`) +
    `## Import command\n\n\`node bin/sec-hub.mjs import ${bridge.id} findings.json --target /absolute/repository/path --out ./sec-hub-import\`\n`;
}

/** Export execution notes and the explicit JSON import contract. */
export async function exportBridge(id, directory) {
  const bridge = getBridge(id);
  const outputDirectory = path.resolve(directory);
  await ensureSafeDirectory(outputDirectory);
  const paths = {
    guide: path.join(outputDirectory, `${id}-guide.md`),
    schema: path.join(outputDirectory, `${id}-bridge.schema.json`),
    example: path.join(outputDirectory, `${id}-bridge.example.json`),
  };
  await Promise.all([
    atomicWriteFile(paths.guide, guideFor(bridge)),
    atomicWriteFile(paths.schema, `${JSON.stringify(schemaFor(id), null, 2)}\n`),
    atomicWriteFile(paths.example, `${JSON.stringify(exampleFor(id), null, 2)}\n`),
  ]);
  return paths;
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  return value;
}
function requireString(value, label, { nonEmpty = true } = {}) {
  if (typeof value !== 'string' || (nonEmpty && !value.trim())) throw new TypeError(`${label} must be ${nonEmpty ? 'a non-empty ' : 'a '}string`);
}
function shape(value, label, allowed, required = []) {
  requireObject(value, label);
  const unknown = Object.keys(value).find((key) => !allowed.includes(key));
  if (unknown) throw new TypeError(`${label}.${unknown} is not allowed`);
  for (const key of required) if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  return value;
}
function uniqueItems(items, label) {
  const keys = items.map((item) => JSON.stringify(item));
  if (new Set(keys).size !== keys.length) throw new TypeError(`${label} items must be unique`);
}
function validateTraceOrEvidence(items, label, isTrace) {
  if (!Array.isArray(items) || items.length === 0) throw new TypeError(`${label} must be a non-empty array`);
  uniqueItems(items, label);
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    const allowed = isTrace ? ['kind', 'file', 'line', 'scope', 'description'] : ['file', 'line', 'description'];
    shape(item, `${label}[${i}]`, allowed, allowed);
    if (isTrace && !['entrypoint', 'propagation', 'sink'].includes(item.kind)) throw new TypeError(`${label}[${i}].kind is unsupported`);
    for (const field of (isTrace ? ['file', 'scope', 'description'] : ['file', 'description'])) requireString(item[field], `${label}[${i}].${field}`);
    if (!Number.isInteger(item.line) || item.line < 1) throw new TypeError(`${label}[${i}].line must be a positive integer`);
  }
}
function validateNativeRecord(record, index) {
  const label = `Cloudflare finding ${index}`;
  requireObject(record, label);
  const common = ['verdict', 'fingerprint', 'title', 'description'];
  if (!['confirmed', 'needs_validation', 'rejected'].includes(record.verdict)) throw new TypeError(`${label}.verdict is unsupported`);
  const fields = record.verdict === 'confirmed'
    ? [...common, 'root_cause', 'intended_behavior', 'trace', 'evidence', 'conditions', 'execution', 'remediation', 'severity', 'confidence']
    : record.verdict === 'needs_validation'
      ? [...common, 'claimed_root_cause', 'trace', 'evidence', 'blockers', 'validation_plan']
      : [...common, 'claimed_root_cause', 'trace', 'evidence', 'reason'];
  shape(record, label, fields, fields);
  requireString(record.fingerprint, `${label}.fingerprint`);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(record.fingerprint)) throw new TypeError(`${label}.fingerprint has an invalid format`);
  for (const field of ['title', 'description', record.verdict === 'confirmed' ? 'root_cause' : 'claimed_root_cause', ...(record.verdict === 'confirmed' ? ['intended_behavior'] : []), ...(record.verdict === 'rejected' ? ['reason'] : [])]) requireString(record[field], `${label}.${field}`);
  validateTraceOrEvidence(record.trace, `${label}.trace`, true);
  validateTraceOrEvidence(record.evidence, `${label}.evidence`, false);

  if (record.verdict === 'confirmed') {
    if (!Array.isArray(record.conditions)) throw new TypeError(`${label}.conditions must be an array`);
    uniqueItems(record.conditions, `${label}.conditions`);
    for (let i = 0; i < record.conditions.length; i += 1) {
      const condition = record.conditions[i];
      shape(condition, `${label}.conditions[${i}]`, ['kind', 'description'], ['kind', 'description']);
      if (!['authentication_level', 'authorization_role', 'user_interaction', 'system_configuration', 'network_routing', 'environmental_dependency', 'data_state', 'timing_dependency', 'third_party_dependency'].includes(condition.kind)) throw new TypeError(`${label}.conditions[${i}].kind is unsupported`);
      requireString(condition.description, `${label}.conditions[${i}].description`);
    }
    const execution = shape(record.execution, `${label}.execution`, ['attacker_perspective', 'payloads', 'instructions', 'observed_result'], ['attacker_perspective', 'payloads', 'instructions', 'observed_result']);
    requireString(execution.attacker_perspective, `${label}.execution.attacker_perspective`);
    requireString(execution.observed_result, `${label}.execution.observed_result`);
    for (const field of ['payloads', 'instructions']) {
      const values = execution[field];
      if (!Array.isArray(values) || values.length === 0 || values.some((item) => typeof item !== 'string' || (field === 'instructions' && !item.trim()))) throw new TypeError(`${label}.execution.${field} must be a non-empty string array`);
      if (field === 'payloads') uniqueItems(values, `${label}.execution.${field}`);
    }
    const remediation = shape(record.remediation, `${label}.remediation`, ['strategy', 'code_changes'], ['strategy']);
    requireString(remediation.strategy, `${label}.remediation.strategy`);
    if (remediation.code_changes !== undefined) {
      if (!Array.isArray(remediation.code_changes)) throw new TypeError(`${label}.remediation.code_changes must be an array`);
      remediation.code_changes.forEach((change, i) => {
        shape(change, `${label}.remediation.code_changes[${i}]`, ['file_name', 'fixed_code'], ['file_name', 'fixed_code']);
        requireString(change.file_name, `${label}.remediation.code_changes[${i}].file_name`);
        requireString(change.fixed_code, `${label}.remediation.code_changes[${i}].fixed_code`, { nonEmpty: false });
      });
    }
    const severity = shape(record.severity, `${label}.severity`, ['likelihood', 'impact', 'overall_severity'], ['likelihood', 'impact', 'overall_severity']);
    const scores = ['informational', 'low', 'medium', 'high', 'critical'];
    if (!scores.includes(severity.overall_severity)) throw new TypeError(`${label}.severity.overall_severity is unsupported`);
    for (const part of ['likelihood', 'impact']) {
      const value = shape(severity[part], `${label}.severity.${part}`, ['score', 'reason'], ['score', 'reason']);
      if (!scores.includes(value.score)) throw new TypeError(`${label}.severity.${part}.score is unsupported`);
      requireString(value.reason, `${label}.severity.${part}.reason`);
    }
    const confidence = shape(record.confidence, `${label}.confidence`, ['score', 'reason'], ['score', 'reason']);
    if (!['low', 'medium', 'high'].includes(confidence.score)) throw new TypeError(`${label}.confidence.score is unsupported`);
    requireString(confidence.reason, `${label}.confidence.reason`);
  }
  if (record.verdict === 'needs_validation') {
    if (!Array.isArray(record.blockers) || record.blockers.length === 0) throw new TypeError(`${label}.blockers must be a non-empty array`);
    uniqueItems(record.blockers, `${label}.blockers`);
    record.blockers.forEach((item, i) => requireString(item, `${label}.blockers[${i}]`));
    const plan = shape(record.validation_plan, `${label}.validation_plan`, ['local', 'deployment']);
    for (const field of ['local', 'deployment']) if (plan[field] !== undefined) requireString(plan[field], `${label}.validation_plan.${field}`);
  }
}
function validateContract(parsed, provider) {
  shape(parsed, 'bridge document', ['schemaVersion', 'provider', 'findings'], ['schemaVersion', 'provider', 'findings']);
  if (parsed.schemaVersion !== 1 || parsed.provider !== provider) throw new TypeError(`Unsupported bridge schema: expected schemaVersion 1 and provider ${provider}`);
  if (!Array.isArray(parsed.findings) || parsed.findings.length === 0) throw new TypeError('Unsupported bridge schema: findings must be a non-empty array');
  const fields = ['id', 'toolId', 'ruleId', 'title', 'severity', 'description', 'location', 'vulnerabilityId', 'aliases', 'references', 'evidence', 'verification', 'rawRef'];
  const required = ['toolId', 'ruleId', 'title', 'severity', 'location'];
  const validSeverity = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  const validVerification = ['candidate', 'reported', 'confirmed'];
  return parsed.findings.map((record, index) => {
    const label = `finding ${index}`;
    shape(record, label, fields, required);
    for (const field of ['id', 'description', 'vulnerabilityId']) if (record[field] !== undefined) requireString(record[field], `${label}.${field}`);
    for (const field of ['toolId', 'ruleId', 'title']) requireString(record[field], `${label}.${field}`);
    if (!validSeverity.includes(record.severity)) throw new TypeError(`${label}.severity is unsupported`);
    if (record.verification !== undefined && !validVerification.includes(record.verification)) throw new TypeError(`${label}.verification is unsupported`);
    const locationFields = ['path', 'line', 'package', 'version', 'url'];
    shape(record.location, `${label}.location`, locationFields);
    for (const field of ['path', 'package', 'version', 'url']) if (record.location[field] !== undefined) requireString(record.location[field], `${label}.location.${field}`);
    if (record.location.line !== undefined && (!Number.isInteger(record.location.line) || record.location.line < 1)) throw new TypeError(`${label}.location.line must be a positive integer`);
    for (const field of ['aliases', 'references']) if (record[field] !== undefined) {
      if (!Array.isArray(record[field])) throw new TypeError(`${label}.${field} must be an array`);
      record[field].forEach((item, i) => requireString(item, `${label}.${field}[${i}]`));
    }
    return { ...record, toolId: provider, verification: record.verification ?? 'reported', evidence: record.evidence === undefined ? undefined : { importedEvidence: record.evidence, originalToolId: record.toolId } };
  });
}

function nativeFinding(record, index) {
  const firstLocation = record.trace[0];
  const severity = record.severity?.overall_severity?.toLowerCase();
  const mappedSeverity = ({ critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low', info: 'info', informational: 'info' })[severity] ?? 'unknown';
  return {
    toolId: 'cloudflare', ruleId: record.fingerprint, title: record.title, severity: mappedSeverity,
    description: record.description, location: { path: firstLocation.file, line: firstLocation.line },
    verification: record.verdict === 'confirmed' ? 'confirmed' : 'candidate',
    evidence: { native: record }, rawRef: { format: 'cloudflare-native', index, fingerprint: record.fingerprint },
  };
}
function contractFinding(record, index, provider) {
  requireObject(record, `finding ${index}`);
  for (const key of ['toolId', 'ruleId', 'title', 'severity']) requireString(record[key], `finding ${index}.${key}`);
  const validSeverity = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  if (!validSeverity.includes(record.severity)) throw new TypeError(`finding ${index}.severity is unsupported`);
  requireObject(record.location, `finding ${index}.location`);
  const normalized = { ...record, toolId: provider, verification: record.verification ?? 'reported', evidence: record.evidence === undefined ? undefined : { importedEvidence: record.evidence, originalToolId: record.toolId } };
  return normalized;
}

/** Read only documented Sec Hub contract JSON or Cloudflare's verified native report format. */
export async function importBridge(id, file, target) {
  const bridge = getBridge(id);
  requireString(target, 'target');
  const sourceFile = path.resolve(file);
  let parsed;
  try { parsed = JSON.parse(await readFile(sourceFile, 'utf8')); }
  catch (error) { throw new TypeError(`Could not parse bridge JSON: ${error.message}`); }
  let sourceFindings;
  let rejected = 0;
  let format;
  if (Array.isArray(parsed)) {
    if (id !== 'cloudflare') throw new TypeError('Anthropic native schema is unsupported; use the Sec Hub bridge contract');
    if (parsed.length === 0) throw new TypeError('Empty unsupported Cloudflare native report');
    parsed.forEach(validateNativeRecord);
    rejected = parsed.filter((record) => record.verdict === 'rejected').length;
    sourceFindings = parsed.filter((record) => record.verdict !== 'rejected').map(nativeFinding);
    format = 'cloudflare-native';
  } else {
    sourceFindings = validateContract(parsed, id);
    format = 'sec-hub-bridge-v1';
  }
  const findings = normalizeFindings(sourceFindings);
  const now = new Date().toISOString();
  return {
    schemaVersion: 1, id: `import-${id}-${Date.now()}`, startedAt: now, endedAt: now,
    target: { path: path.resolve(target) }, status: 'completed',
    tools: [{ id, name: bridge.name, source: 'external import', status: 'imported', reason: 'Imported results; Sec Hub did not execute this integration locally.', findings, artifacts: { format, sourceFile, rejected } }],
    findings,
  };
}
