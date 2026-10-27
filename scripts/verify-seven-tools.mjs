#!/usr/bin/env node
// Verification only: no scanner execution and no changes to any source evidence.
import { open, readdir, lstat, mkdtemp, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { combineVerifiedRuns } from './combine-verified-runs.mjs';
import { cleanVerificationLog } from './live-verify-redaction.mjs';
import { loadConfig } from '../src/config.mjs';
import { normalizeFindings, writeReports } from '../src/reports.mjs';
import { redactValue } from '../src/redaction.mjs';
import { prepareRunDirectory } from '../src/runner.mjs';
import { assertSafeDirectory, atomicWriteFile } from '../src/safe-io.mjs';

const legacyIds = ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell'];
const agentIds = ['cloudflare', 'anthropic'];
const allIds = [...legacyIds, ...agentIds];
const sha = value => createHash('sha256').update(value).digest('hex');
const equal = (a, b) => isDeepStrictEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
function requireValue(value, message) { if (!value) throw new Error(message); }
async function bytes(file) {
  await assertSafeDirectory(path.dirname(file));
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const info = await handle.stat();
    requireValue(info.isFile() && info.nlink === 1 && info.size <= 20 * 1024 * 1024, `Unsafe or oversized verification artifact: ${file}`);
    const data = await handle.readFile(), after = await handle.stat();
    requireValue(data.length <= 20 * 1024 * 1024 && info.ino === after.ino && info.size === after.size && info.mtimeMs === after.mtimeMs, `Verification artifact changed during read: ${file}`);
    return data;
  } finally { await handle.close(); }
}
async function json(file) { return JSON.parse((await bytes(file)).toString('utf8')); }
async function hashes(directory, prefix = '') {
  await assertSafeDirectory(path.join(directory, prefix));
  const result = {};
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const relative = path.join(prefix, entry.name);
    requireValue(!entry.isSymbolicLink(), `Verification refuses symbolic link: ${relative}`);
    if (entry.isDirectory()) Object.assign(result, await hashes(directory, relative));
    else { requireValue(entry.isFile(), `Unknown artifact metadata: ${relative}`); result[relative] = sha(await bytes(path.join(directory, relative))); }
  }
  return result;
}
const date = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
function runMetadata(run, label) {
  requireValue(run?.schemaVersion === 1 && typeof run.id === 'string' && run.id && typeof run.target?.path === 'string' && path.isAbsolute(run.target.path) && /^[a-f0-9]{40,64}$/.test(run.target.revision ?? '') && run.target.dirty === false, `Invalid ${label} target/run metadata`);
  requireValue(date(run.startedAt) && date(run.endedAt) && Date.parse(run.startedAt) <= Date.parse(run.endedAt), `Invalid ${label} timestamps`);
}

// Only generated aggregate identity/time and output-relative links may differ.
// All tool records, failure history, native hashes, source identities and paths must match.
export function canonicalFiveAggregate(run) {
  const result = structuredClone(run);
  delete result.id;
  if (result.provenance) delete result.provenance.createdAt;
  for (const source of result.provenance?.sourceRuns ?? []) { delete source.link; delete source.reportLink; }
  for (const tool of result.tools ?? []) if (tool.provenance) delete tool.provenance.sourceRunLink;
  return result;
}

export function validateAgentRunMetadata(run, five) {
  runMetadata(run, 'agent');
  requireValue(!run.provenance && run.status === 'completed' && run.id !== five.id, 'Agents must be an original completed local run');
  requireValue(equal(run.target, five.target), 'Agent target path/revision/clean state must exactly match the original five');
  requireValue(Date.parse(five.endedAt) <= Date.parse(run.startedAt), 'Agent execution must follow the verified five-tool runs');
  requireValue(Array.isArray(run.tools) && run.tools.length === 7 && equal(run.tools.map(tool => tool.id).sort(), [...allIds].sort()), 'Agent run must contain exactly seven unique registry records');
  requireValue(Array.isArray(run.findings), 'Agent findings must be an array');
  for (const tool of run.tools) {
    requireValue(Array.isArray(tool.findings) && tool.findings.every(finding => finding.toolId === tool.id), `Invalid agent findings metadata: ${tool.id}`);
    normalizeFindings(tool.findings);
    if (agentIds.includes(tool.id)) {
      requireValue(tool.selected === true && tool.status === 'completed' && tool.exitCode === 0 && !tool.provenance && typeof tool.version === 'string' && tool.version.trim() && date(tool.startedAt) && date(tool.endedAt) && Date.parse(tool.startedAt) >= Date.parse(run.startedAt) && Date.parse(tool.endedAt) <= Date.parse(run.endedAt) && Date.parse(tool.startedAt) <= Date.parse(tool.endedAt), `Agent ${tool.id} must actually complete locally`);
    } else requireValue(tool.selected === false && tool.status === 'skipped' && tool.findings.length === 0 && !tool.artifacts && !tool.execution, `Unused legacy record ${tool.id} must be empty and skipped`);
  }
  requireValue(equal(normalizeFindings(run.findings), normalizeFindings(run.tools.flatMap(tool => tool.findings))), 'Agent run findings do not match its tool records');
}

function link(out, destination) {
  const relative = path.relative(out, destination).split(path.sep).map(encodeURIComponent).join('/');
  return relative.startsWith('.') ? relative : `./${relative}`;
}
function source(directory, run, out, artifacts) {
  return { id: run.id, path: path.join(directory, 'run.json'), link: link(out, path.join(directory, 'run.json')), reportLink: link(out, path.join(directory, 'report.html')), status: run.status, startedAt: run.startedAt, endedAt: run.endedAt, sha256: artifacts['run.json'], tools: run.tools.map(({ id, selected, status, reason }) => ({ id, selected, status, ...(reason ? { reason } : {}) })) };
}
export function cleanVerificationValue(value) {
  function visit(item, key = '') {
    if (/^(?:account|organization|workspace)[_-]?id$/i.test(key) && typeof item === 'string') return '[REDACTED_ID]';
    if (/^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret)$/i.test(key) && typeof item === 'string') return '[REDACTED_CREDENTIAL]';
    if (typeof item === 'string') return cleanVerificationLog(item);
    if (Array.isArray(item)) return item.map(value => visit(value));
    if (item && typeof item === 'object') return Object.fromEntries(Object.entries(item).map(([key, value]) => [key, visit(value, key)]));
    return item;
  }
  return visit(redactValue(value));
}

export async function verifySevenRuns({ five, agents, config: configFile, out }) {
  requireValue([five, agents, configFile, out].every(value => typeof value === 'string' && path.isAbsolute(value)), 'Five, agents, config and output paths must be absolute');
  five = path.resolve(five); agents = path.resolve(agents); out = path.resolve(out);
  requireValue(five !== agents && ![five, agents].some(directory => out === directory || out.startsWith(directory + path.sep)), 'Output must be separate from source runs');
  try { await lstat(out); throw new Error('Output path already exists; choose a new directory'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const fiveBytes = await bytes(path.join(five, 'run.json')), legacy = JSON.parse(fiveBytes.toString('utf8'));
  runMetadata(legacy, 'five-tool aggregate');
  requireValue(legacy.status === 'completed' && legacy.provenance?.kind === 'aggregate' && legacy.tools?.length === 5 && equal(legacy.tools.map(tool => tool.id).sort(), [...legacyIds].sort()) && legacy.tools.every(tool => tool.selected === true && tool.status === 'completed'), 'Five input must be the strict completed five-tool aggregate');
  requireValue(![legacy.target.path, configFile].some(directory => out === directory || out.startsWith(directory + path.sep)), 'Output must stay outside the target/config');
  const leaves = legacy.provenance.sourceRuns;
  requireValue(Array.isArray(leaves) && leaves.length === 2 && leaves.every(item => typeof item.path === 'string' && path.isAbsolute(item.path) && path.basename(item.path) === 'run.json') && leaves[0].path !== leaves[1].path, 'Five aggregate requires its original two native leaf runs');
  requireValue(!leaves.some(item => out === path.dirname(item.path) || out.startsWith(path.dirname(item.path) + path.sep)), 'Output must stay outside native leaf runs');
  const temporary = await mkdtemp(path.join(tmpdir(), 'sec-hub-seven-verify-'));
  try {
    const regenerated = path.join(temporary, 'five');
    await combineVerifiedRuns({ original: path.dirname(leaves[0].path), retry: path.dirname(leaves[1].path), out: regenerated });
    requireValue(equal(canonicalFiveAggregate(legacy), canonicalFiveAggregate(await json(path.join(regenerated, 'run.json')))), 'Five aggregate differs from revalidated native leaf evidence');
  } finally { await rm(temporary, { recursive: true, force: true }); }
  const agentBytes = await bytes(path.join(agents, 'run.json')), agentRun = JSON.parse(agentBytes.toString('utf8'));
  validateAgentRunMetadata(agentRun, legacy);
  const initialAgentArtifacts = await hashes(agents);
  const config = await loadConfig(configFile);
  const { validateNativeExecution } = await import('../src/agents/validation.mjs');
  const targetHashes = legacy.provenance.targetHashEvidence.before;
  requireValue(equal(targetHashes, await hashes(legacy.target.path)), 'Target source bytes changed after five-tool validation');
  for (const id of agentIds) {
    const tool = agentRun.tools.find(item => item.id === id), artifactDir = path.join(agents, 'raw', id);
    requireValue(tool.artifacts?.stdout === path.join(artifactDir, 'stdout.txt') && tool.artifacts?.stderr === path.join(artifactDir, 'stderr.txt'), `Invalid native artifact paths: ${id}`);
    const manifest = await json(path.join(artifactDir, 'execution-manifest.json'));
    requireValue(manifest.finalRetainedHashes && typeof manifest.finalRetainedHashes === 'object' && !Array.isArray(manifest.finalRetainedHashes) && Object.keys(manifest.finalRetainedHashes).length > 0 && Object.values(manifest.finalRetainedHashes).every(value => /^[a-f0-9]{64}$/.test(value)), `Missing finalized native retained-byte hashes: ${id}`);
    const stdout = (await bytes(tool.artifacts.stdout)).toString('utf8'), stderr = (await bytes(tool.artifacts.stderr)).toString('utf8');
    const parsed = await validateNativeExecution(id, { artifactDir, target: legacy.target.path, config, stdout, stderr, exitCode: tool.exitCode });
    const findings = redactValue(normalizeFindings(parsed.findings).map(finding => ({ ...finding, rawRef: finding.rawRef ?? tool.artifacts.stdout })));
    requireValue(equal(findings, tool.findings), `Reparsed native findings mismatch: ${id}`);
    requireValue(parsed.execution && equal(redactValue(parsed.execution), tool.execution), `Revalidated execution metadata mismatch: ${id}`);
  }
  requireValue(equal(targetHashes, await hashes(legacy.target.path)), 'Target source bytes changed during native evidence validation');
  const sourceArtifacts = { five: await hashes(five), agents: await hashes(agents) };
  requireValue(sourceArtifacts.five['run.json'] === sha(fiveBytes) && sourceArtifacts.agents['run.json'] === sha(agentBytes), 'Source run metadata changed during verification');
  requireValue(equal(initialAgentArtifacts, sourceArtifacts.agents), 'Native source artifacts changed during verification');
  for (const required of ['run.json', 'report.html', 'results.sarif']) for (const label of ['five', 'agents']) requireValue(sourceArtifacts[label][required], `Missing ${label} source artifact: ${required}`);
  const agentSource = source(agents, agentRun, out, sourceArtifacts.agents);
  const sourceRuns = [...leaves.map(item => ({ ...structuredClone(item), link: link(out, item.path), reportLink: link(out, path.join(path.dirname(item.path), 'report.html')) })), agentSource];
  const tools = [...legacy.tools.map(tool => ({ ...structuredClone(tool), provenance: { ...structuredClone(tool.provenance), sourceRunLink: link(out, tool.provenance.sourceRunPath) } })), ...agentRun.tools.filter(tool => agentIds.includes(tool.id)).map(tool => ({ ...structuredClone(tool), provenance: { sourceRunId: agentRun.id, sourceRunPath: agentSource.path, sourceRunLink: agentSource.link } }))];
  const combined = { schemaVersion: 1, id: randomUUID(), startedAt: legacy.startedAt, endedAt: agentRun.endedAt, target: structuredClone(legacy.target), status: 'completed', tools, findings: normalizeFindings(tools.flatMap(tool => tool.findings)), provenance: { kind: 'aggregate', integrationCount: 7, createdAt: new Date().toISOString(), description: 'Verified results from existing five-native-run evidence plus actual Cloudflare/Anthropic executions on the same unchanged target.', summary: 'Seven completed integrations across multiple native executions; source-only agent workflows retain their static coverage limitations.', sourceRuns, legacyAggregate: { ...source(five, legacy, out, sourceArtifacts.five), provenance: structuredClone(legacy.provenance) }, targetHashEvidence: structuredClone(legacy.provenance.targetHashEvidence), artifactHashEvidence: sourceArtifacts, limitations: ['This is an aggregate of multiple executions, not one seven-tool CLI invocation.', 'Cloudflare quick security-audit and Anthropic vuln-scan single/no-score are static source workflows; dynamic exploitation is not confirmed.'] } };
  const directory = await prepareRunDirectory(out);
  const reports = await writeReports(cleanVerificationValue(combined), directory);
  const outputs = await hashes(directory);
  await atomicWriteFile(path.join(directory, 'verification-manifest.json'), JSON.stringify(cleanVerificationValue({ schema: 'sec-hub.seven-verification/v1', createdAt: new Date().toISOString(), aggregateRunId: combined.id, sourceRuns, legacyAggregateRunId: legacy.id, targetHashes, sourceArtifactHashes: sourceArtifacts, outputArtifactHashes: outputs, hashScope: 'Retained bytes after source-run redaction; no source evidence was modified.' }), null, 2) + '\n', { mode: 0o600 });
  return { id: combined.id, status: combined.status, integrations: tools.length, findings: combined.findings.length, ...reports, manifest: path.join(directory, 'verification-manifest.json') };
}

function options(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireValue(['--five', '--agents', '--config', '--out'].includes(name) && !result[name.slice(2)] && argv[index + 1], 'Usage: node scripts/verify-seven-tools.mjs --five ABS_DIR --agents ABS_DIR --config ABS_FILE --out NEW_ABS_DIR');
    result[name.slice(2)] = argv[index + 1];
  }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { console.log(JSON.stringify(await verifySevenRuns(options(process.argv.slice(2))), null, 2)); }
  catch (error) { console.error(cleanVerificationLog(error.message)); process.exitCode = 2; }
}
