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
import { getAdapter } from '../src/adapters/index.mjs';

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
async function hashes(directory, prefix = '', excludeGit = false) {
  await assertSafeDirectory(path.join(directory, prefix));
  const result = {};
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    if (entry.name === '.git' && excludeGit) continue;
    const relative = path.join(prefix, entry.name);
    requireValue(!entry.isSymbolicLink(), `Verification refuses symbolic link: ${relative}`);
    if (entry.isDirectory()) Object.assign(result, await hashes(directory, relative, excludeGit));
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
    if (tool.selected === true) {
      requireValue(agentIds.includes(tool.id) && tool.status === 'completed' && tool.exitCode === 0 && !tool.provenance && typeof tool.version === 'string' && tool.version.trim() && date(tool.startedAt) && date(tool.endedAt) && Date.parse(tool.startedAt) >= Date.parse(run.startedAt) && Date.parse(tool.endedAt) <= Date.parse(run.endedAt) && Date.parse(tool.startedAt) <= Date.parse(tool.endedAt), `Agent ${tool.id} must actually complete locally`);
    } else requireValue(tool.selected === false && tool.status === 'skipped' && tool.findings.length === 0 && Object.keys(tool).every(key => ['id', 'name', 'source', 'selected', 'status', 'findings', 'reason'].includes(key)), `Unused record ${tool.id} must be empty and skipped`);
  }
  requireValue(run.tools.some(tool => tool.selected === true), 'Agent cohort must select at least one native integration');
  requireValue(equal(normalizeFindings(run.findings), normalizeFindings(run.tools.flatMap(tool => tool.findings))), 'Agent run findings do not match its tool records');
}

// Metadata planning never establishes native success; the public verifier also
// reparses every selected tool through validateNativeExecution before writing.
export function validateAgentCohorts(runs, five, { allowPartial = false } = {}) {
  requireValue(typeof allowPartial === 'boolean', 'allowPartial must be a boolean');
  requireValue(Array.isArray(runs) && runs.length > 0, 'At least one native execution cohort is required');
  const runIds = new Set([five.id, ...(five.provenance?.sourceRuns ?? []).map(source => source.id)]), completed = new Set();
  for (const run of runs) {
    validateAgentRunMetadata(run, five);
    requireValue(!runIds.has(run.id), 'Native cohort run identities must be unique'); runIds.add(run.id);
    for (const tool of run.tools.filter(tool => tool.selected === true)) {
      requireValue(!completed.has(tool.id), `Duplicate completed native integration: ${tool.id}`); completed.add(tool.id);
    }
  }
  const completedIds = agentIds.filter(id => completed.has(id)), missingIds = agentIds.filter(id => !completed.has(id));
  requireValue(allowPartial || missingIds.length === 0, `Missing completed native execution: ${missingIds.join(', ')}`);
  return { completedIds, missingIds, verifiedIntegrations: legacyIds.length + completedIds.length, verificationPassed: missingIds.length === 0, status: missingIds.length ? 'partial' : 'completed' };
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

export async function verifySevenRuns({ five, agents, config: configFile, out, allowPartial = false }) {
  const supplied = Array.isArray(agents) ? agents : [agents];
  requireValue(supplied.length > 0 && [five, configFile, out, ...supplied].every(value => typeof value === 'string' && path.isAbsolute(value)), 'Five, agents, config and output paths must be absolute');
  requireValue(typeof allowPartial === 'boolean', 'allowPartial must be a boolean');
  five = path.resolve(five); const agentDirectories = supplied.map(directory => path.resolve(directory)); out = path.resolve(out);
  requireValue(new Set(agentDirectories).size === agentDirectories.length && !agentDirectories.includes(five), 'Native cohort paths must be unique and separate from the five-tool aggregate');
  requireValue(![five, ...agentDirectories].some(directory => out === directory || out.startsWith(directory + path.sep)), 'Output must be separate from source runs');
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
  const cohorts = [];
  for (const directory of agentDirectories) {
    const runBytes = await bytes(path.join(directory, 'run.json'));
    cohorts.push({ directory, runBytes, run: JSON.parse(runBytes.toString('utf8')) });
  }
  const progress = validateAgentCohorts(cohorts.map(cohort => cohort.run), legacy, { allowPartial });
  for (const cohort of cohorts) cohort.initialArtifacts = await hashes(cohort.directory);
  const config = await loadConfig(configFile);
  const { validateNativeExecution } = await import('../src/agents/validation.mjs');
  const targetHashes = legacy.provenance.targetHashEvidence.before;
  requireValue(equal(targetHashes, await hashes(legacy.target.path, '', true)), 'Target source bytes changed after five-tool validation');
  for (const cohort of cohorts) for (const tool of cohort.run.tools.filter(tool => tool.selected === true)) {
    const id = tool.id, artifactDir = path.join(cohort.directory, 'raw', id);
    requireValue(tool.artifacts?.stdout === path.join(artifactDir, 'stdout.txt') && tool.artifacts?.stderr === path.join(artifactDir, 'stderr.txt'), `Invalid native artifact paths: ${id}`);
    const manifest = await json(path.join(artifactDir, 'execution-manifest.json'));
    requireValue(manifest.finalRetainedHashes && typeof manifest.finalRetainedHashes === 'object' && !Array.isArray(manifest.finalRetainedHashes) && Object.keys(manifest.finalRetainedHashes).length > 0 && Object.values(manifest.finalRetainedHashes).every(value => /^[a-f0-9]{64}$/.test(value)), `Missing finalized native retained-byte hashes: ${id}`);
    const stdout = (await bytes(tool.artifacts.stdout)).toString('utf8'), stderr = (await bytes(tool.artifacts.stderr)).toString('utf8');
    const parsed = await validateNativeExecution(id, { artifactDir, target: legacy.target.path, config, stdout, stderr, exitCode: tool.exitCode });
    const findings = redactValue(normalizeFindings(parsed.findings).map(finding => ({ ...finding, rawRef: finding.rawRef ?? tool.artifacts.stdout })));
    requireValue(equal(findings, tool.findings), `Reparsed native findings mismatch: ${id}`);
    requireValue(parsed.execution && equal(redactValue(parsed.execution), tool.execution), `Revalidated execution metadata mismatch: ${id}`);
  }
  requireValue(equal(targetHashes, await hashes(legacy.target.path, '', true)), 'Target source bytes changed during native evidence validation');
  const sourceArtifacts = { five: await hashes(five), agents: [] };
  requireValue(sourceArtifacts.five['run.json'] === sha(fiveBytes), 'Five-tool source metadata changed during verification');
  for (const cohort of cohorts) {
    const retained = await hashes(cohort.directory);
    requireValue(retained['run.json'] === sha(cohort.runBytes), 'Native source run metadata changed during verification');
    requireValue(equal(cohort.initialArtifacts, retained), 'Native source artifacts changed during verification');
    for (const required of ['run.json', 'report.html', 'results.sarif']) requireValue(retained[required], `Missing native source artifact: ${required}`);
    cohort.source = source(cohort.directory, cohort.run, out, retained);
    sourceArtifacts.agents.push({ runId: cohort.run.id, path: cohort.directory, hashes: retained });
  }
  for (const required of ['run.json', 'report.html', 'results.sarif']) requireValue(sourceArtifacts.five[required], `Missing five-tool source artifact: ${required}`);
  const sourceRuns = [...leaves.map(item => ({ ...structuredClone(item), link: link(out, item.path), reportLink: link(out, path.join(path.dirname(item.path), 'report.html')) })), ...cohorts.map(cohort => cohort.source)];
  const tools = legacy.tools.map(tool => ({ ...structuredClone(tool), provenance: { ...structuredClone(tool.provenance), sourceRunLink: link(out, tool.provenance.sourceRunPath), sourceRunSha256: sourceRuns.find(source => source.path === tool.provenance.sourceRunPath).sha256 } }));
  for (const id of agentIds) {
    const cohort = cohorts.find(item => item.run.tools.some(tool => tool.id === id && tool.selected === true));
    if (cohort) {
      const tool = cohort.run.tools.find(tool => tool.id === id);
      tools.push({ ...structuredClone(tool), provenance: { sourceRunId: cohort.run.id, sourceRunPath: cohort.source.path, sourceRunLink: cohort.source.link, sourceRunSha256: cohort.source.sha256 } });
    } else {
      const descriptor = getAdapter(id);
      tools.push({ id, name: descriptor.name, source: descriptor.source, selected: false, status: 'skipped', reason: 'No completed native execution supplied', findings: [] });
    }
  }
  const pendingText = progress.missingIds.join(', '), count = progress.verifiedIntegrations;
  const description = progress.verificationPassed ? 'Verified results from existing five-native-run evidence plus actual Cloudflare/Anthropic executions on the same unchanged target.' : `Verified progress: ${count} of 7 required integrations completed on the same unchanged target. Pending native execution: ${pendingText}.`;
  const combined = { schemaVersion: 1, id: randomUUID(), startedAt: legacy.startedAt, endedAt: cohorts.reduce((latest, cohort) => Date.parse(cohort.run.endedAt) > Date.parse(latest) ? cohort.run.endedAt : latest, legacy.endedAt), target: structuredClone(legacy.target), status: progress.status, verificationPassed: progress.verificationPassed, requiredIntegrations: 7, verifiedIntegrations: count, pendingIntegrations: progress.missingIds, tools, findings: normalizeFindings(tools.flatMap(tool => tool.findings)), provenance: { kind: 'aggregate', integrationCount: 7, requiredIntegrations: 7, verifiedIntegrations: count, pendingIntegrations: progress.missingIds, verificationPassed: progress.verificationPassed, createdAt: new Date().toISOString(), description, summary: `${count} of 7 required integrations completed across multiple native executions; source-only agent workflows retain their static coverage limitations.${pendingText ? ` Pending: ${pendingText}.` : ''}`, sourceRuns, legacyAggregate: { ...source(five, legacy, out, sourceArtifacts.five), provenance: structuredClone(legacy.provenance) }, targetHashEvidence: structuredClone(legacy.provenance.targetHashEvidence), artifactHashEvidence: sourceArtifacts, limitations: ['This is an aggregate of multiple executions, not one seven-tool CLI invocation.', 'Cloudflare quick security-audit and Anthropic vuln-scan single/no-score are static source workflows; dynamic exploitation is not confirmed.'] } };
  const directory = await prepareRunDirectory(out);
  const reports = await writeReports(cleanVerificationValue(combined), directory);
  const outputs = await hashes(directory);
  await atomicWriteFile(path.join(directory, 'verification-manifest.json'), JSON.stringify(cleanVerificationValue({ schema: 'sec-hub.seven-verification/v1', createdAt: new Date().toISOString(), aggregateRunId: combined.id, status: combined.status, verificationPassed: progress.verificationPassed, requiredIntegrations: 7, verifiedIntegrations: count, pendingIntegrations: progress.missingIds, sourceRuns, legacyAggregateRunId: legacy.id, targetHashes, sourceArtifactHashes: sourceArtifacts, outputArtifactHashes: outputs, hashScope: 'Retained bytes after source-run redaction; no source evidence was modified.' }), null, 2) + '\n', { mode: 0o600 });
  return { id: combined.id, status: combined.status, verificationPassed: progress.verificationPassed, integrations: tools.length, requiredIntegrations: 7, verifiedIntegrations: count, pendingIntegrations: progress.missingIds, findings: combined.findings.length, ...reports, manifest: path.join(directory, 'verification-manifest.json') };
}

function options(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === '--allow-partial') { requireValue(!result.allowPartial, 'Duplicate --allow-partial flag'); result.allowPartial = true; continue; }
    requireValue(['--five', '--agents', '--config', '--out'].includes(name) && argv[index + 1] && !argv[index + 1].startsWith('--') && (name === '--agents' || !result[name.slice(2)]), 'Usage: node scripts/verify-seven-tools.mjs --five ABS_DIR --agents ABS_DIR [--agents ABS_DIR] --config ABS_FILE --out NEW_ABS_DIR [--allow-partial]');
    const value = argv[++index];
    if (name === '--agents') result.agents = result.agents === undefined ? value : [...(Array.isArray(result.agents) ? result.agents : [result.agents]), value];
    else result[name.slice(2)] = value;
  }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { const result = await verifySevenRuns(options(process.argv.slice(2))); console.log(JSON.stringify(result, null, 2)); if (!result.verificationPassed) process.exitCode = 2; }
  catch (error) { console.error(cleanVerificationLog(error.message)); process.exitCode = 2; }
}
