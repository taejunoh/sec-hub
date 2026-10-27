#!/usr/bin/env node
// Verification-only aggregation. Never invokes scanners or changes source runs.
import { open, readdir, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { getAdapter } from '../src/adapters/index.mjs';
import { normalizeFindings, writeReports } from '../src/reports.mjs';
import { prepareRunDirectory } from '../src/runner.mjs';
import { assertSafeDirectory } from '../src/safe-io.mjs';
import { cleanVerificationLog } from './live-verify-redaction.mjs';

const ids = ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell'];
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const plain = value => JSON.parse(JSON.stringify(value));
const equal = (left, right) => isDeepStrictEqual(plain(left), plain(right));
function requireValue(condition, message) { if (!condition) throw new Error(message); }
async function bytes(file) {
  await assertSafeDirectory(path.dirname(file));
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    requireValue(info.isFile() && info.size <= 20 * 1024 * 1024, `Unsafe or oversized verification artifact: ${file}`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
async function json(file) { return JSON.parse((await bytes(file)).toString('utf8')); }
async function hashes(directory, prefix = '') {
  await assertSafeDirectory(path.join(directory, prefix));
  const result = {};
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const relative = path.join(prefix, entry.name);
    requireValue(!entry.isSymbolicLink(), `Target/artifact hash refuses symbolic links: ${relative}`);
    if (entry.isDirectory()) Object.assign(result, await hashes(directory, relative));
    else { requireValue(entry.isFile(), `Unknown target/artifact metadata: ${relative}`); result[relative] = sha(await bytes(path.join(directory, relative))); }
  }
  return result;
}
function validateRun(run, label) {
  requireValue(run?.schemaVersion === 1 && typeof run.id === 'string' && run.id.length > 0 && typeof run.target?.path === 'string' && path.isAbsolute(run.target.path) && /^[a-f0-9]{40,64}$/.test(run.target.revision ?? '') && run.target.dirty === false && !run.provenance, `Invalid ${label} target/run metadata`);
  requireValue([run.startedAt, run.endedAt].every(value => typeof value === 'string' && Number.isFinite(Date.parse(value))) && Date.parse(run.startedAt) <= Date.parse(run.endedAt), `Invalid ${label} timestamps`);
  requireValue(Array.isArray(run.tools) && run.tools.length === 5 && equal(run.tools.map(tool => tool.id).sort(), [...ids].sort()) && Array.isArray(run.findings), `Invalid ${label} tool metadata`);
  for (const tool of run.tools) {
    requireValue(typeof tool.selected === 'boolean' && Array.isArray(tool.findings) && tool.findings.every(finding => finding.toolId === tool.id), `Invalid ${label} findings metadata`);
    normalizeFindings(tool.findings);
  }
}
async function verifyNative(directory, run, tool) {
  const artifactDir = path.join(directory, 'raw', tool.id);
  requireValue(tool.artifacts?.stdout === path.join(artifactDir, 'stdout.txt') && tool.artifacts?.stderr === path.join(artifactDir, 'stderr.txt'), `Invalid artifact paths for ${tool.id}`);
  const stdout = (await bytes(tool.artifacts.stdout)).toString('utf8');
  await bytes(tool.artifacts.stderr);
  const parsed = normalizeFindings(await getAdapter(tool.id).parse({ artifactDir, target: run.target.path, url: tool.findings[0]?.location?.url, stdout, exitCode: tool.exitCode }));
  requireValue(equal(parsed, tool.findings), `Native artifact findings mismatch for ${tool.id}`);
}
function localLink(out, destination) {
  const relative = path.relative(out, destination).split(path.sep).map(encodeURIComponent).join('/');
  return relative.startsWith('.') ? relative : `./${relative}`;
}

export async function combineVerifiedRuns({ original, retry, out }) {
  requireValue([original, retry, out].every(value => typeof value === 'string' && path.isAbsolute(value)), 'Original, retry and output paths must be absolute');
  original = path.resolve(original); retry = path.resolve(retry); out = path.resolve(out);
  requireValue(original !== retry && ![original, retry].some(directory => out === directory || out.startsWith(directory + path.sep)), 'Output must be separate from both source runs');
  try { await lstat(out); throw new Error('Output path already exists; choose a new directory'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const initial = await json(path.join(original, 'run.json')), retried = await json(path.join(retry, 'run.json'));
  validateRun(initial, 'original'); validateRun(retried, 'retry');
  requireValue(out !== initial.target.path && !out.startsWith(initial.target.path + path.sep), 'Output must stay outside the unchanged target');
  requireValue(initial.id !== retried.id && initial.target.path === retried.target.path && initial.target.revision === retried.target.revision, 'Original and retry target path/revision must match exactly');
  requireValue(Date.parse(initial.endedAt) <= Date.parse(retried.startedAt), 'Retry must follow the original run');
  requireValue(initial.status === 'partial' && initial.tools.every(tool => tool.selected && tool.status === (tool.id === 'open-code-review' ? 'failed' : 'completed')), 'Original must contain four completed tools and failed OCR');
  requireValue(retried.status === 'completed' && retried.tools.every(tool => tool.id === 'open-code-review' ? tool.selected && tool.status === 'completed' : !tool.selected && tool.status === 'skipped' && tool.findings.length === 0), 'Retry must select and complete only OCR');
  const evidenceFile = path.join(original, 'verification-commands.json'), evidence = await json(evidenceFile);
  requireValue(evidence.fixturePath === initial.target.path && evidence.runStatus === initial.status && Array.isArray(evidence.tools) && evidence.tools.length === 5, 'Original verification metadata is missing or inconsistent');
  for (const tool of initial.tools) {
    const item = evidence.tools.find(item => item.id === tool.id);
    requireValue(item?.selected === tool.selected && item.status === tool.status && item.findings === tool.findings.length, 'Original verification tool metadata mismatch');
  }
  const { before, after } = evidence.targetHashes ?? {};
  const current = await hashes(initial.target.path);
  requireValue(before && Object.keys(before).length > 0 && equal(before, after) && equal(before, current) && Object.values(before).every(value => /^[a-f0-9]{64}$/.test(value)) && equal(evidence.targetChanges, { added: [], removed: [], changed: [] }), 'Target hash mismatch or unknown target metadata');
  requireValue(evidence.artifactHashes && Object.keys(evidence.artifactHashes).length > 0, 'Original artifact hashes are missing');
  for (const [relative, expected] of Object.entries(evidence.artifactHashes)) {
    requireValue(!path.isAbsolute(relative) && relative.split(/[\\/]/).every(part => part && part !== '.' && part !== '..') && /^[a-f0-9]{64}$/.test(expected), 'Invalid original artifact hash metadata');
    requireValue(sha(await bytes(path.join(original, relative))) === expected, `Original artifact hash mismatch: ${relative}`);
  }
  const requiredOriginal = ['run.json', 'report.html', 'results.sarif', ...ids.flatMap(id => [`raw/${id}/stdout.txt`, `raw/${id}/stderr.txt`, ...(id === 'php2shell' ? [] : [`raw/${id}/${id === 'codex-security' ? 'findings.json' : 'native.json'}`])])];
  for (const required of requiredOriginal) requireValue(evidence.artifactHashes[required], `Missing original artifact hash: ${required}`);
  const previous = initial.tools.find(tool => tool.id === 'open-code-review');
  const budget = await json(path.join(original, 'raw/open-code-review/native.json'));
  requireValue(budget.summary?.budget_exceeded === true && budget.warnings?.some(warning => warning.type === 'token_budget_reached'), 'Original OCR failure is not a verified budget dispatch guard');
  for (const tool of initial.tools.filter(tool => tool.status === 'completed')) await verifyNative(original, initial, tool);
  const replacement = retried.tools.find(tool => tool.id === 'open-code-review');
  await verifyNative(retry, retried, replacement);
  const retryArtifacts = await hashes(retry);
  for (const required of ['run.json', 'report.html', 'results.sarif', 'raw/open-code-review/native.json', 'raw/open-code-review/stdout.txt', 'raw/open-code-review/stderr.txt']) requireValue(retryArtifacts[required], `Missing retry artifact: ${required}`);
  const sources = [[original, initial], [retry, retried]].map(([directory, run]) => ({ id: run.id, path: path.join(directory, 'run.json'), link: localLink(out, path.join(directory, 'run.json')), reportLink: localLink(out, path.join(directory, 'report.html')), status: run.status, startedAt: run.startedAt, endedAt: run.endedAt, sha256: directory === original ? evidence.artifactHashes['run.json'] : retryArtifacts['run.json'], tools: run.tools.map(({ id, selected, status, reason }) => ({ id, selected, status, ...(reason ? { reason } : {}) })) }));
  const tools = initial.tools.map(tool => {
    const isRetry = tool.id === 'open-code-review', record = structuredClone(isRetry ? replacement : tool), source = sources[isRetry ? 1 : 0];
    return { ...record, provenance: { sourceRunId: source.id, sourceRunPath: source.path, sourceRunLink: source.link } };
  });
  const combined = { schemaVersion: 1, id: randomUUID(), startedAt: initial.startedAt, endedAt: retried.endedAt, target: structuredClone(initial.target), status: 'completed', tools, findings: normalizeFindings(tools.flatMap(tool => tool.findings)), provenance: { kind: 'aggregate', createdAt: new Date().toISOString(), sourceRuns: sources, retry: { toolId: 'open-code-review', previousStatus: previous.status, reason: 'budget dispatch guard', previousRecord: structuredClone(previous), nativeFailure: { status: budget.status, summary: budget.summary, warnings: budget.warnings }, replacementRunId: retried.id }, targetHashEvidence: { evidencePath: evidenceFile, evidenceSha256: sha(await bytes(evidenceFile)), excludes: ['.git'], before, after, current }, artifactHashEvidence: { original: evidence.artifactHashes, retry: retryArtifacts } } };
  const directory = await prepareRunDirectory(out);
  return { id: combined.id, status: combined.status, findings: combined.findings.length, ...(await writeReports(combined, directory)) };
}

function options(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireValue(['--original', '--retry', '--out'].includes(name) && !result[name.slice(2)] && argv[index + 1], 'Usage: node scripts/combine-verified-runs.mjs --original ABS_DIR --retry ABS_DIR --out NEW_ABS_DIR');
    result[name.slice(2)] = argv[index + 1];
  }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { console.log(JSON.stringify(await combineVerifiedRuns(options(process.argv.slice(2))), null, 2)); }
  catch (error) { console.error(cleanVerificationLog(error.message)); process.exitCode = 2; }
}
