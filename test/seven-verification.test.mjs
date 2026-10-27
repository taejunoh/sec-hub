import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getAdapter } from '../src/adapters/index.mjs';
import { normalizeFindings, writeReports } from '../src/reports.mjs';
import { combineVerifiedRuns } from '../scripts/combine-verified-runs.mjs';
import { verifySevenRuns, validateAgentRunMetadata, validateAgentCohorts, canonicalFiveAggregate, cleanVerificationValue } from '../scripts/verify-seven-tools.mjs';

const legacyIds = ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell'];
const ids = [...legacyIds, 'cloudflare', 'anthropic'];
const hash = value => createHash('sha256').update(value).digest('hex');
const execute = promisify(execFile);
async function hashes(directory, prefix = '') {
  const result = {};
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) Object.assign(result, await hashes(directory, relative));
    else result[relative] = hash(await readFile(path.join(directory, relative)));
  }
  return result;
}
function agentRun(target, selected = ['cloudflare', 'anthropic']) {
  return { schemaVersion: 1, id: 'agent-id', startedAt: '2026-10-27T00:04:00.000Z', endedAt: '2026-10-27T00:05:00.000Z', target, status: 'completed', findings: [], tools: ids.map(id => ({ id, selected: selected.includes(id), status: selected.includes(id) ? 'completed' : 'skipped', findings: [], ...(selected.includes(id) ? { version: 'native 1.0', startedAt: '2026-10-27T00:04:00.000Z', endedAt: '2026-10-27T00:05:00.000Z', exitCode: 0 } : {}) })) };
}
async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'seven-verification-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = path.join(root, 'target'), original = path.join(root, 'original'), retry = path.join(root, 'retry'), five = path.join(root, 'five'), agents = path.join(root, 'agents'), out = path.join(root, 'seven'), config = path.join(root, 'config.json');
  await cp(new URL('./fixtures/live-five/', import.meta.url), target, { recursive: true });
  const initial = { schemaVersion: 1, id: 'initial-id', startedAt: '2026-10-27T00:00:00.000Z', endedAt: '2026-10-27T00:01:00.000Z', target: { path: target, revision: 'a'.repeat(40), dirty: false }, status: 'partial', tools: [], findings: [] };
  const repeated = { ...structuredClone(initial), id: 'retry-id', startedAt: '2026-10-27T00:02:00.000Z', endedAt: '2026-10-27T00:03:00.000Z', status: 'completed', tools: [], findings: [] };
  for (const [directory, run, isRetry] of [[original, initial, false], [retry, repeated, true]]) {
    for (const id of legacyIds) {
      const selected = !isRetry || id === 'open-code-review', status = selected ? id === 'open-code-review' && !isRetry ? 'failed' : 'completed' : 'skipped';
      const tool = { id, name: id, source: getAdapter(id).source, selected, status, findings: [] };
      if (!selected) { run.tools.push(tool); continue; }
      const artifactDir = path.join(directory, 'raw', id); await mkdir(artifactDir, { recursive: true });
      let payload = id === 'php2shell' ? { patch_status: 'potentially_vulnerable', php_version: '8.1.2', reason: 'fixture', exit_code: 1 } : JSON.parse(await readFile(new URL(`./fixtures/adapters/${({ 'codex-security': 'codex', 'open-code-review': 'ocr' })[id] ?? id}-positive.json`, import.meta.url), 'utf8'));
      if (status === 'failed') payload = { status: 'completed_with_warnings', comments: [], summary: { budget_exceeded: true }, warnings: [{ type: 'token_budget_reached' }] };
      const stdout = id === 'php2shell' ? JSON.stringify(payload) : '';
      await writeFile(path.join(artifactDir, 'stdout.txt'), stdout); await writeFile(path.join(artifactDir, 'stderr.txt'), '');
      if (id !== 'php2shell') await writeFile(path.join(artifactDir, id === 'codex-security' ? 'findings.json' : 'native.json'), JSON.stringify(payload));
      Object.assign(tool, { artifacts: { stdout: path.join(artifactDir, 'stdout.txt'), stderr: path.join(artifactDir, 'stderr.txt') }, exitCode: id === 'php2shell' ? 1 : 0, startedAt: run.startedAt, endedAt: run.endedAt });
      if (status === 'completed') tool.findings = normalizeFindings(await getAdapter(id).parse({ artifactDir, stdout, exitCode: tool.exitCode, target }));
      run.tools.push(tool); run.findings.push(...tool.findings);
    }
    await writeReports(run, directory);
  }
  const snapshot = await hashes(target);
  await writeFile(path.join(original, 'verification-commands.json'), JSON.stringify({ fixturePath: target, runStatus: 'partial', targetHashes: { before: snapshot, after: snapshot }, targetChanges: { added: [], removed: [], changed: [] }, tools: initial.tools.map(({ id, selected, status, findings }) => ({ id, selected, status, findings: findings.length })), artifactHashes: await hashes(original) }));
  await combineVerifiedRuns({ original, retry, out: five });
  const legacy = JSON.parse(await readFile(path.join(five, 'run.json'), 'utf8')), native = agentRun(legacy.target);
  for (const tool of native.tools.filter(tool => tool.selected)) {
    const artifactDir = path.join(agents, 'raw', tool.id); await mkdir(artifactDir, { recursive: true });
    tool.artifacts = { stdout: path.join(artifactDir, 'stdout.txt'), stderr: path.join(artifactDir, 'stderr.txt') };
    await writeFile(tool.artifacts.stdout, 'I completed the audit'); await writeFile(tool.artifacts.stderr, '');
  }
  await writeReports(native, agents); await writeFile(config, JSON.stringify({ tools: {} }));
  return { root, target, original, retry, five, agents, config, out, legacy, native };
}

test('agent metadata supports two completed zero-finding workflows without counting skipped legacy tools', () => {
  const target = { path: '/target', revision: 'a'.repeat(40), dirty: false };
  const five = { id: 'five', target, endedAt: '2026-10-27T00:03:00.000Z' };
  assert.doesNotThrow(() => validateAgentRunMetadata(agentRun(target), five));
  for (const mutation of ['missing', 'duplicate', 'imported', 'legacy-selected', 'legacy-findings', 'dirty', 'revision', 'early', 'failure', 'version']) {
    const run = agentRun(structuredClone(target));
    if (mutation === 'missing') run.tools.pop();
    if (mutation === 'duplicate') run.tools.at(-1).id = 'cloudflare';
    if (mutation === 'imported') run.tools.at(-1).status = 'imported';
    if (mutation === 'legacy-selected') run.tools[0].selected = true;
    if (mutation === 'legacy-findings') run.tools[0].execution = { mode: 'fabricated' };
    if (mutation === 'dirty') run.target.dirty = true;
    if (mutation === 'revision') run.target.revision = 'b'.repeat(40);
    if (mutation === 'early') run.startedAt = '2026-10-27T00:02:00.000Z';
    if (mutation === 'failure') run.tools.at(-1).exitCode = 1;
    if (mutation === 'version') delete run.tools.at(-1).version;
    assert.throws(() => validateAgentRunMetadata(run, five), undefined, mutation);
  }
});

test('disjoint native cohorts cover seven while explicit partial progress leaves exactly one pending', () => {
  const target = { path: '/target', revision: 'a'.repeat(40), dirty: false }, five = { id: 'five', target, endedAt: '2026-10-27T00:03:00.000Z' };
  const cloudflare = agentRun(structuredClone(target), ['cloudflare']), anthropic = { ...agentRun(structuredClone(target), ['anthropic']), id: 'anthropic-id' };
  assert.doesNotThrow(() => validateAgentRunMetadata(cloudflare, five));
  assert.throws(() => validateAgentCohorts([cloudflare], five), /missing.*anthropic/i);
  assert.deepEqual(validateAgentCohorts([cloudflare], five, { allowPartial: true }), { completedIds: ['cloudflare'], missingIds: ['anthropic'], verifiedIntegrations: 6, verificationPassed: false, status: 'partial' });
  assert.deepEqual(validateAgentCohorts([cloudflare, anthropic], five), { completedIds: ['cloudflare', 'anthropic'], missingIds: [], verifiedIntegrations: 7, verificationPassed: true, status: 'completed' });
  assert.throws(() => validateAgentCohorts([cloudflare, { ...structuredClone(cloudflare), id: 'other-id' }], five, { allowPartial: true }), /duplicate.*cloudflare/i);
  assert.throws(() => validateAgentCohorts([cloudflare, { ...anthropic, id: cloudflare.id }], five), /run identit/i);
  const crossTarget = structuredClone(anthropic); crossTarget.target.revision = 'b'.repeat(40);
  assert.throws(() => validateAgentCohorts([cloudflare, crossTarget], five), /target/i);
  assert.throws(() => validateAgentCohorts([], five, { allowPartial: true }), /at least one/i);
  assert.throws(() => validateAgentCohorts([agentRun(target, [])], five, { allowPartial: true }), /select/i);
  const fabricatedUnused = structuredClone(cloudflare); fabricatedUnused.tools.at(-1).version = 'never executed';
  assert.throws(() => validateAgentCohorts([fabricatedUnused], five, { allowPartial: true }), /unused/i);
});

test('partial mode cannot promote fake native completion and default missing-native mode writes no report', async t => {
  for (const allowPartial of [false, true]) {
    const data = await fixture(t);
    data.native = agentRun(data.legacy.target, ['cloudflare']);
    const artifactDir = path.join(data.agents, 'raw/cloudflare');
    data.native.tools.find(tool => tool.id === 'cloudflare').artifacts = { stdout: path.join(artifactDir, 'stdout.txt'), stderr: path.join(artifactDir, 'stderr.txt') };
    await writeReports(data.native, data.agents);
    await assert.rejects(verifySevenRuns({ ...data, agents: [data.agents], allowPartial }), allowPartial ? /manifest|native|configuration/i : /missing.*anthropic/i);
    await assert.rejects(lstatOutput(data.out), /ENOENT/);
  }
});

test('multiple public cohorts reject duplicate completions and cross-target cohorts before trusting native artifacts', async t => {
  for (const mutation of ['duplicate', 'cross-target', 'imported', 'selected-cli']) {
    const data = await fixture(t), second = path.join(data.root, 'second');
    const first = agentRun(structuredClone(data.legacy.target), ['cloudflare']);
    const later = { ...agentRun(structuredClone(data.legacy.target), mutation === 'duplicate' ? ['cloudflare'] : ['anthropic']), id: 'second-native-id' };
    if (mutation === 'cross-target') later.target.path = path.join(data.root, 'another-target');
    if (mutation === 'imported') later.tools.at(-1).status = 'imported';
    if (mutation === 'selected-cli') { later.tools[0].selected = true; later.tools[0].status = 'completed'; }
    await writeReports(first, data.agents); await writeReports(later, second);
    await assert.rejects(verifySevenRuns({ ...data, agents: [data.agents, second], allowPartial: true }), /duplicate|target|agent/i, mutation);
    await assert.rejects(lstatOutput(data.out), /ENOENT/);
  }
});

test('CLI accepts repeatable agents and standalone allow-partial while rejecting duplicate cohorts with exit 2', async t => {
  const data = await fixture(t);
  await assert.rejects(execute(process.execPath, [new URL('../scripts/verify-seven-tools.mjs', import.meta.url).pathname, '--allow-partial', '--five', data.five, '--agents', data.agents, '--agents', data.agents, '--config', data.config, '--out', data.out]), error => error.code === 2 && /cohort paths must be unique/i.test(error.stderr));
  await assert.rejects(lstatOutput(data.out), /ENOENT/);
});

test('five canonical comparison excludes only new output identity/time and relative links', () => {
  const a = { id: 'one', findings: [], tools: [{ id: 'osv', provenance: { sourceRunPath: '/original/run.json', sourceRunLink: '../original/run.json' } }], provenance: { createdAt: 'a', sourceRuns: [{ id: 'original', path: '/original/run.json', link: '../original/run.json', reportLink: '../original/report.html', sha256: 'a'.repeat(64) }], retry: { previousStatus: 'failed' } } };
  const b = structuredClone(a); b.id = 'two'; b.provenance.createdAt = 'b'; b.provenance.sourceRuns[0].link = '../../../original/run.json'; b.tools[0].provenance.sourceRunLink = '../../../original/run.json';
  assert.deepEqual(canonicalFiveAggregate(a), canonicalFiveAggregate(b));
  b.provenance.retry.previousStatus = 'completed';
  assert.notDeepEqual(canonicalFiveAggregate(a), canonicalFiveAggregate(b));
});

test('verification redaction preserves structured evidence and escaped text without changing originals', () => {
  const input = { account_id: 'private-account', data: { access_token: 'private-token' }, description: 'account_id: "private-id"\nContact person@example.com; quoted \\"text\\"', hash: 'a'.repeat(64) };
  const cleaned = cleanVerificationValue(input), roundtrip = JSON.parse(JSON.stringify(cleaned));
  assert.equal(roundtrip.account_id, '[REDACTED_ID]');
  assert.equal(roundtrip.data.access_token, '[REDACTED_CREDENTIAL]');
  assert.ok(!roundtrip.description.includes('private-id') && !roundtrip.description.includes('person@example.com'));
  assert.equal(roundtrip.hash, input.hash);
  assert.equal(input.account_id, 'private-account');
});

test('public verifier refuses source bytes, original artifact and aggregate provenance tampering', async t => {
  for (const mutation of ['target', 'leaf', 'aggregate', 'leaf-hash']) {
    const data = await fixture(t);
    if (mutation === 'target') await writeFile(path.join(data.target, 'server.mjs'), 'changed');
    if (mutation === 'leaf') await writeFile(path.join(data.original, 'raw/osv/native.json'), '{}');
    if (mutation === 'aggregate') { data.legacy.provenance.retry.previousRecord.status = 'completed'; await writeReports(data.legacy, data.five); }
    if (mutation === 'leaf-hash') { data.legacy.provenance.sourceRuns[0].sha256 = 'b'.repeat(64); await writeReports(data.legacy, data.five); }
    await assert.rejects(verifySevenRuns(data), /hash|aggregate|evidence/i, mutation);
    await assert.rejects(lstatOutput(data.out), /ENOENT/);
  }
});
async function lstatOutput(file) { return readFile(path.join(file, 'run.json')); }

test('public verifier rejects completed JSON and self-report text without native execution proof', async t => {
  const data = await fixture(t), before = await hashes(data.five);
  await assert.rejects(verifySevenRuns(data), /configuration|manifest|native/i);
  assert.deepEqual(await hashes(data.five), before);
  await assert.rejects(lstatOutput(data.out), /ENOENT/);
});

test('public verifier refuses fabricated sealed manifest schemas and official pins', async t => {
  for (const mutation of ['schema', 'pin', 'unsealed']) {
    const data = await fixture(t), artifactDir = path.join(data.agents, 'raw/cloudflare');
    await writeFile(data.config, JSON.stringify({ tools: { cloudflare: { command: '/native', args: [], agentOptions: { skillRoot: data.root, workRoot: path.join(data.root, 'private'), model: 'model', revision: 'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8' } } } }));
    const manifest = { schema: mutation === 'schema' ? 'model-authored-self-report' : 'sec-hub.native-agent/v1', id: 'cloudflare', source: 'https://github.com/cloudflare/security-audit-skill', sourceCommit: mutation === 'pin' ? 'b'.repeat(40) : 'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8', target: data.target, inputs: [{ path: 'server.mjs', sha256: 'a'.repeat(64) }], ...(mutation === 'unsealed' ? {} : { finalRetainedHashes: { 'native-events.jsonl': 'a'.repeat(64) } }) };
    await writeFile(path.join(artifactDir, 'execution-manifest.json'), JSON.stringify(manifest));
    await assert.rejects(verifySevenRuns(data), /manifest|retained-byte|pin/i, mutation);
    await assert.rejects(lstatOutput(data.out), /ENOENT/);
  }
});

test('public verifier rejects imported agent and duplicate IDs before native validation', async t => {
  for (const mutation of ['imported', 'duplicate', 'missing', 'target-revision']) {
    const data = await fixture(t);
    if (mutation === 'imported') data.native.tools.at(-1).status = 'imported';
    if (mutation === 'duplicate') data.native.tools.at(-1).id = 'cloudflare';
    if (mutation === 'missing') data.native.tools.pop();
    if (mutation === 'target-revision') data.native.target.revision = 'b'.repeat(40);
    await writeReports(data.native, data.agents);
    await assert.rejects(verifySevenRuns(data), /agent|registry|target/i);
  }
});
