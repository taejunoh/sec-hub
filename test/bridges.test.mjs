import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { bridges, exportBridge, importBridge } from '../src/bridges.mjs';
import { writeReports } from '../src/reports.mjs';

test('both bridge exports contain guide, JSON schema, and runnable example', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-bridge-'));
  try {
    assert.deepEqual(bridges.map(({ id }) => id), ['cloudflare', 'anthropic']);
    for (const bridge of bridges) {
      const files = await exportBridge(bridge.id, directory);
      assert.ok(files.guide && files.schema && files.example);
      assert.match(await readFile(files.guide, 'utf8'), /import/);
      assert.equal(JSON.parse(await readFile(files.schema, 'utf8')).properties.provider.const, bridge.id);
      assert.equal(JSON.parse(await readFile(files.example, 'utf8')).provider, bridge.id);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('bridge export replaces a schema symlink without modifying its target', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-bridge-symlink-'));
  const outside = path.join(directory, 'outside.txt');
  try {
    await writeFile(outside, 'sentinel');
    await symlink(outside, path.join(directory, 'cloudflare-bridge.schema.json'));
    await exportBridge('cloudflare', directory);
    assert.equal(await readFile(outside, 'utf8'), 'sentinel');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('bridge export refuses a symlinked output ancestor before creating child directories', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-bridge-ancestor-'));
  const outside = path.join(directory, 'outside');
  const linked = path.join(directory, 'linked');
  try {
    await mkdir(outside);
    await symlink(outside, linked);
    await assert.rejects(exportBridge('anthropic', path.join(linked, 'handoff')), /symbolic link/i);
    await assert.rejects(access(path.join(outside, 'handoff')));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('imports documented contract findings as imported provenance for both providers', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-import-'));
  const file = path.join(directory, 'input.json');
  try {
    for (const provider of ['cloudflare', 'anthropic']) {
      await writeFile(file, JSON.stringify({ schemaVersion: 1, provider, findings: [{
        toolId: provider, ruleId: 'R-1', title: 'Potential issue', severity: 'medium',
        location: { path: 'src/app.js', line: 7 }, verification: 'candidate', evidence: { trace: ['step'] },
      }] }));
      const run = await importBridge(provider, file, '/repo');
      assert.equal(run.tools[0].status, 'imported');
      assert.ok(Array.isArray(run.tools[0].findings));
      assert.equal(run.findings[0].verification, 'candidate');
      assert.equal(run.findings[0].toolId, provider);
      const paths = await writeReports(run, path.join(directory, `${provider}-reports`));
      assert.match(await readFile(paths.html, 'utf8'), /Imported results are external reports/);
      assert.equal(JSON.parse(await readFile(paths.json, 'utf8')).findings.length, 1);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('rejects undeclared contract properties and invalid declared field types', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-contract-types-'));
  const file = path.join(directory, 'input.json');
  const record = { toolId: 'scanner', ruleId: 'R-1', title: 'Issue', severity: 'low', location: { path: 'a.js' } };
  try {
    for (const input of [
      { schemaVersion: 1, provider: 'cloudflare', findings: [record], unexpected: true },
      { schemaVersion: 1, provider: 'cloudflare', findings: [{ ...record, id: 7 }] },
      { schemaVersion: 1, provider: 'cloudflare', findings: [{ ...record, vulnerabilityId: 9 }] },
      { schemaVersion: 1, provider: 'cloudflare', findings: [{ ...record, description: {} }] },
      { schemaVersion: 1, provider: 'cloudflare', findings: [{ ...record, location: { path: 'a.js', extra: true } }] },
    ]) {
      await writeFile(file, JSON.stringify(input));
      await assert.rejects(importBridge('cloudflare', file, '/repo'));
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('rejects wrong provider, empty unsupported input, and malformed findings', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-invalid-'));
  const file = path.join(directory, 'input.json');
  try {
    await writeFile(file, JSON.stringify({ schemaVersion: 1, provider: 'cloudflare', findings: [] }));
    await assert.rejects(importBridge('anthropic', file, '/repo'), /provider/i);
    await writeFile(file, JSON.stringify({ schemaVersion: 1, provider: 'cloudflare', findings: [] }));
    await assert.rejects(importBridge('cloudflare', file, '/repo'), /empty|finding/i);
    await writeFile(file, JSON.stringify([{ verdict: 'rejected' }]));
    await assert.rejects(importBridge('cloudflare', file, '/repo'), /schema|fingerprint|malformed/i);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('imports supported Cloudflare native findings and excludes rejected findings from vulnerabilities', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-cloudflare-'));
  const file = path.join(directory, 'native.json');
  try {
    const native = {
      verdict: 'confirmed', fingerprint: 'AUDIT-1', title: 'Access control bypass', description: 'Issue',
      root_cause: 'Missing guard', intended_behavior: 'Restrict access',
      trace: [{ kind: 'entrypoint', file: 'src/api.js', line: 3, scope: 'request', description: 'entry' }],
      evidence: [{ file: 'src/api.js', line: 3, description: 'repro' }], conditions: [],
      execution: { attacker_perspective: 'User', payloads: ['request'], instructions: ['Send request'], observed_result: 'Access granted' },
      remediation: { strategy: 'Add check' },
      severity: { likelihood: { score: 'high', reason: 'Reachable' }, impact: { score: 'high', reason: 'Sensitive data' }, overall_severity: 'high' },
      confidence: { score: 'high', reason: 'Reproduced' },
    };
    await writeFile(file, JSON.stringify([native]));
    const run = await importBridge('cloudflare', file, '/repo');
    assert.equal(run.findings.length, 1);
    assert.equal(run.findings[0].verification, 'confirmed');
    assert.equal(run.findings[0].location.path, 'src/api.js');
    await writeFile(file, JSON.stringify([{ verdict: 'rejected', fingerprint: 'AUDIT-2', title: 'Refuted issue', description: 'Not exploitable', claimed_root_cause: 'Claimed guard failure', trace: native.trace, evidence: native.evidence, reason: 'Validation showed guard is effective' }]));
    const rejected = await importBridge('cloudflare', file, '/repo');
    assert.equal(rejected.findings.length, 0);
    assert.equal(rejected.tools[0].artifacts.rejected, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('validates Cloudflare needs_validation shape and fingerprint pattern strictly', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-cloudflare-validation-'));
  const file = path.join(directory, 'native.json');
  try {
    const candidate = {
      verdict: 'needs_validation', fingerprint: 'AUDIT:CANDIDATE-1', title: 'Candidate', description: 'Potential issue',
      claimed_root_cause: 'Missing check',
      trace: [{ kind: 'entrypoint', file: 'src/api.js', line: 3, scope: 'request', description: 'entry' }],
      evidence: [{ file: 'src/api.js', line: 3, description: 'trace evidence' }], blockers: ['Local dependency unavailable'], validation_plan: {},
    };
    await writeFile(file, JSON.stringify([candidate]));
    const run = await importBridge('cloudflare', file, '/repo');
    assert.equal(run.findings[0].verification, 'candidate');
    for (const malformed of [
      { ...candidate, blockers: [null] },
      { ...candidate, validation_plan: { local: 123 } },
      { ...candidate, fingerprint: 'bad fingerprint spaces' },
      { ...candidate, unexpected: true },
    ]) {
      await writeFile(file, JSON.stringify([malformed]));
      await assert.rejects(importBridge('cloudflare', file, '/repo'));
    }
    const rejected = { verdict: 'rejected', fingerprint: 123, title: 'Refuted', description: 'Not an issue', claimed_root_cause: 'Claimed issue', trace: candidate.trace, evidence: candidate.evidence, reason: 'Refuted by validation' };
    await writeFile(file, JSON.stringify([rejected]));
    await assert.rejects(importBridge('cloudflare', file, '/repo'), /fingerprint/i);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('redacts configured-looking secrets from imported evidence in regenerated reports', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sec-hub-import-secret-'));
  const file = path.join(directory, 'input.json');
  const secret = 'synthetic-review-secret-value';
  const oldSecret = process.env.REVIEW_API_KEY;
  try {
    process.env.REVIEW_API_KEY = secret;
    await writeFile(file, JSON.stringify({ schemaVersion: 1, provider: 'anthropic', findings: [{
      toolId: 'harness', ruleId: 'R-SECRET', title: 'Evidence redaction check', severity: 'info',
      location: { path: 'src/check.js' }, evidence: { note: `copied sample secret ${secret}` },
    }] }));
    const run = await importBridge('anthropic', file, '/repo');
    const paths = await writeReports(run, path.join(directory, 'reports'));
    for (const output of [paths.json, paths.html]) assert.doesNotMatch(await readFile(output, 'utf8'), new RegExp(secret));
  } finally {
    if (oldSecret === undefined) delete process.env.REVIEW_API_KEY;
    else process.env.REVIEW_API_KEY = oldSecret;
    await rm(directory, { recursive: true, force: true });
  }
});
