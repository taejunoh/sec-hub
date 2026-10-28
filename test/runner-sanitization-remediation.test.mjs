import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const runnerUrl = new URL('../src/runner.mjs', import.meta.url).href;
const reportsUrl = new URL('../src/reports.mjs', import.meta.url).href;

// Each filesystem fault lives in its own process, including synchronized ESM
// bindings, so it cannot affect another test file or the parent's cleanup.
async function scenario(body) {
  const source = `
    import assert from 'node:assert/strict';
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    import { join } from 'node:path';
    import { tmpdir } from 'node:os';
    const original = Object.fromEntries(['readFile','readdir','rename','rm','lstat','open'].map(key => [key, fs[key]]));
    const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'sec-runner-sanitization-')));
    const target = join(root, 'target'), out = join(root, 'out');
    await fs.mkdir(target);
    const secret = 'synthetic-runner-secret-038';
    process.env.SEC_HUB_REMEDIATION_SECRET = secret;
    const { runScan } = await import(${JSON.stringify(runnerUrl)});
    const { writeReports } = await import(${JSON.stringify(reportsUrl)});
    const raw = join(out, 'raw', 'affected');
    const nativePath = join(raw, 'private-native-evidence.json');
    const fault = () => Object.assign(new Error('synthetic filesystem failure ' + secret + ' ' + nativePath), { code: 'EACCES' });
    let reads = 0;
    function readFailure() {
      fs.readFile = async (file, ...args) => {
        if (String(file) === join(raw, '00-fail.txt')) { reads++; throw fault(); }
        return original.readFile(file, ...args);
      };
    }
    function adapter(id, overrides = {}) {
      return {
        id, name: id, source: 'offline synthetic fixture', kind: 'local',
        check: async () => ({ available: true }),
        build: async () => ({ command: process.execPath, args: ['-e', 'console.log("synthetic stdout");console.error("synthetic stderr")'], successCodes: [0] }),
        parse: async () => [], ...overrides,
      };
    }
    const affected = adapter('affected', {
      check: async ctx => {
        await fs.writeFile(join(ctx.artifactDir, '00-fail.txt'), secret);
        await fs.writeFile(join(ctx.artifactDir, '99-later.txt'), secret);
        await fs.mkdir(join(ctx.artifactDir, 'nested'));
        await fs.writeFile(join(ctx.artifactDir, 'nested', 'secret.txt'), secret);
        return { available: true };
      },
      parse: async () => [{
        toolId: 'preserved', ruleId: 'AFFECTED', title: 'Affected finding', severity: 'high',
        location: { path: nativePath }, rawRef: nativePath,
        evidence: { nativePath, text: secret },
        sourceRecords: [{ toolId: 'preserved', rawRef: nativePath, evidence: { nativePath, text: secret } }],
      }],
      executionMetadata: async () => ({ nativePath }),
    });
    const absent = async file => assert.rejects(original.lstat(file), { code: 'ENOENT' });
    try {
      ${body}
    } finally {
      Object.assign(fs, original); syncBuiltinESMExports();
      delete process.env.SEC_HUB_REMEDIATION_SECRET;
      await fs.rm(root, { recursive: true, force: true });
    }
  `;
  const result = await execute(process.execPath, ['--input-type=module', '-e', source], { timeout: 15000, maxBuffer: 1024 * 1024 })
    .catch(error => { throw new Error(error.stderr || error.message); });
  assert.equal(result.stderr, '');
}

// Removing failed-tool cleanup or retaining any finding copies must expose the
// raw subtree or its native paths to this real run/report publication boundary.
for (const failure of ['read', 'nested traversal', 'atomic rewrite']) {
  test(`sanitization ${failure} failure discards the whole tool subtree and all finding references`, async () => {
    const inject = failure === 'read' ? 'readFailure();' : failure === 'nested traversal' ? `
      fs.readdir = async (directory, ...args) => {
        if (String(directory) === join(raw, 'nested')) { reads++; throw fault(); }
        return original.readdir(directory, ...args);
      };` : `
      fs.rename = async (from, to, ...args) => {
        if (String(to) === join(raw, '00-fail.txt')) { reads++; throw fault(); }
        return original.rename(from, to, ...args);
      };`;
    await scenario(`
      ${inject}
      syncBuiltinESMExports();
      const run = await runScan({ target, out, tools: ['affected'], adapters: [affected] });
      assert.equal(reads, 1, 'the intended sanitizer fault must be reached');
      await absent(raw);
      assert.equal(run.status, 'failed');
      assert.equal(run.tools[0].status, 'failed');
      assert.deepEqual(run.tools[0].findings, []);
      assert.deepEqual(run.findings, []);
      assert.equal(run.tools[0].artifacts, undefined);
      assert.equal(run.tools[0].execution, undefined);
      assert.equal(run.tools[0].reason, 'Artifact sanitization failed; affected tool artifacts and findings were discarded.');
      await writeReports(run, out);
      for (const filename of ['run.json', 'report.html', 'results.sarif']) {
        const serialized = await original.readFile(join(out, filename), 'utf8');
        assert.ok(!serialized.includes(secret), filename + ' must not contain the synthetic secret');
        assert.ok(!serialized.includes(nativePath), filename + ' must not advertise discarded native paths');
        assert.ok(!serialized.includes('AFFECTED'), filename + ' must not retain discarded findings');
      }
      const saved = JSON.parse(await original.readFile(join(out, 'run.json'), 'utf8'));
      assert.deepEqual(saved.findings, []);
      assert.deepEqual(saved.tools[0].findings, []);
      assert.equal(saved.tools[0].artifacts, undefined);
    `);
  });
}

test('discarding findings uses producer ownership and preserves another completed tool despite spoofed toolId', async () => {
  await scenario(`
    readFailure(); syncBuiltinESMExports();
    const preserved = adapter('preserved', {
      check: async ctx => { await fs.writeFile(join(ctx.artifactDir, 'native.txt'), secret); return { available: true }; },
      parse: async () => [{ toolId: 'affected', ruleId: 'PRESERVED', title: 'Preserved finding', severity: 'low', location: { path: 'source.js' } }],
      executionMetadata: async () => ({ mode: 'synthetic' }),
    });
    const run = await runScan({ target, out, tools: ['affected', 'preserved'], adapters: [preserved, affected] });
    await absent(raw);
    assert.equal(run.status, 'partial');
    assert.deepEqual(run.findings.map(f => f.ruleId), ['PRESERVED']);
    const kept = run.tools[0];
    assert.equal(kept.status, 'completed');
    assert.deepEqual(kept.execution, { mode: 'synthetic' });
    assert.deepEqual(kept.findings.map(f => f.ruleId), ['PRESERVED']);
    assert.equal(await original.readFile(join(out, 'raw', 'preserved', 'native.txt'), 'utf8'), '[REDACTED]');
    assert.match(await original.readFile(kept.artifacts.stdout, 'utf8'), /synthetic stdout/);
    const saved = JSON.parse(await original.readFile(join(out, 'run.json'), 'utf8'));
    assert.deepEqual(saved.findings.map(f => f.ruleId), ['PRESERVED']);
  `);
});

for (const cleanup of ['throws', 'returns without removal', 'absence check fails']) {
  test(`unconfirmed cleanup (${cleanup}) rejects without publishing a run or leaking the filesystem error`, async () => {
    await scenario(`
      readFailure();
      ${cleanup === 'throws' ? `fs.rm = async file => { if (String(file) === raw) throw fault(); return original.rm(file, { recursive: true, force: true }); };` : cleanup === 'returns without removal' ? `fs.rm = async (file, ...args) => { if (String(file) === raw) return; return original.rm(file, ...args); };` : `
        let removed = false;
        fs.rm = async (file, ...args) => { const result = await original.rm(file, ...args); if (String(file) === raw) removed = true; return result; };
        fs.lstat = async (file, ...args) => { if (removed && String(file) === raw) throw fault(); return original.lstat(file, ...args); };`}
      syncBuiltinESMExports();
      let returned = false;
      await assert.rejects(async () => {
        const run = await runScan({ target, out, tools: ['affected'], adapters: [affected] });
        returned = true;
        await writeReports(run, out);
      }, error => {
        assert.equal(error.message, 'Artifact sanitization failed and cleanup could not be confirmed; scan results were not published.');
        assert.ok(!String(error).includes(secret));
        assert.ok(!String(error).includes(nativePath));
        assert.equal(error.cause, undefined);
        return true;
      });
      assert.equal(returned, false);
      assert.equal(reads, 1);
      for (const name of ['run.json', 'report.html', 'results.sarif']) await absent(join(out, name));
    `);
  });
}

test('metadata-only validation failure retains already sanitized artifacts and findings', async () => {
  await scenario(`
    affected.executionMetadata = async () => { throw new Error('missing synthetic completion evidence'); };
    const run = await runScan({ target, out, tools: ['affected'], adapters: [affected] });
    assert.equal(run.tools[0].status, 'failed');
    assert.equal(run.tools[0].reason, 'missing synthetic completion evidence');
    assert.equal(run.findings.length, 1);
    assert.equal(run.tools[0].findings.length, 1);
    assert.ok(run.tools[0].artifacts.stdout);
    assert.equal(await original.readFile(join(raw, '99-later.txt'), 'utf8'), '[REDACTED]');
    assert.ok(!JSON.stringify(run).includes(secret));
  `);
});

for (const lateWriter of ['completes', 'rejects']) {
  test(`stdout/stderr writers settle before cleanup when one rejects and the delayed writer ${lateWriter}`, async () => {
    await scenario(`
      let settled = false, sanitizedWhilePending = false;
      readFailure();
      const failingRead = fs.readFile;
      fs.readFile = async (file, ...args) => {
        if (String(file) === join(raw, '00-fail.txt')) sanitizedWhilePending = !settled;
        return failingRead(file, ...args);
      };
      fs.open = async (file, ...args) => {
        if (String(file).startsWith(join(raw, '.stdout.txt.'))) throw fault();
        if (String(file).startsWith(join(raw, '.stderr.txt.'))) {
          await new Promise(resolve => setTimeout(resolve, 120));
          ${lateWriter === 'rejects' ? 'settled = true; throw fault();' : ''}
        }
        return original.open(file, ...args);
      };
      fs.rename = async (from, to, ...args) => {
        const result = await original.rename(from, to, ...args);
        if (String(to) === join(raw, 'stderr.txt')) settled = true;
        return result;
      };
      syncBuiltinESMExports();
      const run = await runScan({ target, out, tools: ['affected'], adapters: [affected] });
      assert.equal(sanitizedWhilePending, false, 'sanitization must await the other runner-owned writer');
      assert.equal(settled, true);
      assert.equal(reads, 1);
      await absent(raw);
      await new Promise(resolve => setTimeout(resolve, 180));
      await absent(raw);
      assert.equal(run.tools[0].artifacts, undefined);
    `);
  });
}
