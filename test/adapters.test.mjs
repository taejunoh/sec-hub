import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, symlink, truncate } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { adapters, getAdapter } from '../src/adapters/index.mjs';

const fixtures = new URL('./fixtures/adapters/', import.meta.url);
async function fixture(name) { return JSON.parse(await readFile(new URL(name + '.json', fixtures), 'utf8')); }
async function parse(id, payload, exitCode = 0) {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-adapter-'));
  if (id !== 'php2shell') await writeFile(join(artifactDir, id === 'codex-security' ? 'findings.json' : 'native.json'), JSON.stringify(payload));
  return getAdapter(id).parse({ artifactDir, target: '/repo', url: 'http://localhost:8080/', stdout: JSON.stringify(payload), stderr: '', exitCode });
}

test('seven official integrations expose the public contract', () => {
  assert.deepEqual(adapters.map(a => a.id), ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell', 'cloudflare', 'anthropic']);
  assert.equal(getAdapter('missing'), undefined);
  for (const a of adapters) {
    assert.equal(a.kind, ['cloudflare','anthropic'].includes(a.id) ? 'agent' : 'cli');
    assert.match(a.source, /^https:\/\/github.com\//);
    assert.equal(typeof a.requiresAI, 'boolean');
    assert.equal(typeof a.check, 'function');
    assert.equal(typeof a.build, 'function');
    assert.equal(typeof a.parse, 'function');
  }
});

test('native argv preserves executable prefixes and hostile target as a single argument', () => {
  const target = '/repo name/$(touch NO); --flag';
  const ctx = { target, url: 'http://localhost:8080/', artifactDir: '/out artifacts', config: { tools: { osv: { command: '/custom/node', args: ['/custom/osv.mjs'] } } } };
  const spec = getAdapter('osv').build(ctx);
  assert.equal(spec.command, '/custom/node');
  assert.equal(spec.args[0], '/custom/osv.mjs');
  assert.ok(spec.args.includes(target));
  assert.ok(spec.args.includes('--no-resolve'));
  assert.ok(spec.args.includes('--no-call-analysis=go'));
  assert.ok(spec.args.includes('--no-call-analysis=rust'));
  assert.deepEqual(spec.findingCodes, [1]);
  const skill = getAdapter('skillspector').build(ctx);
  assert.ok(skill.args.includes('--no-llm'));
  const ocr = getAdapter('open-code-review').build(ctx);
  assert.deepEqual(ocr.args.slice(0, 5), ['scan', '--repo', target, '--format', 'json']);
  assert.equal(getAdapter('php2shell').build({ ...ctx, config: { tools: { php2shell: { command: 'node', args: ['/checker/phpcheck.js'] } } } }).args[0], '/checker/phpcheck.js');
});

test('OSV maps package advisories, aliases, severity and native evidence', async () => {
  const out = await parse('osv', await fixture('osv-positive'), 1);
  assert.equal(out.length, 1);
  assert.equal(out[0].vulnerabilityId, 'GHSA-aaaa-bbbb-cccc');
  assert.equal(out[0].severity, 'high');
  assert.deepEqual(out[0].location, { path: '/repo/package-lock.json', package: 'npm:example', version: '1.0.0' });
  assert.deepEqual(out[0].aliases, ['CVE-2026-12345']);
  assert.equal(out[0].evidence.nativeSeverity, '8.1');
  assert.equal(out[0].verification, 'reported');
});

test('OSV clean, unknown severity, malformed nested records and failure exits', async () => {
  assert.deepEqual(await parse('osv', { results: [] }), []);
  const data = await fixture('osv-positive');
  data.results[0].packages[0].groups[0].max_severity = 'new-rating';
  assert.equal((await parse('osv', data, 1))[0].severity, 'unknown');
  await assert.rejects(parse('osv', { results: [{}] }), /OSV/);
  await assert.rejects(parse('osv', { results: [] }, 128), /exit/);
  await assert.rejects(parse('osv', {}), /OSV/);
});

test('SkillSpector current issues schema preserves rule, locations and remediation', async () => {
  const out = await parse('skillspector', await fixture('skillspector-positive'), 1);
  assert.equal(out[0].ruleId, 'static.shell.remote-exec');
  assert.equal(out[0].id, 'finding-demo');
  assert.equal(out[0].severity, 'critical');
  assert.equal(out[0].location.line, 8);
  assert.equal(out[0].evidence.remediation, 'Avoid remote execution.');
  assert.equal(out[0].verification, 'candidate');
});

test('SkillSpector clean and incomplete results are distinguished; valid partial findings retained', async () => {
  const data = await fixture('skillspector-positive');
  assert.deepEqual(await parse('skillspector', { ...data, issues: [] }), []);
  data.analysis_completeness = { status: 'partial', is_complete: false };
  await assert.rejects(parse('skillspector', data), e => e.findings?.length === 1 && /incomplete/i.test(e.message));
  await assert.rejects(parse('skillspector', { findings: [] }), /SkillSpector/);
  await assert.rejects(parse('skillspector', { ...data, issues: [{}] }), /SkillSpector/);
  await assert.rejects(parse('skillspector', data, 2), /exit/);
});

test('Codex Security exported schema maps occurrences and evidence', async () => {
  const data = await fixture('codex-positive');
  const out = await parse('codex-security', data);
  assert.equal(out[0].ruleId, 'sql-injection');
  assert.equal(out[0].id, 'occ_aaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(out[0].severity, 'high');
  assert.equal(out[0].location.path, 'src/db.ts');
  assert.equal(out[0].location.line, 42);
  assert.equal(out[0].evidence.codeEvidence[0].code, 'query(userInput)');
  assert.equal(out[0].verification, 'reported');
  assert.deepEqual(await parse('codex-security', { ...data, findings: [] }), []);
  await assert.rejects(parse('codex-security', { findings: [] }), /Codex Security/);
  await assert.rejects(parse('codex-security', { ...data, findings: [{}] }), /Codex Security/);
  await assert.rejects(parse('codex-security', data, 2), /exit/);
});

test('OCR full-scan comments preserve categories, source and unknown severity', async () => {
  const data = await fixture('ocr-positive');
  const out = await parse('open-code-review', data);
  assert.equal(out[0].ruleId, 'security');
  assert.equal(out[0].severity, 'medium');
  assert.equal(out[0].location.line, 11);
  assert.equal(out[0].evidence.existingCode, 'danger(input)');
  assert.deepEqual(await parse('open-code-review', { status: 'success', comments: [] }), []);
  data.comments[0].severity = 'future';
  assert.equal((await parse('open-code-review', data))[0].severity, 'unknown');
  data.status = 'completed_with_errors';
  await assert.rejects(parse('open-code-review', data), e => e.findings?.length === 1 && /incomplete/.test(e.message));
  await assert.rejects(parse('open-code-review', { comments: [] }), /Open Code Review/);
  await assert.rejects(parse('open-code-review', { status: 'success', comments: [{}] }), /Open Code Review/);
});

test('PHP heuristic emits potentially vulnerable and unknown findings without claiming confirmation', async () => {
  const positive = { patch_status: 'potentially_vulnerable', php_version: '8.2.34', reason: 'Header only; backport unknown.', exit_code: 1 };
  const out = await parse('php2shell', positive, 1);
  assert.equal(out[0].severity, 'high');
  assert.equal(out[0].verification, 'candidate');
  assert.equal(out[0].location.url, 'http://localhost:8080/');
  assert.equal(out[0].evidence.patchStatus, 'potentially_vulnerable');
  assert.deepEqual(await parse('php2shell', { ...positive, patch_status: 'ok', exit_code: 0 }, 0), []);
  assert.equal((await parse('php2shell', { ...positive, patch_status: 'unknown', php_version: null, exit_code: 3 }, 3))[0].severity, 'unknown');
  await assert.rejects(parse('php2shell', { ...positive, exit_code: 0 }, 0), /exit/);
  await assert.rejects(parse('php2shell', {}), /PHP2Shell/);
  await assert.rejects(parse('php2shell', positive, 2), /exit/);
});

test('parsers reject invalid JSON and absent native output rather than assuming clean', async () => {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-malformed-'));
  for (const a of adapters) {
    await assert.rejects(a.parse({ artifactDir, stdout: 'not-json', exitCode: 0 }), /JSON|native|output/i);
  }
  await writeFile(join(artifactDir, 'native.json'), '{broken');
  await assert.rejects(getAdapter('osv').parse({ artifactDir, exitCode: 0 }), /JSON/);
  await truncate(join(artifactDir, 'native.json'), 21 * 1024 * 1024);
  await assert.rejects(getAdapter('osv').parse({ artifactDir, exitCode: 0 }), /limit/);
});

test('native JSON parser refuses symbolic links', async () => {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-link-'));
  await writeFile(join(artifactDir, 'other.json'), '{"results":[]}');
  await symlink(join(artifactDir, 'other.json'), join(artifactDir, 'native.json'));
  await assert.rejects(getAdapter('osv').parse({ artifactDir, exitCode: 0 }), /native/);
});

test('Codex parser rejects missing identity evidence and OCR detects native review limits', async () => {
  const data = await fixture('codex-positive');
  delete data.findings[0].identity;
  await assert.rejects(parse('codex-security', data), /Codex Security/);
  const ocr = await fixture('ocr-positive');
  ocr.status = 'completed_with_warnings';
  ocr.warnings = [{ type: 'review_limit_reached', message: 'Partial work.' }];
  await assert.rejects(parse('open-code-review', ocr), e => e.findings?.length === 1);
});

test('CLI prerequisite probes execute only --version and reject missing executables', async () => {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-probe-'));
  const fake = join(artifactDir, 'probe.mjs');
  await writeFile(fake, `if (process.argv[2] !== '--version') process.exit(5); console.log('scanner 1.2.3');`);
  for (const a of adapters.filter(adapter=>adapter.kind==='cli')) {
    const config = { tools: { [a.id]: { command: process.execPath, args: [fake] } } };
    const result = await a.check({ config, url: 'http://localhost/', artifactDir });
    assert.equal(result.available, true, a.id + ': ' + result.reason);
    assert.match(result.version, /1\.2\.3/);
    assert.equal((await a.check({ ...config, config: { tools: { [a.id]: { command: join(artifactDir, 'missing') } } }, url: 'http://localhost/' })).available, false);
  }
  assert.equal((await getAdapter('php2shell').check({ config: {} })).available, false);
  assert.equal((await getAdapter('codex-security').check({ config: {} })).available, false);
});

test('version probe escalates timeout and terminates a SIGTERM-resistant descendant', { timeout: 5000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sec-probe-timeout-'));
  const fake = join(directory, 'probe.mjs');
  const pidFile = join(directory, 'pids.json');
  await writeFile(fake, `import {spawn} from 'node:child_process'; import {writeFileSync} from 'node:fs';
    process.on('SIGTERM',()=>{});
    const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});process.send('ready');setInterval(()=>{},1000)"],{stdio:['ignore','ignore','ignore','ipc']});
    child.on('message',()=>writeFileSync(${JSON.stringify(pidFile)},JSON.stringify([process.pid,child.pid])));
    setInterval(()=>{},1000);`);
  let pids = [];
  let deadline;
  const started = Date.now();
  try {
    const check = getAdapter('osv').check({ probeTimeoutMs: 300, config: { tools: { osv: { command: process.execPath, args: [fake] } } } });
    const guard = new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('version probe exceeded bounded timeout')), 1800); });
    const result = await Promise.race([check, guard]);
    pids = JSON.parse(await readFile(pidFile, 'utf8'));
    assert.equal(result.available, false);
    assert.match(result.reason, /timed out/i);
    assert.ok(Date.now() - started < 1800);
    for (const pid of pids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  } finally {
    clearTimeout(deadline);
    if (!pids.length) { try { pids = JSON.parse(await readFile(pidFile, 'utf8')); } catch {} }
    for (const pid of pids) { try { process.kill(pid, 'SIGKILL'); } catch {} }
  }
});

test('version probe cancellation is bounded and an already-aborted probe never spawns', { timeout: 5000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sec-probe-cancel-'));
  const fake = join(directory, 'probe.mjs');
  const pidFile = join(directory, 'pid.txt');
  await writeFile(fake, `import {writeFileSync} from 'node:fs';process.on('SIGTERM',()=>{});writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);`);
  const config = { tools: { osv: { command: process.execPath, args: [fake] } } };
  const controller = new AbortController();
  const check = getAdapter('osv').check({ config, signal: controller.signal });
  let deadline;
  let pid;
  try {
    for (let n = 0; n < 40; n++) { try { pid = Number(await readFile(pidFile, 'utf8')); break; } catch { await new Promise(resolve => setTimeout(resolve, 10)); } }
    assert.ok(pid, 'controlled executable started');
    controller.abort();
    const result = await Promise.race([check, new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('version probe ignored cancellation')), 1800); })]);
    assert.equal(result.available, false);
    assert.match(result.reason, /cancel/i);
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
    const preAborted = new AbortController(); preAborted.abort();
    const missingExecutable = { tools: { osv: { command: join(directory, 'must-not-start') } } };
    assert.match((await getAdapter('osv').check({ config: missingExecutable, signal: preAborted.signal })).reason, /cancel/i);
  } finally { clearTimeout(deadline); if (pid) { try { process.kill(pid, 'SIGKILL'); } catch {} } }
});

test('Codex wrapper scans then exports fixed results and preserves native streams', async () => {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-codex-wrapper-'));
  const fake = join(artifactDir, 'fake-cs.mjs');
  const native = await fixture('codex-positive');
  await writeFile(fake, `import {writeFile,mkdir} from 'node:fs/promises'; import {join} from 'node:path';
    const a=process.argv.slice(2); console.log(a[0]+' native stdout'); console.error(a[0]+' native stderr');
    if(a[0]==='scan'){await mkdir(a[a.indexOf('--output-dir')+1],{recursive:true}); process.exitCode=1;}
    else if(a[0]==='export'){await writeFile(a[a.indexOf('--output')+1],${JSON.stringify(JSON.stringify(native))});}
    else process.exitCode=2;`);
  const spec = getAdapter('codex-security').build({ target: '/repo', artifactDir, config: { tools: { 'codex-security': { command: process.execPath, args: [fake] } } } });
  const result = await new Promise((resolve, reject) => { const p=spawn(spec.command,spec.args,{shell:false}); let stdout='',stderr=''; p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);p.on('error',reject);p.on('close',exitCode=>resolve({stdout,stderr,exitCode})); });
  assert.equal(result.exitCode,1);
  assert.match(result.stdout,/scan native stdout/);
  assert.match(result.stdout,/export native stdout/);
  assert.match(await readFile(join(artifactDir,'scan.stderr.log'),'utf8'),/scan native stderr/);
  assert.equal((await getAdapter('codex-security').parse({ artifactDir, ...result })).length,1);
});

test('Codex wrapper forwards termination and does not export a failed scan', async () => {
  const artifactDir = await mkdtemp(join(tmpdir(), 'sec-codex-cancel-'));
  const fake = join(artifactDir, 'slow-cs.mjs');
  await writeFile(fake, `if(process.argv[2]!=='scan')process.exit(9); process.on('SIGTERM',()=>{console.log('native-terminated');process.exit(143)});console.log('native-ready');setInterval(()=>{},1000);`);
  const spec = getAdapter('codex-security').build({ target: '/repo', artifactDir, config: { tools: { 'codex-security': { command: process.execPath, args: [fake] } } } });
  const result = await new Promise((resolve, reject) => {
    const p=spawn(spec.command,spec.args,{shell:false}); let output='';
    const timer=setTimeout(()=>{p.kill('SIGKILL');reject(new Error('termination was not forwarded'));},5000);
    p.stdout.on('data',b=>{output+=b;if(output.includes('native-ready'))p.kill('SIGTERM');});
    p.on('error',reject); p.on('close',exitCode=>{clearTimeout(timer);resolve({exitCode,output});});
  });
  assert.equal(result.exitCode,143);
  assert.match(result.output,/native-terminated/);
  await assert.rejects(readFile(join(artifactDir,'export.stdout.log')), { code: 'ENOENT' });
});

test('AI scan flags are appended after subcommands while probes retain only executable prefixes',async()=>{
  const artifactDir=await mkdtemp(join(tmpdir(),'sec-ai-options-'));
  const fake=join(artifactDir,'probe.mjs');
  await writeFile(fake,`if(JSON.stringify(process.argv.slice(2))!==JSON.stringify(['--version']))process.exit(3);else console.log('fixture 1.0');`);
  const scanOptions={provider:'chatgpt',model:'gpt-6.1-sol',maxTokensBudget:20000,concurrency:1,timeoutMinutes:3,noPlan:true,noDedup:false,noSummary:true};
  const config={tools:{'open-code-review':{command:process.execPath,args:[fake],scanOptions}}};
  const adapter=getAdapter('open-code-review');
  assert.equal((await adapter.check({config})).available,true);
  assert.deepEqual(adapter.build({target:'/repo',artifactDir,config}).args,[fake,'scan','--repo','/repo','--format','json','--output',join(artifactDir,'native.json'),'--provider','chatgpt','--model','gpt-6.1-sol','--max-tokens-budget','20000','--concurrency','1','--timeout','3','--no-plan','--no-summary']);
  assert.throws(()=>adapter.build({target:'/repo',artifactDir,config:{tools:{'open-code-review':{command:'ocr',scanOptions:{patch:true}}}}}),/scanOptions/);
});

test('Codex wrapper applies scan options only to scan and keeps native result directory external',async()=>{
  const artifactDir=await mkdtemp(join(tmpdir(),'sec-codex-options-')),fake=join(artifactDir,'fake-cs.mjs');
  const native=await fixture('codex-positive');
  await writeFile(fake,`import {writeFile,mkdir} from 'node:fs/promises';
    const a=process.argv.slice(2);console.log(JSON.stringify(a));
    if(a[0]==='scan')await mkdir(a[a.indexOf('--output-dir')+1],{recursive:true});
    else if(a[0]==='export')await writeFile(a[a.indexOf('--output')+1],${JSON.stringify(JSON.stringify(native))});else process.exitCode=2;`);
  const scanOptions={auth:'chatgpt',model:'gpt-6.1-sol',effort:'medium',maxCost:2,maxTimeMinutes:3};
  const spec=getAdapter('codex-security').build({target:artifactDir,artifactDir,config:{tools:{'codex-security':{command:process.execPath,args:[fake],scanOptions}}}});
  const result=await new Promise((resolve,reject)=>{const p=spawn(spec.command,spec.args,{shell:false});let stdout='';p.stdout.on('data',b=>stdout+=b);p.on('error',reject);p.on('close',code=>resolve({code,stdout}));});
  assert.equal(result.code,0);
  const [scan,exported]=result.stdout.trim().split('\n').map(line=>JSON.parse(line));
  assert.deepEqual(scan.slice(-10),['--auth','chatgpt','--model','gpt-6.1-sol','--effort','medium','--max-cost','2','--max-time','3']);
  assert.equal(scan[scan.indexOf('--output-dir')+1].startsWith(artifactDir),false);
  assert.deepEqual(exported.slice(2),['--export-format','json','--output',join(artifactDir,'findings.json')]);
});
