import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, symlink, mkdir, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const runner = await import('../src/runner.mjs').catch(() => ({}));
const configuration = await import('../src/config.mjs').catch(() => ({}));
const node = (source, ...args) => ({command:process.execPath,args:['-e',source,...args],successCodes:[0]});
const temp = () => mkdtemp(join(tmpdir(),'sec-hub-core-'));

test('spawn preserves hostile arguments as literal argv', async () => {
  assert.equal(typeof runner.runProcess,'function');
  const literal='$(touch /tmp/sec-hub-injection); & " spaces';
  const result=await runner.runProcess(node('console.log(JSON.stringify(process.argv.slice(1)))',literal));
  assert.equal(result.status,'completed');
  assert.deepEqual(JSON.parse(result.stdout),[literal]);
});
test('missing executable and unexpected nonzero exit are failures', async () => {
  assert.equal(typeof runner.runProcess,'function');
  assert.equal((await runner.runProcess({command:'/definitely/missing/sec-hub',args:[],successCodes:[0]})).status,'failed');
  const result=await runner.runProcess(node('process.exit(7)'));
  assert.equal(result.status,'failed');
  assert.equal(result.exitCode,7);
});
test('finding exit codes remain parseable completed processes', async () => {
  assert.equal(typeof runner.runProcess,'function');
  const result=await runner.runProcess({...node('process.exit(1)'),findingCodes:[1]});
  assert.equal(result.status,'completed');
});
test('timeout and cancellation remain distinct from scan success', async () => {
  assert.equal(typeof runner.runProcess,'function');
  assert.equal((await runner.runProcess(node('setInterval(()=>{},1000)'),{timeoutMs:40})).status,'timed_out');
  const controller=new AbortController();
  const pending=runner.runProcess(node('setInterval(()=>{},1000)'),{signal:controller.signal});
  setTimeout(()=>controller.abort(),30);
  assert.equal((await pending).status,'cancelled');
});
test('output bounds fail instead of accepting truncated clean results', async () => {
  assert.equal(typeof runner.runProcess,'function');
  const result=await runner.runProcess(node('process.stdout.write("x".repeat(100000));setInterval(()=>{},1000)'),{maxOutputBytes:1024});
  assert.equal(result.status,'failed');
  assert.match(result.reason,/output/i);
  assert.ok(Buffer.byteLength(result.stdout)<=1024);
});
test('subprocess environment secret values are redacted from captured output', async () => {
  assert.equal(typeof runner.runProcess,'function');
  const result=await runner.runProcess(node('console.log(process.env.EXAMPLE_API_KEY)'),{env:{...process.env,EXAMPLE_API_KEY:'sensitive-example-value'}});
  assert.equal(result.status,'completed');
  assert.equal(result.stdout.trim(),'[REDACTED]');
});
test('JSON-escaped environment secrets are redacted without invalidating JSON', async () => {
  const result=await runner.runProcess(node('console.log(JSON.stringify({value:process.env.EXAMPLE_API_KEY}))'),{env:{...process.env,EXAMPLE_API_KEY:'sensitive-"quote\\slash\nend'}});
  assert.equal(JSON.parse(result.stdout).value,'[REDACTED]');
});

function fakeAdapter(id, options={}) {
  return {id,name:id,source:'controlled fixture',requiresAI:false,
    check:async()=>({available:true}),build:()=>node('console.log("[]")'),
    parse:async ctx=>JSON.parse(ctx.stdout),...options};
}
test('explicit AI selection cannot bypass consent or invoke prerequisite', async () => {
  assert.equal(typeof runner.runScan,'function');
  const directory=await temp(); let checked=false;
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['ai'],adapters:[fakeAdapter('ai',{requiresAI:true,check:async()=>{checked=true;return{available:true};}})]});
  assert.equal(checked,false);
  assert.equal(run.tools[0].status,'skipped');
  assert.equal(run.status,'failed');
});
test('invalid parser data cannot become a clean completed run', async () => {
  assert.equal(typeof runner.runScan,'function');
  const directory=await temp();
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['bad'],adapters:[fakeAdapter('bad',{parse:()=>{throw new Error('malformed output');}})]});
  assert.equal(run.tools[0].status,'failed');
  assert.equal(run.status,'failed');
  assert.deepEqual(run.findings,[]);
  assert.match(await readFile(run.tools[0].artifacts.stdout,'utf8'),/\[\]/);
});
test('missing selected tool causes partial coverage alongside a successful scan', async () => {
  assert.equal(typeof runner.runScan,'function');
  const directory=await temp();
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['ok','absent'],adapters:[fakeAdapter('ok'),fakeAdapter('absent',{check:async()=>({available:false,reason:'not installed'})})]});
  assert.equal(run.status,'partial');
  assert.deepEqual(run.tools.map(x=>x.status),['completed','skipped']);
  assert.equal(run.tools[1].selected,true);
});
test('config is explicit JSON with safe executable argv only', async () => {
  assert.equal(typeof configuration.loadConfig,'function');
  assert.deepEqual(await configuration.loadConfig(),{tools:{}});
  const directory=await temp(), file=join(directory,'config.json');
  await writeFile(file,JSON.stringify({tools:{osv:{command:'scanner',args:['prefix with spaces']}}}));
  assert.equal((await configuration.loadConfig(file)).tools.osv.args[0],'prefix with spaces');
  await writeFile(file,JSON.stringify({tools:{osv:{command:'scanner',args:'shell string'}}}));
  await assert.rejects(configuration.loadConfig(file),/args/);
});

const cliPath=new URL('../bin/sec-hub.mjs',import.meta.url);
const cli=(...args)=>spawnSync(process.execPath,[cliPath.pathname,...args],{encoding:'utf8'});
test('CLI help is actionable and rejects unknown flags before scanning',()=>{
  const help=cli('--help');assert.equal(help.status,0);assert.match(help.stdout,/doctor/);assert.match(help.stdout,/--ai/);
  const bad=cli('scan','.', '--typo');assert.equal(bad.status,2);assert.match(bad.stderr,/Unknown option/);
});
test('CLI regenerates three reports from saved run data',async()=>{
  const directory=await temp();
  const saved={schemaVersion:1,id:'test-regeneration',startedAt:'2026-10-27T00:00:00Z',endedAt:'2026-10-27T00:00:01Z',target:{path:directory},status:'completed',tools:[{id:'osv',name:'OSV',source:'fixture',status:'completed',findings:[]}],findings:[]};
  await writeFile(join(directory,'run.json'),JSON.stringify(saved));
  const result=cli('report',directory);assert.equal(result.status,0,result.stderr);
  assert.match(await readFile(join(directory,'report.html'),'utf8'),/test-regeneration/);
  const sarif=JSON.parse(await readFile(join(directory,'results.sarif'),'utf8'));assert.equal(sarif.version,'2.1.0');
});
test('CLI refuses malformed canonical runs during regeneration',async()=>{
  const directory=await temp();await writeFile(join(directory,'run.json'),'{"schemaVersion":1,"findings":[]}');
  const result=cli('report',directory);assert.equal(result.status,2);assert.match(result.stderr,/Invalid saved run/);
});
test('failed native coverage retains validated findings without claiming completion',async()=>{
  const directory=await temp();
  const finding={toolId:'partial',ruleId:'TEST-1',title:'Reported issue',severity:'high',location:{path:'a.js'}};
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['partial'],adapters:[fakeAdapter('partial',{parse:()=>{const error=new Error('Native scan incomplete');error.findings=[finding];throw error;}})]});
  assert.equal(run.status,'partial');assert.equal(run.tools[0].status,'failed');assert.equal(run.findings[0].ruleId,'TEST-1');
});
test('scanner native artifact files are redacted after parsing original output',async()=>{
  const directory=await temp(), key='SEC_HUB_TEST_API_KEY';process.env[key]='native-output-secret';
  try{
    const adapter=fakeAdapter('native',{build:ctx=>node('require("fs").writeFileSync(process.argv[1],process.env.SEC_HUB_TEST_API_KEY);console.log("[]")',join(ctx.artifactDir,'native.txt'))});
    const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['native'],adapters:[adapter]});
    assert.equal(run.status,'completed');assert.equal(await readFile(join(directory,'run','raw','native','native.txt'),'utf8'),'[REDACTED]');
  }finally{delete process.env[key];}
});
test('explicit URL selects the URL checker in the default non-AI plan',async()=>{
  const directory=await temp();
  const run=await runner.runScan({target:directory,url:'http://127.0.0.1:1234',out:join(directory,'run'),adapters:[fakeAdapter('osv'),fakeAdapter('skillspector'),fakeAdapter('php2shell')]});
  assert.equal(run.tools.find(tool=>tool.id==='php2shell').status,'completed');
});

test('timeout waits for process-group escalation after the leader closes',{skip:process.platform==='win32'},async()=>{
  const directory=await temp(), heartbeat=join(directory,'heartbeat'), pidFile=join(directory,'pid');
  const grandchild='const fs=require("node:fs");process.on("SIGTERM",()=>{});fs.writeFileSync(process.argv[2],String(process.pid));setInterval(()=>fs.appendFileSync(process.argv[1],"x"),10)';
  const leader='require("node:child_process").spawn(process.execPath,["-e",process.argv[1],process.argv[2],process.argv[3]],{stdio:"ignore"});setInterval(()=>{},1000)';
  let pid;
  try{
    const result=await runner.runProcess(node(leader,grandchild,heartbeat,pidFile),{timeoutMs:300});
    pid=Number(await readFile(pidFile,'utf8'));assert.equal(result.status,'timed_out');
    const before=await readFile(heartbeat,'utf8');await new Promise(resolve=>setTimeout(resolve,100));
    assert.equal(await readFile(heartbeat,'utf8'),before,'grandchild must stop writing before the process promise resolves');
    assert.ok(result.durationMs>=580,'timeout must wait for the 300ms SIGKILL cleanup grace');
  }finally{if(!pid)try{pid=Number(await readFile(pidFile,'utf8'));}catch{}if(pid)try{process.kill(pid,'SIGKILL');}catch{}}
});
test('scanner stdout and run symlinks cannot overwrite external files',async()=>{
  const directory=await temp(),sentinel=join(directory,'sentinel');await writeFile(sentinel,'keep me');
  const adapter=fakeAdapter('fixture',{build:ctx=>node('const f=require("node:fs"),p=require("node:path");for(const n of ["stdout.txt","stderr.txt"])f.symlinkSync(process.argv[2],p.join(process.argv[1],n));f.symlinkSync(process.argv[2],p.resolve(process.argv[1],"../..","run.json"));console.log("[]")',ctx.artifactDir,sentinel)});
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['fixture'],adapters:[adapter]});
  assert.equal(await readFile(sentinel,'utf8'),'keep me');
  assert.equal(run.status,'completed');assert.equal((await lstat(run.tools[0].artifacts.stdout)).isSymbolicLink(),false);
});
test('atomic outputs reject scanner-controlled ancestor directory links',async()=>{
  const safe=await import('../src/safe-io.mjs').catch(()=>({}));assert.equal(typeof safe.atomicWriteFile,'function');
  const directory=await temp(),outside=await temp();await symlink(outside,join(directory,'link'),'dir');
  await assert.rejects(safe.atomicWriteFile(join(directory,'link','report.html'),'unsafe'),/symbolic link/i);
});
test('scan prerequisite cancellation receives the signal and remains cancelled',async()=>{
  const directory=await temp(),controller=new AbortController();
  const adapter=fakeAdapter('fixture',{check:async ctx=>{assert.equal(ctx.signal,controller.signal);controller.abort();return{available:false,reason:'cancelled prerequisite'};}});
  const run=await runner.runScan({target:directory,out:join(directory,'run'),tools:['fixture'],adapters:[adapter],signal:controller.signal});
  assert.equal(run.tools[0].status,'cancelled');
});
test('scan refuses an output ancestor symlink before running a tool',async()=>{
  const directory=await temp(),outside=await temp();await symlink(outside,join(directory,'link'),'dir');let checked=false;
  await assert.rejects(runner.runScan({target:directory,out:join(directory,'link','run'),tools:['fixture'],adapters:[fakeAdapter('fixture',{check:async()=>{checked=true;return{available:true};}})]}),/symbolic link/i);
  assert.equal(checked,false);await assert.rejects(lstat(join(outside,'run')),/ENOENT/);
});
test('doctor CLI cancellation cleans up its version probe before returning',{skip:process.platform==='win32'},async()=>{
  const directory=await temp(),probeFile=join(directory,'probe.mjs'),pidFile=join(directory,'pid'),configFile=join(directory,'config.json');
  await writeFile(probeFile,`import {writeFileSync} from 'node:fs';process.on('SIGTERM',()=>{});writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);`);
  await writeFile(configFile,JSON.stringify({tools:{osv:{command:process.execPath,args:[probeFile]}}}));
  const child=spawn(process.execPath,[cliPath.pathname,'doctor',directory,'--json','--config',configFile],{stdio:['ignore','pipe','pipe']});
  let output='',probePid;child.stdout.on('data',chunk=>output+=chunk);
  const closed=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
  try{
    for(let i=0;i<100&&!probePid;i++){try{probePid=Number(await readFile(pidFile,'utf8'));}catch{}if(!probePid)await new Promise(resolve=>setTimeout(resolve,20));}
    assert.ok(probePid,'version probe must have started');child.kill('SIGTERM');
    const result=await Promise.race([closed,new Promise((_,reject)=>setTimeout(()=>reject(new Error('doctor cancellation did not finish')),2000).unref())]);
    assert.equal(result.code,2);assert.match(output,/cancelled/i);
    assert.throws(()=>process.kill(probePid,0),/ESRCH/);
  }finally{child.kill('SIGKILL');if(probePid)try{process.kill(probePid,'SIGKILL');}catch{}}
});

test('AI scan options accept bounded typed values and preserve executable prefixes',async()=>{
  const directory=await temp(),file=join(directory,'config.json');
  const tools={
    'codex-security':{command:'cs',args:['prefix'],scanOptions:{auth:'chatgpt',model:'gpt-6.1-sol',effort:'medium',maxCost:2,maxTimeMinutes:3}},
    'open-code-review':{command:'ocr',scanOptions:{provider:'chatgpt',model:'gpt-6.1-sol',maxTokensBudget:20000,concurrency:1,timeoutMinutes:3,noPlan:true,noDedup:false,noSummary:true}}
  };
  await writeFile(file,JSON.stringify({tools}));
  const loaded=await configuration.loadConfig(file);
  assert.deepEqual(loaded.tools['codex-security'],tools['codex-security']);
  assert.deepEqual(loaded.tools['open-code-review'].scanOptions,tools['open-code-review'].scanOptions);
});

test('AI scan options reject unknown unsafe and invalid fields before invocation',async()=>{
  const directory=await temp(),file=join(directory,'config.json');
  for(const [id,scanOptions] of [
    ['codex-security',{patch:true}],['codex-security',{outputDir:'/elsewhere'}],['codex-security',{auth:'other'}],
    ['codex-security',{model:''}],['codex-security',{effort:'max'}],['codex-security',{maxCost:0}],['codex-security',{maxTimeMinutes:-1}],
    ['open-code-review',{provider:''}],['open-code-review',{maxTokensBudget:2.5}],['open-code-review',{concurrency:0}],
    ['open-code-review',{timeoutMinutes:'3'}],['open-code-review',{noPlan:'true'}],['osv',{model:'anything'}]
  ]){
    await writeFile(file,JSON.stringify({tools:{[id]:{command:'must-not-run',scanOptions}}}));
    await assert.rejects(configuration.loadConfig(file),/scanOptions/);
  }
});

async function fiveToolConfig(directory,{failOCR=false}={}) {
  const fake=join(directory,'fake-native.mjs'),file=join(directory,'five.config.json');
  const payloads={};
  for(const [id,name] of [['osv','osv-positive'],['skillspector','skillspector-positive'],['codex-security','codex-positive'],['open-code-review','ocr-positive']])payloads[id]=JSON.parse(await readFile(new URL(`./fixtures/adapters/${name}.json`,import.meta.url),'utf8'));
  await writeFile(fake,`import {mkdir,writeFile} from 'node:fs/promises';
    const [id,...a]=process.argv.slice(2),data=${JSON.stringify(payloads)};
    if(a[0]==='--version'){console.log('controlled-fixture 1.0');process.exit(0);}
    if(id==='open-code-review'&&${JSON.stringify(failOCR)}){console.error('controlled native failure');process.exit(9);}
    if(id==='codex-security'&&a[0]==='scan'){await mkdir(a[a.indexOf('--output-dir')+1],{recursive:true});process.exit(0);}
    if(id==='php2shell'){console.log(JSON.stringify({patch_status:'potentially_vulnerable',php_version:'8.1.2',reason:'Controlled fixture',exit_code:1}));process.exit(1);}
    const flag=id==='osv'?'--output-file':'--output';
    await writeFile(a[a.indexOf(flag)+1],JSON.stringify(data[id]));`);
  const tools=Object.fromEntries(['osv','skillspector','codex-security','open-code-review','php2shell'].map(id=>[id,{command:process.execPath,args:[fake,id]}]));
  tools['codex-security'].scanOptions={auth:'chatgpt',model:'gpt-6.1-sol',effort:'medium',maxCost:2,maxTimeMinutes:3};
  tools['open-code-review'].scanOptions={provider:'chatgpt',model:'gpt-6.1-sol',maxTokensBudget:20000,concurrency:1,timeoutMinutes:3,noPlan:true,noDedup:true,noSummary:true};
  await writeFile(file,JSON.stringify({tools}));return file;
}

test('five-tool verification helper executes adapters and records reports hashes and coverage using controlled CLIs',async()=>{
  const directory=await temp(),config=await fiveToolConfig(directory),out=join(directory,'run');
  const result=await runner.runProcess({command:process.execPath,args:[new URL('../scripts/live-verify-five.mjs',import.meta.url).pathname,'--config',config,'--out',out],successCodes:[0]},{timeoutMs:15000});
  assert.equal(result.status,'completed',result.stderr);
  const evidence=JSON.parse(await readFile(join(out,'verification-commands.json'),'utf8'));
  assert.equal(evidence.verificationPassed,true);
  assert.equal(evidence.tools.length,5);
  assert.ok(evidence.tools.every(tool=>tool.status==='completed'));
  assert.equal(evidence.targetChanges.changed.length,0);
  assert.ok(evidence.targetHashes.before['server.mjs']);
  assert.ok(evidence.artifactHashes['results.sarif']);
  assert.equal(JSON.parse(await readFile(join(out,'results.sarif'),'utf8')).version,'2.1.0');
});

test('five-tool verification helper retains failed coverage and evidence instead of claiming success',async()=>{
  const directory=await temp(),config=await fiveToolConfig(directory,{failOCR:true}),out=join(directory,'run');
  const result=await runner.runProcess({command:process.execPath,args:[new URL('../scripts/live-verify-five.mjs',import.meta.url).pathname,'--config',config,'--out',out],successCodes:[0]},{timeoutMs:15000});
  assert.equal(result.exitCode,2);
  const evidence=JSON.parse(await readFile(join(out,'verification-commands.json'),'utf8'));
  assert.equal(evidence.verificationPassed,false);
  assert.equal(evidence.tools.find(tool=>tool.id==='open-code-review').status,'failed');
  const saved=JSON.parse(await readFile(join(out,'run.json'),'utf8'));
  assert.equal(saved.status,'partial');assert.ok(saved.findings.length>0);
});
