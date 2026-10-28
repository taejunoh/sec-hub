import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,readFile,rm,realpath } from 'node:fs/promises';
import childProcess from 'node:child_process';
import { promisify } from 'node:util';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { nativeAgentAdapters } from '../src/agents/index.mjs';
import { PINS,SOURCES,runOfficialValidators,validateNativeExecution,sha256 } from '../src/agents/validation.mjs';
import { codexArgs,cloudflarePrompt } from '../src/agents/invocation.mjs';
const execute=promisify(childProcess.execFile),pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const alive=pid=>{try{process.kill(pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
async function ready(file){const until=Date.now()+5000;while(Date.now()<until){try{const value=JSON.parse(await readFile(file,'utf8'));if(value.pid&&value.ticks>=2)return value.pid;}catch{}await pause(10);}throw new Error('process never became ready');}
async function fixture(t){const root=await realpath(await mkdtemp(join(tmpdir(),'sec-hub-native-supervision-')));t.after(()=>rm(root,{recursive:true,force:true}));const skillRoot=join(root,'pin'),artifactDir=join(root,'artifacts'),bin=join(root,'bin'),marker=join(root,'ready.json');for(const dir of [skillRoot,artifactDir,bin])await mkdir(dir);const options={skillRoot,workRoot:join(root,'work'),revision:PINS.cloudflare,model:'fixture',strategy:'native-collab'};return {root,skillRoot,artifactDir,bin,marker,options};}
function resistant(marker){return `const fs=require('node:fs');let ticks=0;process.on('SIGTERM',()=>{});setInterval(()=>fs.writeFileSync(${JSON.stringify(marker)},JSON.stringify({pid:process.pid,ticks:++ticks})),15);`;}
async function fakeGit(t,f){await writeFile(join(f.bin,'git'),`#!${process.execPath}\n${resistant(f.marker)}\n`,{mode:0o700});const old=process.env.PATH;process.env.PATH=f.bin+':'+old;t.after(()=>process.env.PATH=old);}
async function cancelReady(pending,controller,marker){let pid,rescue,rescued=false;try{pid=await ready(marker);assert.equal(alive(pid),true);rescue=setTimeout(()=>{rescued=true;try{process.kill(pid,'SIGKILL');}catch{}},1500);controller.abort();const result=await pending;const running=alive(pid);await pause(50);return {result,running,pid,rescued};}finally{clearTimeout(rescue);if(pid&&alive(pid))try{process.kill(pid,'SIGKILL');}catch{}}}

test('native prerequisite joins a ready TERM-resistant Git before cancellation settles',async t=>{
  const f=await fixture(t);await fakeGit(t,f);const controller=new AbortController();let observed=0;
  const pending=nativeAgentAdapters.find(item=>item.id==='cloudflare').check({signal:controller.signal,onCleanupUnconfirmed(){observed++;},config:{tools:{cloudflare:{command:process.execPath,args:[],agentOptions:f.options}}}});
  const result=await cancelReady(pending,controller,f.marker);assert.equal(result.result.available,false);assert.equal(result.rescued,false);assert.equal(result.running,false,'Git must stop before check settles');assert.equal(observed,0);
});

test('parent native validation propagates cancellation into joined source-pin Git work',async t=>{
  const f=await fixture(t);await fakeGit(t,f);const controller=new AbortController(),target=join(f.root,'target'),copyTarget=join(f.root,'stage','target'),runner=join(f.root,'stage','runner');
  const manifest={schema:'sec-hub.native-agent/v1',id:'cloudflare',sourceCommit:PINS.cloudflare,source:SOURCES.cloudflare,target,inputs:[{path:'source'}],strategy:'native-collab',model:'fixture',backend:'codex',mode:'official-security-audit-skill',backendVersion:'1',nativeNodeExecutable:process.execPath,nativeNodeVersion:process.versions.node,copyTarget,invocation:{command:process.execPath,args:codexArgs(runner,{...f.options,effort:'medium',profile:'quick',maxAgents:10},process.execPath),cwd:runner},promptSha256:sha256(cloudflarePrompt(copyTarget,join(runner,'audit'),{...f.options,effort:'medium',profile:'quick',maxAgents:10}))};
  await writeFile(join(f.artifactDir,'execution-manifest.json'),JSON.stringify(manifest));
  const pending=validateNativeExecution('cloudflare',{target,artifactDir:f.artifactDir,signal:controller.signal,onCleanupUnconfirmed(){},config:{tools:{cloudflare:{command:process.execPath,args:[],agentOptions:f.options}}}}).catch(error=>error);
  const result=await cancelReady(pending,controller,f.marker);assert.ok(result.result instanceof Error);assert.equal(result.rescued,false,'cancellation must settle without fixture rescue');assert.equal(result.running,false,'parent parse/finalization must join Git');
});

test('official validator cancellation joins a ready TERM-resistant validator',async t=>{
  const f=await fixture(t),skill=join(f.skillRoot,'skills','security-audit');await mkdir(skill,{recursive:true});await writeFile(join(skill,'SKILL.md'),'fixture');await writeFile(join(skill,'validate-findings.cjs'),resistant(f.marker));await writeFile(join(skill,'validate-coverage-ledger.cjs'),'process.exit(0)');
  const git=async(...args)=>execute('git',['-C',f.skillRoot,...args],{env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'}});await git('init','-q');await git('config','user.name','Fixture');await git('config','user.email','fixture@example.invalid');await git('add','.');await git('commit','-qm','fixture');const original=PINS.cloudflare;PINS.cloudflare=(await git('rev-parse','HEAD')).stdout.trim();f.options.revision=PINS.cloudflare;t.after(()=>PINS.cloudflare=original);
  const controller=new AbortController();const pending=runOfficialValidators(f.options,f.artifactDir,{signal:controller.signal,superviseProcesses:true,onCleanupUnconfirmed(){}}).catch(error=>error);
  const result=await cancelReady(pending,controller,f.marker);assert.ok(result.result instanceof Error);assert.equal(result.rescued,false,'cancellation must settle without fixture rescue');assert.equal(result.running,false,'validator must stop before cancellation returns');
});

test('source-pin cleanup uncertainty reaches parent observer even when abort replaces the diagnostic',async t=>{
  const f=await fixture(t),spawn=childProcess.spawn,kill=process.kill,controller=new AbortController();let observed=0,child;
  childProcess.spawn=(command,...args)=>{if(command!=='git')return spawn(command,...args);child=new EventEmitter();Object.assign(child,{pid:2100000000,stdout:new PassThrough(),stderr:new PassThrough(),unref(){},kill(){}});queueMicrotask(()=>controller.abort());return child;};process.kill=(pid,...args)=>pid===-2100000000?true:kill(pid,...args);syncBuiltinESMExports();t.after(()=>{childProcess.spawn=spawn;process.kill=kill;syncBuiltinESMExports();child?.stdout.destroy();child?.stderr.destroy();});
  const result=await nativeAgentAdapters.find(item=>item.id==='cloudflare').check({signal:controller.signal,onCleanupUnconfirmed(){observed++;},config:{tools:{cloudflare:{command:process.execPath,args:[],agentOptions:f.options}}}});
  assert.equal(result.available,false);assert.equal(observed,1);
});
