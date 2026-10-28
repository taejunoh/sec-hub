import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runScan,runProcess } from '../src/runner.mjs';
import { adapters } from '../src/adapters/index.mjs';
async function fixture(t){const root=await fs.realpath(await fs.mkdtemp(join(tmpdir(),'sec-hub-run-lifecycle-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));const target=join(root,'target'),out=join(root,'out');await fs.mkdir(target);return {root,target,out};}
function fakeProcess(t,accept,onStart,{closeOnKill=false}={}){
  const spawn=childProcess.spawn,kill=process.kill;let child;const calls=[];
  childProcess.spawn=(command,args,options)=>{if(!accept(command,args))return spawn(command,args,options);calls.push({command,args});child=new EventEmitter();Object.assign(child,{pid:2100000000,stdout:new PassThrough(),stderr:new PassThrough(),unref(){},kill(){if(closeOnKill)queueMicrotask(()=>child.emit('close',null));}});queueMicrotask(()=>onStart(child));return child;};
  process.kill=(pid,...args)=>{if(pid===-2100000000){if(closeOnKill)queueMicrotask(()=>child.emit('close',null));return true;}return kill(pid,...args);};syncBuiltinESMExports();
  t.after(()=>{child?.stdout.destroy();child?.stderr.destroy();childProcess.spawn=spawn;process.kill=kill;syncBuiltinESMExports();});return calls;
}

test('runner emits structured real tool progress and isolates throwing and rejecting observers',async t=>{
  const f=await fixture(t),events=[];const adapter={id:'fixture',name:'Fixture',source:'local',check:async()=>({available:true}),build:()=>({command:process.execPath,args:['-e','process.stdout.write("done")']}),parse:()=>[]};
  const run=await runScan({...f,adapters:[adapter],tools:['fixture'],onProgress:event=>{events.push(event);if(events.length%2)throw new Error('observer');return Promise.reject(new Error('observer rejected'));}});
  assert.equal(run.status,'completed');assert.ok(events.some(e=>e.phase==='preparing'));assert.ok(events.some(e=>e.phase==='checking'&&e.toolId==='fixture'));assert.ok(events.some(e=>e.phase==='scanning'&&e.toolStatus==='completed'&&e.completedCount===1&&e.totalCount===1));assert.ok(events.every(e=>Object.keys(e).every(key=>['phase','toolId','toolStatus','completedCount','totalCount'].includes(key))));
});

test('Git cancellation reaches first probe and prevents second probe and output creation',async t=>{
  const f=await fixture(t),controller=new AbortController();const calls=fakeProcess(t,command=>command==='git',()=>controller.abort(),{closeOnKill:true});
  await assert.rejects(runScan({...f,signal:controller.signal,adapters:[],tools:[]}));assert.equal(calls.length,1);await assert.rejects(fs.stat(f.out),e=>e.code==='ENOENT');
});

test('already cancelled scan never starts Git or creates output',async t=>{
  const f=await fixture(t),controller=new AbortController();controller.abort();const calls=fakeProcess(t,command=>command==='git',child=>child.emit('close',0));
  await assert.rejects(runScan({...f,signal:controller.signal,adapters:[],tools:[]}));assert.equal(calls.length,0);await assert.rejects(fs.stat(f.out),e=>e.code==='ENOENT');
});

test('process hard deadline exposes structured cleanup uncertainty despite observer failure',async t=>{
  const controller=new AbortController();fakeProcess(t,command=>command==='fixture-process',()=>controller.abort());let observed=0;
  const result=await runProcess({command:'fixture-process',args:[]},{signal:controller.signal,onCleanupUnconfirmed(){observed++;return Promise.reject(new Error('observer'));}});
  assert.equal(result.cleanupUnconfirmed,true);assert.equal(observed,1);
});

test('Git cleanup uncertainty survives aborted preparation',async t=>{
  const f=await fixture(t),controller=new AbortController();fakeProcess(t,command=>command==='git',()=>controller.abort());let observed=0;
  await assert.rejects(runScan({...f,signal:controller.signal,tools:[],adapters:[],onCleanupUnconfirmed(){observed++;}}));assert.equal(observed,1);
});

test('version probe keeps cleanup uncertainty when replacing human-readable reason',async t=>{
  const controller=new AbortController();fakeProcess(t,command=>command==='fixture-version',()=>controller.abort());let observed=0;
  const result=await adapters.find(item=>item.id==='osv').check({config:{tools:{osv:{command:'fixture-version',args:[]}}},signal:controller.signal,onCleanupUnconfirmed(){observed++;}});
  assert.equal(result.available,false);assert.equal(observed,1);
});

test('main scan cleanup uncertainty survives artifact sanitization overwriting the tool reason',async t=>{
  const f=await fixture(t),controller=new AbortController();fakeProcess(t,command=>command==='fixture-main',()=>controller.abort());let observed=0;
  const readdir=fs.readdir;fs.readdir=async(path,...args)=>{if(String(path).endsWith('/raw/fixture'))throw new Error('sanitization fixture');return readdir(path,...args);};syncBuiltinESMExports();t.after(()=>{fs.readdir=readdir;syncBuiltinESMExports();});
  const adapter={id:'fixture',name:'Fixture',source:'local',check:async()=>({available:true}),build:()=>({command:'fixture-main',args:[]}),parse:()=>[]};
  const run=await runScan({...f,signal:controller.signal,adapters:[adapter],tools:['fixture'],onCleanupUnconfirmed(){observed++;}});
  assert.equal(observed,1);assert.equal(run.tools[0].status,'failed');assert.match(run.tools[0].reason,/sanitization failed/);
});

test('Windows tree-killer failure publishes structured uncertainty before settling cancellation',async t=>{
  const originalPlatform=Object.getOwnPropertyDescriptor(process,'platform'),spawn=childProcess.spawn,root=process.env.SystemRoot;
  Object.defineProperty(process,'platform',{value:'win32',configurable:true});process.env.SystemRoot='C:\\Windows';
  const leader=new EventEmitter();Object.assign(leader,{pid:12345,stdout:new PassThrough(),stderr:new PassThrough(),unref(){},kill(){queueMicrotask(()=>leader.emit('close',null));}});
  childProcess.spawn=(command)=>{if(command==='fixture-win')return leader;const helper=new EventEmitter();helper.kill=()=>{};helper.unref=()=>{};queueMicrotask(()=>helper.emit('close',5));return helper;};syncBuiltinESMExports();
  t.after(()=>{Object.defineProperty(process,'platform',originalPlatform);childProcess.spawn=spawn;syncBuiltinESMExports();if(root===undefined)delete process.env.SystemRoot;else process.env.SystemRoot=root;leader.stdout.destroy();leader.stderr.destroy();});
  const controller=new AbortController();let observed=0;const pending=runProcess({command:'fixture-win',args:[]},{signal:controller.signal,onCleanupUnconfirmed(){observed++;throw new Error('observer');}});controller.abort();const result=await pending;
  assert.equal(result.status,'cancelled');assert.equal(result.cleanupUnconfirmed,true);assert.equal(observed,1);
});

test('cancelled native prerequisite never starts source-pin filesystem inspection',async t=>{
  const controller=new AbortController();controller.abort();const original=fs.lstat;let inspected=false;
  fs.lstat=async(path,...args)=>{if(path==='/fixture-skill-root')inspected=true;return original(path,...args);};syncBuiltinESMExports();t.after(()=>{fs.lstat=original;syncBuiltinESMExports();});
  const result=await adapters.find(item=>item.id==='cloudflare').check({signal:controller.signal,config:{tools:{cloudflare:{command:process.execPath,args:[],agentOptions:{skillRoot:'/fixture-skill-root',workRoot:'/fixture-work-root',revision:'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',model:'fixture'}}}}});
  assert.equal(result.available,false);assert.equal(inspected,false,'aborted preparation must not enter filesystem pin checks');
});
