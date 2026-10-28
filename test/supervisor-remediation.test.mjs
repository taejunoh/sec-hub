import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { registerHooks } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

// These child fixtures run the actual supervisor entry and role-process code.
// Module hooks replace contracts/provider transport and validators only; no
// vendor program, network request, or operating-system process signal is used.
// Keep lifecycle fixtures out of watched workspace trees: unrelated metadata
// writers can correctly trip the production bounded-read ctime guard there.
const testFile=fileURLToPath(import.meta.url),workspace=tmpdir();
const scenario=process.env.SEC_HUB_SUPERVISOR_REMEDIATION_SCENARIO;
if(scenario){
  const root=process.env.SEC_HUB_SUPERVISOR_REMEDIATION_ROOT,target=join(root,'target'),artifactDir=join(root,'raw'),workRoot=join(root,'staging');
  await mkdir(target,{recursive:true});await writeFile(join(target,'source.mjs'),'export const value=1;\n');
  const actualNow=Date.now,actualKill=process.kill,seen={attempts:0,pids:0,terminations:{},timerFired:false};
  let clockOffset=0,clockTicks=0,finalizing=false;
  Date.now=()=>actualNow()+clockOffset+(clockTicks+=scenario.includes('cleanup-')?2000:0);
  process.kill=(negativePid,signal)=>{
    const pid=-negativePid;
    if(signal==='SIGTERM')seen.terminations[pid]=(seen.terminations[pid]??0)+1;
    const uncertain=pid===424241&&(scenario.endsWith('cleanup-persistent')||scenario==='cleanup-retry'&&(seen.terminations[pid]??0)<2);
    if(uncertain){if(signal===0)return true;throw Object.assign(new Error('Synthetic termination permission failure'),{code:'EPERM'});}
    throw Object.assign(new Error('Synthetic group has exited'),{code:'ESRCH'});
  };
  const state={architecture:'Synthetic lifecycle fixture.',plan:{companion_selection:[]},assignments:[],ledger:[],candidates:new Map([['fixture:candidate',{fingerprint:'fixture:candidate'}]]),records:[]};
  const fakeSpawn=()=>{
    const child=new EventEmitter();child.pid=424241+seen.pids++;child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();
    child.stdin.resume();child.stdin.once('finish',()=>setImmediate(()=>{
      child.stdout.write(JSON.stringify({type:'thread.started',thread_id:`fixture-${child.pid}`})+'\n');
      child.stdout.write(JSON.stringify({type:'item.completed',item:{type:'agent_message',text:'{}'}})+'\n');
      child.stdout.end();child.stderr.end();child.emit('close',0,null);
    }));return child;
  };
  const fakeExec=()=>{};fakeExec[promisify.custom]=async()=>({stdout:'synthetic native version',stderr:''});
  const policy=Object.assign(new Error('Synthetic hard policy failure'),{fatalPolicy:true});
  globalThis.__supervisorFixture={
    spawn:fakeSpawn,execFile:fakeExec,
    nativeOptions:(_id,options)=>options,
    verifySourcePin:async()=>{if(seen.pinCalls)finalizing=true;seen.pinCalls=(seen.pinCalls??0)+1;return [];},
    runOfficialValidators:async()=>[],
    loadCloudflareContracts:async()=>({root:join(root,'unused-validator-root')}),
    buildRolePrompt:(_c,context)=>{
      if(context.role==='verifier'){
        seen.attempts++;
        if(scenario==='pre-registration'){
          if(seen.attempts===1)setTimeout(()=>{seen.timerFired=true;},0);
          if(seen.attempts===1000)process.stdout.write(JSON.stringify({checkpoint:seen})+'\n');
          throw new Error('Synthetic pre-registration prompt failure');
        }
      }
      return {prompt:'Synthetic deterministic role prompt.',sourceBlocks:[],context};
    },
    supervisedArgs:()=>[],reconOutputSchema:()=>null,
    validateRecon:()=>{},preparePlan:()=>state,assignHunter:()=>{},applyHunter:()=>{},
    applyCritic:()=>{
      if(scenario==='expired-deadline'){
        clockOffset=2_000_000;setTimeout(()=>{seen.timerFired=true;},0);
      }
    },
    applyVerifier:()=>{
      if(scenario==='counted-retry'&&seen.attempts===1)throw new Error('Synthetic malformed counted verifier');
      state.records.push({fingerprint:'fixture:candidate'});
    },
    inspectRoleEvidence:(_events,record)=>{if(scenario==='policy-failure'&&record.role==='verifier')throw policy;return {response:{}};},assertObservedPolicy:()=>{},
    renderSupervisedReports:()=>({'REPORT.md':'Synthetic report.','FINDINGS-DETAIL.md':'Synthetic details.','NEEDS-VALIDATION.md':'Synthetic validation.'}),officialHelpers:()=>({ledger:{validateDocument:()=>[]}}),validateRecords:()=>{},
    failFinalSave:()=>scenario.startsWith('final-save')&&finalizing,
    failManifestWrite:()=>scenario==='manifest-write',
  };
  const replacements={
    'validation.mjs':['nativeOptions','verifySourcePin','runOfficialValidators'],
    'cloudflare-prompts.mjs':['loadCloudflareContracts','buildRolePrompt','supervisedArgs','reconOutputSchema'],
    'supervised-validation.mjs':['validateRecon','preparePlan','assignHunter','applyHunter','applyCritic','applyVerifier','inspectRoleEvidence','assertObservedPolicy','renderSupervisedReports','officialHelpers','validateRecords'],
  };
  registerHooks({
    resolve(specifier,context,next){
      if(specifier==='node:child_process'&&context.parentURL?.includes('/src/agents/supervised-cloudflare.mjs'))return {url:'fixture:child-process',shortCircuit:true};
      return next(specifier,context);
    },
    load(url,context,next){
      if(url==='fixture:child-process')return {format:'module',shortCircuit:true,source:'export const {spawn,execFile}=globalThis.__supervisorFixture;'};
      if(url.includes('?supervisor-fixture-original'))return next(url,context);
      const basename=url.split('/').at(-1),names=replacements[basename];
      if(names&&url.includes('/src/agents/'))return {format:'module',shortCircuit:true,source:`export * from ${JSON.stringify(url+'?supervisor-fixture-original')}; export const {${names.join(',')}}=globalThis.__supervisorFixture;`};
      if(basename==='safe-io.mjs'&&url.includes('/src/'))return {format:'module',shortCircuit:true,source:`export * from ${JSON.stringify(url+'?supervisor-fixture-original')}; import {atomicWriteFile as original} from ${JSON.stringify(url+'?supervisor-fixture-original')}; export async function atomicWriteFile(...args){if(args[0].endsWith('/execution-manifest.json')&&globalThis.__supervisorFixture.failManifestWrite())throw new Error('Synthetic manifest publication failure');if(args[0].endsWith('/run-metadata.json')&&globalThis.__supervisorFixture.failFinalSave())throw new Error('Synthetic final save failure');return original(...args);}`};
      return next(url,context);
    },
  });
  try{
    const {runSupervisedCloudflare}=await import('../src/agents/supervised-cloudflare.mjs');
    let exitCode,error;
    try{exitCode=await runSupervisedCloudflare({id:'cloudflare',command:'synthetic-native',args:[],target,artifactDir,agentOptions:{strategy:'supervised-codex-workers',skillRoot:join(root,'skill'),workRoot,model:'gpt-6.1-sol',effort:'medium',profile:'quick',maxAgents:10}});}catch(e){error=e.message;}
    await new Promise(resolve=>setImmediate(resolve));
    let manifest;try{manifest=JSON.parse(await readFile(join(artifactDir,'execution-manifest.json'),'utf8'));}catch{}
    process.stdout.write(JSON.stringify({exitCode,error,seen,manifest,stages:await readdir(workRoot).catch(()=>[])})+'\n');
  }finally{Date.now=actualNow;process.kill=actualKill;}
}else{
  async function runFixture(mode,expectedError){
    const root=await mkdtemp(join(workspace,'supervisor-remediation-'));
    try{
      const result=spawnSync(process.execPath,[testFile],{cwd:process.cwd(),env:{...process.env,SEC_HUB_SUPERVISOR_REMEDIATION_SCENARIO:mode,SEC_HUB_SUPERVISOR_REMEDIATION_ROOT:root},encoding:'utf8',timeout:15000,killSignal:'SIGKILL',maxBuffer:2*1024*1024});
      assert.equal(result.signal,null,`Supervisor fixture ${mode} failed to settle before external deadline: ${result.stdout}\n${result.stderr}`);
      assert.equal(result.status,0,result.stderr);
      const output=JSON.parse(result.stdout.trim().split('\n').at(-1));
      if(expectedError)assert.match(output.error,expectedError);else assert.equal(output.error,undefined,output.error);
      return output;
    }finally{await rm(root,{recursive:true,force:true});}
  }
  test('supervisor stops an expired verifier deadline without consuming roles or starving a timer',async()=>{
    const out=await runFixture('expired-deadline');
    assert.equal(out.exitCode,1);assert.equal(out.seen.attempts,0);assert.equal(out.seen.timerFired,true);
    assert.equal(out.manifest.roles.filter(r=>r.role==='verifier').length,0);assert.match(out.manifest.reasons.join(';'),/wall-time|deadline/);
  });
  test('supervisor stops verifier exceptions before registration without an uncounted retry loop',async()=>{
    const out=await runFixture('pre-registration');assert.equal(out.exitCode,1);assert.equal(out.seen.attempts,1);assert.equal(out.seen.timerFired,true);
    assert.equal(out.manifest.roles.filter(r=>r.role==='verifier').length,0);assert.match(out.manifest.reasons.join(';'),/pre-registration/);
  });
  test('supervisor preserves a legitimate counted verifier retry',async()=>{
    const out=await runFixture('counted-retry');assert.equal(out.exitCode,0);assert.equal(out.seen.attempts,2);
    assert.equal(out.manifest.roles.filter(r=>r.role==='verifier').length,2);assert.equal(out.manifest.roles.at(-2).accepted,false);assert.equal(out.manifest.roles.at(-1).accepted,true);
  });
  test('supervisor never retries a hard policy failure',async()=>{
    const out=await runFixture('policy-failure');assert.equal(out.exitCode,1);assert.equal(out.seen.attempts,1);assert.match(out.manifest.reasons.join(';'),/hard policy/);
  });
  test('supervisor retries termination of a still-registered process group in outer cleanup',async()=>{
    const out=await runFixture('cleanup-retry');assert.equal(out.exitCode,1);assert.equal(out.seen.terminations[424241],2);assert.deepEqual(out.stages,[]);
  });
  test('supervisor retains staging while owned group termination remains uncertain',async()=>{
    const out=await runFixture('cleanup-persistent');assert.equal(out.exitCode,1);assert.equal(out.seen.terminations[424241],2);assert.equal(out.stages.length,1);assert.match(out.manifest.reasons.join(';'),/process group cleanup failed/);
  });
  test('supervisor publishes an incomplete manifest and removes safe staging after final save failure',async()=>{
    const out=await runFixture('final-save');assert.equal(out.exitCode,1);assert.equal(out.manifest.status,'incomplete');assert.match(out.manifest.reasons.join(';'),/final save failure/);assert.equal(out.manifest.nativeEnvironment,undefined);assert.deepEqual(out.stages,[]);
  });
  test('supervisor retains uncertain staging even when the final save also fails',async()=>{
    const out=await runFixture('final-save-cleanup-persistent');assert.equal(out.exitCode,1);assert.equal(out.manifest.status,'incomplete');assert.match(out.manifest.reasons.join(';'),/final save failure/);assert.match(out.manifest.reasons.join(';'),/process group cleanup failed/);assert.equal(out.stages.length,1);
  });
  test('supervisor removes confirmed safe staging even if manifest publication fails',async()=>{
    const out=await runFixture('manifest-write',/manifest publication failure/);assert.equal(out.manifest,undefined);assert.deepEqual(out.stages,[]);
  });
  test('supervisor unregisters groups after confirmed termination',async()=>{
    const out=await runFixture('success');assert.equal(out.exitCode,0);assert.ok(Object.values(out.seen.terminations).every(count=>count===1));assert.deepEqual(out.stages,[]);
  });
}
