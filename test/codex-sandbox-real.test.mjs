import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {codexArgs} from '../src/agents/invocation.mjs';
import {supervisedArgs} from '../src/agents/cloudflare-prompts.mjs';
import {probeSandbox,sandboxCommandArgs} from '../src/agents/codex-sandbox.mjs';
import {PINS} from '../src/agents/validation.mjs';
import {cloudflareSourceRoot} from './helpers/cloudflare-source.mjs';
const execute=promisify(execFile),binary=process.env.SEC_HUB_TEST_CODEX_SANDBOX_BINARY,skillRoot=cloudflareSourceRoot();
const skip=!binary||process.platform!=='darwin';
for(const strategy of ['native-collab','supervised-codex-workers'])test(`real OS sandbox through ${strategy} wrapper with FAKE provider transport`,{skip},async()=>{
 const root=await mkdtemp(join(tmpdir(),'sec-hub-real-sandbox-'));
 try{
  const target=join(root,'target'),artifactDir=join(root,'raw'),outside=join(root,'outside'),workRoot=join(root,'work');await mkdir(target);await writeFile(join(target,'target.mjs'),'export const x = 1;\n');await writeFile(outside,'SYNTHETIC_FORBIDDEN');
  const payload={id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/sandbox-native-codex.mjs'),binary,outside],target,artifactDir,agentOptions:{strategy,skillRoot,workRoot,revision:PINS.cloudflare,model:'FAKE-no-provider',maxAgents:10}};
  await assert.rejects(execute(process.execPath,[resolve('src/agents/native-wrapper.mjs'),JSON.stringify(payload)],{timeout:60000,maxBuffer:128*1024}));
  const manifest=JSON.parse(await readFile(join(artifactDir,'execution-manifest.json'),'utf8'));assert.equal(manifest.sandboxInvocationPolicyVersion,2);assert.equal(manifest.status,'incomplete');
  const records=strategy==='native-collab'?[manifest]:manifest.roles;assert.equal(records.length,strategy==='native-collab'?1:4);
  for(const r of records){assert.ok(r.sandboxProbe,r.failure??manifest.reasons.join('; '));assert.equal(r.sandboxProbe.policyVersion,2);const path=strategy==='native-collab'?join(artifactDir,'native-events.jsonl'):join(artifactDir,'roles',r.agentId,'events.jsonl');const event=(await readFile(path,'utf8')).trim().split('\n').map(JSON.parse).find(e=>e.type==='sec_hub.fixture_sandbox_result');assert.ok(event,'fixture must reach actual execution wrapper');assert.equal(event.provider,'FAKE');assert.equal(event.actualSandbox,true);assert.equal(event.exitCode,0,JSON.stringify(event));assert.equal(event.stdout,'REAL_SANDBOX_CHECKS_PASSED');}
 }finally{await rm(root,{recursive:true,force:true});}
});
test('direct real sandbox denies outside/symlink reads and honors exact document/schema grants for both profiles',{skip},async()=>{
 const root=await mkdtemp(join(tmpdir(),'sec-hub-profile-os-'));
 try{
  const runner=join(root,'runner'),target=join(root,'target'),skill=join(root,'pin/skills/security-audit');for(const dir of [runner,target,skill])await mkdir(dir,{recursive:true});
  const file=join(target,'target.mjs'),doc=join(skill,'SKILL.md'),other=join(skill,'OTHER.md'),schema=join(root,'raw/schema.json'),outside=join(root,'outside');await mkdir(join(root,'raw'));for(const path of [file,doc,other,schema,outside])await writeFile(path,'SYNTHETIC');
  await symlink(outside,join(target,'symlink'));
  for(const args of [codexArgs(runner,{model:'FAKE',skillRoot:join(root,'pin')},process.execPath),supervisedArgs(runner,{model:'FAKE'},process.execPath,schema,2,[doc])]){
   await probeSandbox({command:binary,execArgs:args,runner,targetFile:file,skillFile:doc,nodeExecutable:process.execPath,env:{PATH:'/usr/bin:/bin',HOME:root}});
   for(const path of [file,doc,schema,other,outside,join(target,'symlink')]){
    const allowed=path===file||path===doc||(args.includes('--output-schema')?path===schema:path===other);
    const run=()=>execute(binary,sandboxCommandArgs(args,['/bin/cat',path]),{cwd:runner,timeout:10000,maxBuffer:64*1024});
    if(allowed)assert.equal((await run()).stdout,'SYNTHETIC');else await assert.rejects(run(),e=>e.code!==0&&/Operation not permitted|Permission denied/.test(e.stderr));
   }
  }
 }finally{await rm(root,{recursive:true,force:true});}
});
