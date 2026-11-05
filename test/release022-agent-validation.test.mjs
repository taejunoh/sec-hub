import test from 'node:test';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,readFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve,join } from 'node:path';
import { inspectNativeEvents,validateNativeExecution,sourceManifest,verifySourcePin,sha256,PINS,SOURCES,OUTPUTS } from '../src/agents/validation.mjs';
import { codexArgs,cloudflarePrompt } from '../src/agents/invocation.mjs';
import { runSupervisedCloudflare } from '../src/agents/supervised-cloudflare.mjs';
import { preparePlan,assignHunter,applyHunter } from '../src/agents/supervised-validation.mjs';
import { loadCloudflareContracts } from '../src/agents/cloudflare-prompts.mjs';
import { cloudflareSourceRoot } from './helpers/cloudflare-source.mjs';
const skillRoot=cloudflareSourceRoot();
const event=command=>({type:'item.completed',item:{type:'command_execution',command,status:'completed',exit_code:0}});
const proof=command=>inspectNativeEvents('cloudflare',[event(command)],{skillRoot:'/official',copyTarget:'/stage/target'}).instructionRead;
test('#15 rejects echoed commented substring and foreign-file instruction claims',()=>{
 for(const command of ["echo 'cat /official/skills/security-audit/SKILL.md'",'cat /other/file # /official/skills/security-audit/SKILL.md','cat /official/skills/security-audit/SKILL.md.backup','cat /foreign/.agents/skills/security-audit/SKILL.md','cat /other/SKILL.md /official/unrelated','sed -- /official/skills/security-audit/SKILL.md',"/bin/zsh -lc \"echo 'cat /official/skills/security-audit/SKILL.md'\"",'cd /official; cat skills/security-audit/SKILL.md','false; cat /official/skills/security-audit/SKILL.md','cd -; cat .agents/skills/security-audit/SKILL.md','cd -- -; cat .agents/skills/security-audit/SKILL.md','cat /official/skills/security-audit/SKILL.md > /other/out'])assert.equal(proof(command),false,command);
});
test('#15 accepts literal supported pinned readers and static cwd shell wrappers',()=>{
 for(const command of ['cat /official/skills/security-audit/SKILL.md',"/bin/zsh -lc 'cat /official/skills/security-audit/SKILL.md'","sed -n '1,200p' /official/skills/security-audit/SKILL.md",'head -n 200 /official/skills/security-audit/SKILL.md',"/bin/zsh -lc 'cd /official/skills/security-audit && cat SKILL.md'",'cat .agents/skills/security-audit/SKILL.md'])assert.equal(proof(command),true,command);
});
test('#15 retained genuine native command evidence still proves pinned reads offline',async()=>{
 const path=resolve('verification/native-agent-execution-retry/raw/cloudflare/native-events.jsonl');const events=(await readFile(path,'utf8')).trim().split('\n').map(JSON.parse);
 // Frozen provenance context for this retained recording; string parsing only.
 // Never resolve or read the historic host path, or rewrite retained event bytes.
 const historicalSkillRoot='/Users/example/Documents/Codex/2026-10-27/ai-7-cloudflare-anthropic-openai-nvidia/work/tools/cloudflare-security-audit';
 assert.equal(inspectNativeEvents('cloudflare',events,{skillRoot:historicalSkillRoot}).instructionRead,true);
});
test('#14 real legacy validator rejects incomplete and absent status even with empty reasons',async()=>{
 const root=await mkdtemp(join(tmpdir(),'release022-legacy-'));try{
 const target=join(root,'target'),artifactDir=join(root,'raw'),copyTarget=join(root,'stage','target'),runner=join(root,'stage','runner');await mkdir(target);await mkdir(artifactDir);await writeFile(join(target,'source.txt'),'source\n');
 const options={skillRoot,workRoot:join(root,'work'),revision:PINS.cloudflare,model:'model',maxAgents:10,effort:'medium',profile:'quick',strategy:'native-collab'},inputs=await sourceManifest(target),instructions=await verifySourcePin('cloudflare',options);
 const events=[event(`cat '${join(skillRoot,'skills/security-audit/SKILL.md')}'`)];
 for(const [i,role]of ['recon-architecture','recon-boundaries','recon-execution','recon-companions','hunter-1','critic-final','verifier-final'].entries()){events.push({type:'item.completed',item:{type:'collab_tool_call',tool:'spawn_agent',status:'completed',prompt:`SEC_HUB_ROLE=${role}`,receiver_thread_ids:[`child${i}`]}},{type:'item.completed',item:{type:'collab_tool_call',tool:'wait',status:'completed',agents_states:{[`child${i}`]:{status:'completed',message:'{"decision":"verified","scope":"final-empty-result"}'}}}});}events.push({type:'turn.completed'});
 const values=Object.fromEntries(OUTPUTS.cloudflare.map(name=>[name,'fixture\n']));Object.assign(values,{'run-metadata.json':JSON.stringify({run_status:'complete',profile:'quick'}),'findings.json':'[]','coverage-ledger.json':'[]','native-events.jsonl':events.map(JSON.stringify).join('\n'),'native-stderr.log':''});
 for(const [name,bytes]of Object.entries(values))await writeFile(join(artifactDir,name),bytes);
 const manifest={schema:'sec-hub.native-agent/v1',id:'cloudflare',sourceCommit:PINS.cloudflare,source:SOURCES.cloudflare,target,inputs,copyBefore:inputs,copyAfter:inputs,originalAfter:inputs,instructions,model:'model',backend:'codex',mode:'official-security-audit-skill',backendVersion:'fixture',nativeNodeExecutable:process.execPath,nativeNodeVersion:process.versions.node,copyTarget,invocation:{command:'never-executed',args:codexArgs(runner,options,process.execPath,1),cwd:runner},promptSha256:sha256(cloudflarePrompt(copyTarget,join(runner,'audit'),options)),preRedactionHashes:Object.fromEntries(Object.entries(values).map(([k,v])=>[k,sha256(v)])),process:{exitCode:0},status:'complete',reasons:[]};
 const ctx={target,artifactDir,exitCode:0,config:{tools:{cloudflare:{command:'never-executed',args:[],agentOptions:options}}}};
 const save=()=>writeFile(join(artifactDir,'execution-manifest.json'),JSON.stringify(manifest));await save();assert.deepEqual((await validateNativeExecution('cloudflare',ctx)).findings,[]);
 for(const version of [null,0,3,'2']){manifest.sandboxInvocationPolicyVersion=version;await save();await assert.rejects(validateNativeExecution('cloudflare',ctx),/Unsupported Codex sandbox invocation policy version/);}delete manifest.sandboxInvocationPolicyVersion;
 manifest.sandboxInvocationPolicyVersion=2;await save();await assert.rejects(validateNativeExecution('cloudflare',ctx),/invocation does not match/);delete manifest.sandboxInvocationPolicyVersion;
 for(const status of ['incomplete',undefined]){manifest.status=status;await save();await assert.rejects(validateNativeExecution('cloudflare',ctx),/Wrapper marked execution incomplete/);}
 }finally{await rm(root,{recursive:true,force:true});}
});
test('#13 real pinned ledger rejects invalid unit paths before state mutation',async()=>{
 const root=await mkdtemp(join(tmpdir(),'release022-hunter-'));try{const target=join(root,'target'),artifactDir=join(root,'raw');await mkdir(target);await writeFile(join(target,'target.mjs'),'export const run = input => input;\n');
 const payload={id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/supervised-fake-codex.mjs'),'zero'],target,artifactDir,agentOptions:{strategy:'supervised-codex-workers',skillRoot,workRoot:join(root,'work'),revision:PINS.cloudflare,model:'model',maxAgents:10}};assert.equal(await runSupervisedCloudflare(payload),0);
 const read=async path=>JSON.parse(await readFile(join(artifactDir,path),'utf8')),m=await read('execution-manifest.json'),plan=await read('roles/planner-5/response.json'),hunter=m.roles.find(r=>r.role==='hunter'),response=await read(`roles/${hunter.agentId}/response.json`),c=await loadCloudflareContracts(skillRoot);
 for(const paths of [['missing.mjs'],['../outside'],['target.mjs','missing.mjs'],'target.mjs',null,[1]]){const state=preparePlan(plan,c,m.inputs,10),assignment=state.assignments[0];assignHunter(state,assignment,c);const before=JSON.stringify(state.ledger),reply=structuredClone(response);reply.units[0].reviewed_paths=paths;assert.throws(()=>applyHunter(state,reply,assignment,c,m.inputs));assert.equal(JSON.stringify(state.ledger),before);}
 const state=preparePlan(plan,c,m.inputs,10),assignment=state.assignments[0];assignHunter(state,assignment,c);applyHunter(state,response,assignment,c,m.inputs);assert.equal(state.ledger[0].status,'covered');
 }finally{await rm(root,{recursive:true,force:true});}
});

test('#15 failed semicolon cd cannot prove a pinned read from actual decoy output',async()=>{
 const root=await mkdtemp(join(tmpdir(),'r022-cd-proof-'));try{
 const runner=join(root,'runner'),skillRoot=join(root,'pinned'),pinnedDir=join(skillRoot,'skills/security-audit');await mkdir(runner);await mkdir(pinnedDir,{recursive:true});await writeFile(join(runner,'SKILL.md'),'DECOY\n');await writeFile(join(pinnedDir,'SKILL.md'),'PINNED\n');
 const failed=`cd -P '${pinnedDir}/missing/..'; cat SKILL.md`,actual=spawnSync('/bin/sh',['-c',failed],{cwd:runner,encoding:'utf8'});assert.equal(actual.status,0);assert.equal(actual.stdout,'DECOY\n');assert.match(actual.stderr,/cd:/);
 const inspect=(command,result)=>inspectNativeEvents('cloudflare',[{type:'item.completed',item:{type:'command_execution',command,status:'completed',exit_code:result.status,aggregated_output:result.stdout}}],{skillRoot,copyTarget:join(root,'target')}).instructionRead;
 assert.equal(inspect(failed,actual),false);
 const masked=`cat '${root}/missing' && cat '${pinnedDir}/SKILL.md'; cat '${runner}/SKILL.md'`,maskedResult=spawnSync('/bin/sh',['-c',masked],{cwd:runner,encoding:'utf8'});assert.equal(maskedResult.status,0);assert.equal(maskedResult.stdout,'DECOY\n');assert.equal(inspect(masked,maskedResult),false);
 for(const command of [`cd '${pinnedDir}' && cat SKILL.md`,`cat '${pinnedDir}/SKILL.md'`]){const result=spawnSync('/bin/sh',['-c',command],{cwd:runner,encoding:'utf8'});assert.equal(result.status,0);assert.equal(result.stdout,'PINNED\n');assert.equal(inspect(command,result),true);}
 }finally{await rm(root,{recursive:true,force:true});}
});
