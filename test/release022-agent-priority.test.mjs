import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSupervisedCloudflare } from '../src/agents/supervised-cloudflare.mjs';
import { assertObservedPolicy } from '../src/agents/supervised-validation.mjs';
import { PINS } from '../src/agents/validation.mjs';
import { cloudflareSourceRoot } from './helpers/cloudflare-source.mjs';
for (const location of ['artifact','work']) test(`#9 supervisor rejects .. descendant ${location} before mutation or dispatch`,async()=>{
 const root=await mkdtemp(join(tmpdir(),'release022-isolation-'));try{
 const target=join(root,'target');await mkdir(target);await writeFile(join(target,'source.txt'),'source\n');
 const payload={id:'cloudflare',command:'/must-not-dispatch',args:[],target,artifactDir:location==='artifact'?join(target,'..reports'):join(root,'raw'),agentOptions:{strategy:'supervised-codex-workers',skillRoot:cloudflareSourceRoot(),workRoot:location==='work'?join(target,'..work'):join(root,'work'),revision:PINS.cloudflare,model:'model',maxAgents:7}};
 await assert.rejects(runSupervisedCloudflare(payload),/must be isolated/);
 assert.deepEqual(await readdir(target),['source.txt']);assert.deepEqual(await readdir(root),['target']);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('#9 supervisor permits genuinely outside sibling paths',async()=>{
 const root=await mkdtemp(join(tmpdir(),'release022-isolation-'));try{const target=join(root,'target');await mkdir(target);await writeFile(join(target,'source.txt'),'source\n');const artifactDir=join(root,'..reports'),workRoot=join(root,'..work');
 assert.equal(await runSupervisedCloudflare({id:'cloudflare',command:'/must-not-dispatch',args:[],target,artifactDir,agentOptions:{strategy:'supervised-codex-workers',skillRoot:cloudflareSourceRoot(),workRoot,revision:PINS.cloudflare,model:'model',maxAgents:7}}),1);assert.deepEqual(await readdir(target),['source.txt']);assert.deepEqual(await readdir(workRoot),[]);
 }finally{await rm(root,{recursive:true,force:true});}
});
const expected={context:{target:'/tmp/stage/target',runner:'/tmp/stage/runner'},readFiles:['/pinned/SKILL.md'],readCommands:["cat '/pinned/SKILL.md'"]};
const observe=command=>assertObservedPolicy({type:'item.started',item:{type:'command_execution',command}},expected);
test('#12 rejects executable sed script disguised as normalized confined operand without executing it',()=>{
 for(const command of ["sed -- '/x/e id #/../../tmp/stage/target/file' '/tmp/stage/target/input'",'sed -- /tmp/stage/target/file','sed -n -- /tmp/stage/target/input',"sed -n '1e id' /tmp/stage/target/input","sed -n '1p' -- /tmp/stage/target/input"])assert.throws(()=>observe(command),/source-only command policy/);
});
test('#12 preserves restricted numeric sed readers and other literal readers',()=>{
 for(const command of ["sed -n '1,20p' /tmp/stage/target/input","sed -n '1p' /tmp/stage/target/input","cat -- /tmp/stage/target/input","rg -- needle /tmp/stage/target/input","head -n 10 /tmp/stage/target/input"])assert.doesNotThrow(()=>observe(command));
});
