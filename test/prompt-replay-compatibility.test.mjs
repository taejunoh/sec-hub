import test from 'node:test';
import assert from 'node:assert/strict';
import {access,mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {buildRolePrompt,replayPromptVersion,CLOUDFLARE_PROMPT_VERSION} from '../src/agents/cloudflare-prompts.mjs';
import {sha256,PINS} from '../src/agents/validation.mjs';
import {runSupervisedCloudflare} from '../src/agents/supervised-cloudflare.mjs';
import {validateSupervisedCloudflare,assertObservedPolicy} from '../src/agents/supervised-validation.mjs';
import {cloudflareSourceRoot} from './helpers/cloudflare-source.mjs';
const block=name=>({file:'HUNTING.md',ref:name,text:`official ${name}\n`,sha256:sha256(`official ${name}\n`)});
const contracts={root:'/pinned/security-audit',companions:[],catalog:[],recon:['1a','1b','1c','1d'].map(block),...Object.fromEntries(['method','promotion','gate','hunterContract','critic','candidateVerifier','phase5'].map(k=>[k,block(k)])),branches:['confirmed','needs_validation','rejected'].map(block)};
const context=role=>({role,agentId:'role-1',target:'/copy/target',runner:'/runner',architecture:'source architecture',plan:{source_objects:[],companion_selection:[]},candidate:{fingerprint:'candidate-1'}});
// Independently frozen whole-prompt SHA256 values from the exact 95f697e builder,
// with the deterministic contracts/context above. No current builder output is
// used to construct these expected values, and tests need no Git checkout.
const legacyHashes={
 'recon-1a':'d86f5fdc6c6d25e1ea033959144178e991db489b98a3df21451f6697c11ed5c6',
 'recon-1b':'04d30664b43b21279bbb5f14fa83b5ec433fea164cb209b8b6de471b1c6244d9',
 'recon-1c':'25ca6149590b7afe7f393cab1380372c586c15c9611874cf5c1b81fab117e906',
 'recon-1d':'71ebaa758c2d8d3ad5d472de6087b76944dc021395c7674f7d6f0f4dd7280693',
 planner:'961c054c7f2e46a16f509d91815d89668435faca2749a1788e6246cc680e8bb2',
 hunter:'6648bd0e2c669da90876d0c3e9704d6def20bd060795625a419278364b36c576',
 critic:'278b1ed3efa1e6fbb1e9e98a60a2b2f0a4cdd71f9f91c0d52a07e4a6a92474c7',
 verifier:'8b68a43cc4b5c44042ee6b689304d1915449de7dd16f47720b1fe90b7ead5ba1'
};
test('legacy replay reconstructs every role byte-exactly while new prompts default to version 2',()=>{
 assert.equal(CLOUDFLARE_PROMPT_VERSION,2);
 for(const [role,hash] of Object.entries(legacyHashes)){
  const old=buildRolePrompt(contracts,context(role),1),current=buildRolePrompt(contracts,context(role));
  assert.equal(sha256(old.prompt),hash,role);
  assert.match(current.prompt,/Every command must be one standalone read command with an explicit absolute filesystem path/);
  assert.notEqual(current.prompt,old.prompt);
  assert.deepEqual(current.sourceBlocks,old.sourceBlocks);
  assert.equal(current.prompt.slice(current.prompt.indexOf('\nSEC_HUB_CONTEXT=')),old.prompt.slice(old.prompt.indexOf('\nSEC_HUB_CONTEXT=')));
  // Choosing legacy bytes never changes the current command evidence policy.
  for(const expected of [old,current])assert.throws(()=>assertObservedPolicy({type:'item.started',item:{type:'command_execution',command:'rg --files'}},expected),/source-only command policy/);
 }
});
test('only absent version or explicit supported integer formats may replay',()=>{
 assert.equal(replayPromptVersion({}),1);
 for(const version of [1,2])assert.equal(replayPromptVersion({promptVersion:version}),version);
 for(const version of [undefined,null,0,3,'1','2',{},true]){
  assert.throws(()=>replayPromptVersion({promptVersion:version}),/Unsupported Cloudflare prompt version/);
  if(version!==undefined)assert.throws(()=>buildRolePrompt(contracts,context('recon-1a'),version),/Unsupported Cloudflare prompt version/);
 }
});
const skillRoot=cloudflareSourceRoot();
let available=true;try{await access(join(skillRoot,'skills/security-audit/SKILL.md'));}catch{available=false;}
test('fresh runner records v2 and rejects relabeling, missing or unknown versions without accepting saved prompt hashes',{skip:!available},async()=>{
 const root=await mkdtemp(join(tmpdir(),'cf-prompt-version-')),target=join(root,'target'),artifactDir=join(root,'raw');
 try{
  await mkdir(target);await writeFile(join(target,'target.mjs'),'export const run = input => input;\n');
  const agentOptions={strategy:'supervised-codex-workers',skillRoot,workRoot:join(root,'staging'),revision:PINS.cloudflare,model:'gpt-6.1-sol',effort:'medium',profile:'quick',maxAgents:10};
  const payload={id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/supervised-fake-codex.mjs'),'zero'],agentOptions,target,artifactDir};
  const ctx={target,artifactDir,exitCode:0,config:{tools:{cloudflare:{command:payload.command,args:payload.args,agentOptions}}}};
  assert.equal(await runSupervisedCloudflare(payload),0);
  const path=join(artifactDir,'execution-manifest.json'),manifest=JSON.parse(await readFile(path,'utf8'));
  assert.equal(manifest.promptVersion,2);assert.deepEqual((await validateSupervisedCloudflare(ctx)).findings,[]);
  for(const version of [1,undefined,3]){
   const changed=structuredClone(manifest);if(version===undefined)delete changed.promptVersion;else changed.promptVersion=version;
   await writeFile(path,JSON.stringify(changed));
   await assert.rejects(validateSupervisedCloudflare(ctx),version===3?/Unsupported Cloudflare prompt version/:/invocation\/prompt differs from trusted reconstruction/);
  }
 }finally{await rm(root,{recursive:true,force:true});}
});
