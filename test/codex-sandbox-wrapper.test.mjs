import test from 'node:test';
import assert from 'node:assert/strict';
import {access,mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {PINS} from '../src/agents/validation.mjs';
import {cloudflareSourceRoot} from './helpers/cloudflare-source.mjs';
const execute=promisify(execFile),skillRoot=cloudflareSourceRoot();
let available=true;try{await access(join(skillRoot,'skills/security-audit/SKILL.md'));}catch{available=false;}
for(const strategy of ['native-collab','supervised-codex-workers'])for(const mode of ['unsupported-version','failed-sandbox'])test(`${strategy} refuses ${mode} before any model exec`,{skip:!available||process.platform!=='darwin'},async()=>{
 const root=await mkdtemp(join(tmpdir(),'sec-hub-refuse-sandbox-'));
 try{
  const target=join(root,'target'),artifactDir=join(root,'raw');await mkdir(target);await writeFile(join(target,'target.mjs'),'export const x = 1;\n');
  const payload={id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/supervised-fake-codex.mjs'),mode],target,artifactDir,agentOptions:{strategy,skillRoot,workRoot:join(root,'work'),revision:PINS.cloudflare,model:'FAKE',maxAgents:10}};
  await assert.rejects(execute(process.execPath,[resolve('src/agents/native-wrapper.mjs'),JSON.stringify(payload)],{timeout:60000,maxBuffer:64*1024}));
  const m=JSON.parse(await readFile(join(artifactDir,'execution-manifest.json'),'utf8'));assert.equal(m.sandboxInvocationPolicyVersion,2);assert.equal(m.status,'incomplete');assert.ok(m.reasons.some(s=>/refusing.*(?:fallback|execution)/.test(s)),m.reasons.join('; '));
  if(strategy==='native-collab'){assert.equal(m.process,undefined);await assert.rejects(access(join(artifactDir,'native-events.jsonl')));}
  else{if(mode==='unsupported-version')assert.equal(m.roles.length,0);for(const r of m.roles){assert.equal(r.pid,undefined);assert.equal(r.sandboxProbe,undefined);await assert.rejects(access(join(artifactDir,'roles',r.agentId,'events.jsonl')));}}
 }finally{await rm(root,{recursive:true,force:true});}
});
