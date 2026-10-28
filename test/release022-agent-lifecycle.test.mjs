import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { registerHooks } from 'node:module';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { resolve,join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cloudflareSourceRoot } from './helpers/cloudflare-source.mjs';
const scenario=process.env.SEC_HUB_RELEASE022_SCENARIO;
if(scenario){
 const root=process.env.SEC_HUB_RELEASE022_ROOT,target=join(root,'target'),artifactDir=join(root,'raw'),workRoot=join(root,'work');await fs.mkdir(target);await fs.writeFile(join(target,'target.mjs'),'export const run = input => input;\n');let pins=0,finalizing=false;
 globalThis.__r022={
  mkdir:async(...args)=>{if(scenario==='mkdir'&&String(args[0]).endsWith('/runner'))throw new Error('fixture mkdir failure');return fs.mkdir(...args);},
  failCopy:scenario==='copy',failManifest:scenario==='source-manifest',
  pin:()=>{if(++pins>1)finalizing=true;},
  failRead:path=>scenario==='retained'&&finalizing&&String(path).endsWith('/stderr.log'),
 };
 registerHooks({resolve(specifier,context,next){if(specifier==='node:fs/promises'&&context.parentURL?.endsWith('/supervised-cloudflare.mjs'))return {url:'fixture:fs',shortCircuit:true};return next(specifier,context);},load(url,context,next){
 if(url==='fixture:fs')return {format:'module',shortCircuit:true,source:"export * from 'node:fs/promises'; export const mkdir=globalThis.__r022.mkdir;"};
 if(url.includes('?r022-original'))return next(url,context);
 if(url.endsWith('/src/agents/validation.mjs'))return {format:'module',shortCircuit:true,source:`export * from ${JSON.stringify(url+'?r022-original')}; import * as original from ${JSON.stringify(url+'?r022-original')}; export async function verifySourcePin(...args){globalThis.__r022.pin();return original.verifySourcePin(...args);} export async function copySources(...args){await original.copySources(...args);if(globalThis.__r022.failCopy)throw new Error('fixture partial copy failure');} export async function sourceManifest(path){if(globalThis.__r022.failManifest&&path.includes('sec-hub-supervised-'))throw new Error('fixture staged manifest failure');return original.sourceManifest(path);} export async function safeRead(path,...args){if(globalThis.__r022.failRead(path))throw new Error('fixture retained read failure');return original.safeRead(path,...args);}`};
 if(scenario==='preparation'&&url.endsWith('/src/agents/cloudflare-preparation.mjs'))return {format:'module',shortCircuit:true,source:'export async function inspectCloudflarePreparation(){return {receipt:{chargedAgents:5},retainedFiles:[],source:{inputs:[]}};} export async function materializeCloudflarePreparation(){throw new Error("must not reach materialization");}'};
 return next(url,context);
 }});
 const {runSupervisedCloudflare}=await import('../src/agents/supervised-cloudflare.mjs');const {PINS}=await import('../src/agents/validation.mjs');
 let exitCode,error;try{exitCode=await runSupervisedCloudflare({id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/supervised-fake-codex.mjs'),'zero'],target,artifactDir,agentOptions:{strategy:'supervised-codex-workers',skillRoot:cloudflareSourceRoot(),workRoot,revision:PINS.cloudflare,model:'model',maxAgents:10,...(scenario==='preparation'?{preparationFrom:join(root,'prior/raw/cloudflare/execution-manifest.json'),preparationSha256:'a'.repeat(64)}:{})}});}catch(e){error=e.message;}
 const read=async file=>fs.readFile(join(artifactDir,file),'utf8').catch(()=>null);process.stdout.write(JSON.stringify({exitCode,error,stages:await fs.readdir(workRoot),manifest:JSON.parse(await read('execution-manifest.json')),metadata:JSON.parse(await read('run-metadata.json')),report:await read('REPORT.md'),canonicalHashes:Object.fromEntries(await Promise.all(['run-metadata.json','REPORT.md'].map(async name=>[name,createHash('sha256').update((await read(name))??'').digest('hex')])))})+'\n');
}else{
 async function run(mode){const root=await fs.mkdtemp(join(tmpdir(),'release022-lifecycle-'));try{const result=spawnSync(process.execPath,[fileURLToPath(import.meta.url)],{env:{...process.env,SEC_HUB_RELEASE022_SCENARIO:mode,SEC_HUB_RELEASE022_ROOT:root},encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024});assert.equal(result.status,0,`error=${result.error?.code??'none'} signal=${result.signal??'none'}: ${result.stderr}`);return JSON.parse(result.stdout.trim().split('\n').at(-1));}finally{await fs.rm(root,{recursive:true,force:true});}}
 for(const mode of ['mkdir','copy','source-manifest','preparation'])test(`#10 cleans stage when initialization fails at ${mode}`,async()=>{const result=await run(mode);assert.match(result.error,/fixture|Continuation source copy differs/);assert.deepEqual(result.stages,[]);});
 test('#11 retained evidence failure publishes consistent incomplete manifest metadata and report',async()=>{const result=await run('retained');assert.equal(result.exitCode,1);assert.equal(result.manifest.status,'incomplete');assert.match(result.manifest.reasons.join(';'),/Missing retained role evidence/);assert.equal(result.metadata.run_status,'incomplete');assert.match(result.metadata.incomplete_reason,/Missing retained role evidence/);assert.match(result.report,/Status: incomplete/);assert.doesNotMatch(result.report,/Status: complete/);for(const [name,hash]of Object.entries(result.canonicalHashes))assert.equal(result.manifest.preRedactionHashes[name],hash);assert.deepEqual(result.stages,[]);});
 test('#10 #11 healthy supervision still completes and cleans stage',async()=>{const result=await run('healthy');assert.equal(result.exitCode,0);assert.equal(result.metadata.run_status,'complete');assert.equal(result.manifest.status,'complete');assert.match(result.report,/Status: complete/);assert.deepEqual(result.stages,[]);});
}
