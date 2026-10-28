import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile,spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { registerHooks } from 'node:module';
import { mkdtemp,writeFile,rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { cloudflareSourceRoot } from './helpers/cloudflare-source.mjs';
const scenario=process.env.SEC_HUB_R022_VALIDATOR;
if(scenario){
 const root=await mkdtemp(join(tmpdir(),'r022-validator-')),controller=new AbortController(),calls=[];try{
 await writeFile(join(root,'findings.json'),'[]');await writeFile(join(root,'coverage-ledger.json'),'[]');
 const execute=promisify(execFile),replacement=()=>{};replacement[promisify.custom]=async(command,args,options)=>{calls.push({command,args,hasSignal:options.signal===controller.signal,startedAfterAbort:controller.signal.aborted});const result=await execute(command,args,options);if(scenario==='mid-pin'&&calls.length===1||scenario==='between'&&args[0]?.endsWith('validate-findings.cjs'))controller.abort(new Error('fixture cancellation'));return result;};globalThis.__r022Exec=replacement;
 registerHooks({resolve(specifier,context,next){if(specifier==='node:child_process'&&context.parentURL?.endsWith('/src/agents/validation.mjs'))return {url:'fixture:validator-process',shortCircuit:true};return next(specifier,context);},load(url,context,next){return url==='fixture:validator-process'?{format:'module',shortCircuit:true,source:'export const execFile=globalThis.__r022Exec;'}:next(url,context);}});
 const {runOfficialValidators,PINS}=await import('../src/agents/validation.mjs');if(scenario==='pre-aborted')controller.abort(new Error('fixture cancellation'));
 let result,error;try{result=await runOfficialValidators({skillRoot:cloudflareSourceRoot(),revision:PINS.cloudflare},root,{signal:controller.signal});}catch(e){error=e.message;}
 process.stdout.write(JSON.stringify({calls,result,error})+'\n');
 }finally{await rm(root,{recursive:true,force:true});}
}else{
 for(const scenario of ['pre-aborted','mid-pin','between','healthy'])test(`#7 real official validator cancellation guard ${scenario}`,()=>{const result=spawnSync(process.execPath,[fileURLToPath(import.meta.url)],{env:{...process.env,SEC_HUB_R022_VALIDATOR:scenario},encoding:'utf8',timeout:10000});assert.equal(result.status,0,result.stderr);const out=JSON.parse(result.stdout.trim());const validators=out.calls.filter(x=>x.args[0]?.endsWith('.cjs'));assert.equal(validators.length,['pre-aborted','mid-pin'].includes(scenario)?0:scenario==='between'?1:2);assert.ok(validators.every(x=>x.hasSignal));assert.equal(out.calls.filter(x=>x.startedAfterAbort).length,0);if(scenario==='mid-pin'){assert.equal(out.calls.length,1);assert.equal(out.calls[0].hasSignal,true);}if(scenario==='pre-aborted')assert.equal(out.calls.length,0);if(scenario==='healthy'){assert.equal(out.error,undefined);assert.ok(out.result.every(x=>x.exitCode===0));}else assert.equal(out.error,'fixture cancellation');});
}
