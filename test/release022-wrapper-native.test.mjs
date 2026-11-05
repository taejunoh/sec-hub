import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
const wrapper=fileURLToPath(new URL('../src/agents/native-wrapper.mjs',import.meta.url));
async function fixture(t){const root=await mkdtemp(join(tmpdir(),'release022-native-'));t.after(()=>rm(root,{recursive:true,force:true}));for(const p of ['target','artifacts','work'])await mkdir(join(root,p));return root;}
function child(args,env){
  const proc=spawn(process.execPath,args,{env:{...process.env,...env},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';proc.stdout.setEncoding('utf8').on('data',x=>stdout+=x);proc.stderr.setEncoding('utf8').on('data',x=>stderr+=x);
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{proc.kill('SIGKILL');reject(new Error('Native fixture timeout'));},5000);proc.once('error',reject);proc.once('close',code=>{clearTimeout(timer);resolve({code,stdout,stderr});});});
}

test('release022 #8 successful short writes retain all native event and stderr bytes',async t=>{
  const root=await fixture(t),preload=join(root,'short.mjs'),runner=join(root,'runner.mjs');
  await writeFile(preload,`import fs from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';const original=fs.open;fs.open=async(...args)=>{const handle=await original(...args),write=handle.write.bind(handle);handle.write=(buffer,offset=0,length=buffer.length-offset,position=null)=>write(buffer,offset,Math.min(7,length),position);return handle;};syncBuiltinESMExports();`);
  const program='process.stdout.write(\'{"message":"retained-한글-event"}\\n\');process.stderr.write(\'retained-error-bytes\')';
  await writeFile(runner,`import {run} from ${JSON.stringify(pathToFileURL(wrapper).href)};const r=await run(process.execPath,['-e',${JSON.stringify(program)}],{cwd:process.env.ROOT,env:process.env,artifactDir:process.env.ROOT+'/artifacts'});console.log(JSON.stringify(r));`);
  const result=await child(['--import',preload,runner],{ROOT:root});assert.equal(result.code,0,result.stderr);
  const memory=JSON.parse(result.stdout);assert.equal(memory.stdout,'{"message":"retained-한글-event"}\n');assert.equal(memory.stderr,'retained-error-bytes');
  assert.equal(await readFile(join(root,'artifacts/native-events.jsonl'),'utf8'),memory.stdout);
  assert.equal(await readFile(join(root,'artifacts/native-stderr.log'),'utf8'),memory.stderr);
});

for(const invalid of ['zero','oversized','negative'])test(`release022 #8 ${invalid} evidence writes fail boundedly instead of accepting lost bytes`,async t=>{
  const root=await fixture(t),preload=join(root,'bad.mjs'),runner=join(root,'runner.mjs');
  await writeFile(preload,`import fs from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';const original=fs.open;fs.open=async(...args)=>{const handle=await original(...args);handle.write=async(buffer,offset=0,length=buffer.length-offset)=>({bytesWritten:${invalid==='zero'?'0':invalid==='negative'?'-1':'length+1'},buffer});return handle;};syncBuiltinESMExports();`);
  await writeFile(runner,`import {run} from ${JSON.stringify(pathToFileURL(wrapper).href)};try{await run(process.execPath,['-e','console.log("evidence")'],{cwd:process.env.ROOT,env:process.env,artifactDir:process.env.ROOT+'/artifacts'});console.log('accepted');}catch(error){console.error(error.message);process.exitCode=2;}`);
  const result=await child(['--import',preload,runner],{ROOT:root});assert.equal(result.code,2,result.stdout);assert.match(result.stderr,/evidence log write failed/i);
});

async function cancellationFixture(t,phase){
  const root=await fixture(t),loader=join(root,'loader.mjs'),fake=join(root,'fake.mjs');await writeFile(fake,'console.log("{}");');
  const validation=`
    import {mkdir,writeFile} from 'node:fs/promises';
    const root=process.env.ROOT,phase=process.env.PHASE;
    const mark=word=>writeFile(root+'/calls',word+'\\n',{flag:'a'});
    export const PINS={cloudflare:'pin'},SOURCES={cloudflare:'source'},OUTPUTS={cloudflare:['findings.json']};
    export function nativeOptions(id,value){return {...value,strategy:'native-collab'}};
    export async function safeRead(file){if(phase==='copy'&&file.endsWith('/findings.json'))process.emit('SIGTERM');return Buffer.from(file.endsWith('/run-metadata.json')?'({})'.replace('({})','{"run_status":"complete","profile":"quick"}'):'[]')};
    export function sha256(){return 'hash'};
    let manifests=0;export async function sourceManifest(){manifests++;if(phase==='final'&&manifests===3)process.emit('SIGTERM');return [{path:'source.txt',sha256:'hash',lines:1}]};
    export async function copySources(source,copy){await mkdir(copy);await writeFile(copy+'/source.txt','fixture')};
    export function sameInputs(){return true};export function inspectNativeEvents(){return {reasons:[]}};export function verifyCloudflareRecords(){return []};
    let pinChecks=0;export async function verifySourcePin(id,options,{signal}={}){pinChecks++;await mark('pin');if(phase==='final-pin'&&pinChecks===2||phase==='initial-pin'&&pinChecks===1){process.emit('SIGTERM');signal?.throwIfAborted();await mark('later-git');}return []};
    export async function runOfficialValidators(){await mark('validators');if(phase==='validators')process.emit('SIGTERM');return []};
    export function parseAnthropicDocument(){return []};
  `;
  const sandbox=`export const SANDBOX_INVOCATION_POLICY_VERSION=2;export function assertSandboxBackend(){}export async function probeSandbox(){return {schema:'sec-hub.codex-sandbox-probe/v1',policyVersion:2,profile:'sec_hub_v2',platform:'darwin',checks:['target-read','pinned-document-read','runtime-exec','outside-read-denied','symlink-read-denied','target-write-denied','runner-write']}}`;
  await writeFile(loader,`const validation=${JSON.stringify(validation)},sandbox=${JSON.stringify(sandbox)};export async function resolve(specifier,context,next){if(context.parentURL?.endsWith('/native-wrapper.mjs')){if(specifier==='./validation.mjs')return {url:'fixture:validation',shortCircuit:true};if(specifier==='./codex-sandbox.mjs')return {url:'fixture:codex-sandbox',shortCircuit:true}}return next(specifier,context)}export async function load(url,context,next){if(url==='fixture:validation')return {format:'module',source:validation,shortCircuit:true};if(url==='fixture:codex-sandbox')return {format:'module',source:sandbox,shortCircuit:true};return next(url,context)}`);
  const options={id:'cloudflare',command:process.execPath,args:[fake],target:join(root,'target'),artifactDir:join(root,'artifacts'),agentOptions:{skillRoot:join(root,'skill'),workRoot:join(root,'work'),revision:'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',model:'fixture'}};
  const preload=join(root,'cancel-late.mjs');
  await writeFile(preload,`import fs from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';let sent=false;const original=fs[process.env.PHASE==='publication'?'rename':'rm'];if(['publication','cleanup'].includes(process.env.PHASE)){const method=process.env.PHASE==='publication'?'rename':'rm';fs[method]=async(...args)=>{const result=await original(...args);if(!sent&&(method==='rename'&&args[1].endsWith('/execution-manifest.json')||method==='rm'&&args[0].startsWith(process.env.ROOT+'/work/'))){sent=true;process.emit('SIGTERM');}return result;};syncBuiltinESMExports();}`);
  const result=await child(['--import',preload,'--experimental-loader',loader,wrapper,JSON.stringify(options)],{ROOT:root,PHASE:phase});
  return {...result,manifest:await readFile(join(root,'artifacts/execution-manifest.json'),'utf8').then(JSON.parse).catch(error=>{if(error.code==='ENOENT')return undefined;throw error;}),calls:await readFile(join(root,'calls'),'utf8')};
}
for(const phase of ['copy','validators','final','final-pin','publication','cleanup'])test(`release022 #7 SIGTERM during ${phase} keeps native manifest incomplete and avoids later children`,async t=>{
  const result=await cancellationFixture(t,phase);assert.equal(result.code,143,result.stderr);assert.equal(result.manifest.status,'incomplete');assert.match(result.manifest.reasons.join(';'),/interrupt|cancel/i);
  if(phase==='copy')assert.equal(result.calls,'pin\n');
  if(phase==='final')assert.equal(result.calls,'pin\nvalidators\n');
  if(phase==='final-pin')assert.equal(result.calls,'pin\nvalidators\npin\n');
});
test('release022 #7 uncancelled native entry still publishes complete with validators and final checks',async t=>{const result=await cancellationFixture(t,'healthy');assert.equal(result.code,0,result.stderr);assert.equal(result.manifest.status,'complete');assert.equal(result.calls,'pin\nvalidators\npin\n');});

test('release022 #7 initial pin cancellation aborts before any later Git child or native stage',async t=>{const result=await cancellationFixture(t,'initial-pin');assert.equal(result.code,143,result.stderr);assert.equal(result.calls,'pin\n');assert.equal(result.manifest,undefined);});
