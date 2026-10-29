import {createAnthropicRegistration,verifyStagedRegistration,validateAnthropicRegistration,registrationFiles} from './anthropic-registration.mjs';
// Trusted parent supervisor: models never write this wrapper's retained manifest.
// Native descendants inherit the core wrapper process group; its wall timeout kills all.
import { spawn, execFile } from 'node:child_process';
import { mkdir, mkdtemp, symlink, writeFile, open, rm } from 'node:fs/promises';
import { join, relative, resolve, isAbsolute, dirname } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { pathToFileURL } from 'node:url';
import { ensureSafeDirectory, atomicWriteFile } from '../safe-io.mjs';
import { validateAgentOptions } from '../config.mjs';
import { PINS,SOURCES,OUTPUTS,nativeOptions,safeRead,sha256,sourceManifest,copySources,sameInputs,inspectNativeEvents,verifyCloudflareRecords,verifySourcePin,runOfficialValidators,parseAnthropicDocument } from './validation.mjs';
import { promisify } from 'node:util';
import { cloudflarePrompt,codexArgs,claudeArgs } from './invocation.mjs';
const execute=promisify(execFile);
let active,interrupted=0;
const cancellation=new AbortController();
function checkInterrupted(){if(interrupted)throw new Error('Native workflow interrupted by cancellation');}
for(const [signal,code] of [['SIGTERM',143],['SIGINT',130]])process.on(signal,()=>{interrupted=code;process.exitCode=code;cancellation.abort();active?.kill(signal);});
function inside(parent,child){const rel=relative(resolve(parent),resolve(child));return rel===''||(!rel.startsWith('..')&&!isAbsolute(rel));}
async function writeComplete(handle,chunk){
  let offset=0;
  while(offset<chunk.length){
    const {bytesWritten}=await handle.write(chunk,offset,chunk.length-offset,null);
    if(!Number.isInteger(bytesWritten)||bytesWritten<=0||bytesWritten>chunk.length-offset)throw new Error('Invalid native evidence write progress');
    offset+=bytesWritten;
  }
}
async function run(command,args,{cwd,env,prompt='',artifactDir,label='native',onEvent,limit=20*1024*1024}){
  checkInterrupted();
  const out=await open(join(artifactDir,`${label}-events.jsonl`),'wx',0o600),err=await open(join(artifactDir,`${label}-stderr.log`),'wx',0o600);
  let bytes=0,outputLimitExceeded=false,writeError=false,eventBuffer='';const stdout=[],stderr=[];let pending=Promise.resolve();const eventDecoder=new StringDecoder('utf8');
  const parseEvents=text=>{eventBuffer+=text;let nl;while((nl=eventBuffer.indexOf('\n'))>=0){const line=eventBuffer.slice(0,nl);eventBuffer=eventBuffer.slice(nl+1);if(line.trim())try{onEvent?.(JSON.parse(line));}catch{active?.kill('SIGTERM');}}};
  try{
    const code=await new Promise((resolveCode,reject)=>{
      checkInterrupted();active=spawn(command,args,{cwd,env,shell:false,detached:false,stdio:['pipe','pipe','pipe'],windowsHide:true});
      const capture=(handle,chunks)=>chunk=>{bytes+=chunk.length;if(bytes>limit){outputLimitExceeded=true;active?.kill('SIGTERM');return;}chunks.push(chunk);pending=pending.then(()=>writeComplete(handle,chunk)).catch(()=>{writeError=true;active?.kill('SIGTERM');});};
      active.stdout.on('data',chunk=>{capture(out,stdout)(chunk);if(bytes<=limit&&onEvent)parseEvents(eventDecoder.write(chunk));});active.stderr.on('data',capture(err,stderr));active.once('error',reject);active.once('close',(code,signal)=>{if(onEvent){parseEvents(eventDecoder.end());if(eventBuffer.trim())parseEvents('\n');}active=undefined;resolveCode(code??(signal==='SIGINT'?130:143));});active.stdin.on('error',()=>{});active.stdin.end(prompt);
    });await pending;if(writeError)throw new Error('Native evidence log write failed');return {exitCode:code,interrupted,outputLimitExceeded,stdout:Buffer.concat(stdout).toString(),stderr:Buffer.concat(stderr).toString()};
  }finally{await out.close();await err.close();}
}
async function main(){
  const cfg=JSON.parse(process.argv[2]);if(!['cloudflare','anthropic'].includes(cfg.id)||typeof cfg.command!=='string'||!Array.isArray(cfg.args)||cfg.args.some(x=>typeof x!=='string'))throw new Error('Invalid native wrapper input');
  const options=nativeOptions(cfg.id,validateAgentOptions(cfg.id,cfg.agentOptions));
  if(cfg.id==='cloudflare'&&options.strategy==='supervised-codex-workers')return (await import('./supervised-cloudflare.mjs')).runSupervisedCloudflare({...cfg,agentOptions:options});
  checkInterrupted();const instructions=await verifySourcePin(cfg.id,options,{signal:cancellation.signal});
  if(inside(cfg.target,options.workRoot)||inside(cfg.artifactDir,options.workRoot)||inside(cfg.target,cfg.artifactDir))throw new Error('Native work/output directories must be outside source target');
  const inputs=await sourceManifest(cfg.target);if(!inputs.length)throw new Error('Empty source target');
  await ensureSafeDirectory(cfg.artifactDir);await ensureSafeDirectory(options.workRoot);
  const stage=await mkdtemp(join(options.workRoot,`sec-hub-${cfg.id}-`));
  if(inside(cfg.artifactDir,stage)||inside(cfg.target,stage))throw new Error('Execution source staging must be outside target and raw artifacts');
  const copy=join(stage,'target'),runner=join(stage,'runner'),output=join(runner,'audit');await mkdir(runner,{mode:0o700});await mkdir(output,{mode:0o700});
  let copyBefore;try{await copySources(cfg.target,copy,inputs);copyBefore=await sourceManifest(copy);}catch(error){await rm(stage,{recursive:true,force:true});throw error;}
  const manifest={schema:'sec-hub.native-agent/v1',id:cfg.id,...(cfg.id==='anthropic'?{invocationPolicyVersion:3}:{}),source:SOURCES[cfg.id],sourceCommit:PINS[cfg.id],nativeNodeExecutable:process.execPath,nativeNodeVersion:process.versions.node,instructions,model:options.model,backend:cfg.id==='cloudflare'?'codex':'claude',...(cfg.id==='cloudflare'?{strategy:options.strategy}:{}),mode:cfg.id==='cloudflare'?'official-security-audit-skill':'official-claude-code-vuln-scan',target:resolve(cfg.target),copyTarget:copy,inputs,copyBefore,startedAt:new Date().toISOString(),status:'incomplete',reasons:[],preRedactionHashes:{},hashScope:'native retained bytes before core redaction'};
  try{
    checkInterrupted();let args,cwd,prompt='';
    if(cfg.id==='cloudflare'){
      await mkdir(join(runner,'.agents/skills'),{recursive:true,mode:0o700});await symlink(join(options.skillRoot,'skills/security-audit'),join(runner,'.agents/skills/security-audit'),'dir');
      args=codexArgs(runner,options);cwd=runner;prompt=cloudflarePrompt(copy,output,options);
    }else{
      manifest.skillRegistration=await createAnthropicRegistration(copy,options.skillRoot,instructions,cfg.artifactDir);
      for(const file of registrationFiles)manifest.preRedactionHashes[file]=sha256(await safeRead(join(cfg.artifactDir,file)));
      args=claudeArgs(copy,options,cfg,inputs,3);cwd=options.skillRoot;
    }
    manifest.invocation={command:cfg.command,args:[...cfg.args,...args],cwd};
    if(prompt)manifest.promptSha256=sha256(prompt);
    const env={PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:stage,LANG:'en_US.UTF-8',CLAUDE_CODE_DISABLE_AUTO_MEMORY:'1',CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD:'0'};
    // Native backends discover their existing login internally. No credential material is read or copied.
    if(cfg.id==='anthropic'&&process.env.USER)env.USER=process.env.USER;
    if(cfg.id==='cloudflare'&&process.env.CODEX_HOME)env.CODEX_HOME=process.env.CODEX_HOME;
    checkInterrupted();const version=await execute(cfg.command,[...cfg.args,'--version'],{cwd,env,timeout:10000,maxBuffer:64*1024,signal:cancellation.signal});manifest.backendVersion=(version.stdout||version.stderr).trim().slice(0,500);
    let spawns=0;const onEvent=event=>{if(cfg.id==='cloudflare'&&event.type==='item.completed'&&event.item?.type==='collab_tool_call'&&event.item.tool==='spawn_agent'&&event.item.status==='completed'){spawns+=(event.item.receiver_thread_ids??[]).length;if(spawns>options.maxAgents){manifest.reasons.push('Native delegation budget exceeded');active?.kill('SIGTERM');}}};
    const result=await run(cfg.command,[...cfg.args,...args],{cwd,env,prompt,artifactDir:cfg.artifactDir,onEvent});
    for(const file of ['native-events.jsonl','native-stderr.log'])manifest.preRedactionHashes[file]=sha256(await safeRead(join(cfg.artifactDir,file)));
    manifest.process={exitCode:result.exitCode,interrupted:result.interrupted,outputLimitExceeded:result.outputLimitExceeded};
    const events=result.stdout.split('\n').filter(x=>x.trim()).map(x=>JSON.parse(x));manifest.nativeEvidence=inspectNativeEvents(cfg.id,events,{...options,copyTarget:copy,exitCode:result.exitCode,...(cfg.id==='anthropic'?{invocationPolicyVersion:3,registrationValidated:true}:{})});manifest.reasons.push(...manifest.nativeEvidence.reasons);
    if(result.exitCode!==0||interrupted||result.outputLimitExceeded)manifest.reasons.push('Native process did not succeed');
    for(const file of OUTPUTS[cfg.id]){
      try{const data=await safeRead(join(cfg.id==='cloudflare'?output:copy,file),5*1024*1024);await writeFile(join(cfg.artifactDir,file),data,{flag:'wx',mode:0o600});manifest.preRedactionHashes[file]=sha256(data);}catch{manifest.reasons.push(`Missing or unsafe native output: ${file}`);}
    }
    if(cfg.id==='cloudflare'){
      try{const doc=JSON.parse((await safeRead(join(cfg.artifactDir,'findings.json'))).toString());manifest.independentRecords=verifyCloudflareRecords(doc,events,manifest.nativeEvidence);}catch(error){manifest.reasons.push(error.message);}
      checkInterrupted();manifest.validators=await runOfficialValidators(options,cfg.artifactDir,{signal:cancellation.signal});if(manifest.validators.some(x=>x.exitCode!==0))manifest.reasons.push('Official validators failed');
      try{const metadata=JSON.parse((await safeRead(join(cfg.artifactDir,'run-metadata.json'))).toString());if(metadata.run_status!=='complete'||metadata.profile!=='quick')manifest.reasons.push('Official audit metadata is incomplete');}catch{manifest.reasons.push('Invalid official run metadata');}
    }else try{parseAnthropicDocument(JSON.parse((await safeRead(join(cfg.artifactDir,'VULN-FINDINGS.json'))).toString()),{copyTarget:copy,inputs,artifactDir:cfg.artifactDir});}catch(error){manifest.reasons.push(error.message);}
  }catch(error){manifest.reasons.push(error.message);}
  finally{
    if(cfg.id==='anthropic'&&manifest.skillRegistration)try{
      manifest.skillRegistration.finalFiles=await verifyStagedRegistration(copy);
      await validateAnthropicRegistration(manifest.skillRegistration,copy,options.skillRoot,instructions,cfg.artifactDir);
    }catch(error){manifest.reasons.push(error.message);}
    try{
      manifest.originalAfter=await sourceManifest(cfg.target);const after=await sourceManifest(copy);
      const allowedNew=cfg.id==='anthropic'?OUTPUTS.anthropic:[];
      manifest.copyAfter=after.filter(x=>inputs.some(old=>old.path===x.path));manifest.addedFiles=after.filter(x=>!inputs.some(old=>old.path===x.path));
      if(!sameInputs(inputs,manifest.originalAfter)||!sameInputs(inputs,manifest.copyBefore)||!sameInputs(inputs,manifest.copyAfter)||manifest.addedFiles.some(x=>!allowedNew.includes(x.path)))manifest.reasons.push('Source preservation or unexpected addition failed');
      checkInterrupted();const finalInstructions=await verifySourcePin(cfg.id,options,{signal:cancellation.signal});if(!sameInputs(instructions,finalInstructions))manifest.reasons.push('Official source changed during execution');
    }catch(error){manifest.reasons.push(error.message);}
    if(interrupted)manifest.reasons.push('Native workflow interrupted by cancellation');
    manifest.endedAt=new Date().toISOString();manifest.status=manifest.reasons.length?'incomplete':'complete';
    let finalizationError;
    try{await atomicWriteFile(join(cfg.artifactDir,'execution-manifest.json'),`${JSON.stringify(manifest,null,2)}\n`);}catch(error){finalizationError=error;}finally{
      // Keep a stage that may still be in use; otherwise clean it even when publication failed.
      try{if(active){console.error(`Native staging retained while process termination is pending at ${stage}.`);}else await rm(stage,{recursive:true,force:true});}catch(error){console.error(`Native staging cleanup failed at ${stage}: ${error.message}`);if(!finalizationError)finalizationError=error;}
    }
    if(finalizationError)throw finalizationError;
    // Publication and cleanup also yield to signal handlers. Replace a complete
    // snapshot if cancellation arrived during either asynchronous operation.
    if(interrupted&&manifest.status==='complete'){
      manifest.reasons.push('Native workflow interrupted by cancellation');manifest.status='incomplete';manifest.endedAt=new Date().toISOString();
      await atomicWriteFile(join(cfg.artifactDir,'execution-manifest.json'),`${JSON.stringify(manifest,null,2)}\n`);
    }
  }
  console.log(`${cfg.id}: native workflow ${manifest.status}; trusted execution manifest retained.`);return interrupted|| (manifest.status==='complete'?0:2);
}
export { run };
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){try{process.exitCode=await main();}catch(error){console.error(`Native agent wrapper failed: ${error.message}`);process.exitCode=interrupted||2;}}
