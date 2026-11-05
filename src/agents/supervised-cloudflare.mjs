// Trusted deterministic supervisor. Fresh native CLI roles have no shared-write
// authority; only this code writes canonical artifacts and execution provenance.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { StringDecoder } from 'node:string_decoder';
import { mkdir, mkdtemp, writeFile, open, rm, readdir } from 'node:fs/promises';
import { join, resolve, relative, isAbsolute, sep } from 'node:path';
import { ensureSafeDirectory, atomicWriteFile } from '../safe-io.mjs';
import { validateAgentOptions } from '../config.mjs';
import { nativeOptions, PINS, SOURCES, OUTPUTS, safeRead, sha256, sourceManifest, copySources, sameInputs, verifySourcePin, runOfficialValidators } from './validation.mjs';
import { loadCloudflareContracts, buildRolePrompt, supervisedArgs, reconOutputSchema, supervisedRoleTimeoutMs, SUPERVISED_WALL_TIMEOUT_MS, STRATEGY, LABEL, CLOUDFLARE_PROMPT_VERSION } from './cloudflare-prompts.mjs';
import { validateRecon, preparePlan, assignHunter, applyHunter, applyCritic, applyVerifier, inspectRoleEvidence, assertObservedPolicy, renderSupervisedReports, officialHelpers, validateRecords } from './supervised-validation.mjs';
import {SANDBOX_INVOCATION_POLICY_VERSION,assertSandboxBackend,probeSandbox} from './codex-sandbox.mjs';
import {inspectCloudflarePreparation,materializeCloudflarePreparation} from './cloudflare-preparation.mjs';
const execute=promisify(execFile),json=x=>JSON.stringify(x,null,2)+'\n';
const inside=(parent,child)=>{const p=relative(resolve(parent),resolve(child));return p!=='..'&&!p.startsWith('..'+sep)&&!isAbsolute(p);};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function groupAlive(pid){try{process.kill(-pid,0);return true;}catch(e){return e.code!=='ESRCH';}}
async function terminateGroup(pid){
  if(!pid)return;try{process.kill(-pid,'SIGTERM');}catch{}
  const until=Date.now()+80;while(groupAlive(pid)&&Date.now()<until)await pause(10);
  if(groupAlive(pid)){try{process.kill(-pid,'SIGKILL');}catch{}const killUntil=Date.now()+1000;while(groupAlive(pid)&&Date.now()<killUntil)await pause(20);}
  if(groupAlive(pid))throw new Error('Native process group cleanup could not be established');
}
async function runRoleProcess(command,args,{cwd,env,prompt,dir,record,deadline,active,signalState,onEvent}){
  const out=await open(join(dir,'events.jsonl'),'wx',0o600),err=await open(join(dir,'stderr.log'),'wx',0o600);let pending=Promise.resolve(),bytes=0,limit=false,writeError=false,child,timer,streamFailure;
  try{
    record.startedAt=new Date().toISOString();record.command=command;record.args=args;record.cwd=cwd;
    await new Promise(resolveClose=>{
      try{child=spawn(command,args,{cwd,env,shell:false,detached:true,windowsHide:true,stdio:['pipe','pipe','pipe']});}catch{record.exitCode=1;resolveClose();return;}
      record.pid=child.pid??null;if(child.pid)active.add(child.pid);
      let escalation;
      const kill=()=>{if(child.pid)try{process.kill(-child.pid,'SIGTERM');}catch{}if(!escalation)escalation=setTimeout(()=>{if(child.pid)try{process.kill(-child.pid,'SIGKILL');}catch{}},80);};
      timer=setTimeout(()=>{record.timedOut=true;kill();},Math.max(1,Math.min(supervisedRoleTimeoutMs(record.role),deadline-Date.now())));
      const capture=handle=>chunk=>{bytes+=chunk.length;if(bytes>20*1024*1024){limit=true;kill();return;}pending=pending.then(()=>handle.write(chunk)).catch(()=>{writeError=true;kill();});};
      const decoder=new StringDecoder('utf8');let buffer='';
      const inspect=line=>{if(!line.trim())return;onEvent(JSON.parse(line));};
      child.stdout.on('data',chunk=>{capture(out)(chunk);if(limit||streamFailure)return;try{buffer+=decoder.write(chunk);let newline;while((newline=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);if(Buffer.byteLength(line)>5*1024*1024)throw new Error('Native JSONL event exceeds byte limit');inspect(line);}if(Buffer.byteLength(buffer)>5*1024*1024)throw new Error('Native JSONL event exceeds byte limit');}catch(error){streamFailure=error;if(error.fatalPolicy)record.policyFailure=error.message;kill();}});child.stderr.on('data',capture(err));
      child.once('error',()=>{record.exitCode=1;});child.once('close',(code,signal)=>{clearTimeout(escalation);record.exitCode=code??(signal==='SIGINT'?130:143);if(!streamFailure)try{buffer+=decoder.end();inspect(buffer);}catch(error){streamFailure=error;if(error.fatalPolicy)record.policyFailure=error.message;}resolveClose();});child.stdin.on('error',()=>{});child.stdin.end(prompt);
    });
    await pending;record.interrupted=signalState.code||0;record.outputLimitExceeded=limit;record.writeError=writeError;
  }finally{
    clearTimeout(timer);await Promise.all([out.close(),err.close()]);
    // Keep ownership until termination is established so outer cleanup can retry.
    try{await terminateGroup(record.pid);if(record.pid)active.delete(record.pid);}finally{record.endedAt=new Date().toISOString();}
  }
  if(streamFailure)throw streamFailure;if(record.timedOut)throw new Error('Native role wall-time limit exceeded');if(writeError)throw new Error('Native evidence log write failed');
}
export async function runSupervisedCloudflare(payload){
  if(payload?.id!=='cloudflare'||typeof payload.command!=='string'||!Array.isArray(payload.args)||payload.args.some(s=>typeof s!=='string'))throw new Error('Invalid supervised native input');
  const options=nativeOptions('cloudflare',validateAgentOptions('cloudflare',payload.agentOptions));if(options.strategy!==STRATEGY)throw new Error('Explicit supervised strategy required');
  const instructions=await verifySourcePin('cloudflare',options),c=await loadCloudflareContracts(options.skillRoot),inputs=await sourceManifest(payload.target);if(!inputs.length)throw new Error('Empty source target');
  const prepared=options.preparationFrom?await inspectCloudflarePreparation({options,target:payload.target,artifactDir:payload.artifactDir,command:payload.command,args:payload.args}):null,charged=prepared?.receipt.chargedAgents??0;
  if(inside(payload.target,options.workRoot)||inside(payload.artifactDir,options.workRoot)||inside(payload.target,payload.artifactDir)||inside(options.workRoot,payload.artifactDir))throw new Error('Supervised work/output paths must be isolated outside target');
  await ensureSafeDirectory(payload.artifactDir);await ensureSafeDirectory(options.workRoot);
  if(prepared&&(await readdir(payload.artifactDir)).length)throw new Error('Preparation continuation requires a fresh empty raw output directory');
  const stage=await mkdtemp(join(options.workRoot,'sec-hub-supervised-')),copy=join(stage,'target'),runner=join(stage,'runner'),active=new Set();
  try{
  await mkdir(runner,{mode:0o700});await copySources(payload.target,copy,inputs);
  const manifest={schema:'sec-hub.native-agent/v1',promptVersion:CLOUDFLARE_PROMPT_VERSION,sandboxInvocationPolicyVersion:SANDBOX_INVOCATION_POLICY_VERSION,id:'cloudflare',strategy:STRATEGY,label:LABEL,adapted:true,source:SOURCES.cloudflare,sourceCommit:PINS.cloudflare,instructions,nativeNodeExecutable:process.execPath,nativeNodeVersion:process.versions.node,backend:'codex',model:options.model,mode:'supervised-official-security-audit-skill',target:resolve(payload.target),copyTarget:copy,runner,inputs,copyBefore:await sourceManifest(copy),startedAt:new Date().toISOString(),status:'incomplete',reasons:[],invocation:{command:payload.command,args:payload.args},roles:[],retainedFiles:[...OUTPUTS.cloudflare],preRedactionHashes:{},hashScope:'native retained bytes before core redaction'};
  const metadata={run_id:`supervised-${Date.now()}-${process.pid}`,repo:resolve(payload.target),target:copy,source_ref:`sha256:${sha256(JSON.stringify(inputs))}`,profile:'quick',scope_paths:inputs.map(i=>i.path),budget:{max_agents:options.maxAgents,spent:0,planned_minimum:8},execution_policy:'sandboxed-source-and-local-only',selected_companion_files:[],prior_run_paths:[],shared_file_owners:Object.fromEntries(OUTPUTS.cloudflare.map(f=>[f,'trusted-supervisor'])),run_status:'in_progress',strategy:STRATEGY};
  if(prepared){manifest.preparation=prepared.receipt;manifest.retainedFiles.push(...prepared.retainedFiles);metadata.preparation={source_manifest:prepared.receipt.sourceManifestPath,source_manifest_sha256:prepared.receipt.sourceManifestSha256,source_status:prepared.receipt.sourceStatus,charged_agents:charged,source_sandbox_invocation_policy_version:prepared.source.sandboxInvocationPolicyVersion??1};if(!sameInputs(manifest.copyBefore,prepared.source.inputs))throw new Error('Continuation source copy differs from preparation inputs');}
  const knownThreads=new Set(prepared?.threadIds??[]),signalState={code:0},probeCancellation=new AbortController(),deadline=Date.now()+SUPERVISED_WALL_TIMEOUT_MS,handlers=[];let state=prepared?.state??null;
  const stop=code=>{signalState.code=code;probeCancellation.abort();const owned=[...active];for(const pid of owned)try{process.kill(-pid,'SIGTERM');}catch{}
    // Outer runProcess escalates at300ms. Kill detached child groups first,
    // retaining this timer even if a leader exits before its descendants.
    setTimeout(()=>{for(const pid of owned)try{process.kill(-pid,'SIGKILL');}catch{}},80);
  };
  for(const [signal,code]of [['SIGINT',130],['SIGTERM',143]]){const handler=()=>stop(code);process.on(signal,handler);handlers.push([signal,handler]);}
  const wholeTimer=setTimeout(()=>stop(124),SUPERVISED_WALL_TIMEOUT_MS);wholeTimer.unref();
  const save=async()=>{
    metadata.budget.spent=charged+manifest.roles.length;if(prepared){metadata.budget.reused_agents=charged;metadata.budget.new_agents=manifest.roles.length;}
    const values={'run-metadata.json':json(metadata),'architecture.md':state?.architecture??'Architecture was not established; run incomplete.\n','coverage-ledger.json':json(state?.ledger??[]),'findings.json':json(state?.records??[]),...renderSupervisedReports(state,metadata)};
    for(const [name,value]of Object.entries(values))await atomicWriteFile(join(payload.artifactDir,name),value);
    // Official ledger validation on every trusted parent update, including seed.
    const result=officialHelpers(c).ledger.validateDocument(state?.ledger??[]);if(result.length)throw new Error('Official coverage ledger update invalid');
    await execute(process.execPath,[join(c.root,'validate-coverage-ledger.cjs'),join(payload.artifactDir,'coverage-ledger.json')],{timeout:10000,maxBuffer:256*1024});
  };
  async function invoke(role,ownerId,extra={}){
    if(signalState.code||Date.now()>=deadline)throw new Error('Supervised workflow interrupted or wall-time exceeded');
    if(charged+manifest.roles.length>=options.maxAgents)throw new Error('Strict total-agent budget exhausted');
    const agentId=`${ownerId}-${charged+manifest.roles.length+1}`,dir=join(payload.artifactDir,'roles',agentId);
    const expected=buildRolePrompt(c,{role,agentId:ownerId,target:copy,runner,...extra},manifest.promptVersion),record={role,agentId,ownerId,...(extra.candidate?{fingerprint:extra.candidate.fingerprint}:{}),promptSha256:sha256(expected.prompt),promptBytes:Buffer.byteLength(expected.prompt),sourceBlocks:expected.sourceBlocks,accepted:false};
    manifest.roles.push(record);metadata.budget.spent=charged+manifest.roles.length;await mkdir(dir,{recursive:true,mode:0o700});
    await mkdir(join(runner,'agents',ownerId,'scratch'),{recursive:true,mode:0o700});await mkdir(join(runner,'agents',ownerId,'artifacts'),{recursive:true,mode:0o700});
    for(const name of ['prompt.txt','events.jsonl','stderr.log','response.json'])manifest.retainedFiles.push(`roles/${agentId}/${name}`);
    const schema=reconOutputSchema(role),schemaText=schema?json(schema):null,schemaFile=schema?`roles/${agentId}/output-schema.json`:null;
    if(schema){record.outputSchema={file:schemaFile,sha256:sha256(schemaText),bytes:Buffer.byteLength(schemaText)};manifest.retainedFiles.push(schemaFile);await writeFile(resolve(payload.artifactDir,schemaFile),schemaText,{flag:'wx',mode:0o400});}
    await writeFile(join(dir,'prompt.txt'),expected.prompt,{flag:'wx',mode:0o600});
    try{
      const execArgs=supervisedArgs(runner,options,process.execPath,schemaFile?resolve(payload.artifactDir,schemaFile):null,manifest.sandboxInvocationPolicyVersion,expected.readFiles);
      record.sandboxProbe=await probeSandbox({command:payload.command,args:payload.args,execArgs,runner,targetFile:join(copy,inputs[0].path),skillFile:expected.readFiles[0],nodeExecutable:process.execPath,env:manifest.nativeEnvironment,signal:probeCancellation.signal});
      if(signalState.code||Date.now()>=deadline)throw new Error('Supervised workflow interrupted or wall-time exceeded');
      await runRoleProcess(payload.command,[...payload.args,...execArgs],{cwd:runner,env:manifest.nativeEnvironment,prompt:expected.prompt,dir,record,deadline,active,signalState,onEvent:event=>assertObservedPolicy(event,expected)});
      const events=(await safeRead(join(dir,'events.jsonl'))).toString().split('\n').filter(s=>s.trim()).map(s=>JSON.parse(s));
      const starts=events.filter(e=>e.type==='thread.started');if(starts.length===1)record.threadId=starts[0].thread_id;
      if(record.threadId&&(knownThreads.has(record.threadId)||manifest.roles.some(r=>r!==record&&r.threadId===record.threadId)))throw new Error('Native fresh thread identity reused');if(record.threadId)knownThreads.add(record.threadId);
      const finalText=events.filter(e=>e.type==='item.completed'&&e.item?.type==='agent_message').at(-1)?.item.text;
      await writeFile(join(dir,'response.json'),typeof finalText==='string'?finalText:'null',{flag:'wx',mode:0o600});
      const proof=inspectRoleEvidence(events,record,expected,c);record.accepted=true;return {response:proof.response,record};
    }catch(error){
      let failure=error,lastText='null';
      // A timeout or transport failure cannot hide an already retained forbidden
      // command. Replay complete lines through the SAME policy before choosing
      // the trusted failure reason; preserve native text without repairing it.
      try{const starts=[];let policySeen=false;for(const line of (await safeRead(join(dir,'events.jsonl'))).toString().split('\n').filter(s=>s.trim())){let event;try{event=JSON.parse(line);}catch{continue;}if(event.type==='thread.started')starts.push(event.thread_id);if(event.type==='item.completed'&&event.item?.type==='agent_message'&&typeof event.item.text==='string')lastText=event.item.text;try{assertObservedPolicy(event,expected);}catch(policy){if(policy.fatalPolicy&&!policySeen){failure=policy;record.policyFailure=policy.message;policySeen=true;}}}if(starts.length===1)record.threadId=starts[0];}catch{}
      record.failure=failure.message;record.accepted=false;try{await writeFile(join(dir,'response.json'),lastText,{flag:'wx',mode:0o600});}catch{}throw failure;
    }
  }
  try{
    if(prepared)await materializeCloudflarePreparation(prepared,payload.artifactDir);
    await save();
    // Fund a real hunter and an independent candidate verifier before launching
    // any recon; zero candidates legitimately spend seven rather than eight.
    if(options.maxAgents<8)throw new Error('Pre-recon budget cannot reserve four recon, planner, hunter, critic and verifier');
    const env={PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:stage,LANG:'en_US.UTF-8'};if(process.env.CODEX_HOME)env.CODEX_HOME=process.env.CODEX_HOME;
    // Environment has authentication discovery paths only; no auth file is read.
    const version=await execute(payload.command,[...payload.args,'--version'],{cwd:runner,env,timeout:10000,maxBuffer:64*1024});manifest.backendVersion=(version.stdout||version.stderr).trim().slice(0,500);manifest.nativeEnvironment=env;
    assertSandboxBackend(manifest.backendVersion);
    if(prepared&&manifest.backendVersion!==prepared.receipt.backendVersion)throw new Error('Native backend version changed since preparation');
    if(!prepared){
    const reconResults=await Promise.allSettled(['recon-1a','recon-1b','recon-1c','recon-1d'].map(role=>invoke(role,role)));
    const recon=[];for(let i=0;i<reconResults.length;i++){const item=reconResults[i];if(item.status==='rejected')throw item.reason;try{validateRecon(item.value.response,`recon-1${'abcd'[i]}`,inputs);}catch(e){item.value.record.accepted=false;item.value.record.failure=e.message;throw e;}recon.push(item.value.response);}
    const planned=await invoke('planner','planner',{recon});
    try{state=preparePlan(planned.response,c,inputs,options.maxAgents,{requireGrouped:true});}catch(e){planned.record.accepted=false;planned.record.failure=e.message;throw e;}
    }
    metadata.selected_companion_files=state.plan.companion_selection.filter(s=>s.selected).map(s=>s.file);await save();
    for(const a of state.assignments){await mkdir(join(runner,'agents',a.id,'scratch'),{recursive:true,mode:0o700});await mkdir(join(runner,'agents',a.id,'artifacts'),{mode:0o700});assignHunter(state,a,c);await save();}
    const wave=JSON.parse(JSON.stringify(state.ledger)),hunters=await Promise.allSettled(state.assignments.map(a=>invoke('hunter',a.id,{architecture:state.architecture,ledger:wave,units:wave.filter(u=>a.coverageIds.includes(u.coverage_id))})));
    let hunterError;for(let i=0;i<hunters.length;i++){const h=hunters[i];if(h.status==='rejected'){hunterError??=h.reason;continue;}try{applyHunter(state,h.value.response,state.assignments[i],c,inputs);await save();}catch(e){h.value.record.accepted=false;h.value.record.failure=e.message;hunterError??=e;}}
    if(hunterError)throw hunterError;
    const critic=await invoke('critic','critic-final',{architecture:state.architecture,ledger:state.ledger,plan:state.plan,fingerprints:[...state.candidates.keys()].sort()});
    try{applyCritic(state,critic.response,c,inputs);}catch(e){critic.record.accepted=false;critic.record.failure=e.message;throw e;}await save();
    for(const fingerprint of [...state.candidates.keys()].sort()){
      let decided=false,lastError;
      while(!decided&&charged+manifest.roles.length<options.maxAgents){
        // Only a counted native attempt can justify retrying within this budget.
        const rolesBefore=manifest.roles.length,candidate=state.candidates.get(fingerprint),units=state.ledger.filter(u=>u.result_fingerprints.includes(fingerprint));let v;
        try{v=await invoke('verifier',`verifier-${charged+manifest.roles.length+1}`,{architecture:state.architecture,units,candidate,checks:units.flatMap(u=>u.local_checks)});applyVerifier(state,v.response,fingerprint,c,inputs,v.record.ownerId);decided=true;await save();}catch(e){lastError=e;if(v){v.record.accepted=false;v.record.failure=e.message;}if(e.fatalPolicy)throw e;if(signalState.code||Date.now()>=deadline||manifest.roles.length===rolesBefore)break;}
      }
      if(!decided)manifest.reasons.push(lastError?.message??`Independent verifier budget exhausted for ${fingerprint}`);
    }
    // The official schema is re-read from the pinned source immediately before
    // final findings writing. Records remain exact independent native objects.
    const finalContracts=await loadCloudflareContracts(options.skillRoot);validateRecords(state.records,finalContracts,inputs);
    if(state.records.length!==state.candidates.size)throw new Error('Unvalidated ledger candidates remain; strict budget exhausted');
    if(signalState.code)throw new Error('Supervised workflow interrupted');
    metadata.run_status='complete';await save();const validators=await runOfficialValidators(options,payload.artifactDir);manifest.validators=validators;if(validators.some(v=>v.exitCode!==0))throw new Error('Official final validator failed');
    manifest.status='complete';
  }catch(error){manifest.reasons.push(error.message);metadata.run_status='incomplete';metadata.incomplete_reason=[...new Set(manifest.reasons)].join('; ');}
  finally{
    clearTimeout(wholeTimer);
    const cleanup=await Promise.allSettled([...active].map(async pid=>{await terminateGroup(pid);active.delete(pid);}));if(cleanup.some(r=>r.status==='rejected')){manifest.status='incomplete';manifest.reasons.push('Native process group cleanup failed');metadata.run_status='incomplete';metadata.incomplete_reason='Native process group cleanup failed';}
    for(const [signal,handler]of handlers)process.removeListener(signal,handler);
    try{
      manifest.copyAfter=await sourceManifest(copy);manifest.originalAfter=await sourceManifest(payload.target);
      const after=await verifySourcePin('cloudflare',options);if(!sameInputs(inputs,manifest.copyAfter)||!sameInputs(inputs,manifest.originalAfter)||!sameInputs(instructions,after))throw new Error('Source preservation or pinned instruction verification failed');
    }catch(e){manifest.status='incomplete';manifest.reasons.push(e.message);metadata.run_status='incomplete';metadata.incomplete_reason=e.message;}
    if(manifest.status!=='complete'){metadata.run_status='incomplete';metadata.incomplete_reason=[...new Set(manifest.reasons)].join('; ');}
    {
      try{await save();}catch(error){manifest.status='incomplete';manifest.reasons.push(`Final supervisor save failed: ${error.message}`);metadata.run_status='incomplete';metadata.incomplete_reason=[...new Set(manifest.reasons)].join('; ');}
      delete manifest.nativeEnvironment;manifest.endedAt=new Date().toISOString();
      let retainedReadFailure=false;
      for(const file of manifest.retainedFiles)try{manifest.preRedactionHashes[file]=sha256(await safeRead(join(payload.artifactDir,file)));}catch{retainedReadFailure=true;manifest.status='incomplete';manifest.reasons.push(`Missing retained role evidence ${file}`);}
      if(retainedReadFailure){
        metadata.run_status='incomplete';metadata.incomplete_reason=[...new Set(manifest.reasons)].join('; ');
        try{await save();}catch(error){manifest.reasons.push(`Final supervisor save failed: ${error.message}`);}
        // Canonical reports changed after an evidence failure: seal their final bytes.
        for(const file of OUTPUTS.cloudflare)try{manifest.preRedactionHashes[file]=sha256(await safeRead(join(payload.artifactDir,file)));}catch{delete manifest.preRedactionHashes[file];}
      }
      await atomicWriteFile(join(payload.artifactDir,'execution-manifest.json'),json(manifest));
    }
  }
  return manifest.status==='complete'?0:signalState.code||1;
  }finally{
    // No source copy survives initialization failure; uncertain process groups
    // retain their stage until termination can be established.
    if(active.size===0)await rm(stage,{recursive:true,force:true});
  }
}
