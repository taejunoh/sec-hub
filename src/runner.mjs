import { readdir, realpath, stat, readFile, lstat } from 'node:fs/promises';
import { resolve, join, dirname, relative, isAbsolute } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runProcess } from './processes.mjs';
import { createRedactor, redactValue } from './redaction.mjs';
import { atomicWriteFile, assertSafeDirectory, ensureSafeDirectory } from './safe-io.mjs';
import { validateAgentOptions } from './config.mjs';
export { runProcess, createRedactor };

function runDirectoryPath(out) {
  return resolve(out??join(process.cwd(),'.sec-hub','runs',`${new Date().toISOString().replace(/[:.]/g,'-')}-${randomUUID().slice(0,8)}`));
}

export async function prepareRunDirectory(out) {
  const directory=runDirectoryPath(out);
  await ensureSafeDirectory(directory);
  if((await readdir(directory)).length)throw new Error(`Output directory must be empty: ${directory}`);
  return directory;
}

async function targetDetails(target) {
  const path=await realpath(resolve(target));if(!(await stat(path)).isDirectory())throw new Error('Target must be a local directory');
  const info={path};
  // These read-only plumbing commands do not invoke repository scripts or hooks.
  const gitOptions={timeoutMs:3000,maxOutputBytes:128*1024};
  const revision=await runProcess({command:'git',args:['--no-optional-locks','-C',path,'rev-parse','--verify','HEAD'],successCodes:[0]},gitOptions);
  if(revision.status==='completed'&&/^[a-f0-9]{40,64}$/.test(revision.stdout.trim()))info.revision=revision.stdout.trim();
  const dirty=await runProcess({command:'git',args:['--no-optional-locks','-C',path,'-c','core.fsmonitor=false','status','--porcelain','--untracked-files=normal'],successCodes:[0]},gitOptions);
  if(dirty.status==='completed')info.dirty=Boolean(dirty.stdout.trim());
  return info;
}

async function sanitizeArtifacts(directory,redact) {
  await assertSafeDirectory(directory);
  let oversized=false;
  for(const entry of await readdir(directory,{withFileTypes:true})){
    const file=join(directory,entry.name);
    if(entry.isSymbolicLink()){await atomicWriteFile(file,'[OMITTED: scanner artifact symlink]\n',{mode:0o600});continue;}
    if(entry.isDirectory()){try{await sanitizeArtifacts(file,redact);}catch{oversized=true;}continue;}
    if(!entry.isFile())continue;
    if((await stat(file)).size>20*1024*1024){await atomicWriteFile(file,'[OMITTED: native artifact exceeds 20 MiB limit]\n',{mode:0o600});oversized=true;continue;}
    const original=await readFile(file,'utf8'),sanitized=redact(original);
    if(original!==sanitized)await atomicWriteFile(file,sanitized,{mode:0o600});
  }
  if(oversized)throw new Error('Native artifact sanitization failed or exceeds 20 MiB limit');
}


// Resolve a future directory without creating it. Existing ancestors must pass
// the same no-symlink checks as actual output creation.
async function futureDirectoryPath(directory) {
  const absolute=resolve(directory);let ancestor=absolute;
  while(true){
    try{await lstat(ancestor);break;}catch(error){
      if(error.code!=='ENOENT')throw error;
      const parent=dirname(ancestor);if(parent===ancestor)throw error;ancestor=parent;
    }
  }
  const canonical=await assertSafeDirectory(ancestor);
  return resolve(canonical,relative(ancestor,absolute));
}
function containsPath(parent,child) {
  const rel=relative(parent,child);
  return rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('../')&&!rel.startsWith('..\\'));
}
async function preflightNativeLocations(target,out,agents,config) {
  for(const adapter of agents){
    const agentOptions=config.tools?.[adapter.id]?.agentOptions;
    if(agentOptions && (Object.hasOwn(agentOptions,'preparationFrom')||Object.hasOwn(agentOptions,'preparationSha256'))){
      const preparation=validateAgentOptions(adapter.id,agentOptions);
      const {preflightPreparationLocations}=await import('./agents/cloudflare-preparation.mjs');
      await preflightPreparationLocations({...preparation,target,out});
    }
  }
  const output=await futureDirectoryPath(out);
  if(containsPath(target,output))throw new Error('Native agent output must be outside the original target');
  for(const adapter of agents){
    const workRoot=config.tools?.[adapter.id]?.agentOptions?.workRoot;
    if(workRoot===undefined)continue; // Required-option checks remain the native adapter's responsibility.
    if(typeof workRoot!=='string'||!isAbsolute(workRoot))throw new Error('Native agent workRoot must be an absolute directory outside the original target');
    const work=await futureDirectoryPath(workRoot);
    if(containsPath(target,work))throw new Error('Native agent workRoot must be outside the original target');
    if(containsPath(output,work)||containsPath(work,output))throw new Error('Native agent workRoot must not overlap the output/raw stage');
  }
}

export async function runScan(options) {
  const {ai=false,url,config={tools:{}},timeoutMs=120000,signal}=options;
  if(url){let parsed;try{parsed=new URL(url);}catch{throw new Error('URL must be explicit HTTP(S)');}if(!['http:','https:'].includes(parsed.protocol)||parsed.username||parsed.password)throw new Error('URL must be HTTP(S) without embedded credentials');}
  const available=options.adapters??(await import('./adapters/index.mjs')).adapters;
  const selected=new Set(options.tools??(ai?available.filter(x=>x.kind!=='agent'&&(x.id!=='php2shell'||url)).map(x=>x.id):['osv','skillspector',...(url?['php2shell']:[])]));
  for(const id of selected)if(!available.some(adapter=>adapter.id===id))throw new Error(`Unknown tool: ${id}`);
  for(const id of Object.keys(config.tools??{}))if(!available.some(adapter=>adapter.id===id))throw new Error(`Unknown configured tool: ${id}`);
  const target=await targetDetails(options.target),requestedOut=runDirectoryPath(options.out);
  const nativeSelected=available.filter(adapter=>adapter.kind==='agent'&&selected.has(adapter.id));
  if(nativeSelected.length)await preflightNativeLocations(target.path,requestedOut,nativeSelected,config);
  const directory=await prepareRunDirectory(requestedOut);
  const redact=createRedactor();
  const sanitize=value=>redactValue(value);
  const run={schemaVersion:1,id:randomUUID(),startedAt:new Date().toISOString(),target,status:'failed',tools:[],findings:[]};
  for(const adapter of available){
    const record={id:adapter.id,name:adapter.name,source:adapter.source,selected:selected.has(adapter.id),status:'skipped',findings:[]};run.tools.push(record);
    if(!selected.has(adapter.id)){record.reason='Not selected';continue;}
    if(adapter.requiresAI&&!ai){record.reason='Requires explicit --ai consent';continue;}
    if(adapter.kind==='agent'&&!config.tools?.[adapter.id]){record.reason='Requires explicit executable configuration';continue;}
    if(signal?.aborted){record.status='cancelled';record.reason='Cancelled by user';continue;}
    const artifactDir=join(directory,'raw',adapter.id);await ensureSafeDirectory(artifactDir);
    const ctx={target:target.path,url,ai,config,artifactDir,signal};
    let executionContext;
    try {
      const check=await adapter.check(ctx);if(check.version)record.version=redact(check.version);
      if(signal?.aborted){record.status='cancelled';record.reason='Cancelled by user during prerequisite check';continue;}
      if(!check.available){record.reason=redact(check.reason??'Prerequisite unavailable');continue;}
      record.startedAt=new Date().toISOString();
      const result=await runProcess(await adapter.build(ctx),{timeoutMs,signal,redactOutput:false});
      Object.assign(record,{status:result.status,exitCode:result.exitCode,durationMs:result.durationMs,endedAt:new Date().toISOString()});
      if(result.reason)record.reason=redact(result.reason);
      record.artifacts={stdout:join(artifactDir,'stdout.txt'),stderr:join(artifactDir,'stderr.txt')};
      await Promise.all([atomicWriteFile(record.artifacts.stdout,redact(result.stdout),{mode:0o600}),atomicWriteFile(record.artifacts.stderr,redact(result.stderr),{mode:0o600})]);
      if(result.status==='completed'){
        executionContext={...ctx,stdout:result.stdout,stderr:result.stderr,exitCode:result.exitCode};
        const findings=await adapter.parse(executionContext);
        if(!Array.isArray(findings))throw new Error('Parser must return an array of findings');
        const normalized=findings.length?(await import('./reports.mjs')).normalizeFindings(findings):[];
        record.findings=sanitize(normalized.map(finding=>({...finding,rawRef:finding.rawRef??record.artifacts.stdout})));
        run.findings.push(...record.findings);
      }
    }catch(error){
      record.status='failed';record.reason=redact(error.message);record.endedAt=new Date().toISOString();
      if(Array.isArray(error.findings)&&error.findings.length){
        try{
          record.findings=sanitize((await import('./reports.mjs')).normalizeFindings(error.findings).map(finding=>({...finding,rawRef:finding.rawRef??record.artifacts?.stdout})));
          run.findings.push(...record.findings);
        }catch{record.reason+='; incomplete native findings failed validation';}
      }
    }finally{
      try{
        await sanitizeArtifacts(artifactDir,redact);
        if(record.status==='completed'&&executionContext&&adapter.executionMetadata){
          const execution=await adapter.executionMetadata(executionContext);
          if(!execution||typeof execution!=='object'||Array.isArray(execution))throw new Error('Execution metadata must be a validated object');
          record.execution=sanitize(execution);
        }
      }catch(error){record.status='failed';record.reason=redact(error.message);}
    }
  }
  const requested=run.tools.filter(tool=>selected.has(tool.id));
  const successful=requested.filter(tool=>tool.status==='completed').length;
  run.status=successful===requested.length&&successful>0?'completed':successful>0||run.findings.length>0?'partial':'failed';
  run.endedAt=new Date().toISOString();
  await atomicWriteFile(join(directory,'run.json'),JSON.stringify(run,null,2)+'\n',{mode:0o600});
  Object.defineProperty(run,'directory',{value:directory,enumerable:false});
  return run;
}

export function exitCodeForRun(run) { return run.status==='completed'?(run.findings.length?1:0):2; }

export async function doctor({target,config={tools:{}},ai=false,signal}={}) {
  const {adapters}=await import('./adapters/index.mjs');
  const {bridges}=await import('./bridges.mjs');
  const path=target?await realpath(resolve(target)):process.cwd();
  const bridgeList=Array.isArray(bridges)?bridges:Object.values(bridges);
  const tools=[];const redact=createRedactor();
  for(const adapter of adapters){
    const entry={...(bridgeList.some(bridge=>bridge.id===adapter.id)?{manualImport:true}:{}),id:adapter.id,name:adapter.name,kind:adapter.kind,source:adapter.source,requiresAI:adapter.requiresAI,network:adapter.network,install:adapter.install};
    if(adapter.requiresAI&&!ai){entry.available=false;entry.reason='Requires --ai consent and explicit executable configuration';}
    else try{Object.assign(entry,await adapter.check({target:path,config,ai,signal}));}catch(error){entry.available=false;entry.reason=redact(error.message);}
    tools.push(entry);
  }
  for(const bridge of bridgeList.filter(bridge=>!tools.some(tool=>tool.id===bridge.id)))tools.push({id:bridge.id,name:bridge.name,kind:'bridge',source:bridge.source,available:true,reason:'Export handoff guide; results require explicit import (not locally executed)'});
  return JSON.parse(redact(JSON.stringify({node:process.version,target:path,tools})));
}
