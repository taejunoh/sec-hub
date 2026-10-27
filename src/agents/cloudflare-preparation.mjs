// Narrow recovery of a completed native preparation prefix whose trusted host
// constructor alone failed the pinned ledger's code-unit sorting check.
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve,dirname,basename,relative,isAbsolute} from 'node:path';
import {assertSafeDirectory} from '../safe-io.mjs';
import {safeRead,sha256,sourceManifest,sameInputs,verifySourcePin,PINS,SOURCES,OUTPUTS} from './validation.mjs';
import {loadCloudflareContracts,buildRolePrompt,supervisedArgs,reconOutputSchema,STRATEGY} from './cloudflare-prompts.mjs';
import {stable,validateRecon,inspectRoleEvidence,preparePlan,officialHelpers} from './supervised-validation.mjs';
const inside=(a,b)=>{const p=relative(resolve(a),resolve(b));return p===''||p!=='..'&&!p.startsWith('../')&&!p.startsWith('..\\')&&!isAbsolute(p);};
const fail=message=>{throw new Error(`Cloudflare preparation: ${message}`);};
const text=x=>typeof x==='string'&&x.trim().length>0;
const prefixRoles=['recon-1a','recon-1b','recon-1c','recon-1d','planner'];
const receiptSchema='sec-hub.cloudflare-preparation/v1';
const snapshotRoot='preparation/source';
async function futureDirectory(path){let cursor=resolve(path),suffix=[];for(;;){try{return resolve(await assertSafeDirectory(cursor),...suffix);}catch(error){if(error.code!=='ENOENT')throw error;const parent=dirname(cursor);if(parent===cursor)throw error;suffix.unshift(basename(cursor));cursor=parent;}}}
export async function preflightPreparationLocations({preparationFrom,preparationSha256,target,out,artifactDir,workRoot}){
  if(!isAbsolute(preparationFrom??'')||!/^[a-f0-9]{64}$/.test(preparationSha256??''))fail('explicit absolute source and pinned SHA256 required');
  const sourceManifestPath=resolve(preparationFrom),bytes=await safeRead(sourceManifestPath);
  if(sha256(bytes)!==preparationSha256)fail('source manifest digest differs');
  const sourceArtifactRoot=dirname(sourceManifestPath),sourceRunRoot=resolve(sourceArtifactRoot,'../..');
  if(basename(sourceManifestPath)!=='execution-manifest.json'||basename(sourceArtifactRoot)!=='cloudflare'||basename(dirname(sourceArtifactRoot))!=='raw')fail('source manifest layout differs');
  const old=await assertSafeDirectory(sourceRunRoot);
  for(const [name,path]of [['target',target],['output',out??artifactDir],['workRoot',workRoot]]){if(!path)fail(`missing ${name} location`);const next=await futureDirectory(path);if(inside(old,next)||inside(next,old))fail(`${name} must be disjoint from source old run root`);}
  return {sourceManifestPath,sourceArtifactRoot,sourceRunRoot,sourceManifestBytes:bytes};
}
function optionsIdentity(options,command,args,nativeNodeExecutable,nativeNodeVersion){return {strategy:STRATEGY,command,args,model:options.model,effort:options.effort??'medium',profile:options.profile??'quick',revision:options.revision,skillRoot:resolve(options.skillRoot),workRoot:resolve(options.workRoot),maxAgents:options.maxAgents,nativeNodeExecutable,nativeNodeVersion};}
export async function inspectCloudflarePreparation({options,target,artifactDir,command,args=[],nativeNodeExecutable=process.execPath,nativeNodeVersion=process.versions.node}){
  const location=await preflightPreparationLocations({preparationFrom:options.preparationFrom,preparationSha256:options.preparationSha256,target,artifactDir,workRoot:options.workRoot}),m=JSON.parse(location.sourceManifestBytes),root=location.sourceArtifactRoot;
  if(m.schema!=='sec-hub.native-agent/v1'||m.id!=='cloudflare'||m.strategy!==STRATEGY||m.source!==SOURCES.cloudflare||m.sourceCommit!==PINS.cloudflare||m.backend!=='codex'||m.mode!=='supervised-official-security-audit-skill'||m.preparation!==undefined)fail('wrong source kind, pin, strategy or recursive preparation');
  if(m.status!=='incomplete'||!Array.isArray(m.reasons)||m.reasons.length!==1||!/^Official coverage ledger invalid: \$\[\d+\]\.coverage_id: units must be sorted lexicographically$/.test(m.reasons[0]))fail('source is not the narrow host ledger sorting failure');
  if(m.model!==options.model||m.invocation?.command!==command||!sameInputs(m.invocation.args,args)||m.nativeNodeExecutable!==nativeNodeExecutable||m.nativeNodeVersion!==nativeNodeVersion||!text(m.backendVersion)||resolve(m.runner??'','../..')!==resolve(options.workRoot)||resolve(m.copyTarget??'','../runner')!==resolve(m.runner??''))fail('native configuration or work root differs');
  if(!Array.isArray(m.roles)||stable(m.roles.map(r=>r.role))!==stable(prefixRoles))fail('source must contain exactly four baseline recon roles and one planner; no downstream roles');
  if(m.roles.slice(0,4).some(r=>r.accepted!==true)||m.roles[4].accepted!==false||m.roles[4].failure!==m.reasons[0])fail('source native/host acceptance history differs');
  const instructions=await verifySourcePin('cloudflare',options);if(!sameInputs(instructions,m.instructions))fail('pinned instruction bytes differ');
  const current=await sourceManifest(target);if(!current.length||!sameInputs(current,m.inputs)||!sameInputs(m.inputs,m.copyBefore)||!sameInputs(m.inputs,m.copyAfter)||!sameInputs(m.inputs,m.originalAfter)||(await assertSafeDirectory(target))!==(await assertSafeDirectory(m.target)))fail('source target, original or copied input hashes differ');
  const files=await sourceManifest(root),fileMap=new Map(files.map(f=>[f.path,f])),buffers=new Map([['execution-manifest.json',location.sourceManifestBytes]]),meta=JSON.parse(await safeRead(join(root,'run-metadata.json')));
  if(meta.profile!==(options.profile??'quick')||meta.budget?.max_agents!==options.maxAgents||meta.budget?.spent!==5||meta.execution_policy!=='sandboxed-source-and-local-only'||meta.run_status!=='incomplete'||meta.incomplete_reason!==m.reasons[0]||meta.target!==m.copyTarget||resolve(meta.repo??'')!==resolve(target)||stable(meta.scope_paths)!==stable(m.inputs.map(i=>i.path))||stable(meta.prior_run_paths)!=='[]')fail('source profile, budget or preparation metadata differs');
  if(!Array.isArray(m.retainedFiles)||new Set(m.retainedFiles).size!==m.retainedFiles.length||OUTPUTS.cloudflare.some(f=>!m.retainedFiles.includes(f)))fail('invalid retained source file list');
  const seal=m.finalRetainedHashes??m.preRedactionHashes;
  for(const name of m.retainedFiles){if(!fileMap.has(name)||seal?.[name]!==fileMap.get(name).sha256)fail('source retained evidence hash differs');}
  const c=await loadCloudflareContracts(options.skillRoot),helper=officialHelpers(c).ledger,threads=new Set(),agentIds=new Set(),pids=new Set(),recon=[],proofs=[];let proposal;
  if(files.some(f=>!helper.isSafeRelativePath(f.path)))fail('unsafe source artifact path');
  const required=['execution-manifest.json'];
  for(const r of m.roles){
    if(!helper.isSafeAgentId(r.agentId)||!helper.isSafeAgentId(r.ownerId)||agentIds.has(r.agentId)||!Number.isInteger(r.pid)||r.pid<1||pids.has(r.pid)||!Number.isFinite(Date.parse(r.startedAt))||!Number.isFinite(Date.parse(r.endedAt))||Date.parse(r.endedAt)<Date.parse(r.startedAt))fail('invalid native role identity/time');agentIds.add(r.agentId);pids.add(r.pid);
    const base=`roles/${r.agentId}`,context={role:r.role,agentId:r.ownerId,target:m.copyTarget,runner:m.runner,...(r.role==='planner'?{recon}:{})},expected=buildRolePrompt(c,context),schema=reconOutputSchema(r.role),schemaFile=schema?`${base}/output-schema.json`:null,schemaText=schema?JSON.stringify(schema,null,2)+'\n':null;
    const names=['prompt.txt','events.jsonl','stderr.log','response.json'].map(f=>`${base}/${f}`);if(schemaFile)names.push(schemaFile);
    for(const name of names){if(!m.retainedFiles.includes(name)||!fileMap.has(name))fail('required preparation evidence missing');const data=await safeRead(join(root,name));if(sha256(data)!==fileMap.get(name).sha256)fail('source evidence changed during read');buffers.set(name,data);required.push(name);}
    if(schema){if(stable(r.outputSchema)!==stable({file:schemaFile,sha256:sha256(schemaText),bytes:Buffer.byteLength(schemaText)})||buffers.get(schemaFile).toString()!==schemaText)fail('native recon schema differs');}else if(r.outputSchema!==undefined)fail('planner must not have a replacement schema');
    const expectedArgs=[...args,...supervisedArgs(m.runner,options,m.nativeNodeExecutable,schemaFile?resolve(root,schemaFile):null)];
    if(r.command!==command||r.cwd!==m.runner||stable(r.args)!==stable(expectedArgs)||r.promptSha256!==sha256(expected.prompt)||r.promptBytes!==Buffer.byteLength(expected.prompt)||stable(r.sourceBlocks)!==stable(expected.sourceBlocks)||buffers.get(`${base}/prompt.txt`).toString()!==expected.prompt)fail('native prefix invocation/prompt reconstruction differs');
    const events=buffers.get(`${base}/events.jsonl`).toString().split('\n').filter(l=>l.trim()).map(l=>JSON.parse(l)),native=inspectRoleEvidence(events,r,expected,c);
    if(threads.has(native.threadId)||r.threadId!==native.threadId||buffers.get(`${base}/response.json`).toString()!==native.finalText)fail('reused thread or changed native final message');threads.add(native.threadId);
    if(r.role.startsWith('recon-')){validateRecon(native.response,r.role,m.inputs);recon.push(native.response);}else proposal=native.response;
    proofs.push({role:r.role,agentId:r.agentId,ownerId:r.ownerId,pid:r.pid,threadId:r.threadId,startedAt:r.startedAt,endedAt:r.endedAt,exitCode:r.exitCode,sourceAccepted:r.accepted,...(r.failure?{sourceFailure:r.failure}:{})});
  }
  if(m.roles.slice(0,4).some(r=>Date.parse(r.endedAt)>Date.parse(m.roles[4].startedAt)))fail('native prefix phase order differs');
  if(files.some(f=>f.path.startsWith('roles/')&&!required.includes(f.path)))fail('unrecorded downstream or foreign role artifacts');
  const state=preparePlan(proposal,c,m.inputs,options.maxAgents,{requireGrouped:true});
  if(!sameInputs(files,await sourceManifest(root))||sha256(await safeRead(location.sourceManifestPath))!==options.preparationSha256)fail('source cohort changed during verification');
  const snapshotFiles=required.sort().map(path=>({path,sha256:fileMap.get(path)?.sha256??sha256(buffers.get(path)),size:buffers.get(path).length}));
  const receipt={schema:receiptSchema,sourceManifestPath:location.sourceManifestPath,sourceArtifactRoot:root,sourceRunRoot:location.sourceRunRoot,sourceManifestSha256:options.preparationSha256,sourceStatus:m.status,sourceReasons:[...m.reasons],sourceArtifactFiles:files,snapshotRoot,snapshotFiles,chargedAgents:5,inputSha256:sha256(JSON.stringify(m.inputs)),sourceCommit:m.sourceCommit,instructions:m.instructions,nativeOptions:optionsIdentity(options,command,args,nativeNodeExecutable,nativeNodeVersion),backendVersion:m.backendVersion,roles:proofs};
  return {receipt,state,buffers,source:m,recon,retainedFiles:snapshotFiles.map(f=>`${snapshotRoot}/${f.path}`),threadIds:[...threads],agentIds:[...agentIds]};
}
export async function materializeCloudflarePreparation(prepared,artifactDir){
  for(const file of prepared.receipt.snapshotFiles){const destination=resolve(artifactDir,snapshotRoot,file.path);await mkdir(dirname(destination),{recursive:true,mode:0o700});await writeFile(destination,prepared.buffers.get(file.path),{flag:'wx',mode:0o600});}
  if(!sameInputs(prepared.receipt.sourceArtifactFiles,await sourceManifest(prepared.receipt.sourceArtifactRoot)))fail('source cohort changed during snapshot creation');
}
export async function validateCloudflarePreparation(receipt,ctx,options){
  const cfg=ctx.config.tools.cloudflare,prepared=await inspectCloudflarePreparation({options,target:ctx.target,artifactDir:ctx.artifactDir,command:cfg.command,args:cfg.args??[],nativeNodeExecutable:ctx.nativeNodeExecutable,nativeNodeVersion:ctx.nativeNodeVersion});
  if(stable(receipt)!==stable(prepared.receipt))fail('trusted preparation receipt differs or was rebound');
  for(const file of receipt.snapshotFiles){const data=await safeRead(resolve(ctx.artifactDir,receipt.snapshotRoot,file.path));if(data.length!==file.size||sha256(data)!==file.sha256||!data.equals(prepared.buffers.get(file.path)))fail('preparation snapshot differs from original native evidence');}
  return prepared;
}
