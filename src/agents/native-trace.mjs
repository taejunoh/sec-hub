// Codex 0.164.0 rollout-trace witnesses. These files are written by the host
// runtime, outside every model sandbox grant. Never consume model output as a
// trace, and never retain inference requests/responses or code-cell source.
import {constants} from 'node:fs';
import {open,lstat,readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {assertSafeDirectory} from '../safe-io.mjs';
import {nativeRoleContracts,nativeRoleForTask} from './native-roles.mjs';

export const NATIVE_TRACE_POLICY_VERSION=3;
export const NATIVE_TRACE_FILE='native-trace.json';
export const TRACE_LIMITS=Object.freeze({logBytes:20*1024*1024,payloadBytes:5*1024*1024,totalBytes:100*1024*1024,files:4096,events:100000,retainedBytes:20*1024*1024});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const fail=(code='INCONSISTENT')=>{throw new Error(`Missing, unsafe or inconsistent native runtime trace evidence (TRACE_${code})`);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const id=x=>typeof x==='string'&&x.length>0&&x.length<=500&&!/[\x00-\x1f\x7f]/.test(x);
const digest=x=>createHash('sha256').update(x).digest('hex');
const permittedToolKinds=new Set(['exec_command','write_stdin','spawn_agent','wait_agent','close_agent']);
function nativeToolIdentity(kind,inv,{projected=false}={}){
  const names={exec_command:['exec_command'],write_stdin:['write_stdin'],spawn_agent:['spawn_agent'],wait_agent:['wait_agent'],close_agent:['close_agent','interrupt_agent']}[kind];
  const namespace=inv?.tool_namespace,collab=['spawn_agent','wait_agent','close_agent'].includes(kind);
  if(!names?.includes(inv?.tool_name)||(collab?namespace!=='collaboration':![undefined,null,'functions'].includes(namespace))||inv.payload?.type!=='function'||(projected?!/^[a-f0-9]{64}$/.test(inv.argumentsSha256??''):typeof inv.payload.arguments!=='string'))fail('TOOL_IDENTITY');
}
function directRoleSpawn(e,inv,{model,effort='medium',projected=false}={}){
  nativeToolIdentity('spawn_agent',inv);let a;try{a=JSON.parse(inv.payload.arguments);}catch{fail('ROLE_TRANSPORT');}
  let mapping;try{mapping=nativeRoleForTask(a.task_name);}catch{fail('ROLE_MAPPING');}
  const p=e.payload;
  if(p.requester?.type!=='model'||!id(p.model_visible_call_id)||p.code_mode_runtime_tool_id!=null||a.agent_type!==mapping.agentType||a.fork_turns!=='none'||typeof a.model!=='string'||(model&&a.model!==model)||a.reasoning_effort!==effort||(!projected&&typeof a.message!=='string')||(projected&&(!/^[a-f0-9]{64}$/.test(a.messageSha256??'')||Object.hasOwn(a,'message'))))fail('ROLE_TRANSPORT');
  return {task_name:a.task_name,agent_type:a.agent_type,fork_turns:a.fork_turns,model:a.model,reasoning_effort:a.reasoning_effort,messageSha256:projected?a.messageSha256:digest(a.message),role:mapping.role};
}
const taskHeader=path=>`Message Type: NEW_TASK\nTask name: ${path}\nSender: /root\nPayload:\n`;
function refPath(ref,kind){
  const match=/^raw_payload:([1-9][0-9]*)$/.exec(ref?.raw_payload_id??'');
  if(!match||ref.path!==`payloads/${match[1]}.json`||ref.kind?.type!==kind)fail('PAYLOAD_REF');
  return ref.path;
}
async function readBounded(path,limit,{live=false}={}){
  await assertSafeDirectory(join(path,'..'));
  const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const before=await file.stat();if(!before.isFile()||before.nlink!==1)fail('UNSAFE_FILE');if(before.size>limit)fail('FILE_SIZE');
    const data=Buffer.alloc(before.size);let n=0;
    while(n<data.length){const r=await file.read(data,n,data.length-n,n);if(!r.bytesRead)break;n+=r.bytesRead;}
    const after=await file.stat(),named=await lstat(path);
    if(n!==data.length||!named.isFile()||named.nlink!==1||before.dev!==named.dev||before.ino!==named.ino||before.dev!==after.dev||before.ino!==after.ino||after.size>limit||after.size<before.size||(!live&&(after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)))fail('FILE_CHANGED');
    return data;
  }finally{await file.close();}
}
export async function readSealedNativeTrace(artifactDir,manifest){
  const sealed=manifest.finalRetainedHashes??manifest.preRedactionHashes,expected=sealed?.[NATIVE_TRACE_FILE];
  if(!/^[a-f0-9]{64}$/.test(expected??''))throw new Error('Missing sealed native runtime trace evidence');
  const bytes=await readBounded(join(artifactDir,NATIVE_TRACE_FILE),TRACE_LIMITS.retainedBytes);
  if(createHash('sha256').update(bytes).digest('hex')!==expected)throw new Error('Retained native runtime trace hash differs');
  try{return JSON.parse(bytes.toString());}catch{fail();}
}
async function boundedTree(root,limits){
  await assertSafeDirectory(root);let bytes=0,files=0;
  async function walk(dir,depth){
    if(depth>2)fail('TREE_DEPTH');
    for(const entry of await readdir(dir,{withFileTypes:true})){
      if(++files>limits.files)fail('TREE_COUNT');
      const path=join(dir,entry.name),st=await lstat(path);
      if(entry.isDirectory()&&st.isDirectory()&&!st.isSymbolicLink()){await assertSafeDirectory(path);await walk(path,depth+1);}
      else if(entry.isFile()&&st.isFile()&&st.nlink===1){bytes+=st.size;if(bytes>limits.totalBytes)fail('TREE_BYTES');}
      else fail('TREE_ENTRY');
    }
  }
  await walk(root,0);
}
function parseLog(bytes,live){
  // A concurrent append can end the snapshot inside a UTF-8 scalar as well as
  // inside JSON. Decode only complete newline-delimited events in live mode.
  const last=bytes.lastIndexOf(10);if(!live&&bytes.length&&last!==bytes.length-1)fail('LOG_INCOMPLETE');
  const complete=live?bytes.subarray(0,last+1):bytes;let text;
  try{text=new TextDecoder('utf-8',{fatal:true}).decode(complete);}catch{fail('LOG_UTF8');}
  const lines=text.split('\n');if(lines.at(-1)==='')lines.pop();
  return lines.map(line=>{try{return JSON.parse(line);}catch{fail('LOG_JSON');}});
}
function checkEnvelopes(events,manifest,{contiguous=true}={}){
  let prev=0;
  for(const e of events){
    if(!object(e)||e.schema_version!==1||!Number.isSafeInteger(e.seq)||e.seq<=prev||(contiguous&&e.seq!==prev+1)||e.rollout_id!==manifest.rollout_id||!object(e.payload)||typeof e.payload.type!=='string')fail('ENVELOPE');
    prev=e.seq;
  }
}
const witnessFields={rollout_started:['trace_id','root_thread_id'],rollout_ended:['status'],thread_started:['thread_id','agent_path','metadata_payload'],thread_ended:['thread_id','status'],codex_turn_started:['thread_id','codex_turn_id'],codex_turn_ended:['codex_turn_id','status'],tool_call_started:['tool_call_id','model_visible_call_id','code_mode_runtime_tool_id','requester','kind','invocation_payload'],tool_call_runtime_ended:['tool_call_id','status','runtime_payload'],tool_call_ended:['tool_call_id','status'],agent_result_observed:['edge_id','child_thread_id','child_codex_turn_id','parent_thread_id','carried_payload'],code_cell_started:['runtime_cell_id','model_visible_call_id'],code_cell_ended:['runtime_cell_id','status'],inference_started:['inference_call_id','thread_id','codex_turn_id','model','request_payload']};
function projectEvent(event){
  const fields=witnessFields[event.payload.type];if(!fields)return null;
  return {schema_version:event.schema_version,seq:event.seq,rollout_id:event.rollout_id,thread_id:event.thread_id,codex_turn_id:event.codex_turn_id,payload:Object.fromEntries(['type',...fields].filter(k=>Object.hasOwn(event.payload,k)).map(k=>[k,event.payload[k]]))};
}
function manifestValid(m){
  if(!object(m)||m.schema_version!==1||!uuid.test(m.trace_id??'')||!uuid.test(m.root_thread_id??'')||m.rollout_id!==m.root_thread_id||m.raw_event_log!=='trace.jsonl'||m.payloads_dir!=='payloads')fail('MANIFEST');
}
// The live reader deliberately reads a bounded snapshot; the final partial line
// is retried later. Completed payload files are written before their event.
async function collectNativeTrace(root,{live=false,limits=TRACE_LIMITS,maxAgents,runtimeTracePolicyVersion=1,model,effort='medium',copyTarget,skillRoot}={}){
  if(![1,2,3].includes(runtimeTracePolicyVersion))fail('POLICY');const structured=runtimeTracePolicyVersion>=2,directRoles=runtimeTracePolicyVersion===3,contracts=directRoles?nativeRoleContracts({copyTarget,skillRoot}):null;
  await boundedTree(root,limits);
  const entries=await readdir(root,{withFileTypes:true});
  if(live&&!entries.length)return null;
  if(entries.length!==1||!entries[0].isDirectory()||!/^trace-[0-9a-f-]{36}-[0-9a-f-]{36}$/.test(entries[0].name))fail('BUNDLE_LAYOUT');
  const bundle=join(root,entries[0].name);let manifest,bytes;
  // TraceWriter::create finishes manifest.json before it creates trace.jsonl.
  // Read the log first so live startup never parses a half-written manifest.
  try{bytes=await readBounded(join(bundle,'trace.jsonl'),limits.logBytes,{live});const data=await readBounded(join(bundle,'manifest.json'),4096);try{manifest=JSON.parse(data.toString());}catch{fail('MANIFEST_JSON');}}
  catch(error){if(live&&error.code==='ENOENT')return null;throw error;}
  manifestValid(manifest);
  if(entries[0].name!==`trace-${manifest.trace_id}-${manifest.root_thread_id}`)fail('BUNDLE_ID');
  const raw=parseLog(bytes,live);if(raw.length>limits.events)fail('EVENT_COUNT');checkEnvelopes(raw,manifest);
  const spawnIds=new Set(raw.filter(e=>e.payload.type==='tool_call_started'&&e.payload.kind?.type==='spawn_agent').map(e=>e.payload.tool_call_id));
  // All attempted starts count, including failed calls and nested calls. A
  // repeated tool ID is invalid rather than a way to obtain a free attempt.
  const starts=raw.filter(e=>e.payload.type==='tool_call_started');
  if(new Set(starts.map(e=>e.payload.tool_call_id)).size!==starts.length)fail('DUPLICATE_CALL');
  const spawnCount=starts.filter(e=>e.payload.kind?.type==='spawn_agent').length;
  if(maxAgents!==undefined&&spawnCount>maxAgents)throw new Error('Native delegation budget exceeded');
  if(starts.some(e=>['send_message','assign_agent_task'].includes(e.payload.kind?.type)))throw new Error('Native runtime child steering is forbidden');
  if(structured&&starts.some(e=>!permittedToolKinds.has(e.payload.kind?.type)))fail('FORBIDDEN_TOOL');
  const firstInference=new Set(),selected=raw.filter(e=>{
    const p=e.payload;
    if(['code_cell_started','code_cell_ended'].includes(p.type))return structured;
    if(p.type==='inference_started'){if(!structured||p.thread_id===manifest.root_thread_id||firstInference.has(p.thread_id))return false;firstInference.add(p.thread_id);return true;}
    if(p.type==='tool_call_started')return structured||spawnIds.has(p.tool_call_id);
    return !['tool_call_runtime_ended','tool_call_ended'].includes(p.type)||spawnIds.has(p.tool_call_id);
  });
  const events=selected.map(projectEvent).filter(Boolean);
  const payloads={},refs=new Map(),taskHashes=new Map();
  async function load(ref,kind,{toolKind,identityOnly=false,event}={}){
    const path=refPath(ref,kind),previous=refs.get(path);
    if(previous&&previous!==JSON.stringify(ref))fail();refs.set(path,JSON.stringify(ref));
    if(Object.hasOwn(payloads,path))return;
    let data;const bytes=await readBounded(join(bundle,path),limits.payloadBytes);try{data=JSON.parse(bytes.toString());}catch{fail('PAYLOAD_JSON');}
    // Session metadata carries unnecessary host paths; only the spawn relation
    // and resolved model are witnesses. Agent result messages are notification
    // wrappers; the actual completion is status.completed.
    if(kind==='tool_invocation'&&structured){
      nativeToolIdentity(toolKind,data);
      if(directRoles&&toolKind==='spawn_agent'){
        const args=directRoleSpawn(event,data,{model,effort});delete args.role;
        payloads[path]={tool_name:data.tool_name,tool_namespace:data.tool_namespace,payload:{type:'function',arguments:JSON.stringify(args)},originalArgumentsSha256:digest(data.payload.arguments)};
      }else payloads[path]=identityOnly?{tool_name:data.tool_name,tool_namespace:data.tool_namespace,payload:{type:data.payload.type},argumentsSha256:digest(data.payload.arguments)}:data;
    }else if(kind==='session_metadata'){
      const parent=data.session_source?.subagent?.thread_spawn;
      payloads[path]={thread_id:data.thread_id,agent_path:data.agent_path,model:data.model,session_source:parent?{subagent:{thread_spawn:{parent_thread_id:parent.parent_thread_id,agent_path:parent.agent_path,...(directRoles?{agent_role:parent.agent_role}:{})}}}:data.session_source};
    }else if(kind==='inference_request'){
      const messages=Array.isArray(data.input)?data.input.filter(x=>x.type==='agent_message'):[],m=messages[0],c=m?.content;
      if(messages.length!==1||!Array.isArray(c)||c.length!==(directRoles?2:1)||c[0].type!=='input_text'||typeof c[0].text!=='string')fail('CHILD_TASK_SHAPE');
      const firstTask={type:m.type,author:m.author,recipient:m.recipient,contentType:c[0].type,contentCount:c.length,textSha256:digest(c[0].text)};
      if(directRoles){
        if(c[0].text!==taskHeader(m.recipient)||c[1].type!=='encrypted_content'||typeof c[1].encrypted_content!=='string'||!c[1].encrypted_content)fail('CHILD_TASK_SHAPE');
        firstTask.ciphertextSha256=digest(c[1].encrypted_content);
        const matches=[];
        for(const item of data.input.filter(x=>x.type==='message'&&x.role==='developer'))for(const c of Array.isArray(item.content)?item.content:[])if(c.type==='input_text'&&typeof c.text==='string')for(const [agentType,r]of Object.entries(contracts))if(r.sha256===digest(c.text))matches.push({agentType,role:'developer',type:'message',contentType:'input_text',textSha256:r.sha256});
        if(matches.length!==1)fail('CHILD_ROLE_INSTRUCTIONS');firstTask.developer=matches[0];
      }
      payloads[path]={agentMessageCount:messages.length,firstTask};
    }else payloads[path]=kind==='agent_result'?{child_agent_path:data.child_agent_path,status:data.status}:data;
  }
  for(const e of events){const p=e.payload;
    if(p.type==='thread_started')await load(p.metadata_payload,'session_metadata');
    if(p.type==='tool_call_started')await load(p.invocation_payload,'tool_invocation',{toolKind:p.kind?.type,identityOnly:structured&&p.kind?.type!=='spawn_agent',event:e});
    if(p.type==='tool_call_runtime_ended')await load(p.runtime_payload,'tool_runtime_event');
    if(p.type==='agent_result_observed')await load(p.carried_payload,'agent_result');
    if(p.type==='inference_started')await load(p.request_payload,'inference_request');
  }
  if(structured){
    for(const e of events.filter(e=>e.payload.type==='tool_call_started'&&e.payload.kind?.type==='spawn_agent')){
      const p=e.payload,inv=payloads[p.invocation_payload.path];let a;try{a=JSON.parse(inv.payload.arguments);}catch{fail('ROLE_TRANSPORT');}
      if(directRoles){const args=directRoleSpawn(e,inv,{model,effort,projected:true});if(e.thread_id!==manifest.root_thread_id)fail('ROLE_TRANSPORT');taskHashes.set(`/root/${a.task_name}`,{messageSha256:args.messageSha256,agentType:args.agent_type});continue;}
      const roles=typeof a.message==='string'?[...a.message.matchAll(/(?:^|\s)SEC_HUB_ROLE=([a-z0-9-]+)(?=\s|$)/g)]:[];
      const cell=events.find(c=>c.payload.type==='code_cell_started'&&c.thread_id===e.thread_id&&c.codex_turn_id===e.codex_turn_id&&c.payload.runtime_cell_id===p.requester?.runtime_cell_id&&c.seq<e.seq);
      if(p.requester?.type!=='code_cell'||!cell||!id(p.code_mode_runtime_tool_id)||p.model_visible_call_id!=null||roles.length!==1||!/^recon-(architecture|boundaries|execution|companions)$|^hunter-[1-9][0-9]*$|^critic-final$|^verifier-(?:[1-9][0-9]*|final)$/.test(roles[0][1])||a.fork_turns!=='none'||typeof a.model!=='string'||(model&&a.model!==model)||a.reasoning_effort!==effort||!/^[a-z0-9_]+$/.test(a.task_name??'')||e.thread_id!==manifest.root_thread_id)fail('ROLE_TRANSPORT');
      taskHashes.set(`/root/${a.task_name}`,digest(`Message Type: NEW_TASK\nTask name: /root/${a.task_name}\nSender: /root\nPayload:\n${a.message}`));
    }
    for(const e of events.filter(e=>e.payload.type==='inference_started')){const w=payloads[e.payload.request_payload.path].firstTask,task=taskHashes.get(w.recipient);if(w.author!=='/root'||(directRoles?task?.messageSha256!==w.ciphertextSha256||task?.agentType!==w.developer?.agentType:task!==w.textSha256))fail('CHILD_TASK_DELIVERY');}
  }
  if(live)return {spawnCount,eventCount:raw.length,traceId:manifest.trace_id};
  const evidence={schema:'sec-hub.codex-runtime-trace/v1',...(structured?{runtimeTracePolicyVersion}:{}),manifest,events,payloads};
  if(Buffer.byteLength(JSON.stringify(evidence))>limits.retainedBytes)fail();
  return evidence;
}
export async function readNativeTrace(root,options){
  try{return await collectNativeTrace(root,options);}catch(error){
    if(/\(TRACE_[A-Z0-9_]+\)$/.test(error.message??'')||['Native delegation budget exceeded','Native runtime child steering is forbidden'].includes(error.message))throw error;
    fail(`IO_${/^[A-Z0-9_]{1,30}$/.test(error.code??'')?error.code:'FAILED'}`);
  }
}

export function inspectRuntimeTrace(evidence,stdoutEvents,options={}){
  if(evidence?.schema!=='sec-hub.codex-runtime-trace/v1'||!Array.isArray(evidence.events)||!object(evidence.payloads)||Buffer.byteLength(JSON.stringify(evidence))>TRACE_LIMITS.retainedBytes)fail();
  const {manifest,events,payloads}=evidence,policy=options.runtimeTracePolicyVersion??1,structured=policy>=2,directRoles=policy===3,contracts=directRoles?nativeRoleContracts(options):null;if(![1,2,3].includes(policy)||(evidence.runtimeTracePolicyVersion??1)!==policy)fail('POLICY');manifestValid(manifest);checkEnvelopes(events,manifest,{contiguous:false});
  const root=manifest.root_thread_id,roots=stdoutEvents.filter(e=>e.type==='thread.started');
  if(roots.length!==1||roots[0].thread_id!==root)fail();
  const refs=new Map(),used=new Set();
  function load(ref,kind){const path=refPath(ref,kind),previous=refs.get(path);if(previous&&previous!==JSON.stringify(ref))fail();refs.set(path,JSON.stringify(ref));used.add(path);const data=payloads[path];if(!object(data)||Buffer.byteLength(JSON.stringify(data))>TRACE_LIMITS.payloadBytes)fail();return data;}
  const threads=new Map(),turns=new Map(),calls=new Map(),results=new Map(),edges=new Set(),endedThreads=new Set(),cells=new Map(),inbound=new Map(),allToolIds=new Set();let started=false,ended=false,rootEnded=false;
  const reasons=[];
  for(const e of events){
    const p=e.payload;
    // The root shutdown closes its rollout before some idle children finish
    // flushing thread shutdown. Only those already completed children may end.
    if(ended&&!(p.type==='thread_ended'&&p.thread_id!==root&&results.has(p.thread_id)))fail();
    if(p.type==='rollout_started'){if(started||e.seq!==1||p.root_thread_id!==root||p.trace_id!==manifest.trace_id)fail();started=true;continue;}
    if(!started)fail();
    if(p.type==='thread_started'){
      if(!uuid.test(p.thread_id??'')||threads.has(p.thread_id)||[...threads.values()].some(t=>t.path===p.agent_path)||!/^\/root(?:\/[a-z0-9_]+)*$/.test(p.agent_path??''))fail();
      const m=load(p.metadata_payload,'session_metadata');if(m.thread_id!==p.thread_id||m.agent_path!==p.agent_path||m.model!==options.model)fail();
      const parent=m.session_source?.subagent?.thread_spawn;
      if(p.thread_id===root){if(p.agent_path!=='/root'||parent)fail();}
      else if(!parent||parent.parent_thread_id!==root||parent.agent_path!==p.agent_path||p.agent_path.split('/').length!==3)fail();
      threads.set(p.thread_id,{seq:e.seq,path:p.agent_path,parent:parent?.parent_thread_id,...(directRoles?{agentType:parent?.agent_role}:{})});continue;
    }
    if(p.type==='codex_turn_started'){if(!threads.has(p.thread_id)||!id(p.codex_turn_id)||turns.has(p.codex_turn_id)||[...turns.values()].some(t=>t.thread===p.thread_id))fail();turns.set(p.codex_turn_id,{thread:p.thread_id,seq:e.seq});continue;}
    if(p.type==='codex_turn_ended'){const t=turns.get(p.codex_turn_id);if(!t||t.end||p.status!=='completed'||t.thread===root&&[...calls.values()].some(c=>!c.end||!results.has(c.child)))fail();t.end=e.seq;continue;}
    if(p.type==='code_cell_started'){
      const turn=turns.get(e.codex_turn_id),key=`${e.thread_id}:${p.runtime_cell_id}`;
      if(!structured||!id(p.runtime_cell_id)||!id(p.model_visible_call_id)||turn?.thread!==e.thread_id||turn.end||cells.has(key))fail('CELL_START');
      cells.set(key,{seq:e.seq,turn:e.codex_turn_id});continue;
    }
    if(p.type==='code_cell_ended'){
      const cell=cells.get(`${e.thread_id}:${p.runtime_cell_id}`);if(!structured||!cell||cell.end||cell.turn!==e.codex_turn_id||p.status!=='completed')fail('CELL_END');cell.end=e.seq;continue;
    }
    if(p.type==='inference_started'){
      const t=turns.get(e.codex_turn_id),child=threads.get(e.thread_id),m=load(p.request_payload,'inference_request'),w=m.firstTask;
      if(!structured||e.thread_id===root||p.thread_id!==e.thread_id||p.codex_turn_id!==e.codex_turn_id||p.model!==options.model||t?.thread!==e.thread_id||t.end||!child||inbound.has(e.thread_id)||m.agentMessageCount!==1||w?.type!=='agent_message'||w.author!=='/root'||w.recipient!==child.path||w.contentType!=='input_text'||w.contentCount!==(directRoles?2:1)||!/^[a-f0-9]{64}$/.test(w.textSha256??''))fail('CHILD_INFERENCE');
      if(directRoles){const d=w.developer;if(w.textSha256!==digest(taskHeader(child.path))||!/^[a-f0-9]{64}$/.test(w.ciphertextSha256??'')||d?.agentType!==child.agentType||!contracts[d?.agentType]||d.role!=='developer'||d.type!=='message'||d.contentType!=='input_text'||d.textSha256!==contracts[d.agentType].sha256)fail('CHILD_ROLE_INSTRUCTIONS');}
      inbound.set(e.thread_id,{seq:e.seq,turn:e.codex_turn_id,hash:directRoles?w.ciphertextSha256:w.textSha256,agentType:w.developer?.agentType});continue;
    }
    if(p.type==='tool_call_started'){
      if(structured){if(!id(p.tool_call_id)||allToolIds.has(p.tool_call_id)||!permittedToolKinds.has(p.kind?.type))fail('FORBIDDEN_TOOL');allToolIds.add(p.tool_call_id);if(p.kind.type!=='spawn_agent'){nativeToolIdentity(p.kind.type,load(p.invocation_payload,'tool_invocation'),{projected:true});const t=turns.get(e.codex_turn_id);if(t?.thread!==e.thread_id||t.end)fail('TOOL_CONTEXT');continue;}}
      const t=turns.get(e.codex_turn_id);if(p.kind?.type!=='spawn_agent'||!id(p.tool_call_id)||calls.has(p.tool_call_id)||e.thread_id!==root||t?.thread!==root||t.end||!['model','code_cell'].includes(p.requester?.type))fail();
      const inv=load(p.invocation_payload,'tool_invocation');
      if(structured)nativeToolIdentity('spawn_agent',inv);
      if(inv.tool_name!=='spawn_agent'||![undefined,null,'collaboration'].includes(inv.tool_namespace)||inv.payload?.type!=='function'||typeof inv.payload.arguments!=='string')fail();
      if(directRoles){const args=directRoleSpawn(e,inv,{model:options.model,effort:options.effort,projected:true});calls.set(p.tool_call_id,{seq:e.seq,role:args.role,turn:e.codex_turn_id,taskName:args.task_name,agentType:args.agent_type,taskHash:args.messageSha256});continue;}
      let args;try{args=JSON.parse(inv.payload.arguments);}catch{fail();}
      if(!object(args)||typeof args.message!=='string'||!/^[a-z0-9_]+$/.test(args.task_name??'')||args.task_name==='root'||args.model!==options.model||args.reasoning_effort!==(options.effort??'medium'))fail();
      const cellKey=`${e.thread_id}:${p.requester?.runtime_cell_id}`,cell=cells.get(cellKey);
      if(structured&&(p.requester?.type!=='code_cell'||!id(p.code_mode_runtime_tool_id)||p.model_visible_call_id!=null||!cell||cell.end||cell.turn!==e.codex_turn_id||args.fork_turns!=='none'))fail('SPAWN_PROVENANCE');
      const roles=[...args.message.matchAll(/(?:^|\s)SEC_HUB_ROLE=([a-z0-9-]+)(?=\s|$)/g)].map(m=>m[1]);
      if(roles.length!==1||!/^recon-(architecture|boundaries|execution|companions)$|^hunter-[1-9][0-9]*$|^critic-final$|^verifier-(?:[1-9][0-9]*|final)$/.test(roles[0]))fail();
      calls.set(p.tool_call_id,{seq:e.seq,role:roles[0],turn:e.codex_turn_id,taskName:args.task_name,...(structured?{cellKey,taskHash:digest(`Message Type: NEW_TASK\nTask name: /root/${args.task_name}\nSender: /root\nPayload:\n${args.message}`)}:{})});continue;
    }
    if(p.type==='tool_call_runtime_ended'){
      const c=calls.get(p.tool_call_id),r=load(p.runtime_payload,'tool_runtime_event');
      if(!c||c.runtimeEnd||e.thread_id!==root||e.codex_turn_id!==c.turn||p.status!=='completed'||r.kind!=='started'||r.event_id!==p.tool_call_id||!uuid.test(r.agent_thread_id??'')||r.agent_path!==`/root/${c.taskName}`||r.model!==options.model||r.reasoning_effort!==(options.effort??'medium'))fail();
      c.runtimeEnd=e.seq;c.child=r.agent_thread_id;c.path=r.agent_path;continue;
    }
    if(p.type==='tool_call_ended'){const c=calls.get(p.tool_call_id);if(!c||!c.runtimeEnd||c.end||p.status!=='completed'||e.thread_id!==root||e.codex_turn_id!==c.turn)fail();c.end=e.seq;continue;}
    if(p.type==='agent_result_observed'){
      const c=[...calls.values()].find(c=>c.child===p.child_thread_id),t=turns.get(p.child_codex_turn_id),r=load(p.carried_payload,'agent_result');
      const child=threads.get(p.child_thread_id);
      if(!c||!c.end||!child||child.seq<=c.seq||child.parent!==root||child.path!==c.path||results.has(p.child_thread_id)||p.edge_id!==`edge:agent_result:${p.child_thread_id}:${p.child_codex_turn_id}:${root}`||edges.has(p.edge_id)||p.parent_thread_id!==root||e.thread_id!==p.child_thread_id||e.codex_turn_id!==p.child_codex_turn_id||t?.thread!==p.child_thread_id||!t.end||t.end>=e.seq||r.child_agent_path!==child.path||typeof r.status?.completed!=='string'||Object.keys(r.status).length!==1)fail();
      if(structured){const received=inbound.get(p.child_thread_id);if(!received||received.turn!==p.child_codex_turn_id||received.seq<=c.seq||received.seq>=e.seq||received.hash!==c.taskHash||directRoles&&(received.agentType!==c.agentType||child.agentType!==c.agentType))fail('CHILD_TASK_DELIVERY');}
      edges.add(p.edge_id);results.set(p.child_thread_id,{seq:e.seq,message:r.status.completed});continue;
    }
    if(p.type==='thread_ended'){if(!threads.has(p.thread_id)||endedThreads.has(p.thread_id)||p.status!=='completed')fail();endedThreads.add(p.thread_id);if(p.thread_id===root){if(rootEnded||![...turns.values()].some(t=>t.thread===root&&t.end&&t.end<e.seq))fail();rootEnded=true;}continue;}
    if(p.type==='rollout_ended'){if(!rootEnded||p.status!=='completed')fail();ended=true;continue;}
    fail();
  }
  if(!started||!ended||[...calls.values()].some(c=>!c.end||!results.has(c.child))||new Set([...calls.values()].map(c=>c.child)).size!==calls.size||threads.size!==calls.size+1||calls.size>(options.maxAgents??10)||Object.keys(payloads).some(path=>!used.has(path)))fail();
  if(policy===2&&[...calls.values()].some(c=>!cells.get(c.cellKey)?.end))fail('CELL_INCOMPLETE');
  const roleNames=['recon-architecture','recon-boundaries','recon-execution','recon-companions','hunter','critic-final','verifier'],roles={};
  const matches=(role,c)=>c.role===role||c.role.startsWith(`${role}-`);
  for(const role of roleNames){roles[role]=[...calls.values()].filter(c=>matches(role,c)).map(c=>c.child);if(!roles[role].length)reasons.push(`Missing native delegated role ${role}`);}
  for(const role of roleNames.filter(r=>r.startsWith('recon-')||r==='critic-final'))if(roles[role].length!==1)reasons.push('Expected exactly four baseline recon agents and one final critic');
  const groups=[['recon',c=>c.role.startsWith('recon-')],['hunter',c=>c.role.startsWith('hunter-')],['critic',c=>c.role==='critic-final'],['verifier',c=>c.role.startsWith('verifier-')]];
  for(let i=1;i<groups.length;i++){const prev=[...calls.values()].filter(groups[i-1][1]),next=[...calls.values()].filter(groups[i][1]);if(prev.length&&next.some(c=>c.seq<=Math.max(...prev.map(p=>results.get(p.child).seq))))reasons.push(`Native phase order failed before ${groups[i][0]}`);}
  const result={complete:!reasons.length,reasons,evidenceSource:`codex-runtime-trace-v${policy}`,rootThreadId:root,roles,spawnCount:calls.size,completedAgentIds:[...results.keys()],phaseOrder:groups.map(g=>g[0]),verifierThreadIds:roles.verifier,...(directRoles?{roleAuthority:'host-pinned-developer-instructions',encryptedTaskSemantics:'not-inspected',independentVerificationScope:'source-and-parent-supplied-context; final report/ledger file bytes are not separately attested'}:{})};
  Object.defineProperty(result,'verifierMessages',{value:roles.verifier.map(thread=>({thread,message:results.get(thread).message,...(directRoles?{role:[...calls.values()].find(c=>c.child===thread).role}:{})}))});return result;
}

export function monitorNativeTrace(root,maxAgents,onFailure,{intervalMs=100,startupGraceMs=5000,limits=TRACE_LIMITS,runtimeTracePolicyVersion=1,model,effort,copyTarget,skillRoot}={}){
  let stopped=false,busy=false,failure,rootStartedAt,previous;
  async function inspect(){const s=await readNativeTrace(root,{live:true,limits,maxAgents,runtimeTracePolicyVersion,model,effort,copyTarget,skillRoot});if(s){if(previous&&(previous.traceId!==s.traceId||s.eventCount<previous.eventCount))fail();previous=s;}else if(previous||rootStartedAt&&Date.now()-rootStartedAt>startupGraceMs)fail();return s;}
  async function tick(){if(stopped||busy||failure)return;busy=true;try{await inspect();}catch(error){failure=error;onFailure(error);}finally{busy=false;}}
  const timer=setInterval(()=>void tick(),intervalMs);timer.unref();
  return {noteRootStarted(){rootStartedAt??=Date.now();},async stop(){stopped=true;clearInterval(timer);while(busy)await new Promise(r=>setTimeout(r,5));if(!failure){try{await inspect();}catch(error){failure=error;}}if(failure)throw failure;}};
}
