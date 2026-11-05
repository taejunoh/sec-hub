import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readNativeTrace,readSealedNativeTrace,inspectRuntimeTrace,monitorNativeTrace,TRACE_LIMITS} from '../src/agents/native-trace.mjs';
import {inspectNativeEvents,verifyCloudflareRecords,sha256,validateNativeExecution,PINS,SOURCES} from '../src/agents/validation.mjs';
import {cloudflarePrompt,codexArgs} from '../src/agents/invocation.mjs';
import {nativeRoleContracts,nativeRoleForTask} from '../src/agents/native-roles.mjs';

const rootId='019d0000-0000-7000-8000-000000000001',traceId='019d0000-0000-4000-8000-000000000099';
const options={model:'fixture-model',effort:'medium',maxAgents:10};
const roleContext={copyTarget:'/copy/target',skillRoot:'/skill'};
// Explicit synthetic fixture with the pinned Rust serde shapes. Nothing in this
// file invokes Codex, and these bytes are never reported as live evidence.
function fixture(){
 const events=[],payloads={};let ordinal=0;
 const ref=(kind,data)=>{const n=++ordinal,path=`payloads/${n}.json`;payloads[path]=data;return {raw_payload_id:`raw_payload:${n}`,kind:{type:kind},path};};
 const event=(payload,thread_id=null,codex_turn_id=null)=>{events.push({schema_version:1,seq:events.length+1,wall_time_unix_ms:1,rollout_id:rootId,thread_id,codex_turn_id,payload});return events.at(-1);};
 const thread=(thread_id,path,parent)=>event({type:'thread_started',thread_id,agent_path:path,metadata_payload:ref('session_metadata',{thread_id,agent_path:path,model:options.model,session_source:parent?{subagent:{thread_spawn:{parent_thread_id:parent,agent_path:path}}}:'exec',cwd:'/private/unused-host-path'})});
 event({type:'rollout_started',trace_id:traceId,root_thread_id:rootId});thread(rootId,'/root');
 event({type:'codex_turn_started',thread_id:rootId,codex_turn_id:'root-turn'});
 for(const [i,role] of ['recon-architecture','recon-boundaries','recon-execution','recon-companions','hunter-1','critic-final','verifier-final'].entries()){
  const child=`019d0000-0000-7000-8000-${String(i+2).padStart(12,'0')}`,path=`/root/task${i}`,call=`call${i}`,turn=`child-turn${i}`;
  event({type:'tool_call_started',tool_call_id:call,model_visible_call_id:call,code_mode_runtime_tool_id:null,requester:{type:'model'},kind:{type:'spawn_agent'},summary:{type:'generic',label:'spawn_agent',input_preview:'DO NOT RETAIN THIS PREVIEW'},invocation_payload:ref('tool_invocation',{tool_name:'spawn_agent',tool_namespace:null,payload:{type:'function',arguments:JSON.stringify({message:`SEC_HUB_ROLE=${role}`,task_name:`task${i}`,model:options.model,reasoning_effort:options.effort})}})},rootId,'root-turn');
  thread(child,path,rootId);
  event({type:'tool_call_runtime_ended',tool_call_id:call,status:'completed',runtime_payload:ref('tool_runtime_event',{event_id:call,agent_thread_id:child,agent_path:path,kind:'started',model:options.model,reasoning_effort:options.effort})},rootId,'root-turn');
  event({type:'tool_call_ended',tool_call_id:call,status:'completed',result_payload:null},rootId,'root-turn');
  event({type:'codex_turn_started',thread_id:child,codex_turn_id:turn});
  event({type:'codex_turn_ended',codex_turn_id:turn,status:'completed'});
  event({type:'agent_result_observed',edge_id:`edge:agent_result:${child}:${turn}:${rootId}`,child_thread_id:child,child_codex_turn_id:turn,parent_thread_id:rootId,message:'NOTIFICATION WRAPPER SHOULD NOT BE RETAINED',carried_payload:ref('agent_result',{child_agent_path:path,message:'NOTIFICATION WRAPPER SHOULD NOT BE RETAINED',status:{completed:role==='verifier-final'?' {"decision":"verified","scope":"final-empty-result"}':'done'}})},child,turn);
 }
 event({type:'codex_turn_ended',codex_turn_id:'root-turn',status:'completed'});
 event({type:'thread_ended',thread_id:rootId,status:'completed'});
 event({type:'rollout_ended',status:'completed'});
 return {schema:'sec-hub.codex-runtime-trace/v1',manifest:{schema_version:1,trace_id:traceId,root_thread_id:rootId,rollout_id:rootId,raw_event_log:'trace.jsonl',payloads_dir:'payloads',started_at_unix_ms:1},events,payloads};
}
const stdout=()=>[{type:'thread.started',thread_id:rootId},{type:'turn.completed',usage:{input_tokens:1,output_tokens:1}}];
const payload=(e,type)=>e.events.find(event=>event.payload.type===type).payload;
const content=(e,p,key)=>e.payloads[p[key].path];
const renumber=e=>e.events.forEach((event,i)=>event.seq=i+1);
function codeModeFixture({raw=false}={}){
 const e=fixture();e.runtimeTracePolicyVersion=2;let ordinal=Object.keys(e.payloads).length;
 const events=[];
 for(const original of e.events){const x=structuredClone(original),p=x.payload;
  if(p.type==='tool_call_started'){
   const n=Number(p.tool_call_id.slice(4)),cell=`cell${n}`,inv=content(e,p,'invocation_payload'),args=JSON.parse(inv.payload.arguments);args.fork_turns='none';inv.payload.arguments=JSON.stringify(args);inv.tool_namespace='collaboration';
   events.push({...x,payload:{type:'code_cell_started',runtime_cell_id:cell,model_visible_call_id:`exec${n}`,...(raw?{source_js:'PRIVATE FULL JAVASCRIPT SOURCE'}:{})}});
   p.requester={type:'code_cell',runtime_cell_id:cell};p.model_visible_call_id=null;p.code_mode_runtime_tool_id=`runtime-tool${n}`;
  }
  events.push(x);
  if(p.type==='tool_call_ended'){const n=Number(p.tool_call_id.slice(4));events.push({...x,payload:{type:'code_cell_ended',runtime_cell_id:`cell${n}`,status:'completed'}});}
  if(p.type==='codex_turn_started'&&p.thread_id!==rootId){
   const n=Number(p.codex_turn_id.slice(10)),path=`/root/task${n}`,start=e.events.find(y=>y.payload.type==='tool_call_started'&&y.payload.tool_call_id===`call${n}`),args=JSON.parse(content(e,start.payload,'invocation_payload').payload.arguments),text=`Message Type: NEW_TASK\nTask name: ${path}\nSender: /root\nPayload:\n${args.message}`,relative=`payloads/${++ordinal}.json`;
   e.payloads[relative]=raw?{input:[{type:'agent_message',author:'/root',recipient:path,content:[{type:'input_text',text}]}],private:'PRIVATE FULL INFERENCE REQUEST'}:{agentMessageCount:1,firstTask:{type:'agent_message',author:'/root',recipient:path,contentType:'input_text',contentCount:1,textSha256:sha256(text)}};
   events.push({...x,thread_id:p.thread_id,codex_turn_id:p.codex_turn_id,payload:{type:'inference_started',inference_call_id:`inference${n}`,thread_id:p.thread_id,codex_turn_id:p.codex_turn_id,model:options.model,request_payload:{raw_payload_id:`raw_payload:${ordinal}`,kind:{type:'inference_request'},path:relative}}});
  }
 }
 e.events=events;renumber(e);return e;
}
function directRoleFixture({raw=false}={}){
 const e=fixture();e.runtimeTracePolicyVersion=3;let ordinal=Object.keys(e.payloads).length;const events=[],tasks=['recon_architecture','recon_boundaries','recon_execution','recon_companions','hunter_1','critic_final','verifier_final'],contracts=nativeRoleContracts(roleContext);
 for(const original of e.events){const x=structuredClone(original),p=x.payload;
  if(p.type==='tool_call_started'){
   const i=Number(p.tool_call_id.slice(4)),mapping=nativeRoleForTask(tasks[i]),inv=content(e,p,'invocation_payload'),a=JSON.parse(inv.payload.arguments);a.task_name=tasks[i];a.agent_type=mapping.agentType;a.fork_turns='none';delete a.message;
   if(raw)a.message=`PRIVATE_CIPHERTEXT_${i}`;else a.messageSha256=sha256(`PRIVATE_CIPHERTEXT_${i}`);inv.tool_namespace='collaboration';inv.payload.arguments=JSON.stringify(a);
  }
  if(p.type==='thread_started'&&p.thread_id!==rootId){const i=Number(p.thread_id.slice(-12))-2,path=`/root/${tasks[i]}`,m=content(e,p,'metadata_payload');p.agent_path=path;m.agent_path=path;m.session_source.subagent.thread_spawn.agent_path=path;m.session_source.subagent.thread_spawn.agent_role=nativeRoleForTask(tasks[i]).agentType;}
  if(p.type==='tool_call_runtime_ended'){const i=Number(p.tool_call_id.slice(4));content(e,p,'runtime_payload').agent_path=`/root/${tasks[i]}`;}
  if(p.type==='agent_result_observed'){const i=Number(p.child_thread_id.slice(-12))-2;content(e,p,'carried_payload').child_agent_path=`/root/${tasks[i]}`;}
  events.push(x);
  if(p.type==='codex_turn_started'&&p.thread_id!==rootId){
   const i=Number(p.codex_turn_id.slice(10)),path=`/root/${tasks[i]}`,mapping=nativeRoleForTask(tasks[i]),contract=contracts[mapping.agentType],header=`Message Type: NEW_TASK\nTask name: ${path}\nSender: /root\nPayload:\n`,relative=`payloads/${++ordinal}.json`;
   e.payloads[relative]=raw?{input:[{type:'message',role:'developer',content:[{type:'input_text',text:contract.instructions}]},{type:'agent_message',author:'/root',recipient:path,content:[{type:'input_text',text:header},{type:'encrypted_content',encrypted_content:`PRIVATE_CIPHERTEXT_${i}`}]}],private:'PRIVATE ROLE INFERENCE'}:{agentMessageCount:1,firstTask:{type:'agent_message',author:'/root',recipient:path,contentType:'input_text',contentCount:2,textSha256:sha256(header),ciphertextSha256:sha256(`PRIVATE_CIPHERTEXT_${i}`),developer:{agentType:mapping.agentType,type:'message',role:'developer',contentType:'input_text',textSha256:contract.sha256}}};
   events.push({...x,thread_id:p.thread_id,codex_turn_id:p.codex_turn_id,payload:{type:'inference_started',inference_call_id:`inference${i}`,thread_id:p.thread_id,codex_turn_id:p.codex_turn_id,model:options.model,request_payload:{raw_payload_id:`raw_payload:${ordinal}`,kind:{type:'inference_request'},path:relative}}});
  }
 }
 e.events=events;renumber(e);return e;
}
function numberedVerifier(e,record,{keepFinal=false}={}){
 const oldChild='019d0000-0000-7000-8000-000000000008',newChild=keepFinal?'019d0000-0000-7000-8000-000000000009':oldChild,oldCall='call6',newCall=keepFinal?'call7':oldCall,oldTurn='child-turn6',newTurn=keepFinal?'child-turn7':oldTurn;
 const start=e.events.findIndex(x=>x.payload.type==='tool_call_started'&&x.payload.tool_call_id===oldCall),end=e.events.findIndex((x,i)=>i>start&&x.payload.type==='agent_result_observed'&&x.payload.child_thread_id===oldChild),copy=structuredClone(e.events.slice(start,end+1));let ordinal=Math.max(...Object.keys(e.payloads).map(path=>Number(path.match(/[0-9]+/)[0])));
 for(const x of copy){const p=x.payload;if(x.thread_id===oldChild)x.thread_id=newChild;if(x.codex_turn_id===oldTurn)x.codex_turn_id=newTurn;
  for(const field of ['thread_id','child_thread_id'])if(p[field]===oldChild)p[field]=newChild;
  for(const field of ['codex_turn_id','child_codex_turn_id'])if(p[field]===oldTurn)p[field]=newTurn;
  if(p.tool_call_id===oldCall)p.tool_call_id=newCall;if(p.model_visible_call_id===oldCall)p.model_visible_call_id=newCall;
  if(p.type==='thread_started')p.agent_path='/root/verifier_1';
  for(const field of ['metadata_payload','invocation_payload','runtime_payload','carried_payload','request_payload'])if(p[field]){
   const value=structuredClone(e.payloads[p[field].path]),path=`payloads/${++ordinal}.json`;p[field]={...p[field],raw_payload_id:`raw_payload:${ordinal}`,path};e.payloads[path]=value;
   if(field==='invocation_payload'){const a=JSON.parse(value.payload.arguments);a.task_name='verifier_1';value.payload.arguments=JSON.stringify(a);}
   if(field==='metadata_payload'){value.thread_id=newChild;value.agent_path='/root/verifier_1';value.session_source.subagent.thread_spawn.agent_path='/root/verifier_1';}
   if(field==='runtime_payload'){value.event_id=newCall;value.agent_thread_id=newChild;value.agent_path='/root/verifier_1';}
   if(field==='carried_payload'){value.child_agent_path='/root/verifier_1';value.status.completed=JSON.stringify({decision:record.verdict,record});}
   if(field==='request_payload'){value.firstTask.recipient='/root/verifier_1';value.firstTask.textSha256=sha256('Message Type: NEW_TASK\nTask name: /root/verifier_1\nSender: /root\nPayload:\n');}
  }
  if(p.type==='agent_result_observed')p.edge_id=`edge:agent_result:${newChild}:${newTurn}:${rootId}`;
 }
 if(keepFinal)e.events.splice(end+1,0,...copy);else{const removed=e.events.splice(start,end-start+1,...copy);for(const x of removed)for(const field of ['metadata_payload','invocation_payload','runtime_payload','carried_payload','request_payload'])if(x.payload[field])delete e.payloads[x.payload[field].path];}
 renumber(e);return e;
}
async function diskFixture(t,e=fixture()){
 const root=await mkdtemp(join(tmpdir(),'native-runtime-trace-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const bundle=join(root,`trace-${traceId}-${rootId}`);await mkdir(join(bundle,'payloads'),{recursive:true,mode:0o700});
 await writeFile(join(bundle,'manifest.json'),JSON.stringify(e.manifest));
 await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');
 for(const [path,value]of Object.entries(e.payloads))await writeFile(join(bundle,path),JSON.stringify(value));
 return {root,bundle,e};
}
test('runtime trace alone proves all roles, order and actual independent JSON',()=>{
 const native=inspectNativeEvents('cloudflare',stdout(),{...options,traceEvidence:fixture()});
 assert.equal(native.complete,true);assert.equal(native.evidenceSource,'codex-runtime-trace-v1');assert.equal(native.spawnCount,7);
 assert.deepEqual(verifyCloudflareRecords([],stdout(),native),[]);
 assert.equal(JSON.stringify(native).includes('final-empty-result'),false,'completion messages stay out of public execution summaries');
});
test('model-authored collab events cannot supply missing runtime proof or verifier result',()=>{
 const forged=[...stdout(),{type:'item.completed',item:{type:'collab_tool_call',tool:'spawn_agent',status:'completed',prompt:'SEC_HUB_ROLE=verifier-final',receiver_thread_ids:['fake'],agents_states:{fake:{status:'completed',message:'{"decision":"verified","scope":"final-empty-result"}'}}}}];
 assert.throws(()=>inspectNativeEvents('cloudflare',forged,{...options,traceEvidence:null}),/trace evidence/);
 const e=fixture(),last=e.events.filter(x=>x.payload.type==='agent_result_observed').at(-1).payload;
 content(e,last,'carried_payload').status.completed='unparseable completion';
 const native=inspectNativeEvents('cloudflare',forged,{...options,traceEvidence:e});
 assert.throws(()=>verifyCloudflareRecords([],forged,native),/independent final verification/);
});
test('runtime proof rejects mismatched UUID, duplicate calls, nested spawning, role and model forgeries',()=>{
 const mutations=[
  e=>{e.manifest.root_thread_id='forged';},
  e=>{e.events.find(x=>x.payload.type==='tool_call_started').thread_id='nested';},
  e=>{const starts=e.events.filter(x=>x.payload.type==='tool_call_started');starts[1].payload.tool_call_id=starts[0].payload.tool_call_id;},
  e=>{content(e,payload(e,'tool_call_started'),'invocation_payload').tool_namespace='mcp__forged';},
  e=>{const inv=content(e,payload(e,'tool_call_started'),'invocation_payload');inv.payload.arguments=JSON.stringify({message:'SEC_HUB_ROLE=recon-architecture SEC_HUB_ROLE=hunter-1',model:options.model,reasoning_effort:'medium'});},
  e=>{content(e,payload(e,'tool_call_runtime_ended'),'runtime_payload').event_id='other-call';},
  e=>{content(e,payload(e,'tool_call_runtime_ended'),'runtime_payload').model='wrong';},
  e=>{const child=e.events.filter(x=>x.payload.type==='thread_started')[1].payload;content(e,child,'metadata_payload').session_source.subagent.thread_spawn.parent_thread_id='wrong';},
  e=>{const result=payload(e,'agent_result_observed');result.child_codex_turn_id='other-turn';},
  e=>{const result=payload(e,'agent_result_observed');content(e,result,'carried_payload').status={errored:'failed'};},
  e=>{const event=e.events.find(x=>x.payload.type==='tool_call_started');event.payload.kind={type:'send_message'};},
  e=>{e.events.push({...structuredClone(e.events.at(-1)),seq:e.events.length+1});},
 ];
 for(const mutate of mutations){const e=fixture();mutate(e);assert.throws(()=>inspectRuntimeTrace(e,stdout(),options),/trace evidence/);}
 assert.throws(()=>inspectRuntimeTrace(fixture(),[{type:'thread.started',thread_id:'different'}],options),/trace evidence/);
 assert.throws(()=>inspectRuntimeTrace(fixture(),stdout(),{...options,maxAgents:6}),/trace evidence/);
});
test('next phase dispatch must follow delivered results, even if its runtime completion is later',()=>{
 const e=fixture(),i=e.events.findIndex(x=>x.payload.type==='tool_call_started'&&content(e,x.payload,'invocation_payload').payload.arguments.includes('hunter-1'));
 const [hunter]=e.events.splice(i,1);e.events.splice(4,0,hunter);renumber(e);
 const result=inspectRuntimeTrace(e,stdout(),options);assert.equal(result.complete,false);assert.ok(result.reasons.includes('Native phase order failed before hunter'));
});
test('completed child shutdown may flush after root rollout shutdown, but no new work or duplicate ends may follow',()=>{
 const e=fixture(),child=e.events.filter(x=>x.payload.type==='thread_started')[1].payload.thread_id;
 e.events.push({schema_version:1,seq:e.events.length+1,rollout_id:rootId,thread_id:null,codex_turn_id:null,payload:{type:'thread_ended',thread_id:child,status:'completed'}});
 assert.equal(inspectRuntimeTrace(e,stdout(),options).complete,true);
 e.events.push({...structuredClone(e.events.at(-1)),seq:e.events.length+1});assert.throws(()=>inspectRuntimeTrace(e,stdout(),options),/trace evidence/);
 const changed=fixture();changed.events.push({...structuredClone(changed.events[2]),seq:changed.events.length+1});assert.throws(()=>inspectRuntimeTrace(changed,stdout(),options),/trace evidence/);
});
test('a second child turn cannot replace an independent final result',()=>{
 const e=fixture(),i=e.events.findIndex(x=>x.payload.type==='agent_result_observed'),first=e.events.find(x=>x.payload.type==='codex_turn_started'&&x.payload.thread_id!==rootId);
 e.events.splice(i,0,{...structuredClone(first),payload:{...first.payload,codex_turn_id:'followup-turn'}});renumber(e);
 assert.throws(()=>inspectRuntimeTrace(e,stdout(),options),/trace evidence/);
});
test('root completion must follow every delivered child result and precede root shutdown',()=>{
 const e=fixture(),i=e.events.findIndex(x=>x.payload.type==='codex_turn_ended'&&x.payload.codex_turn_id==='root-turn'),lastResult=e.events.findLastIndex(x=>x.payload.type==='agent_result_observed');
 const [rootEnd]=e.events.splice(i,1);e.events.splice(lastResult,0,rootEnd);renumber(e);assert.throws(()=>inspectRuntimeTrace(e,stdout(),options),/trace evidence/);
 const early=fixture(),threadEnd=early.events.findIndex(x=>x.payload.type==='thread_ended'),[shutdown]=early.events.splice(threadEnd,1);early.events.splice(3,0,shutdown);renumber(early);assert.throws(()=>inspectRuntimeTrace(early,stdout(),options),/trace evidence/);
});
test('verifier record must be unchanged and from its own delivered completion',()=>{
 const e=fixture(),result=e.events.filter(x=>x.payload.type==='agent_result_observed').at(-1).payload,record={fingerprint:'candidate-1',verdict:'needs_validation',title:'Independent'};
 content(e,result,'carried_payload').status.completed=JSON.stringify({decision:'needs_validation',record});
 const native=inspectNativeEvents('cloudflare',stdout(),{...options,traceEvidence:e});
 assert.equal(verifyCloudflareRecords([record],[],native).length,1);
 assert.throws(()=>verifyCloudflareRecords([{...record,title:'Parent rewrite'}],[],native),/unchanged/);
 assert.throws(()=>verifyCloudflareRecords([record,record],[],native),/unchanged/);
 content(e,result,'carried_payload').status.completed=JSON.stringify({decision:'needs_validation',record,private_extra:'PRIVATE_CANARY_SENTINEL'});
 const privateNative=inspectNativeEvents('cloudflare',stdout(),{...options,traceEvidence:e});
 verifyCloudflareRecords([record],[],privateNative);assert.equal(JSON.stringify({manifest:{nativeEvidence:privateNative},run:{execution:{nativeEvidence:privateNative}}}).includes('PRIVATE_CANARY_SENTINEL'),false);
});
test('collector retains only referenced witness payloads and omits source, previews and notification wrappers',async t=>{
 const e=fixture();e.events.splice(3,0,{schema_version:1,seq:0,rollout_id:rootId,thread_id:rootId,codex_turn_id:'root-turn',payload:{type:'code_cell_started',source_js:'PRIVATE CELL CODE'}});renumber(e);
 const {root,bundle}=await diskFixture(t,e);await writeFile(join(bundle,'payloads/999.json'),'PRIVATE INFERENCE BODY');
 const retained=await readNativeTrace(root);const text=JSON.stringify(retained);
 for(const value of ['PRIVATE CELL CODE','PRIVATE INFERENCE BODY','DO NOT RETAIN THIS PREVIEW','NOTIFICATION WRAPPER','unused-host-path'])assert.equal(text.includes(value),false,value);
 assert.equal(inspectRuntimeTrace(retained,stdout(),options).complete,true);
});
test('collector rejects traversal, swapped ref identity, missing refs, symlinks, hardlinks and total raw overflow',async t=>{
 for(const mode of ['traversal','identity','missing','symlink','hardlink','overflow']){
  const {root,bundle,e}=await diskFixture(t);
  const ref=payload(e,'tool_call_started').invocation_payload,path=join(bundle,ref.path);
  if(mode==='traversal'){ref.path='../manifest.json';await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');}
  if(mode==='identity'){ref.raw_payload_id='raw_payload:999';await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');}
  if(mode==='missing')await rm(path);
  if(mode==='symlink'){await rm(path);await symlink(join(bundle,'manifest.json'),path);}
  if(mode==='hardlink'){await rm(path);await link(join(bundle,'manifest.json'),path);}
  if(mode==='overflow')await writeFile(join(bundle,'payloads/999.json'),Buffer.alloc(1000));
  await assert.rejects(readNativeTrace(root,mode==='overflow'?{limits:{...TRACE_LIMITS,totalBytes:100}}:{}),/trace evidence|ENOENT/);
 }
});
test('live collector counts every attempted and nested dispatch and rejects steering, gaps and malformed lines',async t=>{
 const {root,bundle,e}=await diskFixture(t);assert.equal((await readNativeTrace(root,{live:true})).spawnCount,7);
 e.events.find(x=>x.payload.type==='tool_call_started').thread_id='nested-child';
 await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');
 assert.equal((await readNativeTrace(root,{live:true})).spawnCount,7);
 e.events.find(x=>x.payload.type==='tool_call_started').payload.kind={type:'send_message'};
 await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');
 await assert.rejects(readNativeTrace(root,{live:true}),/steering/);
 e.events[3].seq=999;await writeFile(join(bundle,'trace.jsonl'),e.events.map(event=>JSON.stringify(event)).join('\n')+'\n');
 await assert.rejects(readNativeTrace(root,{live:true}),/trace evidence/);
 await writeFile(join(bundle,'trace.jsonl'),'not JSON\n');await assert.rejects(readNativeTrace(root,{live:true}),/trace evidence/);
});
test('live startup waits for the log after a partially written manifest and ignores partial UTF-8 append tails',async t=>{
 const root=await mkdtemp(join(tmpdir(),'trace-startup-race-'));t.after(()=>rm(root,{recursive:true,force:true}));const bundle=join(root,`trace-${traceId}-${rootId}`);await mkdir(join(bundle,'payloads'),{recursive:true});
 await writeFile(join(bundle,'manifest.json'),'{');assert.equal(await readNativeTrace(root,{live:true}),null);
 const e=fixture();await writeFile(join(bundle,'manifest.json'),JSON.stringify(e.manifest));
 const event=e.events[0],line=Buffer.from(JSON.stringify(event)+'\n'),tail=Buffer.from('{"message":"한글');
 await writeFile(join(bundle,'trace.jsonl'),Buffer.concat([line,tail.subarray(0,tail.length-1)]));
 assert.equal((await readNativeTrace(root,{live:true})).eventCount,1);
 await assert.rejects(readNativeTrace(root),/TRACE_LOG_INCOMPLETE/);
});
test('live monitor detects excess attempts and missing startup trace, and final stop checks fast processes',async t=>{
 const {root}=await diskFixture(t);let failed;
 const monitor=monitorNativeTrace(root,6,error=>{failed=error;},{intervalMs:5});
 for(let i=0;i<100&&!failed;i++)await new Promise(r=>setTimeout(r,5));
 assert.match(failed?.message??'',/budget exceeded/);await assert.rejects(monitor.stop(),/budget exceeded/);
 const fast=monitorNativeTrace(root,6,()=>{});await assert.rejects(fast.stop(),/budget exceeded/);
 const empty=await mkdtemp(join(tmpdir(),'empty-native-trace-'));t.after(()=>rm(empty,{recursive:true,force:true}));failed=undefined;
 const missing=monitorNativeTrace(empty,10,error=>{failed=error;},{intervalMs:5,startupGraceMs:5});missing.noteRootStarted();
 for(let i=0;i<100&&!failed;i++)await new Promise(r=>setTimeout(r,5));
 assert.match(failed?.message??'',/trace evidence/);await assert.rejects(missing.stop(),/trace evidence/);
});
test('legacy prompt remains byte-exact; new trace prompt requires independent one-turn children',()=>{
 const old=cloudflarePrompt('/copy','/output',{...options,skillRoot:'/skill'}),fresh=cloudflarePrompt('/copy','/output',{...options,skillRoot:'/skill'},1);
 assert.equal(fresh.startsWith(old+'\nRuntime evidence policy:'),true);assert.match(fresh,/Do not send_message, followup_task/);
 // Frozen from ed5505b, independently evaluated before the trace change.
 assert.equal(sha256(old),'2884118de131bb397e514e15dab4a0aaf49ce0eed8bd8a1e535744599b41ade2');
 assert.throws(()=>cloudflarePrompt('/copy','/output',options,4),/Unsupported/);
});
test('sealed retained witnesses replay after the private raw tree is gone and reject tampering or missing evidence',async t=>{
 const {root}=await diskFixture(t),evidence=await readNativeTrace(root),retained=await mkdtemp(join(tmpdir(),'sealed-native-trace-'));t.after(()=>rm(retained,{recursive:true,force:true}));
 const bytes=JSON.stringify(evidence),manifest={preRedactionHashes:{'native-trace.json':sha256(bytes)}};
 await writeFile(join(retained,'native-trace.json'),bytes);await rm(root,{recursive:true,force:true});
 assert.equal(inspectRuntimeTrace(await readSealedNativeTrace(retained,manifest),stdout(),options).complete,true);
 await writeFile(join(retained,'native-trace.json'),bytes+' ');await assert.rejects(readSealedNativeTrace(retained,manifest),/hash differs/);
 await rm(join(retained,'native-trace.json'));await assert.rejects(readSealedNativeTrace(retained,manifest),/ENOENT/);
 await assert.rejects(readSealedNativeTrace(retained,{}),/Missing sealed/);
});
test('new trace policy rejects unsupported formats and cannot downgrade to legacy with a sealed trace',async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-trace-policy-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const cfg={...options,skillRoot:'/skill',workRoot:'/work',revision:PINS.cloudflare},ctx={target:'/target',artifactDir:root,config:{tools:{cloudflare:{command:'/native',args:[],agentOptions:cfg}}}};
 const base={schema:'sec-hub.native-agent/v1',id:'cloudflare',sourceCommit:PINS.cloudflare,source:SOURCES.cloudflare,target:'/target',inputs:[{path:'source.txt'}],sandboxInvocationPolicyVersion:2,preRedactionHashes:{'native-trace.json':'a'.repeat(64)}};
 for(const value of [undefined,null,0,4,'1',true]){const manifest={...base};if(value!==undefined)manifest.runtimeTracePolicyVersion=value;await writeFile(join(root,'execution-manifest.json'),JSON.stringify(manifest));await assert.rejects(validateNativeExecution('cloudflare',ctx),/runtime trace policy version/);}
});
test('policy2 proves code-cell native spawn and exact plaintext task delivery into the child first inference',()=>{
 const native=inspectNativeEvents('cloudflare',stdout(),{...options,runtimeTracePolicyVersion:2,traceEvidence:codeModeFixture()});assert.equal(native.complete,true);assert.equal(native.evidenceSource,'codex-runtime-trace-v2');verifyCloudflareRecords([],[],native);
 for(const mutate of [
  e=>{payload(e,'tool_call_started').requester={type:'model'};},
  e=>{payload(e,'tool_call_started').code_mode_runtime_tool_id=null;},
  e=>{payload(e,'tool_call_started').requester.runtime_cell_id='other-cell';},
  e=>{const p=payload(e,'tool_call_started'),v=content(e,p,'invocation_payload'),a=JSON.parse(v.payload.arguments);a.fork_turns='all';v.payload.arguments=JSON.stringify(a);},
  e=>{content(e,payload(e,'inference_started'),'request_payload').firstTask.textSha256='a'.repeat(64);},
  e=>{content(e,payload(e,'inference_started'),'request_payload').firstTask.author='/root/forged';},
  e=>{e.events=e.events.filter(x=>x.payload.type!=='inference_started');},
 ]){const e=codeModeFixture();mutate(e);assert.throws(()=>inspectRuntimeTrace(e,stdout(),{...options,runtimeTracePolicyVersion:2}),/trace evidence/);}
 assert.throws(()=>inspectRuntimeTrace(codeModeFixture(),stdout(),options),/TRACE_POLICY/);
});
test('policy2 collection seals only plaintext task hashes and rejects direct encrypted fallback live',async t=>{
 const {root,bundle,e}=await diskFixture(t,codeModeFixture({raw:true})),opts={runtimeTracePolicyVersion:2,model:options.model,effort:options.effort};
 const evidence=await readNativeTrace(root,opts);assert.equal(inspectRuntimeTrace(evidence,stdout(),{...options,...opts}).complete,true);
 const text=JSON.stringify(evidence);assert.equal(text.includes('PRIVATE FULL INFERENCE REQUEST'),false);assert.equal(text.includes('PRIVATE FULL JAVASCRIPT SOURCE'),false);assert.equal(text.includes('agentMessageCount'),true);
 const start=payload(e,'tool_call_started');start.requester={type:'model'};start.model_visible_call_id=start.tool_call_id;start.code_mode_runtime_tool_id=null;
 await writeFile(join(bundle,'trace.jsonl'),e.events.map(x=>JSON.stringify(x)).join('\n')+'\n');await assert.rejects(readNativeTrace(root,{...opts,live:true}),/TRACE_ROLE_TRANSPORT/);
});
test('policy2 blocks MCP, web, patching and permission requests in the runtime, preserving the existing sandbox argv',async t=>{
 const {root,bundle,e}=await diskFixture(t,codeModeFixture({raw:true}));
 for(const kind of [{type:'mcp',server:'forbidden',tool:'fetch'},{type:'web'},{type:'apply_patch'},{type:'other',name:'request_permissions'}]){
  payload(e,'tool_call_started').kind=kind;await writeFile(join(bundle,'trace.jsonl'),e.events.map(x=>JSON.stringify(x)).join('\n')+'\n');await assert.rejects(readNativeTrace(root,{runtimeTracePolicyVersion:2,live:true}),/TRACE_FORBIDDEN_TOOL/);
 }
 const old=codexArgs('/runner',{...options,skillRoot:'/skill'},'/runtime/node',2,1),fresh=codexArgs('/runner',{...options,skillRoot:'/skill'},'/runtime/node',2,2);
 assert.deepEqual(old,codexArgs('/runner',{...options,skillRoot:'/skill'},'/runtime/node',2));
 for(const flag of ['features.code_mode=true','features.code_mode_host.enabled=true','features.code_mode_host_grpc=true','features.multi_agent_v2.enabled=true','features.multi_agent_v2.non_code_mode_only=false','features.multi_agent_v2.tool_namespace="collaboration"','web_search="disabled"'])assert.ok(fresh.includes(flag),flag);
 assert.equal(old.find(x=>x.startsWith('permissions=')),fresh.find(x=>x.startsWith('permissions=')));
 assert.match(cloudflarePrompt('/copy','/output',{...options,skillRoot:'/skill'},2),/tools\.collaboration__spawn_agent/);
 assert.match(cloudflarePrompt('/copy','/output',{...options,skillRoot:'/skill'},2),/top-level functions\.exec JavaScript tool/);
});
test('policy2 validates native identity for every tool and rejects an MCP leaf-name collision',async t=>{
 const e=codeModeFixture({raw:true}),ordinal=Math.max(...Object.keys(e.payloads).map(path=>Number(path.match(/[0-9]+/)[0])))+1,path=`payloads/${ordinal}.json`;
 e.payloads[path]={tool_name:'exec_command',tool_namespace:'functions',payload:{type:'function',arguments:'{"cmd":"PRIVATE COMMAND ARGUMENTS"}'}};
 e.events.splice(3,0,{schema_version:1,seq:0,rollout_id:rootId,thread_id:rootId,codex_turn_id:'root-turn',payload:{type:'tool_call_started',tool_call_id:'native-command',kind:{type:'exec_command'},requester:{type:'model'},model_visible_call_id:'native-command',invocation_payload:{raw_payload_id:`raw_payload:${ordinal}`,kind:{type:'tool_invocation'},path}}});renumber(e);
 const {root,bundle}=await diskFixture(t,e),opts={runtimeTracePolicyVersion:2,model:options.model,effort:options.effort};
 const retained=await readNativeTrace(root,opts);assert.equal(inspectRuntimeTrace(retained,stdout(),{...options,...opts}).complete,true);assert.equal(JSON.stringify(retained).includes('PRIVATE COMMAND ARGUMENTS'),false);
 e.payloads[path].tool_namespace='mcp__forged';await writeFile(join(bundle,path),JSON.stringify(e.payloads[path]));
 await assert.rejects(readNativeTrace(root,{...opts,live:true}),/TRACE_TOOL_IDENTITY/);
 retained.payloads[path].tool_namespace='mcp__forged';assert.throws(()=>inspectRuntimeTrace(retained,stdout(),{...options,...opts}),/TRACE_TOOL_IDENTITY/);
});
test('policy3 binds direct encrypted requests to host-pinned developer roles and actual independent completions',()=>{
 const opts={...options,...roleContext,runtimeTracePolicyVersion:3},events=[stdout()[0],{type:'item.completed',item:{type:'command_execution',status:'completed',exit_code:0,command:'cat /skill/skills/security-audit/SKILL.md'}},stdout()[1]],native=inspectNativeEvents('cloudflare',events,{...opts,traceEvidence:directRoleFixture()});
 assert.equal(native.complete,true);assert.equal(native.evidenceSource,'codex-runtime-trace-v3');assert.equal(native.encryptedTaskSemantics,'not-inspected');verifyCloudflareRecords([],[],native);
 for(const mutate of [
  e=>{payload(e,'tool_call_started').requester={type:'code_cell',runtime_cell_id:'cell'};},
  e=>{const p=payload(e,'tool_call_started'),inv=content(e,p,'invocation_payload'),a=JSON.parse(inv.payload.arguments);a.agent_type='sec_hub_verifier';inv.payload.arguments=JSON.stringify(a);},
  e=>{const p=e.events.filter(x=>x.payload.type==='thread_started')[1].payload;content(e,p,'metadata_payload').session_source.subagent.thread_spawn.agent_role='sec_hub_verifier';},
  e=>{content(e,payload(e,'inference_started'),'request_payload').firstTask.ciphertextSha256='a'.repeat(64);},
  e=>{content(e,payload(e,'inference_started'),'request_payload').firstTask.developer.textSha256='a'.repeat(64);},
  e=>{content(e,payload(e,'inference_started'),'request_payload').firstTask.developer.role='user';},
  e=>{const p=payload(e,'tool_call_started'),inv=content(e,p,'invocation_payload'),a=JSON.parse(inv.payload.arguments);a.fork_turns='all';inv.payload.arguments=JSON.stringify(a);},
 ]){const e=directRoleFixture();mutate(e);assert.throws(()=>inspectRuntimeTrace(e,stdout(),opts),/trace evidence/);}
 assert.throws(()=>inspectRuntimeTrace(directRoleFixture(),stdout(),{...opts,runtimeTracePolicyVersion:2}),/TRACE_POLICY/);
});
test('policy3 collection seals developer and ciphertext hashes without retaining inference or ciphertext',async t=>{
 const {root,bundle,e}=await diskFixture(t,directRoleFixture({raw:true})),opts={...options,...roleContext,runtimeTracePolicyVersion:3},retained=await readNativeTrace(root,opts);
 assert.equal(inspectRuntimeTrace(retained,stdout(),opts).complete,true);const text=JSON.stringify(retained);
 assert.equal(text.includes('PRIVATE_CIPHERTEXT_'),false);assert.equal(text.includes('PRIVATE ROLE INFERENCE'),false);assert.equal(text.includes(nativeRoleContracts(roleContext).sec_hub_verifier.instructions),false);
 const inference=payload(e,'inference_started'),request=content(e,inference,'request_payload');request.input[0].role='user';await writeFile(join(bundle,inference.request_payload.path),JSON.stringify(request));
 await assert.rejects(readNativeTrace(root,{...opts,live:true}),/TRACE_CHILD_ROLE_INSTRUCTIONS/);
 request.input[0].role='developer';request.input.unshift(structuredClone(request.input[0]));await writeFile(join(bundle,inference.request_payload.path),JSON.stringify(request));await assert.rejects(readNativeTrace(root,{...opts,live:true}),/TRACE_CHILD_ROLE_INSTRUCTIONS/);
});
test('policy3 cannot be relabeled as policy1 or policy2 while retaining host role evidence',async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-role-downgrade-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const configured={...options,skillRoot:'/skill',workRoot:'/work',revision:PINS.cloudflare},ctx={target:'/target',artifactDir:root,config:{tools:{cloudflare:{command:'/native',args:[],agentOptions:configured}}}};
 for(const version of [1,2]){await writeFile(join(root,'execution-manifest.json'),JSON.stringify({schema:'sec-hub.native-agent/v1',id:'cloudflare',sourceCommit:PINS.cloudflare,source:SOURCES.cloudflare,target:'/target',inputs:[{path:'source.txt'}],sandboxInvocationPolicyVersion:2,runtimeTracePolicyVersion:version,roleConfiguration:{}}));await assert.rejects(validateNativeExecution('cloudflare',ctx),/role configuration policy mismatch/);}
});
test('policy3 invocation pins direct-only native role files and retains old policy bytes',()=>{
 const fresh=codexArgs('/runner',{...options,...roleContext},'/runtime/node',2,3,'/host-roles');
 assert.ok(fresh.includes('features.multi_agent_v2.non_code_mode_only=true'));assert.ok(fresh.some(s=>s==='agents.sec_hub_verifier.config_file="/host-roles/sec_hub_verifier.toml"'));
 assert.throws(()=>codexArgs('/runner',{...options,...roleContext},'/runtime/node',2,3),/role|path/i);
 const prompt=cloudflarePrompt('/copy','/output',{...options,...roleContext},3);assert.match(prompt,/direct native collaboration.spawn_agent/);assert.match(prompt,/sec_hub_verifier/);assert.doesNotMatch(prompt,/issue every spawn through the top-level functions.exec/);
});
test('policy3 separates numbered candidate and exact final-empty verifier completions',()=>{
 const opts={...options,...roleContext,runtimeTracePolicyVersion:3},record={fingerprint:'candidate-1',verdict:'needs_validation',title:'Independent'};
 const candidate=numberedVerifier(directRoleFixture(),record),native=inspectRuntimeTrace(candidate,stdout(),opts);assert.equal(verifyCloudflareRecords([record],[],native).length,1);
 const delivery=candidate.events.filter(x=>x.payload.type==='agent_result_observed').at(-1).payload;
 content(candidate,delivery,'carried_payload').status.completed='{"decision":"verified","scope":"final-empty-result"}';assert.throws(()=>verifyCloudflareRecords([],[],inspectRuntimeTrace(candidate,stdout(),opts)),/final verification/);
 for(const response of [{decision:'verified',scope:'final-empty-result',extra:true},{decision:'needs_validation',record}]){
  const e=directRoleFixture(),p=e.events.filter(x=>x.payload.type==='agent_result_observed').at(-1).payload;content(e,p,'carried_payload').status.completed=JSON.stringify(response);assert.throws(()=>verifyCloudflareRecords(response.record?[record]:[],[],inspectRuntimeTrace(e,stdout(),opts)),/verification|unchanged/);
 }
 const extra=numberedVerifier(directRoleFixture(),record),p=extra.events.filter(x=>x.payload.type==='agent_result_observed').at(-1).payload;content(extra,p,'carried_payload').status.completed=JSON.stringify({decision:'needs_validation',record,extra:true});assert.throws(()=>verifyCloudflareRecords([record],[],inspectRuntimeTrace(extra,stdout(),opts)),/unchanged/);
});
test('policy3 cannot omit a valid numbered decision even when a final-empty child agrees',()=>{
 const record={fingerprint:'candidate-1',verdict:'needs_validation',title:'Independent'},e=numberedVerifier(directRoleFixture(),record,{keepFinal:true}),opts={...options,...roleContext,runtimeTracePolicyVersion:3},native=inspectRuntimeTrace(e,stdout(),opts);
 assert.throws(()=>verifyCloudflareRecords([],[],native),/omit a valid/);assert.throws(()=>verifyCloudflareRecords([record],[],native),/conflicts with nonempty/);
});
