import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeAgentAdapters } from '../src/agents/index.mjs';
import { inspectNativeEvents, parseAnthropicDocument, sourceManifest, copySources } from '../src/agents/validation.mjs';
import { mkdtemp, writeFile, mkdir, symlink, rm, readFile, cp } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

test('native registry uses isolated wrappers and explicit agent configurations', () => {
  assert.deepEqual(nativeAgentAdapters.map(x=>x.id), ['cloudflare','anthropic']);
  const adapter=nativeAgentAdapters[0];
  assert.throws(()=>adapter.build({target:'/target',artifactDir:'/raw',config:{}}), /configuration/i);
  const invocation=adapter.build({target:'/target',artifactDir:'/raw',config:{tools:{cloudflare:{command:'/native',args:[],agentOptions:{skillRoot:'/skill',workRoot:'/work',revision:'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',model:'model'}}}}});
  assert.equal(invocation.command,process.execPath);
  assert.equal(JSON.parse(invocation.args[1]).command,'/native');
});
test('Anthropic wrapper passes the caller USER to native Claude without forwarding credentials',async t=>{
  const root=await mkdtemp(join(tmpdir(),'native-user-env-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
  for(const path of ['target','artifacts','work','skill'])await mkdir(join(root,path));
  await writeFile(join(root,'target/source.txt'),'fixture');
  await mkdir(join(root,'skill/.claude/skills/vuln-scan'),{recursive:true});
  await cp(fileURLToPath(new URL('./fixtures/anthropic-registration/SKILL.md',import.meta.url)),join(root,'skill/.claude/skills/vuln-scan/SKILL.md'));
  const wrapper=fileURLToPath(new URL('../src/agents/native-wrapper.mjs',import.meta.url));
  const capture=join(root,'capture.jsonl'),fake=join(root,'fake-claude.mjs'),loader=join(root,'loader.mjs');
  await writeFile(fake,`import {writeFile} from 'node:fs/promises';const record=process.argv[2];const version=process.argv.includes('--version');await writeFile(record,JSON.stringify({version,user:process.env.USER,keys:Object.keys(process.env)})+'\\n',{flag:'a'});if(version)console.log('fixture claude 1');else console.log('{}');`);
  const validation=`
    import {copyFile,mkdir,readFile} from 'node:fs/promises';
    export const PINS={anthropic:'fixture'},SOURCES={anthropic:'fixture'},OUTPUTS={anthropic:[]};
    export function nativeOptions(id,value){return value};export async function safeRead(){return Buffer.from('{}')};export function sha256(){return 'fixture'};
    export async function sourceManifest(root){const data=await readFile(root+'/source.txt');return [{path:'source.txt',size:data.length,sha256:'fixture',lines:1}]};
    export async function copySources(source,copy){await mkdir(copy);await copyFile(source+'/source.txt',copy+'/source.txt')};export function sameInputs(){return true};
    export function inspectNativeEvents(){return {reasons:[]}};export function verifyCloudflareRecords(){return []};export async function verifySourcePin(){return [{path:'.claude/skills/vuln-scan/SKILL.md',sha256:'49e44d80ef199e695cae11801bb4f38d5efc15bcd7e5b5522116c977c77e2405'}]};export async function runOfficialValidators(){return []};export function parseAnthropicDocument(){return []};
  `;
  await writeFile(loader,`const source=${JSON.stringify(validation)};export async function resolve(specifier,context,next){if(specifier==='./validation.mjs'&&context.parentURL?.endsWith('/native-wrapper.mjs'))return {url:'fixture:validation',shortCircuit:true};return next(specifier,context)}export async function load(url,context,next){if(url==='fixture:validation')return {format:'module',source,shortCircuit:true};return next(url,context)}`);
  const user='trusted-caller-user',secrets={ANTHROPIC_API_KEY:'synthetic-api-key',ANTHROPIC_AUTH_TOKEN:'synthetic-auth-token',CLAUDE_CODE_OAUTH_TOKEN:'synthetic-oauth-token',CLAUDE_CONFIG_DIR:'/synthetic/claude-config',CLAUDE_CODE_HOST_CREDS_FILE:'/synthetic/host-creds'};
  const nativeNode=process.env.PATH.split(':').map(path=>join(path,'node')).find(path=>{try{return statSync(path).isFile()}catch{return false}});assert.ok(nativeNode);
  const config={id:'anthropic',command:nativeNode,args:[fake,capture],target:join(root,'target'),artifactDir:join(root,'artifacts'),agentOptions:{skillRoot:join(root,'skill'),workRoot:join(root,'work'),revision:'d3bea6b5793b5f3d59a75ebe69a58efa88383145',model:'fixture'}};
  const child=spawn(process.execPath,['--experimental-loader',loader,wrapper,JSON.stringify(config)],{env:{...process.env,USER:user,...secrets},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  child.stdout.setEncoding('utf8').on('data',chunk=>stdout+=chunk);child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
  const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve)});
  const manifest=await readFile(join(root,'artifacts/execution-manifest.json'),'utf8').then(JSON.parse);
  assert.equal(code,0,`${stderr}${stdout} ${JSON.stringify(manifest.reasons)}`);
  const calls=(await readFile(capture,'utf8')).trim().split('\n').map(line=>JSON.parse(line));
  assert.deepEqual(calls.map(call=>call.version),[true,false]);
  for(const call of calls){assert.equal(call.user,user);for(const name of Object.keys(secrets))assert.equal(call.keys.includes(name),false,`${name} was forwarded`);}
});
const cfEvents=()=>[
  {type:'thread.started',thread_id:'parent'},
  ...['recon-architecture','recon-boundaries','recon-execution','recon-companions','hunter-1','critic-final','verifier-final'].flatMap((role,i)=>[
    {type:'item.completed',item:{id:`s${i}`,type:'collab_tool_call',tool:'spawn_agent',status:'completed',prompt:`SEC_HUB_ROLE=${role}`,receiver_thread_ids:[`child${i}`],agents_states:{}}},
    {type:'item.completed',item:{id:`w${i}`,type:'collab_tool_call',tool:'wait',status:'completed',receiver_thread_ids:[`child${i}`],agents_states:{[`child${i}`]:{status:'completed',message:'done'}}}}
  ]), {type:'turn.completed',usage:{input_tokens:1,output_tokens:1}}
];
test('Cloudflare actual delegation requires all mandatory roles and successful child completion',()=>{
  assert.equal(inspectNativeEvents('cloudflare',cfEvents(),{maxAgents:10}).complete,true);
  const missing=cfEvents().filter(x=>!x.item?.prompt?.includes('critic-final'));
  assert.equal(inspectNativeEvents('cloudflare',missing,{maxAgents:10}).complete,false);
  assert.equal(inspectNativeEvents('cloudflare',[{type:'turn.completed'},{type:'item.completed',item:{type:'agent_message',text:'I spawned seven agents'}}],{maxAgents:10}).complete,false);
});
test('Anthropic requires native Skill activation success and rejects turn/budget failures',()=>{
  const events=[{type:'assistant',message:{content:[{type:'tool_use',name:'Skill',id:'s1',input:{skill:'vuln-scan',args:'/copy --single --no-score'}}]}},{type:'user',message:{content:[{type:'tool_result',tool_use_id:'s1',content:'loaded'}]}},{type:'result',subtype:'success',is_error:false,permission_denials:[]}];
  assert.equal(inspectNativeEvents('anthropic',events).complete,true);
  assert.equal(inspectNativeEvents('anthropic',events.slice(1)).complete,false);
  assert.equal(inspectNativeEvents('anthropic',[...events,{type:'result',subtype:'error_max_turns',is_error:true}]).complete,false);
});
test('strict Anthropic native schema preserves static candidate and rejects count/path lies',()=>{
  const doc={target:'/copy',scanned_at:'2026-10-27T00:00:00Z',focus_areas:['auth'],findings:[{id:'F-001',file:'server.mjs',line:2,category:'auth-bypass',severity:'HIGH',confidence:0.9,title:'Missing authorization',description:'Source path',exploit_scenario:'Request changes other user',recommendation:'Check owner'}],summary:{total:1,high:1,medium:0,low:0,low_confidence:0}};
  const inputs=[{path:'server.mjs',size:1,sha256:'a'.repeat(64),lines:10}];
  const result=parseAnthropicDocument(doc,{copyTarget:'/copy',inputs,artifactDir:'/raw'});
  assert.equal(result[0].verification,'candidate');
  assert.equal(result[0].severity,'high');
  assert.throws(()=>parseAnthropicDocument({...doc,summary:{...doc.summary,total:0}},{copyTarget:'/copy',inputs,artifactDir:'/raw'}),/summary/i);
  assert.throws(()=>parseAnthropicDocument({...doc,findings:[{...doc.findings[0],file:'../secret'}]},{copyTarget:'/copy',inputs,artifactDir:'/raw'}),/location/i);
});
test('source staging excludes Git and rejects linked source rather than following it',async()=>{
  const root=await mkdtemp(join(tmpdir(),'native-source-test-'));
  try{
    const target=join(root,'target'),copy=join(root,'copy'); await mkdir(target);await mkdir(join(target,'.git'));await writeFile(join(target,'.git','config'),'secret');await writeFile(join(target,'server.mjs'),'line1\nline2\n');
    const before=await sourceManifest(target);await copySources(target,copy,before);assert.deepEqual(await sourceManifest(copy),before);assert.equal((await readFile(join(copy,'server.mjs'),'utf8')),'line1\nline2\n');
    await symlink('/etc/passwd',join(target,'escape'));await assert.rejects(sourceManifest(target),/link|regular/i);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('one delegated agent cannot claim multiple mandatory phases',()=>{
  const events=cfEvents();events[1].item.prompt='SEC_HUB_ROLE=recon-architecture SEC_HUB_ROLE=recon-boundaries SEC_HUB_ROLE=recon-execution SEC_HUB_ROLE=recon-companions SEC_HUB_ROLE=hunter SEC_HUB_ROLE=critic-final SEC_HUB_ROLE=verifier';
  assert.equal(inspectNativeEvents('cloudflare',events,{maxAgents:10}).complete,false);
});
test('Claude Skill arguments must request the supported single no-score mode',()=>{
  const events=[{type:'assistant',message:{content:[{type:'tool_use',name:'Skill',id:'s1',input:{skill:'vuln-scan',args:'/copy'}}]}},{type:'user',message:{content:[{type:'tool_result',tool_use_id:'s1',content:'loaded'}]}},{type:'result',subtype:'success',is_error:false}];
  assert.equal(inspectNativeEvents('anthropic',events).complete,false);
});
test('Cloudflare critic must be unique and run after hunter completion',()=>{
  const swapped=cfEvents();const hunter=swapped.splice(9,2);swapped.splice(1,0,...hunter);
  assert.equal(inspectNativeEvents('cloudflare',swapped,{maxAgents:10}).complete,false);
  const duplicate=cfEvents();duplicate.splice(-1,0,{type:'item.completed',item:{id:'critic2',type:'collab_tool_call',tool:'spawn_agent',status:'completed',prompt:'SEC_HUB_ROLE=critic-final',receiver_thread_ids:['extra'],agents_states:{extra:{status:'completed',message:'done'}}}});
  assert.equal(inspectNativeEvents('cloudflare',duplicate,{maxAgents:10}).complete,false);
});
test('native Claude activation target is bound to the isolated target',()=>{
  const events=[{type:'assistant',message:{content:[{type:'tool_use',name:'Skill',id:'s1',input:{skill:'vuln-scan',args:'/other --single --no-score'}}]}},{type:'user',message:{content:[{type:'tool_result',tool_use_id:'s1',content:'loaded'}]}},{type:'result',subtype:'success',is_error:false}];
  assert.equal(inspectNativeEvents('anthropic',events,{copyTarget:'/copy'}).complete,false);
});
test('native verifier JSON is preserved exactly and cannot be hand-repaired by parent',async()=>{
  const {verifyCloudflareRecords}=await import('../src/agents/validation.mjs');
  const record={fingerprint:'auth:1',verdict:'needs_validation',title:'Candidate'};
  const event=message=>[{type:'item.completed',item:{type:'collab_tool_call',agents_states:{fresh:{status:'completed',message}}}}];
  const native={verifierThreadIds:['fresh']};
  assert.equal(verifyCloudflareRecords([record],event(JSON.stringify({decision:'needs_validation',record})),native)[0].threadId,'fresh');
  assert.throws(()=>verifyCloudflareRecords([{...record,title:'Parent replacement'}],event(JSON.stringify({decision:'needs_validation',record})),native),/unchanged/i);
  assert.throws(()=>verifyCloudflareRecords([record],event('Here is JSON: '+JSON.stringify({decision:'needs_validation',record})),native),/unchanged/i);
  assert.throws(()=>verifyCloudflareRecords([],event('No findings'),native),/empty output/i);
  assert.deepEqual(verifyCloudflareRecords([],event('{"decision":"verified","scope":"final-empty-result"}'),native),[]);
});
test('Cloudflare trace must contain an actual pinned instruction read',()=>{
  const options={maxAgents:10,skillRoot:'/official'};
  assert.equal(inspectNativeEvents('cloudflare',cfEvents(),options).complete,false);
  const events=cfEvents();events.splice(1,0,{type:'item.completed',item:{id:'read-skill',type:'command_execution',command:'cat /official/skills/security-audit/SKILL.md',status:'completed',exit_code:0,aggregated_output:'# Security Audit'}});
  assert.equal(inspectNativeEvents('cloudflare',events,options).complete,true);
});
test('real native terminal failures survive missing-output diagnostics without leaking identity',()=>{
  const codex=[{type:'error',message:JSON.stringify({type:'error',status:400,error:{type:'invalid_request_error',message:"The 'gpt-6.1-sol' model is not supported when using Codex with a ChatGPT account.",code:'model_not_found'}})},{type:'turn.failed',error:{message:'model_not_found'}}];
  assert.match(inspectNativeEvents('cloudflare',codex).terminalReason,/model.*not supported.*ChatGPT/i);
  const claude=[{type:'result',subtype:'success',is_error:true,result:'Failed to authenticate: OAuth session expired and could not be refreshed',permission_denials:[],num_turns:1}];
  assert.match(inspectNativeEvents('anthropic',claude).terminalReason,/OAuth session expired.*refresh/i);
  assert.equal(inspectNativeEvents('anthropic',claude).complete,false);
});
test('native policy revalidation binds the recorded Node runtime rather than verifier PATH',async()=>{
  const {codexArgs}=await import('../src/agents/invocation.mjs');
  const args=codexArgs('/runner',{model:'gpt-6.1-sol',skillRoot:'/pinned'},'/recorded/runtime/bin/node');
  assert.ok(args.includes('shell_environment_policy.set={ PATH = "/recorded/runtime/bin:/usr/bin:/bin:/usr/sbin:/sbin" }'));
});

test('Cloudflare strategy is explicit, defaults to legacy, and rejects unknown backend settings',async()=>{
  const {validateAgentOptions}=await import('../src/config.mjs');
  const {nativeOptions}=await import('../src/agents/validation.mjs');
  const base={skillRoot:'/skill',workRoot:'/work',revision:'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',model:'gpt-6.1-sol'};
  assert.equal(nativeOptions('cloudflare',base).strategy,'native-collab');
  assert.equal(validateAgentOptions('cloudflare',{...base,strategy:'supervised-codex-workers'}).strategy,'supervised-codex-workers');
  for(const invalid of [{strategy:'fake-collab'},{backend:'fake'},{mode:'supervised'}])assert.throws(()=>validateAgentOptions('cloudflare',{...base,...invalid}),/Invalid config/);
  assert.throws(()=>validateAgentOptions('anthropic',{strategy:'supervised-codex-workers'}),/Invalid config/);
});
test('preparation reuse accepts only an explicit supervised Cloudflare manifest path',async()=>{
  const {validateAgentOptions,loadConfig}=await import('../src/config.mjs');
  const preparationFrom='/old run/raw/cloudflare/execution-manifest.json';
  const options={strategy:'supervised-codex-workers',preparationFrom,preparationSha256:'a'.repeat(64)};
  assert.deepEqual(validateAgentOptions('cloudflare',options),options);
  const root=await mkdtemp(join(tmpdir(),'preparation-config-test-'));
  try{
    const path=join(root,'config.json');
    await writeFile(path,JSON.stringify({tools:{cloudflare:{command:'codex',agentOptions:options}}}));
    assert.equal((await loadConfig(path)).tools.cloudflare.agentOptions.preparationFrom,preparationFrom);
  }finally{await rm(root,{recursive:true,force:true});}
});
test('preparation reuse rejects malformed paths and unsupported strategies or backends',async()=>{
  const {validateAgentOptions}=await import('../src/config.mjs');
  const preparationFrom='/old-run/raw/cloudflare/execution-manifest.json',preparationSha256='a'.repeat(64);
  for(const invalid of ['', ' ', ' '+preparationFrom, preparationFrom+' ', 'relative/raw/cloudflare/execution-manifest.json', null, true, 4, [], {}, '/old-run/raw/cloudflare/execution-manifest.json\0', '/old-run/raw/cloudflare/execution-manifest.json\n', '/old-run/raw/cloudflare/other.json', '/old-run/execution-manifest.json', '/old-run/../old-run/raw/cloudflare/execution-manifest.json']){
    assert.throws(()=>validateAgentOptions('cloudflare',{strategy:'supervised-codex-workers',preparationFrom:invalid,preparationSha256}),/agentOptions\.preparationFrom/);
  }
  for(const invalid of ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), null, 4, {}, true])assert.throws(()=>validateAgentOptions('cloudflare',{strategy:'supervised-codex-workers',preparationFrom,preparationSha256:invalid}),/agentOptions\.preparationSha256/);
  for(const pair of [{preparationFrom},{preparationSha256}])assert.throws(()=>validateAgentOptions('cloudflare',{strategy:'supervised-codex-workers',...pair}),/preparationFrom.*preparationSha256/);
  for(const strategy of [undefined,'native-collab'])assert.throws(()=>validateAgentOptions('cloudflare',{...(strategy?{strategy}:{}),preparationFrom,preparationSha256}),/preparationFrom/);
  assert.throws(()=>validateAgentOptions('anthropic',{preparationFrom,preparationSha256}),/agentOptions\.preparationFrom/);
  assert.throws(()=>validateAgentOptions('cloudflare',{strategy:'supervised-codex-workers',preparationFrom,preparationSha256,nativeBackend:'claude'}),/agentOptions/);
});
test('native backend quota diagnosis takes precedence over missing workflow evidence',()=>{
  const events=[{type:'assistant',is_api_error_message:true,error:{status:429,type:'usage_limit_reached',message:'weekly quota exhausted',reset_at:'2026-10-29T00:00:00Z'}},{type:'result',subtype:'success',is_error:true,result:'usage_limit_reached'}];
  const result=inspectNativeEvents('anthropic',events,{exitCode:1});
  assert.equal(result.complete,false);
  assert.equal(result.terminalOutcome.category,'usage_limit');
  assert.equal(result.terminalOutcome.statusCode,429);
  assert.match(result.terminalReason,/usage allowance/i);
  assert.doesNotMatch(result.terminalReason,/OAuth|sign-in/i);
});
