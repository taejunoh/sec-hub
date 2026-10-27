import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, access, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runSupervisedCloudflare } from '../src/agents/supervised-cloudflare.mjs';
import { validateSupervisedCloudflare, finalizeSupervisedCloudflare, preparePlan, applyCritic, assertObservedPolicy } from '../src/agents/supervised-validation.mjs';
import { loadCloudflareContracts, supervisedArgs } from '../src/agents/cloudflare-prompts.mjs';
import { PINS, sha256 } from '../src/agents/validation.mjs';
import { runProcess } from '../src/processes.mjs';
import * as promptPolicy from '../src/agents/cloudflare-prompts.mjs';

const skillRoot=resolve('../../work/tools/cloudflare-security-audit');
let available=true;try{await access(join(skillRoot,'skills/security-audit/SKILL.md'));}catch{available=false;}
async function fixture(mode='zero',maxAgents=10){
  const root=await mkdtemp(join(tmpdir(),'supervised-cf-test-')),target=join(root,'target'),artifactDir=join(root,'raw');
  await mkdir(target);await writeFile(join(target,'target.mjs'),'export const run = input => input;\n');
  const agentOptions={strategy:'supervised-codex-workers',skillRoot,workRoot:join(root,'staging'),revision:PINS.cloudflare,model:'gpt-6.1-sol',effort:'medium',profile:'quick',maxAgents};
  const payload={id:'cloudflare',command:process.execPath,args:[resolve('test/fixtures/supervised-fake-codex.mjs'),mode],agentOptions,target,artifactDir};
  const ctx={target,artifactDir,exitCode:0,config:{tools:{cloudflare:{command:payload.command,args:payload.args,agentOptions}}}};
  return {root,payload,ctx,async json(file){return JSON.parse(await readFile(join(artifactDir,file),'utf8'));},async dispose(){await rm(root,{recursive:true,force:true});}};
}
test('supervised args isolate fresh read-only roles and contracts preserve official text',{skip:!available},async()=>{
  const c=await loadCloudflareContracts(skillRoot),args=supervisedArgs('/runner',{model:'gpt-6.1-sol',effort:'medium'});
  assert.ok(args.includes('read-only'));assert.ok(args.includes('--ephemeral'));assert.ok(args.includes('features.multi_agent=false'));assert.ok(args.includes('project_doc_max_bytes=0'));
  assert.ok(args.includes('skills.include_instructions=false'));assert.ok(args.some(x=>x.startsWith('developer_instructions=')&&x.includes('externally supervised Cloudflare role')));
  assert.equal(c.recon.length,4);assert.match(c.recon[2].text,/stored or derived copies/);assert.match(c.recon[3].text,/promotion/);
  assert.match(c.method.text,/READ THE CODE AT DEPTH/);assert.match(c.hunterContract.text,/proposed_verdict/);
});
test('supervised recon response schemas are closed role-specific objects using only simple keywords',()=>{
  assert.equal(typeof promptPolicy.reconOutputSchema,'function');for(const [role,count]of [['recon-1a',6],['recon-1b',6],['recon-1c',2],['recon-1d',7]]){const schema=promptPolicy.reconOutputSchema(role);assert.equal(schema.additionalProperties,false);assert.deepEqual(schema.required,['sections']);const section=schema.properties.sections.items;assert.equal(section.additionalProperties,false);assert.equal(section.properties.section.enum.length,count);assert.deepEqual(section.properties.facts.items.required,['file','line','description','text']);assert.equal(section.properties.facts.items.additionalProperties,false);}assert.equal(promptPolicy.reconOutputSchema('hunter'),null);
});
test('supervised recon schema files and argv are retained and tamper checked',{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);const m=await f.json('execution-manifest.json');for(const r of m.roles){if(r.role.startsWith('recon-')){assert.ok(r.outputSchema);assert.equal(r.args[r.args.indexOf('--output-schema')+1],join(f.payload.artifactDir,r.outputSchema.file));assert.deepEqual(await f.json(r.outputSchema.file),promptPolicy.reconOutputSchema(r.role));}else assert.equal(r.args.includes('--output-schema'),false);}const r=m.roles[0],schema=await f.json(r.outputSchema.file);schema.properties.sections.items.properties.section.enum=['foreign'];const bytes=JSON.stringify(schema);await chmod(join(f.payload.artifactDir,r.outputSchema.file),0o600);await writeFile(join(f.payload.artifactDir,r.outputSchema.file),bytes);m.preRedactionHashes[r.outputSchema.file]=sha256(bytes);await writeFile(join(f.payload.artifactDir,'execution-manifest.json'),JSON.stringify(m));await assert.rejects(validateSupervisedCloudflare(f.ctx),/schema|contract|differ/i);}finally{await f.dispose();}
});
test('supervised zero path retains real fresh fixture processes and all seven official outputs',{skip:!available},async()=>{
  const f=await fixture();try{
    assert.equal(await runSupervisedCloudflare(f.payload),0);
    const manifest=await f.json('execution-manifest.json');assert.equal(manifest.strategy,'supervised-codex-workers');assert.equal(manifest.roles.length,7);
    assert.equal(new Set(manifest.roles.map(r=>r.pid)).size,7);assert.equal(new Set(manifest.roles.map(r=>r.threadId)).size,7);
    assert.equal(manifest.roles.filter(r=>r.role.startsWith('recon-')).length,4);
    const result=await validateSupervisedCloudflare(f.ctx);assert.deepEqual(result.findings,[]);assert.equal(result.execution.strategy,'supervised-codex-workers');
    await finalizeSupervisedCloudflare(f.ctx);assert.ok((await f.json('execution-manifest.json')).finalRetainedHashes);
    assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);
  }finally{await f.dispose();}
});
test('supervised real Codex POSIX-quoted shell argv telemetry preserves legitimate bounded readers',{skip:!available},async()=>{
  const f=await fixture('native-command-shape');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);}finally{await f.dispose();}
});
test('supervised native head numeric shorthand retains confined paths and safe count bounds',()=>{
  const expected={context:{target:'/copy',runner:'/runner'},readFiles:['/pinned/SKILL.md'],readCommands:["cat '/pinned/SKILL.md'"]},event=command=>({type:'item.started',item:{type:'command_execution',command}});
  assert.doesNotThrow(()=>assertObservedPolicy(event('/bin/zsh -lc "head -100 \'/copy/package-lock.json\'"'),expected));
  for(const command of ['head -0 /copy/package-lock.json','head -n 100 /copy/package-lock.json','head -c 100 /copy/package-lock.json'])assert.doesNotThrow(()=>assertObservedPolicy(event(command),expected));
  for(const command of ['/bin/zsh -lc "head -100 \'/etc/passwd\'"','head -9007199254740992 /copy/package-lock.json','head -n 9007199254740992 /copy/package-lock.json','tail -c 9007199254740992 /copy/package-lock.json','tail -100 /copy/package-lock.json','head -100c /copy/package-lock.json'])assert.throws(()=>assertObservedPolicy(event(command),expected),/source-only command policy/);
});
test('supervised head shorthand passes streamed and retained native evidence checks',{skip:!available},async()=>{
  const f=await fixture('head-shorthand');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);}finally{await f.dispose();}
});
test('supervised candidate graph preserves unchanged independent verifier decision',{skip:!available},async()=>{
  const f=await fixture('candidate');try{assert.equal(await runSupervisedCloudflare(f.payload),0);const result=await validateSupervisedCloudflare(f.ctx);assert.equal(result.findings.length,1);assert.equal(result.findings[0].severity,'unknown');const m=await f.json('execution-manifest.json');assert.equal(m.roles.at(-1).role,'verifier');assert.equal(m.roles.length,8);assert.equal((await f.json('findings.json'))[0].title,'Independent retained candidate');}finally{await f.dispose();}
});
test('supervised hunter prompt explicitly requires each hardening note to carry its own source citation',{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);const m=await f.json('execution-manifest.json'),hunter=m.roles.find(r=>r.role==='hunter'),prompt=await readFile(join(f.payload.artifactDir,'roles',hunter.agentId,'prompt.txt'),'utf8');assert.ok(prompt.includes('Every hardening string must include its own valid repository-relative file:line citation'));assert.ok(prompt.includes('return hardening:[] when no such note is supported'));}finally{await f.dispose();}
});
test('supervised critic accepts unique canonical source and attack block references and rejects unknown or ambiguous identities',{skip:!available},async()=>{
  const f=await fixture('critic-canonical');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);const m=await f.json('execution-manifest.json'),plan=await f.json('roles/planner-5/response.json'),critic=m.roles.find(r=>r.role==='critic'),response=await f.json(`roles/${critic.agentId}/response.json`),c=await loadCloudflareContracts(skillRoot),ledger=await f.json('coverage-ledger.json');assert.equal(ledger.length,2);assert.equal(ledger.find(u=>u.status==='deferred').surface,response.missing_units[0].surface);for(const mutate of [({reply})=>reply.missing_units[0].surface='missing-source',({reply})=>reply.missing_units[0].surface=reply.missing_units[0].boundary,({reply})=>reply.missing_units[0].attack_class='ATTACK-CLASSES.md#Injection',({reply})=>reply.missing_units[0].attack_class='UNKNOWN.md#Class',({reply})=>reply.missing_units[0].attack_class='Core discipline',({state})=>state.plan.source_objects.push({...state.plan.source_objects[0],label:'Ambiguous source object'})]){const state=preparePlan(plan,c,m.inputs,10),reply=structuredClone(response);mutate({state,reply});assert.throws(()=>applyCritic(state,reply,c,m.inputs),/identity|ground|incomplete|block|coverage/i);}}finally{await f.dispose();}
});
test('supervised compact planner exclusions expand to exactly the same semantic plan',{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);const flat=flatPlan(await f.json('roles/planner-5/response.json')),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot),compact=structuredClone(flat);compact.exclusion_catalog=flat.units[0].excluded_blocks.map((e,i)=>({id:`x${String(i).padStart(3,'0')}`,blocks:[e.block],reason:e.reason}));compact.units[0].excluded_blocks=compact.exclusion_catalog.map(e=>({ref:e.id}));assert.deepEqual(preparePlan(compact,c,m.inputs,10),preparePlan(flat,c,m.inputs,10));for(const mutate of [p=>p.units[0].excluded_blocks[0].ref='missing',p=>p.exclusion_catalog[0].blocks[0]='UNKNOWN.md#Block',p=>p.exclusion_catalog[0].reason='No source citation',p=>p.exclusion_catalog.push(p.exclusion_catalog[0]),p=>p.units[0].excluded_blocks[0].reason='Mixed fields']){const invalid=structuredClone(compact);mutate(invalid);assert.throws(()=>preparePlan(invalid,c,m.inputs,10),/exclusion|ground|reason|contract|block|reference/i);}}finally{await f.dispose();}
});
test('supervised compact native planner runs full graph with unchanged expanded ledger',{skip:!available},async()=>{
  const f=await fixture('compact-planner');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);const ledger=await f.json('coverage-ledger.json');assert.ok(ledger[0].excluded_blocks.every(e=>typeof e.block==='string'&&typeof e.reason==='string'&&!('ref'in e)));}finally{await f.dispose();}
});
test('supervised grouped exclusions retain identical flat semantics and reject per-unit overlaps',{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);const raw=await f.json('roles/planner-5/response.json'),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot),flat=flatPlan(raw),grouped=structuredClone(flat);grouped.exclusion_catalog=[{id:'common',blocks:flat.units[0].excluded_blocks.map(e=>e.block),reason:flat.units[0].excluded_blocks[0].reason}];grouped.units[0].excluded_blocks=[{ref:'common'}];assert.deepEqual(preparePlan(grouped,c,m.inputs,10),preparePlan(flat,c,m.inputs,10));for(const mutate of [p=>p.exclusion_catalog[0].blocks.push(p.exclusion_catalog[0].blocks[0]),p=>p.units[0].excluded_blocks.push({ref:'common'}),p=>p.exclusion_catalog[0].blocks.push('UNKNOWN.md#Block'),p=>p.exclusion_catalog[0].blocks.shift()]){const bad=structuredClone(grouped);mutate(bad);assert.throws(()=>preparePlan(bad,c,m.inputs,10));}}finally{await f.dispose();}
});
test('supervised alternative exclusion groups preserve distinct source reasons for different units',{skip:!available},async()=>{
  const f=await fixture('multi-hunter');try{assert.equal(await runSupervisedCloudflare(f.payload),0);const flat=flatPlan(await f.json('roles/planner-5/response.json')),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot);for(const e of flat.units[1].excluded_blocks)e.reason='Different source exclusion for this unit at target.mjs:1.';const grouped=structuredClone(flat);grouped.exclusion_catalog=flat.units.map((u,i)=>({id:`alternative${i}`,blocks:u.excluded_blocks.map(e=>e.block),reason:u.excluded_blocks[0].reason}));grouped.units.forEach((u,i)=>u.excluded_blocks=[{ref:`alternative${i}`}]);assert.deepEqual(preparePlan(grouped,c,m.inputs,10),preparePlan(flat,c,m.inputs,10));}finally{await f.dispose();}
});
test('supervised planner plain reasons use only valid source evidence on the same object',{skip:!available},async()=>{
  const f=await fixture('structured-reasons');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);const raw=await f.json('roles/planner-5/response.json'),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot);for(const mutate of [p=>p.companion_selection[0].evidence=[],p=>delete p.companion_selection[0].evidence,p=>p.companion_selection[0].evidence[0].line=999,p=>p.units[0].grounding=[],p=>p.units[0].grounding[0].file='missing.mjs',p=>p.assignments[0].evidence=[],p=>p.assignments[0].evidence[0].description='',p=>p.companion_selection[0].reason='',p=>p.units[0].priority_reason='Invalid citation target.mjs:999',p=>p.assignments[0].relation='Invalid citation missing.mjs:1']){const bad=structuredClone(raw);mutate(bad);assert.throws(()=>preparePlan(bad,c,m.inputs,10));}}finally{await f.dispose();}
});
test('supervised canonical source identities survive display-label changes and reject unknown or ambiguous refs',{skip:!available},async()=>{
  const f=await fixture('renamed-labels');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);const raw=await f.json('roles/planner-5/response.json'),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot),ledger=await f.json('coverage-ledger.json');assert.equal(ledger[0].surface,raw.units[0].surface);assert.equal(ledger[0].boundary,raw.units[0].boundary);for(const mutate of [p=>p.units[0].canonical_refs.surface='target.mjs#unknown',p=>p.units[0].canonical_refs.boundary=p.units[0].canonical_refs.surface,p=>p.source_objects.push({...p.source_objects[0],label:'Another display label for duplicate canonical identity'})]){const bad=structuredClone(raw);mutate(bad);assert.throws(()=>preparePlan(bad,c,m.inputs,10),/canonical|ground|source/i);}}finally{await f.dispose();}
});
test('supervised attack class accepts the exact heading or full known canonical block reference',{skip:!available},async()=>{
  const f=await fixture('full-class-reference');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);const raw=await f.json('roles/planner-5/response.json'),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot),ledger=await f.json('coverage-ledger.json');assert.equal(ledger[0].attack_class,raw.units[0].attack_class);const heading=structuredClone(raw);heading.units[0].attack_class=heading.units[0].canonical_refs.attack_class.split('#')[1];assert.ok(preparePlan(heading,c,m.inputs,10).ledger.length);for(const value of ['Access control','UNKNOWN.md#Injection','ATTACK-CLASSES.md#Access control']){const bad=structuredClone(raw);bad.units[0].attack_class=value;assert.throws(()=>preparePlan(bad,c,m.inputs,10),/attack class/i);}}finally{await f.dispose();}
});
test('supervised production rejects flat planner output while normalizer preserves compatibility',{skip:!available},async()=>{
  const f=await fixture('legacy-flat-planner');try{assert.notEqual(await runSupervisedCloudflare(f.payload),0);const raw=await f.json('roles/planner-5/response.json'),m=await f.json('execution-manifest.json'),c=await loadCloudflareContracts(skillRoot);assert.ok(preparePlan(raw,c,m.inputs,10).ledger.length);assert.equal(m.roles.length,5);}finally{await f.dispose();}
});
test('supervised planner gets a bounded ten minutes while other roles stay at five',()=>{
  assert.equal(typeof promptPolicy.supervisedRoleTimeoutMs,'function');assert.equal(promptPolicy.supervisedRoleTimeoutMs('planner'),600000);assert.equal(promptPolicy.supervisedRoleTimeoutMs('hunter'),300000);assert.equal(promptPolicy.SUPERVISED_WALL_TIMEOUT_MS,1800000);
});
function flatPlan(raw){const flat=structuredClone(raw),catalog=new Map((flat.exclusion_catalog??[]).map(e=>[e.id,e]));for(const u of flat.units)u.excluded_blocks=u.excluded_blocks.flatMap(e=>e.ref?(catalog.get(e.ref).blocks??[catalog.get(e.ref).block]).map(block=>({block,reason:catalog.get(e.ref).reason})):e);delete flat.exclusion_catalog;return flat;}
test('supervised parallel hunters reconstruct one immutable wave prompt snapshot',{skip:!available},async()=>{
  const f=await fixture('multi-hunter');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);assert.equal((await f.json('execution-manifest.json')).roles.filter(r=>r.role==='hunter').length,2);}finally{await f.dispose();}
});
test('supervised malformed verifier gets one counted fresh retry without controller repair',{skip:!available},async()=>{
  const f=await fixture('verifier-retry');try{assert.equal(await runSupervisedCloudflare(f.payload),0);const m=await f.json('execution-manifest.json');assert.equal(m.roles.filter(r=>r.role==='verifier').length,2);assert.equal((await validateSupervisedCloudflare(f.ctx)).findings.length,1);}finally{await f.dispose();}
});
for(const [mode,count]of [['budget-overflow',3],['partial-policy',1]])test(`supervised ${mode} preserves only useful independently validated partial findings`,{skip:!available},async()=>{
  const f=await fixture(mode);try{assert.notEqual(await runSupervisedCloudflare(f.payload),0);let failure;try{await validateSupervisedCloudflare({...f.ctx,exitCode:1});}catch(error){failure=error;}assert.ok(failure);assert.equal(failure.findings?.length,count);assert.equal((await f.json('findings.json')).length,count);assert.ok((await f.json('execution-manifest.json')).roles.length<=10);}finally{await f.dispose();}
});
for(const mode of ['foreign-unit','wrong-owner','critic-incomplete','invalid-json','recon-truncated-json','reused-thread','line-overflow','target-write','foreign-read','nested-tool','verifier-policy-failure','native-forbidden-shape'])test(`supervised ${mode} fails closed`,{skip:!available},async()=>{
  const f=await fixture(mode);try{assert.notEqual(await runSupervisedCloudflare(f.payload),0);await assert.rejects(validateSupervisedCloudflare({...f.ctx,exitCode:1}),/incomplete|differ|preservation|invalid|thread|source|prohibited/i);assert.equal((await f.json('execution-manifest.json')).status,'incomplete');}finally{await f.dispose();}
});
test('supervised independently retained record tampering fails even when byte hashes are resealed',{skip:!available},async()=>{
  const f=await fixture('candidate');try{assert.equal(await runSupervisedCloudflare(f.payload),0);const records=await f.json('findings.json');records[0].title='Controller replacement';const bytes=JSON.stringify(records);await writeFile(join(f.payload.artifactDir,'findings.json'),bytes);const m=await f.json('execution-manifest.json');m.preRedactionHashes['findings.json']=sha256(bytes);await writeFile(join(f.payload.artifactDir,'execution-manifest.json'),JSON.stringify(m));await assert.rejects(validateSupervisedCloudflare(f.ctx),/unchanged native decisions/i);}finally{await f.dispose();}
});
test('supervised cancellation through outer process runner kills TERM-resistant owned descendants',{skip:!available},async()=>{
  const f=await fixture('hang');try{const result=await runProcess({command:process.execPath,args:[resolve('src/agents/native-wrapper.mjs'),JSON.stringify(f.payload)]},{timeoutMs:1500,redactOutput:false});assert.equal(result.status,'timed_out');assert.ok(result.durationMs<4000);const events=(await readFile(join(f.payload.artifactDir,'roles/recon-1a-1/events.jsonl'),'utf8')).split('\n').filter(Boolean).map(JSON.parse),pid=Number(events.find(e=>e.item?.text?.startsWith('FAKE_DESCENDANT_PID='))?.item.text.split('=')[1]);assert.ok(pid>0);assert.throws(()=>process.kill(pid,0),/ESRCH/);}finally{await f.dispose();}
});
test('supervised forbidden global-skill command aborts stalled planner before role timeout',{skip:!available},async()=>{
  const f=await fixture('planner-global-skill-stall');try{const result=await runProcess({command:process.execPath,args:[resolve('src/agents/native-wrapper.mjs'),JSON.stringify(f.payload)]},{timeoutMs:1800,redactOutput:false});assert.equal(result.status,'failed');assert.ok(result.durationMs<1600);const m=await f.json('execution-manifest.json');assert.equal(m.roles.length,5);assert.equal(m.roles.at(-1).role,'planner');assert.match(m.reasons.join(';'),/source-only command policy violation/);assert.ok(!m.roles.at(-1).timedOut);}finally{await f.dispose();}
});
test('supervised incremental policy decoder accepts split UTF8 JSONL chunks',{skip:!available},async()=>{
  const f=await fixture('utf8-chunks');try{assert.equal(await runSupervisedCloudflare(f.payload),0);assert.deepEqual((await validateSupervisedCloudflare(f.ctx)).findings,[]);}finally{await f.dispose();}
});
test('supervised strict budget gate launches no native roles',{skip:!available},async()=>{
  const f=await fixture('zero',7);try{assert.notEqual(await runSupervisedCloudflare(f.payload),0);assert.equal((await f.json('execution-manifest.json')).roles.length,0);}finally{await f.dispose();}
});
for(const [name,mutate]of [['source pin',m=>m.instructions[0].sha256='0'.repeat(64)],['prompt rebuild',m=>m.roles[5].promptSha256='0'.repeat(64)],['phase order',m=>m.roles[4].startedAt=m.roles[0].startedAt],['fresh identity',m=>m.roles[4].threadId=m.roles[0].threadId],['skill configuration',m=>{const args=m.roles[0].args;args[args.indexOf('skills.include_instructions=false')]='skills.include_instructions=true';}],['developer role',m=>{const args=m.roles[0].args;args[args.findIndex(x=>x.startsWith('developer_instructions='))]='developer_instructions="Unrelated authority"';}]])test(`supervised manifest ${name} tampering is rejected`,{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);const m=await f.json('execution-manifest.json');mutate(m);await writeFile(join(f.payload.artifactDir,'execution-manifest.json'),JSON.stringify(m));await assert.rejects(validateSupervisedCloudflare(f.ctx),/differ|order|thread|identity/i);}finally{await f.dispose();}
});
for(const file of ['roles/recon-1a-1/prompt.txt','roles/recon-1a-1/events.jsonl','coverage-ledger.json','findings.json'])test(`supervised verification rejects retained tamper: ${file}`,{skip:!available},async()=>{
  const f=await fixture();try{assert.equal(await runSupervisedCloudflare(f.payload),0);await writeFile(join(f.payload.artifactDir,file),'tampered');await assert.rejects(validateSupervisedCloudflare(f.ctx),/hash|JSON|evidence|invalid/i);}finally{await f.dispose();}
});
