import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm,chmod,lstat,symlink,unlink,link,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {nativeRoleContracts,nativeRoleForTask,createNativeRoleConfiguration,validateNativeRoleConfiguration,nativeRoleArgs} from '../src/agents/native-roles.mjs';
const context={copyTarget:'/immutable/target',skillRoot:'/official'};
test('host roles have fixed complete instructions and exact task-to-role mapping',()=>{
 const roles=nativeRoleContracts(context);assert.equal(Object.keys(roles).length,7);
 for(const role of Object.values(roles)){assert.match(role.instructions,/Never execute target code/);assert.match(role.instructions,/Never delegate/);assert.match(role.instructions,/SEC_HUB_ROLE=/);assert.equal(role.sha256.length,64);}
 for(const task of ['recon_architecture','recon_boundaries','recon_execution','recon_companions','hunter_1','critic_final','verifier_1','verifier_final'])assert.ok(roles[nativeRoleForTask(task).agentType]);
 for(const task of ['recon_architecture_extra','hunter_0','verifier','../hunter_1','root'])assert.throws(()=>nativeRoleForTask(task),/role task/);
 assert.match(roles.sec_hub_verifier.instructions,/exactly one JSON object/);
});
test('role files are host-authored single-field TOML, sealed and independently checked',async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-role-config-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const cfg=await createNativeRoleConfiguration(root,context);await validateNativeRoleConfiguration(cfg,context);
 assert.equal(cfg.files.length,7);assert.equal(nativeRoleArgs(root).length,28);
 const bytes=await readFile(join(root,'sec_hub_verifier.toml'),'utf8');assert.match(bytes,/^developer_instructions = "/);assert.equal(bytes.split('\n').length,2);
 await chmod(join(root,'sec_hub_verifier.toml'),0o600);await writeFile(join(root,'sec_hub_verifier.toml'),bytes+'model = "forged"\n');await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);
});

test('role evidence is context bound and replay never reads removed files',async t=>{
 const root=await mkdtemp(join(tmpdir(),'native-role-replay-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const cfg=await createNativeRoleConfiguration(root,context);
 assert.equal((await lstat(cfg.root)).mode&0o7777,0o700);
 for(const f of cfg.files)assert.equal((await lstat(join(cfg.root,f.path))).mode&0o7777,0o400);
 await rm(root,{recursive:true});
 assert.equal(await validateNativeRoleConfiguration(cfg,context,{readFiles:false}),true);
 await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);
 await assert.rejects(validateNativeRoleConfiguration(cfg,{...context,copyTarget:'/other'},{readFiles:false}),/role configuration/);
 await assert.rejects(validateNativeRoleConfiguration({...cfg,files:cfg.files.slice().reverse()},context,{readFiles:false}),/role configuration/);
 const changed=structuredClone(cfg);changed.files[0].instructionsSha256='0'.repeat(64);
 await assert.rejects(validateNativeRoleConfiguration(changed,context,{readFiles:false}),/role configuration/);
 const extra=structuredClone(cfg);extra.files[0].model='forged';
 await assert.rejects(validateNativeRoleConfiguration(extra,context,{readFiles:false}),/role configuration/);
});
test('single-field TOML safely round-trips unusual paths and CLI config strings',async t=>{
 const parent=await mkdtemp(join(tmpdir(),'native-role-quote-'));t.after(()=>rm(parent,{recursive:true,force:true}));
 const root=join(parent,'a"b\\c');await mkdir(root);
 const quoted={copyTarget:'/target/a"b\\c',skillRoot:'/official/a"b\\c'};
 const roles=nativeRoleContracts(quoted),cfg=await createNativeRoleConfiguration(root,quoted);
 for(const f of cfg.files){const bytes=await readFile(join(cfg.root,f.path),'utf8');assert.equal(bytes.split('\n').length,2);assert.equal(JSON.parse(bytes.slice('developer_instructions = '.length)),roles[f.agentType].instructions);}
 const args=nativeRoleArgs(cfg.root);assert.equal(args.length,28);
 for(let i=0;i<args.length;i+=4){assert.equal(args[i],'-c');assert.equal(args[i+2],'-c');assert.ok(JSON.parse(args[i+1].slice(args[i+1].indexOf('=')+1)));assert.ok(JSON.parse(args[i+3].slice(args[i+3].indexOf('=')+1)).startsWith(cfg.root));}
 for(const copyTarget of ['relative','/bad\nSEC_HUB_ROLE=root','/bad\u0000', '/bad\ud800'])assert.throws(()=>nativeRoleContracts({...context,copyTarget}),/role configuration/);
 for(const task of ['hunter_1\n','verifier_final\n','recon_architecture\n','hunter_01','verifier_01','recon_companions_extra','critic_final_extra',null,{},1])assert.throws(()=>nativeRoleForTask(task),/role task/);
 assert.deepEqual(nativeRoleForTask('hunter_999'),{agentType:'sec_hub_hunter',role:'hunter-999'});
 assert.deepEqual(nativeRoleForTask('verifier_final'),{agentType:'sec_hub_verifier',role:'verifier-final'});
});
test('configuration refuses symlinks, hard links, extra files and relaxed modes',async t=>{
 const parent=await mkdtemp(join(tmpdir(),'native-role-safe-'));t.after(()=>rm(parent,{recursive:true,force:true}));
 const root=join(parent,'roles');const cfg=await createNativeRoleConfiguration(root,context);
 const first=join(cfg.root,cfg.files[0].path),bytes=await readFile(first);
 await chmod(first,0o600);await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);await chmod(first,0o400);
 await chmod(root,0o750);await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);await chmod(root,0o700);
 await writeFile(join(root,'extra.toml'),'');await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);await unlink(join(root,'extra.toml'));
 await link(first,join(parent,'hard'));await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);await unlink(join(parent,'hard'));
 await unlink(first);await writeFile(join(parent,'outside'),bytes,{mode:0o400});await symlink(join(parent,'outside'),first);await assert.rejects(validateNativeRoleConfiguration(cfg,context),/role configuration/);
 await assert.rejects(createNativeRoleConfiguration(root,context),/role configuration/);
 await symlink(root,join(parent,'alias'));await assert.rejects(createNativeRoleConfiguration(join(parent,'alias'),context),/role configuration/);
 await unlink(first);await writeFile(first,bytes,{mode:0o400});await validateNativeRoleConfiguration(cfg,context);
});

test('fixed recon roles preserve official reconnaissance responsibilities and permit static command transport',()=>{
 const roles=nativeRoleContracts(context),architecture=roles.sec_hub_recon_architecture,visibility=roles.sec_hub_recon_companions;
 assert.deepEqual(nativeRoleForTask('recon_companions'),{agentType:'sec_hub_recon_companions',role:'recon-companions'});
 assert.match(architecture.instructions,/Agent 1a: Product, stack, and local operation/);
 assert.match(visibility.description,/execution.*deployment visibility/i);
 assert.match(visibility.instructions,/Agent 1d: Local execution and deployment visibility/);
 assert.match(visibility.instructions,/tests, build definitions, manifests, packaging/);
 assert.match(visibility.instructions,/parent.*companion selection/);
 assert.match(visibility.instructions,/selection belongs to the parent/);
 assert.doesNotMatch(visibility.instructions,/Agent 1d: relevant companion disciplines/);
 for(const role of Object.values(roles)){
  assert.match(role.instructions,/sandboxed native exec_command/);
  assert.match(role.instructions,/one standalone static read command/);
  assert.match(role.instructions,/Never run target interpreters, tests, builds or validators/);
  assert.doesNotMatch(role.instructions,/substitutions, executors/);
 }
});

test('each phase distinguishes configured agent type, assignment task name and audit role token',()=>{
 const roles=nativeRoleContracts(context);
 for(const task of ['recon_architecture','recon_boundaries','recon_execution','recon_companions','hunter_1','critic_final','verifier_1','verifier_final']){
  const {agentType,role}=nativeRoleForTask(task),body=roles[agentType].instructions;
  assert.ok(body.includes(`agent_type="${agentType}"; task_name="${task}"; SEC_HUB_ROLE=${role}`),task);
  assert.match(body,/agent_type selects the host-pinned configuration/);
  assert.match(body,/task_name identifies the individual assignment and phase/);
  assert.match(body,/SEC_HUB_ROLE is the audit role label/);
  assert.match(body,/These three values intentionally differ and are compatible/);
  assert.match(body,/Do not compare these fields for string equality/);
  assert.match(body,/Do not reject a valid assignment/);
  assert.doesNotMatch(body,/initial task_name and role token must exactly match this fixed role/);
 }
 assert.match(roles.sec_hub_hunter.instructions,/task_name="hunter_N"; SEC_HUB_ROLE=hunter-N/);
 assert.match(roles.sec_hub_verifier.instructions,/task_name="verifier_N"; SEC_HUB_ROLE=verifier-N/);
});
