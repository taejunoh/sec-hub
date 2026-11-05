import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {codexArgs} from '../src/agents/invocation.mjs';
import {supervisedArgs} from '../src/agents/cloudflare-prompts.mjs';
import {replaySandboxInvocationPolicy,restrictedProfileArgs,sandboxCommandArgs,assertSandboxBackend,validateSandboxProbe} from '../src/agents/codex-sandbox.mjs';
const options={model:'fixture',skillRoot:'/pinned',effort:'medium'},hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
test('unversioned replay preserves exact frozen legacy argv independently of prompts',()=>{
 assert.equal(replaySandboxInvocationPolicy({}),1);
 assert.equal(hash(codexArgs('/runner',options,'/runtime/bin/node',1)),'b9fa56b1fd4f36a6d7067b8761d3cec7fe28fe209c056753b77ffd176566f5a6');
 assert.equal(hash(supervisedArgs('/runner',options,'/runtime/bin/node','/schema.json',1)),'4aaa88469f178612759b0966c2ecdbbd6cc82c52f9347e1391a8e9f3daacc0d2');
 for(const version of [undefined,null,0,3,'1','2',{},true])assert.throws(()=>replaySandboxInvocationPolicy({sandboxInvocationPolicyVersion:version}),/Unsupported/);
 for(const version of [1,2])assert.equal(replaySandboxInvocationPolicy({sandboxInvocationPolicyVersion:version}),version);
 for(const build of [()=>codexArgs('/runner',options,'/runtime/bin/node',3),()=>supervisedArgs('/runner',options,'/runtime/bin/node',null,3)])assert.throws(build,/Unsupported/);
});
test('both strategies default to restricted profiles with exact role documents and schema',()=>{
 const native=codexArgs('/stage/runner',options,'/runtime/bin/node');
 const role=supervisedArgs('/stage/runner',options,'/runtime/bin/node','/raw/role/schema.json',2,['/pinned/skills/security-audit/SKILL.md']);
 for(const args of [native,role]){
  assert.ok(!args.includes('--sandbox'));assert.ok(args.includes('--ignore-user-config'));assert.ok(args.includes('--strict-config'));
  assert.ok(args.includes('default_permissions="sec_hub_v2"'));
  const cfg=args.find(s=>s.startsWith('permissions='));
  assert.ok(cfg.includes('":minimal"="read"'));assert.ok(cfg.includes('"/stage/target"="read"'));assert.ok(cfg.includes('"/runtime/bin/node"="read"'));assert.ok(cfg.includes('network={enabled=false}'));
  assert.ok(!cfg.includes('"/runtime/bin"'));assert.ok(!cfg.includes('.codex'));assert.ok(!cfg.includes('.ssh'));
  assert.deepEqual(sandboxCommandArgs(args,['/bin/cat','/stage/target/file']).slice(-3),['--','/bin/cat','/stage/target/file']);
 }
 assert.ok(native.find(s=>s.startsWith('permissions=')).includes('"/stage/runner"="write"'));
 const cfg=role.find(s=>s.startsWith('permissions='));assert.ok(cfg.includes('"/raw/role/schema.json"="read"'));assert.ok(cfg.includes('"/pinned/skills/security-audit/SKILL.md"="read"'));assert.ok(!cfg.includes('"/pinned/skills/security-audit"='));assert.ok(!cfg.includes('"/stage/runner"='));assert.ok(!cfg.includes('"/raw"='));
 assert.throws(()=>supervisedArgs('/stage/runner',options),/exact role documents/);
});
test('permission patterns, config injection, profile names and unsupported hosts fail closed',()=>{
 for(const path of ['/','relative','/x\npermissions.bad','/x*','/x?','/x[0]','/x{a}','/x\\y'])assert.throws(()=>restrictedProfileArgs({readPaths:[path]}),/path|root/);
 for(const profile of ['proof.foo','proof=x','proof\n','proof"','proof;bad',':workspace'])assert.throws(()=>restrictedProfileArgs({readPaths:['/safe'],profile}),/profile name/);
 const args=restrictedProfileArgs({readPaths:['/safe/"quoted"=deny','/safe/$literal;`name`']});assert.ok(args[1].includes('\\"quoted\\"'));
 for(const version of ['codex-cli 0.154.0','codex-cli 0.165.0','unrecognized',''])assert.throws(()=>assertSandboxBackend(version,'darwin'),/refusing legacy fallback/);
 assert.throws(()=>assertSandboxBackend('codex-cli 0.164.0','linux'),/macOS/);
 assert.doesNotThrow(()=>assertSandboxBackend('codex-cli 0.164.0','darwin'));
 assert.throws(()=>validateSandboxProbe(undefined,true,'codex-cli 0.164.0'));
 assert.throws(()=>validateSandboxProbe({platform:'darwin'},true,'codex-cli 0.164.0'),/preflight/);
});
