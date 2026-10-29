import test from 'node:test';
import assert from 'node:assert/strict';
import {claudeArgs} from '../src/agents/invocation.mjs';
import {inspectNativeEvents} from '../src/agents/validation.mjs';
const options={skillRoot:'/pinned',model:'fixture'};
const events=(skill='sec-hub-anthropic:vuln-scan',args='/stage/target --single --no-score',is_error=false)=>[
  {type:'assistant',message:{content:[{type:'tool_use',name:'Skill',id:'activate',input:{skill,args}}]}},
  {type:'user',message:{content:[{type:'tool_result',tool_use_id:'activate',is_error,content:'loaded'}]}},
  {type:'result',subtype:'success',is_error:false,permission_denials:[]}
];
// Removing the explicit registration or permitting ambient plugin writes breaks this boundary.
test('new Anthropic invocation supplies only the derived plugin and denies its writes',()=>{
  const args=claudeArgs('/stage/target',options,{artifactDir:'/raw'},[]);
  assert.equal(args.filter(x=>x==='--plugin-dir').length,1);
  assert.equal(args[args.indexOf('--plugin-dir')+1],'/stage/runner/anthropic-plugin');
  assert.ok(args.includes('--restricted'));
  assert.match(args[1],/Skill tool named sec-hub-anthropic:vuln-scan/);
  assert.match(args[args.indexOf('--allowedTools')+1],/^Skill\(sec-hub-anthropic:vuln-scan\),/);
  const settings=JSON.parse(args[args.indexOf('--settings')+1]);
  assert.ok(settings.permissions.deny.includes('Write(//stage/runner/anthropic-plugin/**)'));
  assert.equal(settings.disableAllHooks,true);
  assert.deepEqual(JSON.parse(args[args.indexOf('--mcp-config')+1]),{mcpServers:{}});
});
// Accepting bare or unrelated names as registered would turn an imitation into proof.
test('v2 activation requires the exact registered namespace and successful static target invocation',()=>{
  const opts={invocationPolicyVersion:2,registrationValidated:true,copyTarget:'/stage/target'};
  assert.equal(inspectNativeEvents('anthropic',events(),opts).complete,true);
  assert.equal(inspectNativeEvents('anthropic',events(),{...opts,registrationValidated:false}).complete,false);
  for(const skill of ['vuln-scan','/vuln-scan','other:vuln-scan','sec-hub-anthropic:other'])assert.equal(inspectNativeEvents('anthropic',events(skill),opts).complete,false,skill);
  for(const args of ['/other --single --no-score','/stage/target --single','/stage/target --no-score','/stage/target --single --no-score --extra /ambient'])assert.equal(inspectNativeEvents('anthropic',events(undefined,args),opts).complete,false,args);
  assert.equal(inspectNativeEvents('anthropic',events(undefined,undefined,true),opts).complete,false);
  const forged=events();forged[1].type='assistant';assert.equal(inspectNativeEvents('anthropic',forged,opts).complete,false);
  const outOfOrder=events();[outOfOrder[0],outOfOrder[1]]=[outOfOrder[1],outOfOrder[0]];assert.equal(inspectNativeEvents('anthropic',outOfOrder,opts).complete,false);
  const conflicting=events();conflicting.splice(2,0,{type:'user',message:{content:[{type:'tool_result',tool_use_id:'activate',is_error:true,content:'Unknown skill'}]}});assert.equal(inspectNativeEvents('anthropic',conflicting,opts).complete,false);
  assert.equal(inspectNativeEvents('anthropic',events(),{...opts,invocationPolicyVersion:3}).complete,false);
});
test('legacy activation keeps its original bare-name contract only',()=>{
  assert.equal(inspectNativeEvents('anthropic',events('vuln-scan'),{copyTarget:'/stage/target'}).complete,true);
  assert.equal(inspectNativeEvents('anthropic',events(),{copyTarget:'/stage/target'}).complete,false);
});

import {mkdtemp,mkdir,readFile,writeFile,rm,cp,chmod,symlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const sourcePath='.claude/skills/vuln-scan/SKILL.md',sourceHash='49e44d80ef199e695cae11801bb4f38d5efc15bcd7e5b5522116c977c77e2405';
const instruction=[{path:sourcePath,sha256:sourceHash}];
const fixture=fileURLToPath(new URL('./fixtures/anthropic-registration/SKILL.md',import.meta.url));
async function child(args,env=process.env){const proc=spawn(process.execPath,args,{env,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';proc.stdout.on('data',x=>stdout+=x);proc.stderr.on('data',x=>stderr+=x);const code=await new Promise((yes,no)=>{proc.once('error',no);proc.once('close',yes)});return {code,stdout,stderr};}
async function setup(t){
  const root=await mkdtemp(join(tmpdir(),'anthropic-registration-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
  for(const dir of ['target','work','raw','skill'])await mkdir(join(root,dir));
  await mkdir(join(root,'skill/.claude/skills/vuln-scan'),{recursive:true});await cp(fixture,join(root,'skill',sourcePath));await writeFile(join(root,'target/source.txt'),'untrusted source only\n');
  return root;
}
// Failing to register before spawn means the real executable sees no skill.
test('actual wrapper registers pinned bytes before a fake native CLI and retains sealed host proof',async t=>{
  const root=await setup(t),loader=join(root,'loader.mjs'),fake=join(root,'fake.mjs'),capture=join(root,'capture.json');
  const validationUrl=new URL('../src/agents/validation.mjs',import.meta.url).href;
  // Only the external Git-pin verification boundary is substituted. All native
  // invocation, registration, event, preservation, and retained-byte checks run.
  await writeFile(loader,`import {readFile} from 'node:fs/promises';export async function load(url,context,next){if(url===${JSON.stringify(validationUrl)}){let source=await readFile(new URL(url),'utf8');const start=source.indexOf('export async function verifySourcePin('),end=source.indexOf('export async function runOfficialValidators(',start);source=source.slice(0,start)+'export async function verifySourcePin(){return ${JSON.stringify(instruction)}}\\n'+source.slice(end);return {format:'module',source,shortCircuit:true}}return next(url,context)}`);
  await writeFile(fake,`import {readFile,writeFile,readdir,lstat} from 'node:fs/promises';import {join} from 'node:path';import {createHash} from 'node:crypto';if(process.argv.includes('--version')){console.log('fake-native 1');process.exit(0)}const args=process.argv.slice(3),plugin=args[args.indexOf('--plugin-dir')+1],settings=JSON.parse(args[args.indexOf('--settings')+1]),target=args[args.indexOf('--add-dir')+1];let files=[];if(args.includes('--plugin-dir')){async function walk(path=''){for(const e of await readdir(join(plugin,path),{withFileTypes:true})){const p=path?path+'/'+e.name:e.name;if(e.isDirectory())await walk(p);else {const b=await readFile(join(plugin,p));files.push({path:p,sha256:createHash('sha256').update(b).digest('hex'),mode:(await lstat(join(plugin,p))).mode&511})}}}await walk()}await writeFile(process.argv[2],JSON.stringify({args,plugin,files,settings,user:process.env.USER,keys:Object.keys(process.env)}));await writeFile(join(target,'VULN-FINDINGS.json'),JSON.stringify({target,scanned_at:'2026-10-29T00:00:00Z',focus_areas:['static'],findings:[],summary:{total:0,high:0,medium:0,low:0,low_confidence:0}}));await writeFile(join(target,'VULN-FINDINGS.md'),'Static review complete');for(const e of [{type:'assistant',message:{content:[{type:'tool_use',name:'Skill',id:'s1',input:{skill:'sec-hub-anthropic:vuln-scan',args:JSON.stringify(target)+' --single --no-score'}}]}},{type:'user',message:{content:[{type:'tool_result',tool_use_id:'s1',content:'loaded'}]}},{type:'result',subtype:'success',is_error:false,permission_denials:[]}])console.log(JSON.stringify(e));`);
  const cfg={id:'anthropic',command:process.execPath,args:[fake,capture],target:join(root,'target'),artifactDir:join(root,'raw'),agentOptions:{skillRoot:join(root,'skill'),workRoot:join(root,'work'),revision:'d3bea6b5793b5f3d59a75ebe69a58efa88383145',model:'fixture'}};
  const result=await child(['--experimental-loader',loader,fileURLToPath(new URL('../src/agents/native-wrapper.mjs',import.meta.url)),JSON.stringify(cfg)],{...process.env,USER:'fixture-user',ANTHROPIC_API_KEY:'synthetic-secret'});
  const manifest=JSON.parse(await readFile(join(root,'raw/execution-manifest.json'),'utf8').catch(error=>{throw new Error(JSON.stringify(result),{cause:error})}));
  assert.equal(manifest.invocationPolicyVersion,2,JSON.stringify({result,reasons:manifest.reasons}));
  assert.equal(result.code,0,`${result.stderr} ${JSON.stringify(manifest.reasons)}`);
  assert.equal(manifest.status,'complete');
  const captured=JSON.parse(await readFile(capture,'utf8'));
  assert.deepEqual(captured.files.map(x=>x.path).sort(),['.claude-plugin/plugin.json','skills/vuln-scan/SKILL.md']);
  assert.equal(captured.files.find(x=>x.path.endsWith('SKILL.md')).sha256,sourceHash);
  assert.ok(captured.files.every(x=>x.mode===0o400));assert.equal(captured.user,'fixture-user');assert.equal(captured.keys.includes('ANTHROPIC_API_KEY'),false);
  for(const file of ['skill-registration/plugin.json','skill-registration/SKILL.md'])assert.equal(manifest.preRedactionHashes[file],digest(await readFile(join(root,'raw',file))));
  assert.deepEqual(manifest.skillRegistration.initialFiles,manifest.skillRegistration.finalFiles);
  assert.deepEqual(await readFile(join(root,'raw/skill-registration/SKILL.md')),await readFile(fixture));
  await assert.rejects(readFile(join(captured.plugin,'skills/vuln-scan/SKILL.md')),/ENOENT/);
  // Run the real complete validator + redaction finalization with the same one
  // substituted external pin boundary. Mutations must fail even after resealing.
  const check=join(root,'check.mjs');
  await writeFile(check,`import {readFile,writeFile} from 'node:fs/promises';import {createHash} from 'node:crypto';import {join} from 'node:path';import {validateNativeExecution,finalizeNativeExecution} from ${JSON.stringify(validationUrl)};const cfg=${JSON.stringify(cfg)},ctx={target:cfg.target,artifactDir:cfg.artifactDir,exitCode:0,config:{tools:{anthropic:{command:cfg.command,args:cfg.args,agentOptions:cfg.agentOptions}}}};await validateNativeExecution('anthropic',ctx);await finalizeNativeExecution('anthropic',ctx);console.log('sealed');`);
  const checked=await child(['--experimental-loader',loader,check]);assert.equal(checked.code,0,checked.stderr);assert.equal(checked.stdout.trim(),'sealed');
  const sealed=JSON.parse(await readFile(join(root,'raw/execution-manifest.json'),'utf8'));
  for(const file of ['skill-registration/plugin.json','skill-registration/SKILL.md'])assert.equal(sealed.finalRetainedHashes[file],digest(await readFile(join(root,'raw',file))));
  const mutations=[
    m=>delete m.skillRegistration,
    m=>{m.invocationPolicyVersion=3},
    m=>{delete m.invocationPolicyVersion},
    m=>{m.invocationPolicyVersion=1},
    m=>{m.skillRegistration.pluginRoot+='/other'},
    m=>{m.skillRegistration.skillName='other:vuln-scan'},
    m=>{m.skillRegistration.sourceSkillSha256='a'.repeat(64)},
    m=>{m.skillRegistration.files.push({path:'hooks/hooks.json',sha256:'a'.repeat(64)})},
    m=>{m.skillRegistration.extra='forged'},
    m=>{m.skillRegistration.finalFiles=[]},
    m=>{m.invocation.args[m.invocation.args.indexOf('--plugin-dir')+1]+='/other'},
    m=>{m.invocation.args.push('--plugin-dir','/ambient')},
    m=>{m.finalRetainedHashes['skill-registration/SKILL.md']='a'.repeat(64)}
  ];
  await writeFile(check,`import {validateNativeExecution} from ${JSON.stringify(validationUrl)};const cfg=${JSON.stringify(cfg)};await validateNativeExecution('anthropic',{target:cfg.target,artifactDir:cfg.artifactDir,exitCode:0,config:{tools:{anthropic:{command:cfg.command,args:cfg.args,agentOptions:cfg.agentOptions}}}});`);
  for(const mutate of mutations){const value=structuredClone(sealed);mutate(value);await writeFile(join(root,'raw/execution-manifest.json'),JSON.stringify(value));const rejected=await child(['--experimental-loader',loader,check]);assert.notEqual(rejected.code,0,mutate.toString());}
  await writeFile(join(root,'raw/execution-manifest.json'),JSON.stringify(sealed));
  await chmod(join(root,'raw/skill-registration/plugin.json'),0o600);await writeFile(join(root,'raw/skill-registration/plugin.json'),JSON.stringify({name:'sec-hub-anthropic',hooks:{}}));
  const forged=structuredClone(sealed);forged.finalRetainedHashes['skill-registration/plugin.json']=digest(await readFile(join(root,'raw/skill-registration/plugin.json')));await writeFile(join(root,'raw/execution-manifest.json'),JSON.stringify(forged));assert.notEqual((await child(['--experimental-loader',loader,check])).code,0);
});

import {createAnthropicRegistration,verifyStagedRegistration,validateAnthropicRegistration,anthropicPolicyVersion} from '../src/agents/anthropic-registration.mjs';
// A changed source or any unlisted plugin member must never reach native spawn.
test('registration rejects changed source, additional files/directories, symlinks, and forged retained bytes',async t=>{
  for(const mutation of ['extra-file','.git','hooks','symlink','modified-skill','manifest-capability','missing-skill']){
    await t.test(mutation,async t=>{
      const root=await setup(t),copy=join(root,'stage/target'),runner=join(root,'stage/runner');await mkdir(runner,{recursive:true});
      const receipt=await createAnthropicRegistration(copy,join(root,'skill'),instruction,join(root,'raw'));
      receipt.finalFiles=await verifyStagedRegistration(copy);
      assert.equal(await validateAnthropicRegistration(receipt,copy,join(root,'skill'),instruction,join(root,'raw')),true);
      const plugin=join(runner,'anthropic-plugin'),skill=join(plugin,'skills/vuln-scan/SKILL.md');
      if(mutation==='extra-file')await writeFile(join(plugin,'extra.txt'),'ignored?');
      if(mutation==='.git'||mutation==='hooks')await mkdir(join(plugin,mutation));
      if(mutation==='symlink'){await rm(skill);await symlink(fixture,skill);}
      if(mutation==='modified-skill'){await chmod(skill,0o600);await writeFile(skill,'imitation');await chmod(skill,0o400);}
      if(mutation==='manifest-capability'){const file=join(plugin,'.claude-plugin/plugin.json');await chmod(file,0o600);await writeFile(file,JSON.stringify({name:'sec-hub-anthropic',mcpServers:{}}));await chmod(file,0o400);}
      if(mutation==='missing-skill')await rm(skill);
      await assert.rejects(verifyStagedRegistration(copy),/registration|ENOENT/i);
    });
  }
  const root=await setup(t),copy=join(root,'stage/target');await mkdir(join(root,'stage/runner'),{recursive:true});
  await writeFile(join(root,'skill',sourcePath),'modified official instruction');
  await assert.rejects(createAnthropicRegistration(copy,join(root,'skill'),instruction,join(root,'raw')),/source differs/);
});

// Stripping v2's version/receipt cannot reinterpret its sealed bytes as v1.
test('legacy policy rejects mixed registration structures instead of downgrading',()=>{
  assert.equal(anthropicPolicyVersion({}),1);
  for(const value of [{invocationPolicyVersion:1},{invocationPolicyVersion:3},{skillRegistration:{}},{preRedactionHashes:{'skill-registration/SKILL.md':sourceHash}},{finalRetainedHashes:{'skill-registration/plugin.json':sourceHash}}])assert.throws(()=>anthropicPolicyVersion(value),/policy|Legacy/);
});
