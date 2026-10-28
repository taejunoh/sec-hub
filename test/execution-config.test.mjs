import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, symlink, rename, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
const module = await import('../src/dashboard/execution-config.mjs').catch(() => ({}));

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'sec-hub-execution-config-'));
  t.after(() => rm(root,{recursive:true,force:true}));
  const target=join(root,'target'), runsRoot=join(root,'runs'), config=join(root,'scanner.json'), filename=join(root,'execution.json');
  await mkdir(target); await mkdir(runsRoot); await writeFile(config,JSON.stringify({tools:{osv:{command:process.execPath,args:['private-secret']}}}));
  const manifest={schemaVersion:1,targets:[{label:'Local project',path:target,config,tools:['osv'],ai:false}]};
  const save=()=>writeFile(filename,JSON.stringify(manifest)); await save();
  return {root,target,runsRoot,config,filename,manifest,save};
}
test('execution configuration freezes approved scanner scope and exposes opaque target identifiers',async t=>{
  assert.equal(typeof module.loadExecutionConfig,'function');
  const f=await fixture(t), config=await module.loadExecutionConfig(f);
  assert.match(config.targets[0].id,/^[a-f0-9-]{36}$/);
  assert.ok(Object.isFrozen(config.targets[0].config.tools.osv.args));
  await writeFile(f.config,JSON.stringify({tools:{osv:{command:'replaced'}}}));
  assert.equal(config.targets[0].config.tools.osv.command,process.execPath);
  await module.recheckExecutionPaths(config,config.targets[0]);
  await rename(f.target,join(f.root,'old'));await mkdir(f.target);
  await assert.rejects(module.recheckExecutionPaths(config,config.targets[0]));
});
for(const [name,change] of [
  ['unknown manifest field',f=>f.manifest.command='evil'],
  ['unknown target field',f=>f.manifest.targets[0].env={}],
  ['empty tool selection',f=>f.manifest.targets[0].tools=[]],
  ['duplicate tools',f=>f.manifest.targets[0].tools=['osv','osv']],
  ['unknown tool',f=>f.manifest.targets[0].tools=['not-registered']],
  ['deferred Anthropic',f=>{f.manifest.targets[0].tools=['anthropic'];f.manifest.targets[0].ai=true;}],
  ['AI without operator consent',f=>f.manifest.targets[0].tools=['codex-security']],
  ['too many jobs',f=>f.manifest.maxJobs=21],
  ['too long deadline',f=>f.manifest.maxJobTimeMs=900001],
  ['relative target',f=>f.manifest.targets[0].path='relative'],
  ['credential URL',f=>f.manifest.targets[0].url='https://secret:secret@example.test'],
  ['outputs inside target',f=>f.runsRoot=join(f.target,'runs')],
])test(`execution configuration rejects ${name}`,async t=>{assert.equal(typeof module.loadExecutionConfig,'function');const f=await fixture(t);change(f);await f.save();await assert.rejects(module.loadExecutionConfig(f));});
test('execution configuration rejects symlink manifest, scanner config, target and unsafe ancestors',async t=>{
  assert.equal(typeof module.loadExecutionConfig,'function');
  for(const key of ['filename','config','target']){
    const f=await fixture(t), link=join(f.root,`link-${key}`);await symlink(f[key],link);
    if(key==='filename')f.filename=link;else f.manifest.targets[0][key==='config'?'config':'path']=link;
    await f.save();await assert.rejects(module.loadExecutionConfig(f));
  }
  const f=await fixture(t);await chmod(f.target,0o777);await assert.rejects(module.loadExecutionConfig(f));
});
test('execution configuration enforces file byte cap before loading scanner config',async t=>{
  assert.equal(typeof module.loadExecutionConfig,'function');const f=await fixture(t);
  await writeFile(f.config,' '.repeat(256*1024+1));await assert.rejects(module.loadExecutionConfig(f));
});
