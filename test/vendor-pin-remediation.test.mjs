import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,chmod,symlink,access} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {join,resolve} from 'node:path';
import {PINS,verifySourcePin,runOfficialValidators,sha256} from '../src/agents/validation.mjs';
const execute=promisify(execFile),scratch=resolve('../../work');
async function fixture(t){
  const root=await mkdtemp(join(scratch,'vendor-pin-test-')),skill=join(root,'skills/security-audit');
  await mkdir(skill,{recursive:true});
  const marker=join(root,'.git','validator-ran'),source=`require('node:fs').writeFileSync(${JSON.stringify(marker)},'ran');\n`;
  await writeFile(join(skill,'SKILL.md'),'Pinned instructions\n');
  for(const file of ['validate-findings.cjs','validate-coverage-ledger.cjs'])await writeFile(join(skill,file),source);
  const git=async(...args)=>(await execute('git',['-C',root,...args],{env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'}})).stdout.trim();
  await git('init','-q');await git('config','user.name','Pin Test');await git('config','user.email','pin-test@example.invalid');await git('add','.');await git('commit','-qm','fixture');
  const pin=await git('rev-parse','HEAD'),old=PINS.cloudflare;PINS.cloudflare=pin;
  t.after(async()=>{PINS.cloudflare=old;await rm(root,{recursive:true,force:true});});
  return {root,skill,marker,source,git,options:{skillRoot:root,revision:pin}};
}
test('pinned tracked bytes retain the historical instruction evidence shape',async t=>{
  const f=await fixture(t),proof=await verifySourcePin('cloudflare',f.options);
  assert.deepEqual(proof,[{path:'skills/security-audit/SKILL.md',sha256:sha256('Pinned instructions\n')},{path:'skills/security-audit/validate-coverage-ledger.cjs',sha256:sha256(f.source)},{path:'skills/security-audit/validate-findings.cjs',sha256:sha256(f.source)}]);
});
for(const flag of ['--assume-unchanged','--skip-worktree'])test(`hidden edit under ${flag} is refused before validators execute`,async t=>{
  const f=await fixture(t),file='skills/security-audit/validate-findings.cjs';await f.git('update-index',flag,file);await writeFile(join(f.root,file),`${f.source}// hidden edit\n`);
  assert.equal(await f.git('status','--porcelain'),'');
  await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|source|match/i);
  await assert.rejects(runOfficialValidators(f.options,f.root),/pin|source|match/i);
  await assert.rejects(access(f.marker),{code:'ENOENT'});
});
test('executable mode mismatch is refused even when core.filemode ignores it',async t=>{
  const f=await fixture(t);await f.git('config','core.filemode','false');await chmod(join(f.skill,'validate-findings.cjs'),0o755);assert.equal(await f.git('status','--porcelain'),'');await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|mode|source|match/i);
});
test('tracked regular files cannot be replaced by a symbolic link',async t=>{
  const f=await fixture(t),file=join(f.skill,'validate-findings.cjs');await rm(file);await symlink('validate-coverage-ledger.cjs',file);await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|link|source|regular|match/i);
});
test('replacement refs cannot redefine the pinned commit',async t=>{
  const f=await fixture(t);await writeFile(join(f.skill,'validate-findings.cjs'),`${f.source}// replacement\n`);await f.git('add','.');await f.git('commit','-qm','replacement');const replacement=await f.git('rev-parse','HEAD');await f.git('update-ref','HEAD',f.options.revision);await f.git('replace',f.options.revision,replacement);assert.equal(await f.git('status','--porcelain'),'');await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|replace|source|match/i);
});
test('unsupported symlink entries in the pinned tree fail closed',async t=>{
  const f=await fixture(t);await symlink('SKILL.md',join(f.root,'linked.txt'));await f.git('add','.');await f.git('commit','-qm','unsupported tree');PINS.cloudflare=await f.git('rev-parse','HEAD');f.options.revision=PINS.cloudflare;await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|unsupported|source|regular|link/i);
});
test('raw working bytes cannot pass through a configured clean filter',async t=>{
  const f=await fixture(t),file=join(f.skill,'SKILL.md');await writeFile(join(f.root,'.gitattributes'),'*.md filter=pinned\n');await f.git('add','.gitattributes');await f.git('commit','-qm','attributes');PINS.cloudflare=await f.git('rev-parse','HEAD');f.options.revision=PINS.cloudflare;
  await f.git('config','filter.pinned.clean',`printf 'Pinned instructions\\n'`);await writeFile(file,'Filter-hidden instructions\n');await f.git('add',file);assert.equal(await f.git('status','--porcelain'),'');await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|source|match/i);
});
test('unsupported gitlink entries in the pinned tree fail closed',async t=>{
  const f=await fixture(t);await f.git('update-index','--add','--cacheinfo',`160000,${f.options.revision},submodule`);await f.git('commit','-qm','unsupported gitlink');PINS.cloudflare=await f.git('rev-parse','HEAD');f.options.revision=PINS.cloudflare;await mkdir(join(f.root,'submodule'));await assert.rejects(verifySourcePin('cloudflare',f.options),/pin|unsupported|source|regular|link/i);
});
test('ignored extra files cannot introduce unpinned local code',async t=>{
  const f=await fixture(t);await writeFile(join(f.root,'.gitignore'),'ignored.cjs\n');await f.git('add','.gitignore');await f.git('commit','-qm','ignore fixture');PINS.cloudflare=await f.git('rev-parse','HEAD');f.options.revision=PINS.cloudflare;await writeFile(join(f.root,'ignored.cjs'),'// unpinned\n');assert.equal(await f.git('status','--porcelain'),'');await assert.rejects(verifySourcePin('cloudflare',f.options),/unexpected|source|pin/i);
});
test('pin verification never invokes a configured clean filter',async t=>{
  const f=await fixture(t);await writeFile(join(f.root,'.gitattributes'),'*.md filter=observer\n');await f.git('add','.gitattributes');await f.git('commit','-qm','filter fixture');PINS.cloudflare=await f.git('rev-parse','HEAD');f.options.revision=PINS.cloudflare;await f.git('config','filter.observer.clean','touch .git/filter-ran && cat');await writeFile(join(f.skill,'SKILL.md'),'Pinned instructions\n');await verifySourcePin('cloudflare',f.options);await assert.rejects(access(join(f.root,'.git/filter-ran')),{code:'ENOENT'});
});
