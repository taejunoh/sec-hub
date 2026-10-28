import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { spawn, execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
const wrapper=fileURLToPath(new URL('../src/adapters/codex-wrapper.mjs',import.meta.url));
function child(args,env) {
  const proc=spawn(process.execPath,args,{env:{...process.env,...env},stdio:['ignore','pipe','pipe']});let stdout='',stderr='';
  proc.stdout.setEncoding('utf8').on('data',x=>stdout+=x);proc.stderr.setEncoding('utf8').on('data',x=>stderr+=x);
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{proc.kill('SIGKILL');reject(new Error('Codex fixture timeout'));},5000);proc.once('error',reject);proc.once('close',code=>{clearTimeout(timer);resolve({code,stdout,stderr});});});
}
async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),'release022-codex-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const target=join(root,'repo'),artifacts=join(root,'artifacts'),safe=join(root,'safe');for(const p of [target,artifacts,safe])await mkdir(p);
  const fake=join(root,'fake.mjs');await writeFile(fake,`import {mkdir,writeFile} from 'node:fs/promises';import {join} from 'node:path';const a=process.argv.slice(2);await writeFile(process.env.CALLS,a[0]+'\\n',{flag:'a'});if(a[0]==='scan'){const p=a[a.indexOf('--output-dir')+1];await mkdir(p);await writeFile(join(p,'result'),'ok');}else await writeFile(a[a.indexOf('--output')+1],'{}');`);
  const calls=join(root,'calls');const options={command:process.execPath,args:[fake],target,artifactDir:artifacts};return {root,target,artifacts,safe,fake,calls,options};
}

test('release022 #1 refuses TMPDIR inside an enclosing Git worktree before any native child or temporary creation',async t=>{
  const f=await fixture(t);execFileSync('git',['init','--quiet',f.target],{env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'}});
  const nested=join(f.target,'nested'),temp=join(f.target,'temp');await mkdir(nested);await mkdir(temp);
  const hook=join(f.root,'fsmonitor');await writeFile(hook,'#!/bin/sh\ntouch '+join(f.root,'hook-ran')+'\n',{mode:0o700});execFileSync('git',['-C',f.target,'config','core.fsmonitor',hook]);
  const r=await child([wrapper,JSON.stringify({...f.options,target:nested})],{TMPDIR:temp,CALLS:f.calls});
  assert.notEqual(r.code,0,r.stderr);assert.match(r.stderr,/temporary|TMPDIR/i);assert.equal(await readFile(f.calls,'utf8').catch(()=>''),'');assert.deepEqual(await readdir(temp),[]);assert.equal(await readFile(join(f.root,'hook-ran'),'utf8').catch(()=>undefined),undefined);
});

test('release022 #1 canonical TMPDIR symlink cannot disguise an enclosing worktree; safe external TMPDIR succeeds',async t=>{
  const f=await fixture(t);await mkdir(join(f.target,'.git'));const temp=join(f.target,'temp');await mkdir(temp);const link=join(f.root,'linked-temp');await symlink(temp,link);
  const bad=await child([wrapper,JSON.stringify(f.options)],{TMPDIR:link,CALLS:f.calls});assert.notEqual(bad.code,0,bad.stderr);assert.equal(await readFile(f.calls,'utf8').catch(()=>''),'');
  const good=await child([wrapper,JSON.stringify(f.options)],{TMPDIR:f.safe,CALLS:f.calls});assert.equal(good.code,0,good.stderr);assert.equal(await readFile(f.calls,'utf8'),'scan\nexport\n');assert.deepEqual(await readdir(f.safe),[]);
});

test('release022 #2 wrapper exceptions retain bounded actionable code and redact secret filenames',async t=>{
  const f=await fixture(t),secret='synthetic-private-secret-022';
  const r=await child([wrapper,JSON.stringify({...f.options,command:join(f.root,secret)})],{TMPDIR:f.safe,API_TOKEN:secret});
  assert.equal(r.code,2);assert.match(r.stderr,/ENOENT/);assert.match(r.stderr,/wrapper failed/);assert.doesNotMatch(r.stderr,new RegExp(secret));assert.ok(r.stderr.length<2500);
  const preload=join(f.root,'error.mjs');await writeFile(preload,`import fs from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';fs.mkdtemp=async()=>{throw Object.assign(new Error('synthetic safe detail '+process.env.API_TOKEN+' '+('x'.repeat(8000))),{code:'EIO'});};syncBuiltinESMExports();`);
  const failed=await child(['--import',preload,wrapper,JSON.stringify(f.options)],{TMPDIR:f.safe,API_TOKEN:secret});assert.match(failed.stderr,/EIO/);assert.match(failed.stderr,/synthetic safe detail/);assert.doesNotMatch(failed.stderr,new RegExp(secret));assert.ok(failed.stderr.length<2500);
});
