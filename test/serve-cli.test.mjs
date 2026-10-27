import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { once } from 'node:events';

const root=resolve(new URL('..',import.meta.url).pathname),cli=join(root,'bin/sec-hub.mjs');
function launch(args,{env={}}={}){
  const child=spawn(process.execPath,[cli,...args],{cwd:root,env:{...process.env,...env},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.setEncoding('utf8').on('data',chunk=>stdout+=chunk);child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
  const exited=once(child,'exit').then(([code,signal])=>({code,signal}));
  const waitForFirstLine=()=>new Promise((resolveLine,reject)=>{
    const check=()=>{const newline=stdout.indexOf('\n');if(newline>=0){cleanup();resolveLine(stdout.slice(0,newline));}};
    const onExit=()=>{cleanup();if(stdout.includes('\n'))check();else reject(new Error(`CLI exited before startup: ${stderr}`));};
    const deadline=setTimeout(()=>{cleanup();reject(new Error('Timed out waiting for dashboard startup line'));},5000);
    const cleanup=()=>{clearTimeout(deadline);child.stdout.off('data',check);child.off('exit',onExit);};
    child.stdout.on('data',check);child.once('exit',onExit);check();
  });
  return {child,exited,waitForFirstLine,get stdout(){return stdout;},get stderr(){return stderr;}};
}
async function withRoot(callback){
  const parent=await mkdtemp(join(tmpdir(),'sec-hub-serve-cli-')),runs=join(parent,'runs');await mkdir(runs);
  try{return await callback({parent,runs});}finally{await rm(parent,{recursive:true,force:true});}
}
async function terminate(instance,signal){
  if(instance.child.exitCode!==null)return instance.exited;
  instance.child.kill(signal);
  let deadline;
  try{return await Promise.race([instance.exited,new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error(`CLI did not exit after ${signal}`)),5000);})]);}
  finally{clearTimeout(deadline);}
}

test('serve help advertises the absolute runs root and bounded port',async()=>{
  const instance=launch(['serve','--help']);const result=await instance.exited;
  assert.equal(result.code,0);assert.match(instance.stdout,/serve --runs ABS_ROOT \[--port 0\]/);
});

test('serve rejects invalid options and roots before starting the dashboard',async()=>withRoot(async({runs,parent})=>{
  const file=join(parent,'not-a-directory');await writeFile(file,'x');
  const invalid=[
    ['serve'],['serve','--runs',relative(root,runs)],['serve','--runs',join(parent,'missing')],['serve','--runs',file],
    ...['-1','65536','1.5','1e3',''].map(port=>['serve','--runs',runs,'--port',port]),
    ['serve','--runs',runs,'extra'],['serve','--runs',runs,'--runs',runs],
    ...['--host','--config','--ai','--out'].map(flag=>['serve','--runs',runs,flag,...(flag==='--ai'?[]:['value'])])
  ];
  for(const args of invalid){
    const instance=launch(args,{env:{PATH:'',ANTHROPIC_API_KEY:'serve-test-secret-123',OPENAI_API_KEY:'serve-test-secret-456'}}),result=await instance.exited;
    assert.equal(result.code,2,`${args.join(' ')} should fail with 2`);assert.doesNotMatch(instance.stdout,/"event":"listening"/);assert.doesNotMatch(instance.stderr,/serve-test-secret/);
  }
}));

for(const signal of ['SIGINT','SIGTERM'])test(`serve starts a read-only snapshot and shuts down on ${signal}`,async t=>withRoot(async({runs})=>{
  const before=await readdir(runs),instance=launch(['serve','--runs',runs,'--port','0'],{env:{PATH:'',ANTHROPIC_API_KEY:'serve-test-secret-123',OPENAI_API_KEY:'serve-test-secret-456'}});
  t.after(async()=>{if(instance.child.exitCode===null)instance.child.kill('SIGKILL');});
  const line=await instance.waitForFirstLine(),started=JSON.parse(line);
  assert.deepEqual(started,{event:'listening',url:started.url,readOnly:true});assert.match(started.url,/^http:\/\/127\.0\.0\.1:\d+\/$/);
  const response=await fetch(new URL('/api/catalog',started.url));assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
  const catalog=await response.json();assert.equal(catalog.kind,'sec-hub.catalog');
  for(const path of ['/','/assets/app.mjs','/assets/style.css','/assets/view-model.mjs']){
    const asset=await fetch(new URL(path,started.url));assert.equal(asset.status,200,`${path} should be served`);assert.ok((await asset.text()).length>0);
  }
  assert.deepEqual(await readdir(runs),before,'serving and browsing must not modify the saved-artifact root');
  const result=await terminate(instance,signal);assert.equal(result.code,0);assert.equal(instance.stdout.trim().split('\n').length,1);assert.equal(instance.stderr,'');
  await assert.rejects(fetch(started.url));
}));

test('serve reports an occupied loopback port without a listening line',async t=>withRoot(async({runs})=>{
  const occupied=createServer();occupied.listen(0,'127.0.0.1');await once(occupied,'listening');t.after(()=>occupied.close());
  const {port}=occupied.address(),instance=launch(['serve','--runs',runs,'--port',String(port)]),result=await instance.exited;
  assert.equal(result.code,2,`unexpected exit: ${instance.stderr}`);assert.equal(instance.stdout,'');assert.equal(instance.stderr,'sec-hub: Dashboard server failed.\n');
}));
