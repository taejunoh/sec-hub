import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeReports } from '../src/reports.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const run=()=>({schemaVersion:1,id:'fixture',startedAt:'2026-10-28T00:00:00.000Z',endedAt:'2026-10-28T00:00:01.000Z',target:{path:'/fixture'},status:'completed',tools:[{id:'osv',status:'completed',findings:[]}],findings:[]});

test('report serialization failure starts no writes',async t=>{
  const root=await fs.realpath(await fs.mkdtemp(join(tmpdir(),'sec-hub-report-lifecycle-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const original=JSON.stringify;let started=0;const originalOpen=fs.open;
  fs.open=async(...args)=>{if(args[1]==='wx')started++;return originalOpen(...args);};syncBuiltinESMExports();
  JSON.stringify=(value,...args)=>{if(value?.version==='2.1.0')throw new Error('SARIF serialization fixture');return original(value,...args);};
  t.after(()=>{JSON.stringify=original;fs.open=originalOpen;syncBuiltinESMExports();});
  await assert.rejects(writeReports(run(),root),/serialization fixture/);
  await pause(100);assert.equal(started,0,'JSON/HTML writes must not start before SARIF serialization succeeds');
});

test('report failure waits for every already-started sibling write',async t=>{
  const root=await fs.realpath(await fs.mkdtemp(join(tmpdir(),'sec-hub-report-lifecycle-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const original=fs.rename;let release,blocked=false,settled=false;const gate=new Promise(resolve=>release=resolve);
  fs.rename=async(from,to)=>{if(to===join(root,'report.html'))throw new Error('HTML rename fixture');if(to===join(root,'results.sarif')){blocked=true;await gate;}return original(from,to);};syncBuiltinESMExports();
  t.after(()=>{release();fs.rename=original;syncBuiltinESMExports();});
  const pending=writeReports(run(),root).then(()=>{settled=true;},error=>{settled=true;return error;});
  const deadline=Date.now()+3000;while(!blocked&&Date.now()<deadline)await pause(5);assert.equal(blocked,true);await pause(20);
  const settledEarly=settled;release();const error=await pending;
  assert.equal(settledEarly,false,'failure must not settle while another writer owns work');assert.match(error.message,/HTML rename fixture/);
  assert.ok((await fs.readFile(join(root,'results.sarif'))).length);
});
