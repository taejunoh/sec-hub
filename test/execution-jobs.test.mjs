import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,readFile,rm,rename } from 'node:fs/promises';
import { join,dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { loadExecutionConfig } from '../src/dashboard/execution-config.mjs';
const module=await import('../src/dashboard/jobs.mjs').catch(()=>({}));
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
async function until(fn){const end=Date.now()+5000;while(!fn()){if(Date.now()>end)throw new Error('fixture timed out');await pause(5);}}
async function fixture(t,limits={}){
  assert.equal(typeof module.createJobController,'function');
  const root=await mkdtemp(join(tmpdir(),'sec-hub-jobs-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const target=join(root,'target'),runsRoot=join(root,'runs'),filename=join(root,'execution.json'),config=join(root,'scanner.json');await mkdir(target);
  const script=join(root,'scanner.mjs');await writeFile(script,`import{writeFileSync}from'node:fs';if(process.argv.includes('--version'))console.log('fixture 1');else writeFileSync(process.argv[process.argv.indexOf('--output-file')+1],JSON.stringify({results:[]}));`);
  await writeFile(config,JSON.stringify({tools:{osv:{command:process.execPath,args:[script]}}}));
  await writeFile(filename,JSON.stringify({schemaVersion:1,targets:[{label:'Approved',path:target,config,tools:['osv']}],...limits}));
  const configuration=await loadExecutionConfig({filename,runsRoot});return {root,target,configuration,request:{targetId:configuration.targets[0].id,toolIds:['osv']}};
}
function fakeRun(options,status='partial'){return {id:'result-scan-id',status,directory:options.out};}
const terminal=job=>['completed','failed','cancelled'].includes(job.state);

test('controller reserves synchronously, keeps reporting admission, publishes private-safe results and enforces quota',async t=>{
  const f=await fixture(t,{maxJobs:1}),reporting=deferred();let entered=false,out;
  const c=module.createJobController({configuration:f.configuration,scan:async options=>{out=options.out;options.onProgress({phase:'scanning',toolId:'osv',toolStatus:'scanning',completedCount:0,totalCount:1,secret:'private'});return fakeRun(options);},report:async()=>{entered=true;await reporting.promise;}});
  const job=c.start(f.request);assert.equal(job.state,'running');assert.throws(()=>c.start(f.request),e=>e.statusCode===409);
  await until(()=>entered);assert.equal(c.get(job.id).phase,'reporting');assert.throws(()=>c.start(f.request),e=>e.statusCode===409);await assert.rejects(c.withRefresh(async()=>{}),e=>e.statusCode===409);
  reporting.resolve();await until(()=>terminal(c.get(job.id)));
  const done=c.get(job.id);assert.equal(done.state,'completed');assert.equal(done.runStatus,'partial');assert.equal(done.reportsReady,true);assert.equal(done.resultRunId,'result-scan-id');assert.equal(dirname(out),f.configuration.runsRoot);assert.equal(out,join(f.configuration.runsRoot,job.id));assert.notEqual(job.id,done.resultRunId);
  assert.equal(c.describe().currentJob,null);assert.equal(c.describe().jobs[0].id,job.id);
  assert.doesNotMatch(JSON.stringify(c.describe()),/private|scanner\.json|target\/|command|stdout|artifactDir/);
  assert.deepEqual(Object.keys(done).sort(),['id','targetId','targetLabel','toolIds','state','phase','startedAt','updatedAt','completedAt','progress','runStatus','reportsReady','resultRunId','errorCode','abortReason'].sort());
  assert.throws(()=>c.start(f.request),e=>e.statusCode===429);await c.close();
});

test('cancel during reporting stays cancelling until joined completion and terminal cancel is immutable',async t=>{
  const f=await fixture(t),gate=deferred();let entered=false;
  const c=module.createJobController({configuration:f.configuration,scan:async options=>fakeRun(options),report:async()=>{entered=true;await gate.promise;}});
  const job=c.start(f.request);await until(()=>entered);assert.equal(c.cancel(job.id).state,'cancelling');assert.equal(c.cancel(job.id).abortReason,'user');
  let closed=false;const closing=c.close().then(()=>closed=true);await pause(20);assert.equal(closed,false);assert.equal(c.get(job.id).state,'cancelling');
  gate.resolve();await closing;const done=c.get(job.id);assert.equal(done.state,'cancelled');assert.equal(done.abortReason,'user');assert.equal(done.reportsReady,true);assert.deepEqual(c.cancel(job.id),done);assert.throws(()=>c.start(f.request),e=>e.statusCode===503);
});

test('deadline owns first abort cause and shutdown joins a scan that ignores abort until it settles',async t=>{
  const f=await fixture(t,{maxJobTimeMs:35}),gate=deferred(),entered=deferred();
  // Real path checks may exceed 35 ms under suite load. Advance the deadline
  // only after scan entry; this case exercises an in-flight, abort-ignoring scan.
  t.mock.timers.enable({apis:['setTimeout']});
  const c=module.createJobController({configuration:f.configuration,scan:async options=>{entered.resolve();await gate.promise;return fakeRun(options);},report:async()=>{}});
  const job=c.start(f.request);
  try{
    await entered.promise;
    t.mock.timers.tick(34);assert.equal(c.get(job.id).abortReason,null);
    t.mock.timers.tick(1);assert.equal(c.get(job.id).abortReason,'deadline');c.cancel(job.id);
    let closed=false;const closing=c.close().then(()=>closed=true);
    await new Promise(resolve=>setImmediate(resolve));assert.equal(closed,false);assert.equal(c.get(job.id).state,'cancelling');
    gate.resolve();await closing;
    assert.equal(c.get(job.id).state,'failed');assert.equal(c.get(job.id).errorCode,'job_timeout');assert.equal(c.get(job.id).abortReason,'deadline');
  }finally{gate.resolve();await c.close();t.mock.timers.reset();}
});

test('deadline during path preparation prevents the scan from starting',async t=>{
  const f=await fixture(t,{maxJobTimeMs:35});let scans=0,reports=0;
  t.mock.timers.enable({apis:['setTimeout']});
  const c=module.createJobController({configuration:f.configuration,scan:async options=>{scans++;return fakeRun(options);},report:async()=>{reports++;}});
  const job=c.start(f.request);
  try{
    // execute() installs its timer before yielding to the real filesystem check.
    await Promise.resolve();t.mock.timers.tick(35);
    assert.equal(c.get(job.id).abortReason,'deadline');await c.close();
    assert.equal(scans,0);assert.equal(reports,0);assert.equal(c.get(job.id).state,'failed');assert.equal(c.get(job.id).errorCode,'job_timeout');assert.equal(c.get(job.id).abortReason,'deadline');
  }finally{await c.close();t.mock.timers.reset();}
});

test('cleanup uncertainty survives later report failure, quarantines admission and rejects joined close',async t=>{
  const f=await fixture(t),gate=deferred(),scanGate=deferred();let entered=false,scanOptions;
  const c=module.createJobController({configuration:f.configuration,scan:async options=>{scanOptions=options;await scanGate.promise;options.onCleanupUnconfirmed();return fakeRun(options);},report:async()=>{entered=true;await gate.promise;throw new Error('/private/secret');}});
  const job=c.start(f.request);await until(()=>scanOptions);c.cancel(job.id);scanGate.resolve();await until(()=>entered);let settled=false;const closing=c.close().catch(error=>{settled=true;return error;});await pause(15);assert.equal(settled,false);gate.resolve();const error=await closing;
  assert.equal(error.code,'cleanup_unconfirmed');assert.equal(c.get(job.id).state,'failed');assert.equal(c.get(job.id).errorCode,'cleanup_unconfirmed');assert.equal(c.get(job.id).abortReason,'user');assert.equal(c.get(job.id).reportsReady,false);assert.equal(c.get(job.id).resultRunId,null);assert.throws(()=>c.start(f.request),e=>e.statusCode===503);
});

test('refresh owns admission through failures and close joins refresh',async t=>{
  const f=await fixture(t),c=module.createJobController({configuration:f.configuration}),gate=deferred();let entered=false;
  const refresh=c.withRefresh(async()=>{entered=true;await gate.promise;throw new Error('refresh fixture failure');});await until(()=>entered);
  assert.throws(()=>c.start(f.request),e=>e.statusCode===409);await assert.rejects(c.withRefresh(async()=>{}),e=>e.statusCode===409);
  let closed=false;const closing=c.close().then(()=>closed=true);await pause(15);assert.equal(closed,false);gate.resolve();await assert.rejects(refresh,/fixture/);await closing;
});

test('root and target identity replacement fail before a scanner runs',async t=>{
  for(const key of ['target','runsRoot']){
    const f=await fixture(t);let calls=0;const c=module.createJobController({configuration:f.configuration,scan:async()=>{calls++;throw new Error('must not run');}});
    const directory=key==='target'?f.target:f.configuration.runsRoot;await rename(directory,`${directory}-old`);await mkdir(directory);
    const job=c.start(f.request);await until(()=>terminal(c.get(job.id)));assert.equal(calls,0);assert.equal(c.get(job.id).errorCode,'execution_path_changed');await c.close();
  }
});

test('invalid selections cannot admit work or consume quota',async t=>{
  const f=await fixture(t),c=module.createJobController({configuration:f.configuration});
  for(const request of [{...f.request,toolIds:[]},{...f.request,toolIds:['osv','osv']},{...f.request,toolIds:['anthropic']},{...f.request,path:'/evil'},{...f.request,toolIds:['unknown']}])assert.throws(()=>c.start(request),e=>e.statusCode===400);
  assert.equal(c.describe().jobs.length,0);assert.throws(()=>c.get('unknown'),e=>e.statusCode===404);await c.close();
});

test('real runner and configured executable produce three reports in immediate UUID child',async t=>{
  const f=await fixture(t),c=module.createJobController({configuration:f.configuration});const job=c.start(f.request);await until(()=>terminal(c.get(job.id)));
  const done=c.get(job.id);assert.equal(done.state,'completed');assert.equal(done.runStatus,'completed');assert.equal(done.progress.completedCount,1);assert.equal(done.reportsReady,true);
  const directory=join(f.configuration.runsRoot,job.id);for(const name of ['run.json','report.html','results.sarif'])assert.ok((await readFile(join(directory,name))).length);
  assert.equal(JSON.parse(await readFile(join(directory,'run.json'),'utf8')).id,done.resultRunId);await c.close();
});

test('immediate shutdown prevents preparation and retains the shutdown abort cause',async t=>{
  const f=await fixture(t);let calls=0;const c=module.createJobController({configuration:f.configuration,scan:async()=>{calls++;throw new Error('unexpected');}});
  const job=c.start(f.request),closing=c.close();assert.equal(c.close(),closing);await closing;
  assert.equal(calls,0);assert.equal(c.get(job.id).state,'cancelled');assert.equal(c.get(job.id).abortReason,'shutdown');assert.equal(c.get(job.id).errorCode,'server_shutdown');
});

test('cleanup uncertainty aborts current scan before subsequent tool work and still joins reporting',async t=>{
  const f=await fixture(t),gate=deferred();let observedSignal,subsequentWork=0,reporting=false;
  const c=module.createJobController({configuration:f.configuration,scan:async options=>{options.onCleanupUnconfirmed();observedSignal=options.signal.aborted;if(!options.signal.aborted)subsequentWork++;return fakeRun(options);},report:async()=>{reporting=true;await gate.promise;}});
  const job=c.start(f.request);await until(()=>reporting);
  let closed=false;const closing=c.close().catch(error=>{closed=true;return error;});await pause(15);const settledEarly=closed;
  gate.resolve();const error=await closing;
  assert.equal(observedSignal,true,'cleanup uncertainty must synchronously abort subsequent work');assert.equal(subsequentWork,0);assert.equal(settledEarly,false);assert.equal(error.code,'cleanup_unconfirmed');assert.equal(c.get(job.id).state,'failed');assert.equal(c.get(job.id).errorCode,'cleanup_unconfirmed');assert.equal(c.get(job.id).abortReason,'cleanup_unconfirmed');assert.throws(()=>c.start(f.request),e=>e.code==='cleanup_unconfirmed');
});
