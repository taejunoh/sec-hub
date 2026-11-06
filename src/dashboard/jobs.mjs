import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { runScan } from '../runner.mjs';
import { writeReports } from '../reports.mjs';
import { recheckExecutionPaths } from './execution-config.mjs';

const codes={invalid_request:400,target_not_found:404,job_not_found:404,execution_busy:409,job_limit:429,execution_closing:503,cleanup_unconfirmed:503};
export class ExecutionError extends Error {
  constructor(code){super(Object.hasOwn(codes,code)?code:'invalid_request');this.code=this.message;this.statusCode=codes[this.code];}
}
const terminal=new Set(['completed','failed','cancelled']);
const phases=new Set(['preparing','checking','scanning','reporting','ready']);
const toolStates=new Set(['pending','checking','scanning','completed','failed','skipped','timed_out','cancelled']);
const finishedTools=new Set(['completed','failed','skipped','timed_out','cancelled']);
const now=()=>new Date().toISOString();
const publicJob=job=>structuredClone(job.public);

/** Dependencies belong to the trusted host, never to operator JSON or browser input. */
export function createJobController({configuration,scan=runScan,report=writeReports,inspectGit,allowAnthropic=false}){
  const jobs=[];let active=null,refresh=null,closing=false,quarantined=false,closePromise;
  function admission(){if(quarantined)throw new ExecutionError('cleanup_unconfirmed');if(closing)throw new ExecutionError('execution_closing');if(active||refresh)throw new ExecutionError('execution_busy');}
  function find(id){const job=jobs.find(item=>item.public.id===id);if(!job)throw new ExecutionError('job_not_found');return job;}
  function abort(job,cause){
    if(terminal.has(job.public.state)||job.public.abortReason)return;
    job.public.abortReason=cause;job.public.state='cancelling';job.public.updatedAt=now();job.controller.abort();
  }
  async function execute(job,target){
    const view=job.public;let failure=null;
    const timer=setTimeout(()=>abort(job,'deadline'),configuration.limits.maxJobTimeMs);
    try{
      try{await recheckExecutionPaths(configuration,target);}catch{failure='execution_path_changed';throw new Error('Execution paths unavailable');}
      if(job.controller.signal.aborted)throw new Error('Aborted before scan');
      const run=await scan({target:target.path,out:join(configuration.runsRoot,view.id),tools:[...view.toolIds],config:target.config,ai:target.ai,url:target.url,timeoutMs:target.timeoutMs,signal:job.controller.signal,...(inspectGit===undefined?{}:{inspectGit}),
        ...(target.nodeExecutable?{nodeExecutable:target.nodeExecutable}:{}),
        onCleanupUnconfirmed(){job.cleanupUnconfirmed=true;quarantined=true;abort(job,'cleanup_unconfirmed');},
        onProgress(event){
          if(!event||typeof event!=='object')return;
          if(phases.has(event.phase)&&event.phase!=='ready'&&event.phase!=='reporting')view.phase=event.phase;
          const tool=view.progress.tools.find(item=>item.id===event.toolId);
          if(tool&&toolStates.has(event.toolStatus))tool.status=event.toolStatus;
          view.progress.completedCount=view.progress.tools.filter(item=>finishedTools.has(item.status)).length;view.updatedAt=now();
        }});
      if(['completed','partial','failed'].includes(run.status))view.runStatus=run.status;
      view.phase='reporting';view.updatedAt=now();
      try{await report(run,run.directory);}catch{failure='report_failed';throw new Error('Reports failed');}
      view.reportsReady=true;view.resultRunId=run.id;
    }catch{failure??='scan_failed';}
    finally{
      clearTimeout(timer);
      if(job.cleanupUnconfirmed){view.state='failed';view.errorCode='cleanup_unconfirmed';}
      else if(view.abortReason==='deadline'){view.state='failed';view.errorCode='job_timeout';}
      else if(failure==='report_failed'){view.state='failed';view.errorCode=failure;}
      else if(view.abortReason){view.state='cancelled';view.errorCode=view.abortReason==='shutdown'?'server_shutdown':null;}
      else if(failure){view.state='failed';view.errorCode=failure;}
      else view.state='completed';
      view.phase='ready';view.completedAt=now();view.updatedAt=view.completedAt;
    }
  }
  return {
    describe(){return {targets:configuration.targets.map(({id,label,toolIds})=>({id,label,toolIds:[...toolIds]})),limits:{...configuration.limits},currentJob:active?publicJob(active):null,jobs:jobs.slice().reverse().map(publicJob)};},
    start(request){
      admission();
      if(!request||typeof request!=='object'||Array.isArray(request)||Object.keys(request).some(key=>!['targetId','toolIds'].includes(key))||typeof request.targetId!=='string'||!Array.isArray(request.toolIds)||!request.toolIds.length||new Set(request.toolIds).size!==request.toolIds.length)throw new ExecutionError('invalid_request');
      const target=configuration.targets.find(item=>item.id===request.targetId);if(!target)throw new ExecutionError('target_not_found');
      if(request.toolIds.some(id=>typeof id!=='string'||!target.toolIds.includes(id)||(id==='anthropic'&&!allowAnthropic)))throw new ExecutionError('invalid_request');
      if(jobs.length>=configuration.limits.maxJobs)throw new ExecutionError('job_limit');
      const startedAt=now(),job={controller:new AbortController(),cleanupUnconfirmed:false,public:{id:randomUUID(),targetId:target.id,targetLabel:target.label,toolIds:[...request.toolIds],state:'running',phase:'preparing',startedAt,updatedAt:startedAt,completedAt:null,progress:{completedCount:0,totalCount:request.toolIds.length,tools:request.toolIds.map(id=>({id,status:'pending'}))},runStatus:null,reportsReady:false,resultRunId:null,errorCode:null,abortReason:null}};
      active=job;jobs.push(job);
      job.promise=Promise.resolve().then(()=>execute(job,target)).finally(()=>{if(active===job)active=null;});
      return publicJob(job);
    },
    get(id){return publicJob(find(id));},
    cancel(id){const job=find(id);abort(job,'user');return publicJob(job);},
    async withRefresh(task){
      admission();
      const owned=Promise.resolve().then(task);refresh=owned;
      try{return await owned;}finally{if(refresh===owned)refresh=null;}
    },
    close(){
      if(closePromise)return closePromise;
      closing=true;if(active)abort(active,'shutdown');
      const owned=[active?.promise,refresh].filter(Boolean);
      closePromise=(async()=>{await Promise.allSettled(owned);if(quarantined)throw new ExecutionError('cleanup_unconfirmed');})();
      return closePromise;
    },
  };
}
