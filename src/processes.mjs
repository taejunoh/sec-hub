import { spawn } from 'node:child_process';
import { win32 } from 'node:path';
import { createRedactor } from './redaction.mjs';

export function runProcess(spec, options={}) {
  const {timeoutMs=120000,maxOutputBytes=5*1024*1024,signal,env=process.env,redactOutput=true}=options;
  const redact=redactOutput?createRedactor(env):String;
  // The host environment is trusted; per-command env/cwd must not select the
  // cleanup executable. Never search PATH or run a shell for tree termination.
  const windowsRoot=process.env.SystemRoot??process.env.SYSTEMROOT;
  if(!spec||typeof spec.command!=='string'||!spec.command||!Array.isArray(spec.args)||spec.args.some(arg=>typeof arg!=='string'))return Promise.reject(new Error('Executable and string argv are required'));
  if(!Number.isFinite(timeoutMs)||timeoutMs<=0||!Number.isSafeInteger(maxOutputBytes)||maxOutputBytes<1)return Promise.reject(new Error('Positive timeout and output limit are required'));
  return new Promise(resolveResult=>{
    const started=Date.now();
    let child,timer,escalation,hardDeadline,cleanupUnconfirmed=false,bytes=0,outputLimitExceeded=false,state,reason,settled=false,closed=false,stopping=false,escalated=false,exitCode=null;
    const stdout=[],stderr=[];
    const settle=()=>{
      if(settled)return;
      settled=true;clearTimeout(timer);clearTimeout(escalation);clearTimeout(hardDeadline);
      signal?.removeEventListener('abort',cancel);
      const allowed=[...(spec.successCodes??[0]),...(spec.findingCodes??[])];
      if(cleanupUnconfirmed){try{Promise.resolve(options.onCleanupUnconfirmed?.()).catch(()=>{});}catch{}}
      resolveResult({...(cleanupUnconfirmed?{cleanupUnconfirmed:true}:{}),status:state??(allowed.includes(exitCode)?'completed':'failed'),stdout:outputLimitExceeded?'':redact(Buffer.concat(stdout).toString('utf8')),stderr:outputLimitExceeded?'':redact(Buffer.concat(stderr).toString('utf8')),exitCode,reason:reason??(!allowed.includes(exitCode)?`Process exited with ${exitCode===null?'a signal':`code ${exitCode}`}`:undefined),durationMs:Date.now()-started});
    };
    const finishWhenClean=()=>{if(closed&&(!stopping||escalated))settle();};
    const kill=kind=>{
      try{if(process.platform!=='win32'&&child?.pid)process.kill(-child.pid,kind);else child?.kill(kind);}catch{}
    };
    const stop=(status,message)=>{
      if(stopping||settled)return;
      stopping=true;state=status;reason=message;clearTimeout(timer);
      if(process.platform==='win32'){
        let treeKiller,cleanupDone=false;
        const cleanupFailed=detail=>{cleanupUnconfirmed=true;reason=`${message}; Windows process-tree cleanup ${detail}; termination of descendants not confirmed`;};
        const completed=detail=>{
          if(cleanupDone||settled)return;
          cleanupDone=true;escalated=true;
          if(detail){cleanupFailed(detail);kill('SIGKILL');}
          finishWhenClean();
        };
        hardDeadline=setTimeout(()=>{
          cleanupDone=true;cleanupFailed('exceeded its deadline');
          try{treeKiller?.kill('SIGKILL');treeKiller?.unref();}catch{}
          kill('SIGKILL');child?.stdout?.destroy();child?.stderr?.destroy();child?.unref();settle();
        },1000);
        if(!Number.isSafeInteger(child?.pid)||child.pid<=0||typeof windowsRoot!=='string'||!/^[A-Za-z]:[\\/]/.test(windowsRoot)){
          completed('could not start (invalid PID or SystemRoot)');return;
        }
        try{
          // Windows SIGTERM kills the leader abruptly. Tree discovery must run
          // first: no leader-only TERM and no delayed second lookup by reused PID.
          const systemDirectory=win32.join(windowsRoot,'System32');
          treeKiller=spawn(win32.join(systemDirectory,'taskkill.exe'),['/PID',String(child.pid),'/T','/F'],{cwd:systemDirectory,env:process.env,shell:false,windowsHide:true,stdio:'ignore'});
          treeKiller.once('error',()=>completed('could not start'));
          treeKiller.once('close',code=>completed(code===0?undefined:'failed'));
        }catch{completed('could not start');}
        return;
      }
      kill('SIGTERM');
      // A leader may close immediately while same-group descendants ignore TERM.
      // Keep this referenced timer alive and wait for KILL before resolving.
      escalation=setTimeout(()=>{kill('SIGKILL');escalated=true;finishWhenClean();},300);
      hardDeadline=setTimeout(()=>{
        cleanupUnconfirmed=true;reason=`${message}; process-tree cleanup deadline exceeded; termination of descendants not confirmed`;
        kill('SIGKILL');child?.stdout?.destroy();child?.stderr?.destroy();child?.unref();settle();
      },1000);
    };
    const cancel=()=>stop('cancelled','Cancelled by user');
    if(signal?.aborted){state='cancelled';reason='Cancelled by user';settle();return;}
    try{child=spawn(spec.command,spec.args,{cwd:spec.cwd,env,shell:false,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});}
    catch(error){state='failed';reason=`Cannot start executable (${error.code??'spawn error'})`;settle();return;}
    const capture=destination=>chunk=>{
      const remaining=Math.max(0,maxOutputBytes-bytes);
      if(remaining)destination.push(chunk.subarray(0,remaining));bytes+=chunk.length;
      if(bytes>maxOutputBytes){
        // A byte cap can split a known secret before redaction can recognize it.
        // Omit both captured streams on overflow; keep the bounded status/reason.
        outputLimitExceeded=true;stdout.length=0;stderr.length=0;
        stop('failed',`Output exceeds ${maxOutputBytes} byte limit; captured output omitted`);
      }
    };
    child.stdout.on('data',capture(stdout));child.stderr.on('data',capture(stderr));
    child.once('error',error=>{state='failed';reason=`Cannot start executable (${error.code??'spawn error'})`;if(!stopping)settle();});
    child.once('close',code=>{closed=true;exitCode=code;clearTimeout(timer);finishWhenClean();});
    timer=setTimeout(()=>stop('timed_out',`Timeout after ${timeoutMs} ms`),timeoutMs);
    signal?.addEventListener('abort',cancel,{once:true});
  });
}
