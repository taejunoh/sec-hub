// FAKE provider transport. Only subprocess sandbox execution is real.
// No model API, authentication read, or scan-completion evidence is produced.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {symlink,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {sandboxCommandArgs} from '../../src/agents/codex-sandbox.mjs';
const execute=promisify(execFile),[binary,outside,...args]=process.argv.slice(2);
if(args.includes('--version')){const r=await execute(binary,['--version']);process.stdout.write(r.stdout);process.exit(0);}
if(args[0]==='sandbox'){try{const r=await execute(binary,args,{maxBuffer:128*1024});process.stdout.write(r.stdout);process.stderr.write(r.stderr);}catch(e){process.stderr.write(e.stderr??'');process.exitCode=e.code??1;}process.exit();}
let prompt='';for await(const data of process.stdin)prompt+=data;
const runner=args[args.indexOf('-C')+1],context=prompt.match(/^SEC_HUB_CONTEXT=(.*)$/m),role=context?JSON.parse(context[1]):null,target=role?.target??resolve(runner,'../target'),skill=role?.readFiles[0]??prompt.match(/Skill root is (.*?); output directory/)[1]+'/SKILL.md',schema=args.includes('--output-schema')?args[args.indexOf('--output-schema')+1]:skill;
const link=join(runner,`fixture-link-${randomUUID()}`),output=join(runner,'fixture-output'),targetWrite=join(target,'fixture-write');
await symlink(outside,link);
try{
 const script='set -eu; /bin/cat "$1" >/dev/null; /bin/cat "$2" >/dev/null; /bin/cat "$3" >/dev/null; if /bin/cat "$4" >/dev/null 2>&1; then exit 51; fi; if /bin/cat "$5" >/dev/null 2>&1; then exit 52; fi; if (echo x >"$6") 2>/dev/null; then exit 53; fi; if [ "$8" = write ]; then echo x >"$7"; else if (echo x >"$7") 2>/dev/null; then exit 54; fi; fi; /usr/bin/printf "REAL_SANDBOX_CHECKS_PASSED"';
 const command=sandboxCommandArgs(args,['/bin/sh','-c',script,'fixture',join(target,'target.mjs'),skill,schema,outside,link,targetWrite,output,role?'read':'write']);
 try{const result=await execute(binary,command,{cwd:runner,maxBuffer:128*1024});console.log(JSON.stringify({type:'sec_hub.fixture_sandbox_result',provider:'FAKE',actualSandbox:true,exitCode:0,stdout:result.stdout}));}catch(e){console.log(JSON.stringify({type:'sec_hub.fixture_sandbox_result',provider:'FAKE',actualSandbox:true,exitCode:e.code,stderr:e.stderr}));}
}finally{await Promise.all([rm(link,{force:true}),rm(output,{force:true}),rm(targetWrite,{force:true})]);}
// Intentionally incomplete scan; never fabricate native roles or findings.
process.exitCode=7;
