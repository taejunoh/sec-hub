// Version independently of prompts and record schemas. Legacy is replay-only.
import {isAbsolute,join,resolve} from 'node:path';
import {mkdtemp,writeFile,readFile,access,symlink,rm} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
export const SANDBOX_INVOCATION_POLICY_VERSION=2;
export const SANDBOX_PROFILE='sec_hub_v2';
export function replaySandboxInvocationPolicy(manifest){
  const version=Object.hasOwn(manifest,'sandboxInvocationPolicyVersion')?manifest.sandboxInvocationPolicyVersion:1;
  if(version!==1&&version!==2)throw new Error('Unsupported Codex sandbox invocation policy version');
  return version;
}
function pathKey(path){
  // These are TOML keys AND Codex permission patterns. Reject glob syntax and
  // control characters, rather than letting a literal directory expand a grant.
  if(typeof path!=='string'||!isAbsolute(path)||/[\x00-\x1f\x7f\\*?\[\]{}]/.test(path))throw new Error('Unsupported Codex sandbox filesystem path');
  if(resolve(path)=== '/')throw new Error('Codex sandbox cannot grant the filesystem root');
  return JSON.stringify(resolve(path));
}
export function restrictedProfileArgs({readPaths,writePaths=[],profile=SANDBOX_PROFILE}){
  if(!/^[a-z][a-z0-9_]{0,63}$/.test(profile))throw new Error('Invalid Codex sandbox profile name');
  const entries=new Map([[JSON.stringify(':minimal'),'read']]);
  for(const path of readPaths)entries.set(pathKey(path),'read');
  for(const path of writePaths)entries.set(pathKey(path),'write');
  const filesystem=[...entries].map(([key,value])=>`${key}=${JSON.stringify(value)}`).join(',');
  // Replace the whole table: no ambient named-profile inheritance or grants.
  return ['-c',`permissions={${profile}={filesystem={${filesystem}},network={enabled=false}}}`,'-c',`default_permissions=${JSON.stringify(profile)}`];
}
export function nativeSandboxArgs(runner,options,nodeExecutable){
  return restrictedProfileArgs({readPaths:[resolve(runner,'../target'),join(options.skillRoot,'skills/security-audit'),nodeExecutable],writePaths:[runner]});
}
export function roleSandboxArgs(runner,nodeExecutable,outputSchemaPath,readFiles){
  if(!Array.isArray(readFiles)||!readFiles.length)throw new Error('Codex sandbox requires exact role documents');
  return restrictedProfileArgs({readPaths:[resolve(runner,'../target'),...readFiles,nodeExecutable,...(outputSchemaPath?[outputSchemaPath]:[])]});
}
export function sandboxCommandArgs(execArgs,command){
  const configs=[];
  for(let i=0;i<execArgs.length-1;i++)if(execArgs[i]==='-c'&&/^(permissions=|default_permissions=)/.test(execArgs[i+1]))configs.push('-c',execArgs[++i]);
  if(configs.length!==4||execArgs.includes('--sandbox'))throw new Error('Missing restricted Codex sandbox configuration');
  return ['sandbox',...configs,'-P',SANDBOX_PROFILE,'-C',execArgs[execArgs.indexOf('-C')+1],'--',...command];
}
export function assertSandboxBackend(version,platform=process.platform){
  // This combination has standalone profile evidence. Product compatibility
  // still needs integration canaries; every run also performs the OS probe.
  if(platform!=='darwin'||!/^codex-cli 0\.164\.0(?:\s|$)/.test(version))throw new Error('Restricted Codex sandbox requires macOS codex-cli 0.164.0; refusing legacy fallback');
}
function probeReceipt(writable,traceIsolation=false,roleIsolation=false){
  return {schema:'sec-hub.codex-sandbox-probe/v1',policyVersion:2,profile:SANDBOX_PROFILE,platform:'darwin',checks:['target-read','pinned-document-read','runtime-exec','outside-read-denied','symlink-read-denied','target-write-denied',writable?'runner-write':'runner-write-denied',...(traceIsolation?['trace-read-denied','trace-create-denied','trace-modify-denied','trace-delete-denied']:[]),...(roleIsolation?['role-config-read-denied','role-config-create-denied','role-config-modify-denied','role-config-delete-denied']:[])]};
}
export function validateSandboxProbe(receipt,writable,version,traceIsolation=false,roleIsolation=false){
  assertSandboxBackend(version,receipt?.platform);
  if(JSON.stringify(receipt)!==JSON.stringify(probeReceipt(writable,traceIsolation,roleIsolation)))throw new Error('Missing or invalid restricted Codex sandbox preflight evidence');
}
export async function probeSandbox({command,args=[],execArgs,runner,targetFile,skillFile,nodeExecutable,env,signal,traceRoot,roleFile}){
  const probe=await mkdtemp(join(resolve(runner,'..'),'sandbox-probe-')),nonce=randomUUID();
  const outside=join(probe,'outside'),link=join(runner,`sandbox-link-${nonce}`),writeTarget=join(resolve(runner,'../target'),`sandbox-write-${nonce}`),writeRunner=join(runner,`sandbox-write-${nonce}`);
  const traceMarker=traceRoot?join(traceRoot,`sandbox-trace-${nonce}`):undefined,traceCreate=traceRoot?join(traceRoot,`sandbox-create-${nonce}`):undefined;
  const roleCreate=roleFile?join(resolve(roleFile,'..'),`sandbox-create-${nonce}`):undefined;
  try{
    if(roleFile&&!traceRoot)throw new Error('Role isolation requires trace isolation');
    const roleBefore=roleFile?await readFile(roleFile):undefined;
    await writeFile(outside,nonce,{mode:0o600,flag:'wx'});await symlink(outside,link);
    if(traceMarker)await writeFile(traceMarker,nonce,{mode:0o600,flag:'wx'});
    const script='set -eu; /bin/cat "$1" >/dev/null; /bin/cat "$2" >/dev/null; "$3" --version >/dev/null; if /bin/cat "$4" >/dev/null 2>&1; then exit 41; fi; if /bin/cat "$5" >/dev/null 2>&1; then exit 42; fi; if (echo x >"$6") 2>/dev/null; then exit 43; fi; if [ "$8" = write ]; then echo x >"$7"; else if (echo x >"$7") 2>/dev/null; then exit 44; fi; fi; '+(traceMarker?'if /bin/cat "${10}" >/dev/null 2>&1; then exit 45; fi; if (echo x >"${11}") 2>/dev/null; then exit 46; fi; if (echo x >"${10}") 2>/dev/null; then exit 47; fi; if /bin/rm "${10}" >/dev/null 2>&1; then exit 48; fi; ':'')+(roleFile?'if /bin/cat "${12}" >/dev/null 2>&1; then exit 49; fi; if (echo x >"${13}") 2>/dev/null; then exit 50; fi; if (echo x >"${12}") 2>/dev/null; then exit 51; fi; if /bin/rm "${12}" >/dev/null 2>&1; then exit 52; fi; ':'')+'/usr/bin/printf "%s" "$9"';
    const writable=execArgs.some(s=>s.startsWith('permissions=')&&s.includes(`${JSON.stringify(resolve(runner))}="write"`));
    const result=await execute(command,[...args,...sandboxCommandArgs(execArgs,['/bin/sh','-c',script,'sec-hub-probe',targetFile,skillFile,nodeExecutable,outside,link,writeTarget,writeRunner,writable?'write':'read',nonce,...(traceMarker?[traceMarker,traceCreate]:[]),...(roleFile?[roleFile,roleCreate]:[])])],{cwd:runner,env,signal,timeout:10000,maxBuffer:64*1024});
    if(result.stdout!==nonce)throw new Error('Sandbox probe returned unexpected output');
    if(traceMarker){if(await readFile(traceMarker,'utf8')!==nonce)throw new Error('Trace marker changed during sandbox probe');try{await access(traceCreate);throw new Error('Trace root was writable during sandbox probe');}catch(error){if(error.code!=='ENOENT')throw error;}}
    if(roleFile){if(!(await readFile(roleFile)).equals(roleBefore))throw new Error('Role configuration changed during sandbox probe');try{await access(roleCreate);throw new Error('Role configuration root was writable during sandbox probe');}catch(error){if(error.code!=='ENOENT')throw error;}}
    return probeReceipt(writable,Boolean(traceRoot),Boolean(roleFile));
  }catch(cause){throw new Error('Restricted Codex sandbox preflight failed; refusing model execution or legacy fallback',{cause});}
  finally{await Promise.all([rm(probe,{recursive:true,force:true}),rm(link,{force:true}),rm(writeTarget,{force:true}),rm(writeRunner,{force:true}),...(traceMarker?[rm(traceMarker,{force:true}),rm(traceCreate,{force:true})]:[]),...(roleCreate?[rm(roleCreate,{force:true})]:[])]);}
}
