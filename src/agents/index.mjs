import { fileURLToPath } from 'node:url';
import { runProcess } from '../processes.mjs';
import { validateAgentOptions } from '../config.mjs';
import { validateNativeExecution, finalizeNativeExecution, nativeOptions, verifySourcePin, SOURCES } from './validation.mjs';
import { assertSandboxBackend } from './codex-sandbox.mjs';
export { validateNativeExecution } from './validation.mjs';
const wrapper=fileURLToPath(new URL('./native-wrapper.mjs',import.meta.url));
function configuration(id,ctx){
  const cfg=ctx.config?.tools?.[id];if(!cfg||typeof cfg.command!=='string'||!cfg.command.trim()||!Array.isArray(cfg.args??[])||(cfg.args??[]).some(x=>typeof x!=='string'))throw new Error(`${id}: explicit native executable configuration required`);
  return {id,command:cfg.command,args:cfg.args??[],agentOptions:nativeOptions(id,validateAgentOptions(id,cfg.agentOptions)),target:ctx.target,artifactDir:ctx.artifactDir};
}
async function check(id,ctx){
  try{ctx.signal?.throwIfAborted();const cfg=configuration(id,ctx);await verifySourcePin(id,cfg.agentOptions,{signal:ctx.signal,onCleanupUnconfirmed:ctx.onCleanupUnconfirmed,superviseProcesses:true});ctx.signal?.throwIfAborted();const probe=await runProcess({command:cfg.command,args:[...cfg.args,'--version']},{timeoutMs:ctx.probeTimeoutMs??10000,maxOutputBytes:64*1024,signal:ctx.signal,onCleanupUnconfirmed:ctx.onCleanupUnconfirmed});if(probe.status!=='completed'||!(probe.stdout||probe.stderr).trim())return {available:false,reason:'Native CLI version probe failed.'};const version=(probe.stdout||probe.stderr).trim();if(id==='cloudflare')assertSandboxBackend(version);return {available:true,version:version.slice(0,500)};}catch(error){return {available:false,reason:error.message};}
}
export const nativeAgentAdapters=['cloudflare','anthropic'].map(id=>({
  id,name:id==='cloudflare'?'Cloudflare Security Audit Skill (native Codex)':'Anthropic Defending Code (native static vuln-scan)',kind:'agent',source:SOURCES[id],requiresAI:true,
  network:'Source and context are uploaded to the configured model backend; target execution is prohibited.',
  install:'Install the official native backend and configure a clean pinned official skill checkout; existing native authentication is used.',
  check:ctx=>check(id,ctx),
  build:ctx=>({command:ctx.nodeExecutable??process.execPath,args:[wrapper,JSON.stringify(configuration(id,ctx))],successCodes:[0],findingCodes:[2]}),
  parse:async ctx=>(await validateNativeExecution(id,ctx)).findings,
  executionMetadata:async ctx=>(await finalizeNativeExecution(id,ctx)).execution,
}));
