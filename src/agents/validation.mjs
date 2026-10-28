import { constants } from 'node:fs';
import { open, readdir, lstat, mkdir, writeFile } from 'node:fs/promises';
import { join, relative, resolve, isAbsolute } from 'node:path';
import { inspectTerminalOutcome } from './native-errors.mjs';
import { validateAgentOptions } from '../config.mjs';
import { codexArgs,claudeArgs,cloudflarePrompt } from './invocation.mjs';
import { atomicWriteFile } from '../safe-io.mjs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { assertSafeDirectory } from '../safe-io.mjs';
const execute=promisify(execFile);
const prevalidated=new Map();
export const PINS={cloudflare:'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',anthropic:'d3bea6b5793b5f3d59a75ebe69a58efa88383145'};
export const SOURCES={cloudflare:'https://github.com/cloudflare/security-audit-skill',anthropic:'https://github.com/anthropics/defending-code-reference-harness'};
export const OUTPUTS={cloudflare:['run-metadata.json','architecture.md','coverage-ledger.json','findings.json','REPORT.md','FINDINGS-DETAIL.md','NEEDS-VALIDATION.md'],anthropic:['VULN-FINDINGS.json','VULN-FINDINGS.md']};
export function nativeOptions(id,value){
  const options={...(id==='cloudflare'?{strategy:'native-collab',effort:'medium',profile:'quick',maxAgents:10}:{maxTurns:30,maxBudgetUsd:3,mode:'vuln-scan',single:true,noScore:true}),...value};
  if(!['skillRoot','workRoot','revision','model'].every(k=>typeof options[k]==='string'&&options[k].trim()))throw new Error(`${id}: required native agent configuration is missing`);
  return options;
}
export const sha256=value=>createHash('sha256').update(value).digest('hex');
function sameFileState(a,b){return ['dev','ino','mode','nlink','size','mtimeMs','ctimeMs'].every(key=>a[key]===b[key]);}
async function readRegularFile(file,limit){
  if(!Number.isSafeInteger(limit)||limit<0)throw new Error('Invalid bounded read limit');
  await assertSafeDirectory(resolve(file,'..'));
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const before=await handle.stat();if(!before.isFile()||before.nlink!==1||before.size>limit)throw new Error('Unsafe or oversized regular file');
    if(!sameFileState(before,await lstat(file)))throw new Error('File changed during bounded read');
    // One extra byte detects growth, but even a continuously growing file cannot
    // make the descriptor read or allocate beyond its initial size plus one.
    const buffer=Buffer.alloc(before.size+1);let length=0;
    while(length<buffer.length){const {bytesRead}=await handle.read(buffer,length,buffer.length-length,length);if(!bytesRead)break;length+=bytesRead;}
    const after=await handle.stat();await assertSafeDirectory(resolve(file,'..'));
    if(length!==before.size||!sameFileState(before,after)||!sameFileState(before,await lstat(file)))throw new Error('File changed during bounded read');
    return {data:buffer.subarray(0,length),stat:before};
  }finally{await handle.close();}
}
export async function safeRead(file,limit=20*1024*1024){return (await readRegularFile(file,limit)).data;}
export async function sourceManifest(root){
  await assertSafeDirectory(root);const records=[];let total=0;
  async function walk(dir){for(const entry of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){
    if(entry.name==='.git')continue;const path=join(dir,entry.name),rel=relative(root,path).split('\\').join('/');
    if(entry.isSymbolicLink())throw new Error('Source symbolic links are not supported');
    if(entry.isDirectory()){await walk(path);continue;}
    if(!entry.isFile())throw new Error('Source must contain only regular files');
    const data=await safeRead(path);total+=data.length;if(records.length>=10000||total>100*1024*1024)throw new Error('Source manifest size limit exceeded');
    records.push({path:rel,size:data.length,sha256:sha256(data),lines:data.toString('utf8').split('\n').length});
  }}await walk(root);return records.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
}
export async function copySources(source,destination,records){
  await mkdir(destination,{mode:0o700});
  for(const record of records){const src=join(source,record.path),dest=join(destination,record.path);await mkdir(resolve(dest,'..'),{recursive:true,mode:0o700});const data=await safeRead(src);if(sha256(data)!==record.sha256)throw new Error('Source changed before copy');await writeFile(dest,data,{flag:'wx',mode:0o400});}
}
export function sameInputs(a,b){return JSON.stringify(a)===JSON.stringify(b);}

function terminalFailureReason(id,outcome){
  if(outcome.ok)return null;
  // Classification is centralized; these safe provider-specific messages preserve
  // existing diagnostics without copying untrusted backend text or account data.
  if(id==='cloudflare'&&outcome.category==='model_unavailable')return 'Configured native Codex model is not supported with the current CLI and ChatGPT sign-in.';
  if(id==='anthropic'&&outcome.category==='auth_expired')return 'Native Claude OAuth session expired and could not be refreshed; complete native Claude sign-in before retrying.';
  return outcome.reason;
}
// Parse telemetry only; never evaluate shell text. A small literal grammar keeps
// quoted echoes, comments, expansions and unrelated path substrings out of proof.
function literalCommands(command){
  // Validate the entire raw line before comments can truncate parsing. The same
  // check runs again on a decoded shell wrapper's command string.
  if(typeof command!=='string'||/[\x00-\x1f\x7f]/.test(command))return null;
  const commands=[],words=[];let word='',quote=null,started=false;
  const push=()=>{if(started){words.push(word);word='';started=false;}};
  for(let i=0;i<command.length;i++){
    const ch=command[i];if(/[\x00-\x1f\x7f]/.test(ch))return null;
    if(quote==="'"){if(ch==="'")quote=null;else word+=ch;continue;}
    if(quote==='"'){
      if(ch==='"'){quote=null;continue;}
      if(ch==='\\'){const next=command[++i];if(next===undefined)return null;word+='\\"$`'.includes(next)?next:'\\'+next;continue;}
      if(ch==='$'||ch==='`')return null;word+=ch;continue;
    }
    if(ch==="'"||ch==='"'){quote=ch;started=true;continue;}
    if(ch==='\\'){const next=command[++i];if(next===undefined||/[\x00-\x1f\x7f]/.test(next))return null;word+=next;started=true;continue;}
    if(ch==='#'&&!started)break;
    // Only success-chained commands establish a subsequent relative cwd.
    // A semicolon can mask failed cd/read commands with a later successful read.
    if(ch===';')return null;
    if(ch==='&'&&command[i+1]==='&'){
      i++;push();if(!words.length)return null;commands.push(words.splice(0));continue;
    }
    if(/[|&<>`$()]/.test(ch))return null;
    // With raw controls excluded, only ASCII space separates shell words.
    // Unicode whitespace belongs to a literal filename, not a comment boundary.
    if(ch===' '){push();continue;}word+=ch;started=true;
  }
  if(quote)return null;push();if(!words.length)return null;commands.push(words);return commands;
}
function pinnedInstructionRead(command,options){
  let commands=literalCommands(command);if(!commands)return false;
  const wrapper=commands[0];
  if(commands.length===1&&/^\/(?:bin|usr\/bin)\/(?:zsh|bash|sh)$/.test(wrapper[0])){
    if(wrapper.length!==3||!['-c','-lc'].includes(wrapper[1]))return false;
    commands=literalCommands(wrapper[2]);if(!commands)return false;
  }
  if(typeof options.skillRoot!=='string')return false;
  let cwd=options.copyTarget?resolve(options.copyTarget,'../runner'):null,read=false;
  const pinned=resolve(options.skillRoot,'skills/security-audit/SKILL.md'),alias=cwd?resolve(cwd,'.agents/skills/security-audit/SKILL.md'):null;
  const literalPath=path=>typeof path==='string'&&path.length>0&&!/[\x00-\x1f\x7f*?\[\]{}~]/.test(path);
  const count=value=>/^[1-9]\d*$/.test(value??'')&&Number.isSafeInteger(Number(value));
  for(const words of commands){
    const [tool,...args]=words;
    if(tool==='cd'){
      const paths=args[0]==='--'?args.slice(1):args;if(paths.length!==1||!literalPath(paths[0])||paths[0].startsWith('-')||!isAbsolute(paths[0])&&!cwd)return false;
      cwd=resolve(cwd??'/',paths[0]);continue;
    }
    let paths=[];
    if(tool==='cat'){
      let i=0;for(;i<args.length&&args[i].startsWith('-');i++){if(args[i]==='--'){i++;break;}if(!['-n','-b'].includes(args[i]))return false;}paths=args.slice(i);
    }else if(tool==='sed'){
      if(args[0]!=='-n'||!/^([1-9]\d*)(?:,([1-9]\d*))?p$/.test(args[1]??''))return false;paths=args.slice(2);
    }else if(tool==='head'){
      let i=0;if(args[0]==='-n'||args[0]==='-c'){if(!count(args[1]))return false;i=2;}else if(/^-[0-9]+$/.test(args[0]??'')){if(!count(args[0].slice(1)))return false;i=1;}if(args[i]==='--')i++;paths=args.slice(i);
    }else return false;
    if(!paths.length||paths.some(path=>!literalPath(path)||path.startsWith('-')||!isAbsolute(path)&&!cwd))return false;
    if(paths.some(path=>{const file=resolve(cwd??'/',path);return file===pinned||file===alias;}))read=true;
  }
  return read;
}

export function inspectNativeEvents(id,events,options={}){
  const terminalOutcome=inspectTerminalOutcome(id,events,options.exitCode),terminalReason=terminalFailureReason(id,terminalOutcome),reasons=terminalReason?[terminalReason]:[];
  if(id==='cloudflare'){
    const completed=events.filter(e=>e.type==='item.completed').map(e=>e.item).filter(Boolean);
    const instructionRead=completed.some(i=>i.type==='command_execution'&&i.status==='completed'&&i.exit_code===0&&pinnedInstructionRead(i.command,options));
    if(options.skillRoot&&!instructionRead)reasons.push('Missing native pinned security-audit instruction read');
    const spawns=completed.filter(i=>i.type==='collab_tool_call'&&i.tool==='spawn_agent'&&i.status==='completed');
    const roleNames=['recon-architecture','recon-boundaries','recon-execution','recon-companions','hunter','critic-final','verifier'];
    const roles={};for(const role of roleNames)roles[role]=spawns.filter(i=>new RegExp(`SEC_HUB_ROLE=${role}(?:[-\\s]|$)`).test(i.prompt??'')).flatMap(i=>i.receiver_thread_ids??[]);
    for(const role of roleNames)if(!roles[role].length)reasons.push(`Missing native delegated role ${role}`);
    for(const spawn of spawns)if(roleNames.filter(role=>new RegExp(`SEC_HUB_ROLE=${role}(?:[-\\s]|$)`).test(spawn.prompt??'')).length!==1||(spawn.receiver_thread_ids??[]).length!==1)reasons.push('Native phase roles must have distinct single-agent assignments');
    const ids=spawns.flatMap(i=>i.receiver_thread_ids??[]),states=new Set(completed.filter(i=>i.type==='collab_tool_call'&&i.status==='completed').flatMap(i=>Object.entries(i.agents_states??{}).filter(([,state])=>state.status==='completed').map(([key])=>key)));
    if(ids.some(id=>!states.has(id)))reasons.push('Native delegated work did not complete');
    if(ids.length> (options.maxAgents??10)||new Set(ids).size!==ids.length)reasons.push('Native delegation budget or identity violation');
    if(!events.some(e=>e.type==='turn.completed')||events.some(e=>['turn.failed','error'].includes(e.type)))reasons.push('Native Codex turn did not succeed');
    const at=spawn=>events.findIndex(e=>e.type==='item.completed'&&e.item===spawn);
    const completedAt=id=>events.findIndex(e=>e.type==='item.completed'&&e.item?.agents_states?.[id]?.status==='completed');
    const groups={recon:spawns.filter(i=>/^SEC_HUB_ROLE=recon-/m.test(i.prompt??'')||/SEC_HUB_ROLE=recon-/.test(i.prompt??'')),hunter:spawns.filter(i=>/SEC_HUB_ROLE=hunter(?:[-\s]|$)/.test(i.prompt??'')),critic:spawns.filter(i=>/SEC_HUB_ROLE=critic-final(?:\s|$)/.test(i.prompt??'')),verifier:spawns.filter(i=>/SEC_HUB_ROLE=verifier(?:[-\s]|$)/.test(i.prompt??''))};
    if(groups.recon.length!==4||groups.critic.length!==1)reasons.push('Expected exactly four baseline recon agents and one final critic');
    const phases=['recon','hunter','critic','verifier'];
    for(let i=1;i<phases.length;i++){const previous=groups[phases[i-1]],next=groups[phases[i]];if(previous.length&&next.length){const finish=Math.max(...previous.flatMap(x=>(x.receiver_thread_ids??[]).map(completedAt)));if(next.some(x=>at(x)<=finish))reasons.push(`Native phase order failed before ${phases[i]}`);}}
    return {complete:!reasons.length,reasons,terminalReason,terminalOutcome,roles,spawnCount:ids.length,completedAgentIds:[...states],phaseOrder:phases,instructionRead,verifierThreadIds:roles.verifier};
  }
  const content=events.flatMap(e=>e.message?.content??[]);
  const activations=content.filter(c=>c.type==='tool_use'&&c.name==='Skill'&&['vuln-scan','/vuln-scan'].includes(c.input?.skill));
  const targetMatches=args=>{const tokens=(args??'').match(/"(?:[^"\\]|\\.)*"|'[^']*'|[^\s]+/g)??[];let first=tokens[0];if(first?.startsWith('"'))try{first=JSON.parse(first);}catch{return false;}else if(first?.startsWith("'"))first=first.slice(1,-1);return !options.copyTarget||first===options.copyTarget;};
  const loaded=activations.filter(a=>targetMatches(a.input.args)&&typeof a.input.args==='string'&&/(?:^|\s)--single(?:\s|$)/.test(a.input.args)&&/(?:^|\s)--no-score(?:\s|$)/.test(a.input.args)&&content.some(c=>c.type==='tool_result'&&c.tool_use_id===a.id&&c.is_error!==true));
  if(!loaded.length)reasons.push('Missing successful native vuln-scan Skill activation');
  const results=events.filter(e=>e.type==='result'),last=results.at(-1);
  if(!last||last.subtype!=='success'||last.is_error!==false||results.some(e=>e.is_error===true||e.subtype!=='success'))reasons.push('Native Claude terminal result did not succeed');
  if(results.some(e=>Array.isArray(e.permission_denials)&&e.permission_denials.length))reasons.push('Native Claude permission denial');
  return {complete:!reasons.length,reasons,terminalReason,terminalOutcome,skillActivationIds:loaded.map(x=>x.id),terminalSubtype:last?.subtype??null};
}

function canonical(value){if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));return value;}
export function verifyCloudflareRecords(records,events,native){
  if(!Array.isArray(records))throw new Error('Cloudflare native findings must be an array');
  const completed=events.filter(e=>e.type==='item.completed'&&e.item?.type==='collab_tool_call').flatMap(e=>Object.entries(e.item.agents_states??{}).filter(([,s])=>s.status==='completed').map(([thread,state])=>({thread,message:state.message})));
  const verifiers=(native.verifierThreadIds??[]).map(thread=>{const message=completed.filter(x=>x.thread===thread).at(-1)?.message;let response;try{response=JSON.parse(message);}catch{return {thread,invalid:true};}return {thread,response};});
  const used=new Set(),proof=[];
  for(const record of records){
    const match=verifiers.find(v=>!used.has(v.thread)&&v.response?.record?.fingerprint===record.fingerprint&&v.response.decision===record.verdict&&JSON.stringify(canonical(v.response.record))===JSON.stringify(canonical(record)));
    if(!match)throw new Error(`Cloudflare final record lacks unchanged native independent verifier JSON: ${record.fingerprint}`);
    used.add(match.thread);proof.push({fingerprint:record.fingerprint,threadId:match.thread,decision:record.verdict});
  }
  if(!records.length&&!verifiers.some(v=>v.response?.decision==='verified'&&v.response.scope==='final-empty-result'))throw new Error('Cloudflare empty output lacks native independent final verification');
  return proof;
}
const text=x=>typeof x==='string'&&x.trim().length>0;
export function parseAnthropicDocument(doc,{copyTarget,inputs,artifactDir}){
  if(!doc||typeof doc!=='object'||Array.isArray(doc)||resolve(doc.target??'')!==resolve(copyTarget)||!text(doc.scanned_at)||!Number.isFinite(Date.parse(doc.scanned_at))||!Array.isArray(doc.focus_areas)||!doc.focus_areas.length||doc.focus_areas.some(x=>!text(x))||!Array.isArray(doc.findings)||doc.findings.length>1000||!doc.summary)throw new Error('Anthropic unsupported native document');
  const ids=new Set(),counts={total:doc.findings.length,high:0,medium:0,low:0,low_confidence:0};
  const findings=doc.findings.map(f=>{
    if(!f||!/^F-\d{3,}$/.test(f.id)||ids.has(f.id)||!['HIGH','MEDIUM','LOW'].includes(f.severity)||!Number.isFinite(f.confidence)||f.confidence<0||f.confidence>1||!['category','title','description','exploit_scenario','recommendation'].every(k=>text(f[k]))||!text(f.file))throw new Error('Anthropic invalid native finding');ids.add(f.id);
    const path=isAbsolute(f.file)?relative(copyTarget,f.file).split('\\').join('/'):f.file;
    const input=inputs.find(x=>x.path===path);if(!input||path.startsWith('../')||path.includes('\\')||!Number.isInteger(f.line)||f.line<1||f.line>input.lines)throw new Error('Anthropic invalid finding location');
    counts[f.severity.toLowerCase()]++;if(f.confidence<0.4)counts.low_confidence++;
    return {id:f.id,toolId:'anthropic',ruleId:f.category,title:f.title,description:f.description,severity:f.severity.toLowerCase(),location:{path,line:f.line},verification:'candidate',evidence:{native:f,dynamicVerification:'not-performed',limitation:'Official static vuln-scan; no ASAN pipeline or execution verification.'},rawRef:join(artifactDir,'VULN-FINDINGS.json')};
  });
  if(Object.keys(counts).some(k=>doc.summary[k]!==counts[k]))throw new Error('Anthropic native summary counts disagree');return findings;
}
export async function verifySourcePin(id,options,{signal}={}){
  signal?.throwIfAborted();
  if(options.revision!==PINS[id])throw new Error('Unsupported official source pin');
  const root=await assertSafeDirectory(options.skillRoot);
  const git=async args=>{signal?.throwIfAborted();const result=await execute('git',['--no-replace-objects','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',root,...args],{timeout:10000,maxBuffer:2*1024*1024,signal,env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_NO_REPLACE_OBJECTS:'1'}});signal?.throwIfAborted();return result.stdout;};
  if((await git(['rev-parse','--show-toplevel'])).trim()!==root||(await git(['rev-parse','HEAD'])).trim()!==PINS[id])throw new Error('Official source checkout must match pinned revision');
  if((await git(['for-each-ref','--format=%(refname)','refs/replace/'])).trim())throw new Error('Official source replacement refs are unsupported');
  const tree=await git(['ls-tree','-r','-z','--full-tree',PINS[id]]),tracked=new Map(),directories=new Set();
  for(const entry of tree.split('\0').filter(Boolean)){
    const match=/^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/s.exec(entry);
    if(!match)throw new Error('Unsupported pinned source tree entry');
    const [,mode,oid,path]=match,parts=path.split('/');
    if(parts.some(part=>!part||part==='.'||part==='..'||part==='.git'||part.includes('\\'))||tracked.has(path))throw new Error('Unsupported pinned source path');
    tracked.set(path,{mode,oid});for(let i=1;i<parts.length;i++)directories.add(parts.slice(0,i).join('/'));
  }
  if(!tracked.size)throw new Error('Official pinned source tree is empty');
  const files=new Map();let total=0;
  async function walk(dir){
    for(const entry of await readdir(dir,{withFileTypes:true})){
      if(dir===root&&entry.name==='.git')continue;
      const file=join(dir,entry.name),path=relative(root,file).split('\\').join('/');
      if(entry.isDirectory()){if(!directories.has(path))throw new Error('Unexpected official source directory');await walk(file);continue;}
      const expected=tracked.get(path);if(!entry.isFile()||!expected)throw new Error('Unexpected or unsupported official source file');
      const {data,stat}=await readRegularFile(file,20*1024*1024);total+=data.length;
      if(files.size>=10000||total>100*1024*1024)throw new Error('Official source size limit exceeded');
      const oid=createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex');
      if(oid!==expected.oid||Boolean(stat.mode&0o111)!==(expected.mode==='100755'))throw new Error('Official source bytes or executable mode differ from pinned tree');
      files.set(path,data);
    }
  }
  // This authenticates a point-in-time checkout, including files outside the
  // instruction subset, without index flags, status, attributes or clean filters.
  // Git/PATH, local repository metadata and the same-user host remain trusted;
  // subsequent hostile writes cannot be made atomic with later code execution.
  await walk(root);if(files.size!==tracked.size)throw new Error('Official source files missing from pinned tree');
  if((await git(['rev-parse','HEAD'])).trim()!==PINS[id]||(await git(['for-each-ref','--format=%(refname)','refs/replace/'])).trim())throw new Error('Official source revision changed during verification');
  const paths=id==='cloudflare'?[...files.keys()].filter(path=>/^skills\/security-audit\/[^/]+\.(md|json|cjs)$/.test(path)&&!path.includes('.test.')):['.claude/settings.json','.claude/skills/vuln-scan/SKILL.md'];
  const instructions=[];for(const path of paths){const data=files.get(path);if(!data||data.length>2*1024*1024)throw new Error('Missing or oversized pinned instruction');instructions.push({path,sha256:sha256(data)});}
  if(id==='anthropic'){const settings=JSON.parse(files.get('.claude/settings.json').toString());if(JSON.stringify(settings)!==JSON.stringify({env:{ANTHROPIC_CUSTOM_HEADERS:'anthropic-cyber-runbook: skills'}}))throw new Error('Unsupported pinned project settings');}
  return instructions.sort((a,b)=>a.path.localeCompare(b.path));
}
export async function runOfficialValidators(options,artifactDir,{signal}={}){
  signal?.throwIfAborted();await verifySourcePin('cloudflare',options,{signal});signal?.throwIfAborted();
  const results=[];for(const [script,file] of [['validate-findings.cjs','findings.json'],['validate-coverage-ledger.cjs','coverage-ledger.json']]){
    signal?.throwIfAborted();
    try{const result=await execute(process.execPath,[join(options.skillRoot,'skills/security-audit',script),join(artifactDir,file)],{timeout:10000,maxBuffer:256*1024,signal});results.push({script,exitCode:0,stdout:result.stdout.trim()});}catch(error){signal?.throwIfAborted();results.push({script,exitCode:typeof error.code==='number'?error.code:1,stderr:String(error.stderr??'validator failed').slice(0,10000)});}
  }return results;
}
export async function finalizeNativeExecution(id,ctx){
  const options=nativeOptions(id,validateAgentOptions(id,ctx.config?.tools?.[id]?.agentOptions));
  if(id==='cloudflare'&&options.strategy==='supervised-codex-workers')return (await import('./supervised-validation.mjs')).finalizeSupervisedCloudflare(ctx);
  const key=resolve(ctx.artifactDir),expected=prevalidated.get(key);
  if(!expected)throw new Error('Native execution was not validated before redaction');
  const manifestFile=join(ctx.artifactDir,'execution-manifest.json');
  const bytes=await safeRead(manifestFile);if(sha256(bytes)!==expected)throw new Error('Trusted native manifest changed during redaction');
  const manifest=JSON.parse(bytes.toString()),hashes={};
  for(const name of [...OUTPUTS[id],'native-events.jsonl','native-stderr.log'])hashes[name]=sha256(await safeRead(join(ctx.artifactDir,name)));
  manifest.finalRetainedHashes=hashes;manifest.finalHashScope='retained bytes after redaction';
  await atomicWriteFile(manifestFile,`${JSON.stringify(manifest,null,2)}\n`);prevalidated.delete(key);
  return validateNativeExecution(id,ctx);
}
export async function validateNativeExecution(id,ctx){
  const configured=ctx.config?.tools?.[id]?.agentOptions;if(!configured)throw new Error(`${id}: explicit native agent configuration required`);
  const options=nativeOptions(id,validateAgentOptions(id,configured));
  if(id==='cloudflare'&&options.strategy==='supervised-codex-workers')return (await import('./supervised-validation.mjs')).validateSupervisedCloudflare(ctx);
  const manifestBytes=await safeRead(join(ctx.artifactDir,'execution-manifest.json'));
  const manifest=JSON.parse(manifestBytes.toString());
  if(manifest.schema!=='sec-hub.native-agent/v1'||manifest.id!==id||manifest.sourceCommit!==PINS[id]||manifest.source!==SOURCES[id]||resolve(manifest.target??'')!==resolve(ctx.target)||!Array.isArray(manifest.inputs)||!manifest.inputs.length)throw new Error(`${id}: invalid trusted execution manifest`);
  if(id==='cloudflare'&&(manifest.strategy??'native-collab')!==options.strategy)throw new Error('cloudflare: native execution strategy differs');
  if(manifest.model!==options.model||manifest.backend!==(id==='cloudflare'?'codex':'claude')||manifest.mode!==(id==='cloudflare'?'official-security-audit-skill':'official-claude-code-vuln-scan')||!text(manifest.backendVersion)||manifest.invocation?.command!==ctx.config.tools[id].command||!Array.isArray(manifest.invocation.args)||!sameInputs(manifest.invocation.args.slice(0,(ctx.config.tools[id].args??[]).length),ctx.config.tools[id].args??[]))throw new Error(`${id}: native backend configuration differs`);
  if(!text(manifest.nativeNodeExecutable)||!isAbsolute(manifest.nativeNodeExecutable)||/[\x00-\x1f\x7f]/.test(manifest.nativeNodeExecutable)||!/^\d+\.\d+\.\d+/.test(manifest.nativeNodeVersion??'')||Number.parseInt(manifest.nativeNodeVersion)<22)throw new Error(`${id}: missing or invalid native Node runtime evidence`);
  const runner=resolve(manifest.copyTarget,'../runner'),expectedArgs=id==='cloudflare'?codexArgs(runner,options,manifest.nativeNodeExecutable):claudeArgs(manifest.copyTarget,options,{artifactDir:ctx.artifactDir},manifest.inputs);
  if(manifest.invocation.cwd!==(id==='cloudflare'?runner:options.skillRoot)||!sameInputs(manifest.invocation.args,[...(ctx.config.tools[id].args??[]),...expectedArgs])||(id==='cloudflare'&&manifest.promptSha256!==sha256(cloudflarePrompt(manifest.copyTarget,join(runner,'audit'),options))))throw new Error(`${id}: native invocation does not match trusted policy`);
  const instructions=await verifySourcePin(id,options);if(!sameInputs(instructions,manifest.instructions))throw new Error(`${id}: official instruction hashes differ`);
  const current=await sourceManifest(ctx.target);if(!sameInputs(current,manifest.inputs)||!sameInputs(manifest.inputs,manifest.copyBefore)||!sameInputs(manifest.inputs,manifest.copyAfter)||!sameInputs(manifest.inputs,manifest.originalAfter))throw new Error(`${id}: source preservation failed`);
  const events=(await safeRead(join(ctx.artifactDir,'native-events.jsonl'))).toString().split('\n').filter(x=>x.trim()).map(x=>JSON.parse(x));
  const native=inspectNativeEvents(id,events,{...options,copyTarget:manifest.copyTarget,exitCode:manifest.process?.exitCode});const retainedHashes={};
  const missing=[];
  for(const file of [...OUTPUTS[id],'native-events.jsonl','native-stderr.log']){try{const data=await safeRead(join(ctx.artifactDir,file));retainedHashes[file]=sha256(data);}catch{missing.push(file);}}
  if(missing.length){
    const error=new Error(`${id}: native workflow incomplete: ${native.terminalReason??native.reasons[0]??'Native output is missing or unsafe'}; missing or unsafe outputs: ${missing.join(', ')}`);
    error.findings=[];
    if(id==='anthropic'&&!missing.includes('VULN-FINDINGS.json'))try{error.findings=parseAnthropicDocument(JSON.parse((await safeRead(join(ctx.artifactDir,'VULN-FINDINGS.json'))).toString()),{copyTarget:manifest.copyTarget,inputs:manifest.inputs,artifactDir:ctx.artifactDir});}catch{}
    throw error;
  }
  const sealed=manifest.finalRetainedHashes??manifest.preRedactionHashes;if(!sealed||Object.entries(retainedHashes).some(([name,hash])=>sealed[name]!==hash))throw new Error(`${id}: retained native evidence hashes differ`);
  let findings=[],validators=[];const reasons=[...native.reasons];
  if(id==='cloudflare'){
    validators=await runOfficialValidators(options,ctx.artifactDir);if(validators.some(x=>x.exitCode!==0))reasons.push('Official native validator failed');
    const metadata=JSON.parse((await safeRead(join(ctx.artifactDir,'run-metadata.json'))).toString());if(metadata.run_status!=='complete'||metadata.profile!=='quick')reasons.push('Official audit run is incomplete');
    const doc=JSON.parse((await safeRead(join(ctx.artifactDir,'findings.json'))).toString());
    if(validators.every(x=>x.exitCode===0)&&Array.isArray(doc)){native.independentRecords=verifyCloudflareRecords(doc,events,native);findings=doc.filter(f=>f.verdict!=='rejected').map(f=>{const loc=f.trace[0],input=manifest.inputs.find(x=>x.path===loc.file);if(!input||loc.line>input.lines)throw new Error('Cloudflare invalid finding location');if(f.verdict==='confirmed')reasons.push('Source-only workflow cannot retain dynamic confirmation');return {toolId:id,ruleId:f.fingerprint,title:f.title,description:f.description,severity:f.verdict==='needs_validation'?'unknown':f.severity.overall_severity==='informational'?'info':f.severity.overall_severity,verification:'candidate',location:{path:loc.file,line:loc.line},evidence:{native:f,dynamicVerification:'not-performed'},rawRef:join(ctx.artifactDir,'findings.json')};});}
  }else findings=parseAnthropicDocument(JSON.parse((await safeRead(join(ctx.artifactDir,'VULN-FINDINGS.json'))).toString()),{copyTarget:manifest.copyTarget,inputs:manifest.inputs,artifactDir:ctx.artifactDir});
  if(ctx.exitCode!==0||manifest.process?.exitCode!==0||manifest.process?.interrupted||manifest.process?.outputLimitExceeded)reasons.push('Native process did not exit successfully');
  if(manifest.status!=='complete')reasons.push('Wrapper marked execution incomplete',...(Array.isArray(manifest.reasons)?manifest.reasons:[]));
  const execution={mode:id==='cloudflare'?'official-security-audit-skill':'official-claude-code-vuln-scan',backend:id==='cloudflare'?'codex':'claude',...(id==='cloudflare'?{strategy:options.strategy}:{}),sourceCommit:PINS[id],source:SOURCES[id],model:manifest.model,backendVersion:manifest.backendVersion,manifestPath:join(ctx.artifactDir,'execution-manifest.json'),dynamicVerification:'not-performed',limitations:id==='cloudflare'?['Source-only; target execution was not authorized.','Quick profile is partial coverage.']:['Static source candidates only; C/C++ Docker/gVisor/ASAN pipeline was not executed.'],nativeEvidence:native,validators,retainedHashes,hashScope:'retained bytes after redaction',sourcePreserved:true};
  if(reasons.length){const error=new Error(`${id}: native workflow incomplete: ${[...new Set(reasons)].join('; ')}`);error.findings=findings;error.execution=execution;throw error;}if(!manifest.finalRetainedHashes)prevalidated.set(resolve(ctx.artifactDir),sha256(manifestBytes));return {findings,execution};
}
