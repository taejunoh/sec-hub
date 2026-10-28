import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp,mkdir,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectNativeEvents } from '../src/agents/validation.mjs';
const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
const proof=(command,options,result={status:0,stdout:''})=>inspectNativeEvents('cloudflare',[{type:'item.completed',item:{type:'command_execution',command,status:'completed',exit_code:result.status,aggregated_output:result.stdout}}],options).instructionRead;
async function fixture(run){const root=await mkdtemp(join(tmpdir(),'r022-read-control-'));try{const runner=join(root,'runner'),skillRoot=join(root,'pinned'),pinnedDir=join(skillRoot,'skills/security-audit');await mkdir(runner);await mkdir(pinnedDir,{recursive:true});await writeFile(join(runner,'DECOY'),'DECOY\n');await writeFile(join(pinnedDir,'SKILL.md'),'PINNED\n');await run({runner,pinnedDir,options:{skillRoot,copyTarget:join(root,'target')}});}finally{await rm(root,{recursive:true,force:true});}}
test('#15 hidden newline after a comment cannot turn actual DECOY output into pinned-read proof',async()=>fixture(async({runner,pinnedDir,options})=>{
 const failed=`cat ${quote(pinnedDir+'/missing/../SKILL.md')}`;
 for(const prefix of [failed,`/bin/sh -c ${quote(failed)}`])for(const newline of ['\n','\r\n']){
  const command=`${prefix} # harmless comment${newline}cat DECOY`,result=spawnSync('/bin/sh',['-c',command],{cwd:runner,encoding:'utf8'});
  assert.equal(result.status,0);assert.equal(result.stdout,'DECOY\n');assert.match(result.stderr,/No such file/);assert.equal(proof(command,options,result),false,JSON.stringify(command));
 }
}));
test('#15 single-line evidence rejects every raw ASCII control even after comments or wrappers',()=>{
 const options={skillRoot:'/pinned',copyTarget:'/stage/target'},read="cat '/pinned/skills/security-audit/SKILL.md'";
 for(const code of [...Array.from({length:32},(_,i)=>i),127])for(const prefix of [read,`/bin/sh -c ${quote(read)}`]){
  const command=prefix+' # ignored comment'+String.fromCharCode(code)+'suffix';assert.equal(proof(command,options),false,`control ${code}: ${prefix}`);
 }
});
test('#15 actual one-line commented pinned readers and pure successful chains remain valid',async()=>fixture(async({runner,pinnedDir,options})=>{
 const read=`cat ${quote(pinnedDir+'/SKILL.md')}`;
 for(const command of [read+' # harmless comment',`/bin/sh -c ${quote(read+' # harmless comment')}`,`/bin/sh -c ${quote(read)} # harmless comment`,`cd ${quote(pinnedDir)} && cat SKILL.md # harmless comment`]){
  const result=spawnSync('/bin/sh',['-c',command],{cwd:runner,encoding:'utf8'});assert.equal(result.status,0);assert.equal(result.stdout,'PINNED\n');assert.equal(proof(command,options,result),true,command);
 }
}));
test('#15 Unicode filename whitespace cannot fabricate a shell comment hiding a decoy command',async()=>fixture(async({runner,pinnedDir,options})=>{
 for(const whitespace of ['\u00a0','\u2003','\u2028','\ufeff']){
  const command=`cat ${quote(pinnedDir+'/SKILL.md')}${whitespace}# harmless; cat DECOY`,result=spawnSync('/bin/sh',['-c',command],{cwd:runner,encoding:'utf8'});
  assert.equal(result.status,0);assert.equal(result.stdout,'DECOY\n');assert.match(result.stderr,/No such file/);assert.equal(proof(command,options,result),false,JSON.stringify(command));
 }
}));

test('#15 unquoted literal Unicode whitespace in a pinned filename preserves a genuine read',async()=>fixture(async({runner,pinnedDir,options})=>{
 const unicodeRoot=options.skillRoot+'\u00a0literal',unicodeDir=join(unicodeRoot,'skills/security-audit');await mkdir(unicodeDir,{recursive:true});await writeFile(join(unicodeDir,'SKILL.md'),'PINNED\n');
 for(const command of [`cat ${unicodeDir}/SKILL.md`,`/bin/sh -c ${quote(`cat ${unicodeDir}/SKILL.md`)}`]){const result=spawnSync('/bin/sh',['-c',command],{cwd:runner,encoding:'utf8'});assert.equal(result.status,0);assert.equal(result.stdout,'PINNED\n');assert.equal(proof(command,{...options,skillRoot:unicodeRoot},result),true);}
}));
