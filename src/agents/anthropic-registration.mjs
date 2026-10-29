// This session-only plugin is host-owned; no target/model/config data defines it.
import {constants} from 'node:fs';
import {mkdir,writeFile,open,lstat,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {assertSafeDirectory} from '../safe-io.mjs';
export const ANTHROPIC_SKILL='sec-hub-anthropic:vuln-scan';
const sourceCommit='d3bea6b5793b5f3d59a75ebe69a58efa88383145',sourceSkillPath='.claude/skills/vuln-scan/SKILL.md',sourceSkillSha256='49e44d80ef199e695cae11801bb4f38d5efc15bcd7e5b5522116c977c77e2405';
const pluginManifest=Buffer.from(`${JSON.stringify({name:'sec-hub-anthropic',version:'1.0.0',description:'Pinned official Anthropic static vulnerability scan.'},null,2)}\n`);
const digest=data=>createHash('sha256').update(data).digest('hex');
const pluginFiles=[{path:'.claude-plugin/plugin.json',sha256:digest(pluginManifest)},{path:'skills/vuln-scan/SKILL.md',sha256:sourceSkillSha256}];
export const registrationFiles=['skill-registration/plugin.json','skill-registration/SKILL.md'];
export const anthropicPluginRoot=copy=>resolve(copy,'../runner/anthropic-plugin');
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
// Avoid a validation/invocation import cycle. Reads are bounded and check the
// same inode, size and metadata before/after; same-user host code is trusted.
async function read(file,limit=16*1024){
  await assertSafeDirectory(resolve(file,'..'));
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  const same=(a,b)=>['dev','ino','mode','nlink','size','mtimeMs','ctimeMs'].every(k=>a[k]===b[k]);
  try{
    const before=await handle.stat();if(!before.isFile()||before.nlink!==1||before.size>limit||!same(before,await lstat(file)))throw new Error('Unsafe Anthropic registration file');
    const data=Buffer.alloc(before.size+1);let n=0;while(n<data.length){const {bytesRead}=await handle.read(data,n,data.length-n,n);if(!bytesRead)break;n+=bytesRead;}
    await assertSafeDirectory(resolve(file,'..'));
    if(n!==before.size||!same(before,await handle.stat())||!same(before,await lstat(file)))throw new Error('Anthropic registration file changed during read');
    return data.subarray(0,n);
  }finally{await handle.close();}
}
function expectedReceipt(copy){return {schema:'sec-hub.anthropic-skill-registration/v1',pluginName:'sec-hub-anthropic',skillName:ANTHROPIC_SKILL,pluginRoot:anthropicPluginRoot(copy),sourceCommit,sourceSkillPath,sourceSkillSha256,files:pluginFiles,retainedFiles:registrationFiles,initialFiles:pluginFiles,finalFiles:pluginFiles};}
export function anthropicPolicyVersion(manifest){
  const version=manifest.invocationPolicyVersion;
  if(version===undefined){if(manifest.skillRegistration!==undefined||[manifest.preRedactionHashes,manifest.finalRetainedHashes].some(hashes=>Object.keys(hashes??{}).some(key=>key.startsWith('skill-registration/'))))throw new Error('Legacy Anthropic policy cannot contain a registration receipt');return 1;}
  if(![2,3].includes(version))throw new Error('Unsupported Anthropic invocation policy version');
  return version;
}
async function sourceBytes(skillRoot,instructions){
  if(!instructions.some(x=>x.path===sourceSkillPath&&x.sha256===sourceSkillSha256))throw new Error('Anthropic registration lacks verified pinned instruction');
  const bytes=await read(join(skillRoot,sourceSkillPath));if(bytes.length!==12126||digest(bytes)!==sourceSkillSha256)throw new Error('Anthropic registration source differs from pinned skill');return bytes;
}
export async function verifyStagedRegistration(copy){
  const root=anthropicPluginRoot(copy),seen=[];
  const dirs=new Set(['','.claude-plugin','skills','skills/vuln-scan']);
  async function walk(path=''){
    const directory=join(root,path);await assertSafeDirectory(directory);
    if(((await lstat(directory)).mode&0o777)!==0o700)throw new Error('Unsafe Anthropic registration directory mode');
    for(const entry of await readdir(directory,{withFileTypes:true})){
      const rel=path?`${path}/${entry.name}`:entry.name,file=join(root,rel);
      if(entry.isDirectory()){if(!dirs.has(rel))throw new Error('Unexpected Anthropic registration directory');await walk(rel);continue;}
      if(!entry.isFile()||!pluginFiles.some(x=>x.path===rel)||((await lstat(file)).mode&0o777)!==0o400)throw new Error('Unsafe or unexpected Anthropic registration file');
      seen.push({path:rel,sha256:digest(await read(file))});
    }
  }
  await walk();seen.sort((a,b)=>a.path.localeCompare(b.path));
  if(!equal(seen,pluginFiles))throw new Error('Anthropic registration bytes or inventory differ');return seen;
}
export async function createAnthropicRegistration(copy,skillRoot,instructions,artifactDir){
  const skill=await sourceBytes(skillRoot,instructions),root=anthropicPluginRoot(copy);
  for(const dir of ['', '.claude-plugin','skills','skills/vuln-scan'])await mkdir(join(root,dir),{mode:0o700});
  await writeFile(join(root,pluginFiles[0].path),pluginManifest,{flag:'wx',mode:0o400});await writeFile(join(root,pluginFiles[1].path),skill,{flag:'wx',mode:0o400});
  const initialFiles=await verifyStagedRegistration(copy);
  await mkdir(join(artifactDir,'skill-registration'),{mode:0o700});
  for(const [i,bytes] of [pluginManifest,skill].entries())await writeFile(join(artifactDir,registrationFiles[i]),bytes,{flag:'wx',mode:0o400});
  const receipt=expectedReceipt(copy);delete receipt.finalFiles;receipt.initialFiles=initialFiles;return receipt;
}
export async function validateAnthropicRegistration(receipt,copy,skillRoot,instructions,artifactDir){
  if(!equal(receipt,expectedReceipt(copy)))throw new Error('Anthropic registration receipt differs from trusted policy');
  const skill=await sourceBytes(skillRoot,instructions);
  const retained=join(artifactDir,'skill-registration');await assertSafeDirectory(retained);
  const entries=await readdir(retained);if(entries.length!==2||!entries.includes('plugin.json')||!entries.includes('SKILL.md'))throw new Error('Unexpected retained Anthropic registration inventory');
  if(!(await read(join(artifactDir,registrationFiles[0]))).equals(pluginManifest)||!(await read(join(artifactDir,registrationFiles[1]))).equals(skill))throw new Error('Retained Anthropic registration bytes differ');
  return true;
}
