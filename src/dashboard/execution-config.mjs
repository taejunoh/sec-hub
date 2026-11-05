import { open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, relative, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { assertSafeDirectory, ensureSafeDirectory } from '../safe-io.mjs';
import { loadConfig } from '../config.mjs';
import { adapters } from '../adapters/index.mjs';

const MAX_BYTES=256*1024;
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).every(key=>keys.includes(key));
const positive=(value,max)=>Number.isSafeInteger(value)&&value>0&&value<=max;
function freeze(value){if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
function invalid(){throw Object.assign(new Error('Invalid execution configuration'),{code:'invalid_execution_config',statusCode:400});}
function contains(parent,child){const rel=relative(parent,child);return rel===''||(!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith(`..${sep}`));}
export async function directoryIdentity(requested,create=false){
  if(typeof requested!=='string'||!isAbsolute(requested))invalid();
  const path=await (create?ensureSafeDirectory:assertSafeDirectory)(requested);
  const entry=await lstat(path);return {path,dev:entry.dev,ino:entry.ino};
}
async function readBounded(filename){
  if(typeof filename!=='string'||!isAbsolute(filename))invalid();
  await assertSafeDirectory(dirname(filename));
  const before=await lstat(filename);
  if(!before.isFile()||before.isSymbolicLink()||before.size>MAX_BYTES)invalid();
  const handle=await open(filename,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const opened=await handle.stat();
    if(!opened.isFile()||opened.dev!==before.dev||opened.ino!==before.ino||opened.size>MAX_BYTES)invalid();
    const buffer=Buffer.alloc(MAX_BYTES+1);let count=0;
    while(count<buffer.length){const {bytesRead}=await handle.read(buffer,count,buffer.length-count,null);if(!bytesRead)break;count+=bytesRead;}
    if(count>MAX_BYTES)invalid();
    return {text:buffer.subarray(0,count).toString('utf8'),dev:opened.dev,ino:opened.ino};
  }finally{await handle.close();}
}

/** Operator-only startup validation. Returned values never form a public API response. */
export async function loadExecutionConfig({filename,runsRoot}){
  try{
    const manifest=JSON.parse((await readBounded(filename)).text);
    if(!exact(manifest,['schemaVersion','targets','maxJobTimeMs','maxJobs'])||manifest.schemaVersion!==1||!Array.isArray(manifest.targets)||!manifest.targets.length||manifest.targets.length>20)invalid();
    const maxJobTimeMs=manifest.maxJobTimeMs??900000,maxJobs=manifest.maxJobs??20;
    if(!positive(maxJobTimeMs,900000)||!positive(maxJobs,20))invalid();
    const targets=[];
    for(const entry of manifest.targets){
      if(!exact(entry,['label','path','config','tools','ai','timeoutMs','url'])||typeof entry.label!=='string'||!entry.label.trim()||entry.label.length>120||/[\x00-\x1f\x7f]/.test(entry.label))invalid();
      if(entry.ai!==undefined&&typeof entry.ai!=='boolean')invalid();
      const ai=entry.ai??false,timeoutMs=entry.timeoutMs??120000;
      if(!positive(timeoutMs,900000)||!Array.isArray(entry.tools)||!entry.tools.length||new Set(entry.tools).size!==entry.tools.length)invalid();
      for(const id of entry.tools){const adapter=adapters.find(item=>item.id===id);if(!adapter||id==='anthropic'||(adapter.requiresAI&&!ai))invalid();}
      if(entry.url!==undefined){const url=new URL(entry.url);if(typeof entry.url!=='string'||!['http:','https:'].includes(url.protocol)||url.username||url.password)invalid();}
      const identity=await directoryIdentity(entry.path);
      const before=await readBounded(entry.config);
      const config=await loadConfig(entry.config);
      const after=await readBounded(entry.config);
      if(before.dev!==after.dev||before.ino!==after.ino||before.text!==after.text||Object.keys(config.tools).some(id=>!adapters.some(adapter=>adapter.id===id)))invalid();
      targets.push({id:randomUUID(),label:entry.label,toolIds:[...entry.tools],path:identity.path,identity,config,ai,timeoutMs,...(entry.url===undefined?{}:{url:entry.url})});
    }
    // Validate the requested layout before canonicalization or creation.
    if(typeof runsRoot!=='string'||!isAbsolute(runsRoot))invalid();
    if(targets.some(target=>contains(target.path,runsRoot)))invalid();
    const rootIdentity=await directoryIdentity(runsRoot,true);
    if(targets.some(target=>contains(target.path,rootIdentity.path)||contains(rootIdentity.path,target.path)))invalid();
    return freeze({runsRoot:rootIdentity.path,rootIdentity,targets,limits:{maxActiveJobs:1,maxJobs,maxJobTimeMs,maxHistory:20}});
  }catch{invalid();}
}

export async function recheckExecutionPaths(configuration,target){
  for(const identity of [configuration.rootIdentity,target.identity]){
    const current=await directoryIdentity(identity.path);
    if(current.path!==identity.path||current.dev!==identity.dev||current.ino!==identity.ino)throw new Error('Execution directory identity changed');
  }
}
