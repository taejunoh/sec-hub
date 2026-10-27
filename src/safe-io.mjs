import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join, parse, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

/** Reject task-controlled directory links. macOS's fixed system aliases are allowed. */
async function walkDirectory(directory,create=false,mode=0o700) {
  const absolute=resolve(directory),root=parse(absolute).root;
  let current=root;
  for(const component of absolute.slice(root.length).split(/[\\/]/).filter(Boolean)){
    current=join(current,component);
    let entry;
    try{entry=await lstat(current);}catch(error){
      if(error.code!=='ENOENT'||!create)throw error;
      try{await mkdir(current,{mode});}catch(createError){if(createError.code!=='EEXIST')throw createError;}
      entry=await lstat(current);
    }
    if(entry.isSymbolicLink()){
      const systemAlias=process.platform==='darwin'&&['/var','/tmp'].includes(current)&&(await realpath(current))===`/private${current}`;
      if(!systemAlias)throw new Error(`Refusing symbolic link output directory: ${current}`);
    }else if(!entry.isDirectory())throw new Error(`Output ancestor is not a directory: ${current}`);
  }
  return realpath(absolute);
}

export function assertSafeDirectory(directory) { return walkDirectory(directory); }
export function ensureSafeDirectory(directory,{mode=0o700}={}) { return walkDirectory(directory,true,mode); }

/** Replace the final directory entry atomically, never opening its existing target. */
export async function atomicWriteFile(file,content,{mode=0o600}={}) {
  const parent=await assertSafeDirectory(dirname(resolve(file)));
  const destination=join(parent,basename(file));
  const temporary=join(parent,`.${basename(file)}.${randomUUID()}.tmp`);
  let handle;
  try{
    handle=await open(temporary,'wx',mode);
    await handle.writeFile(content);
    await handle.close();handle=undefined;
    await assertSafeDirectory(parent);
    await rename(temporary,destination);
  }finally{
    await handle?.close().catch(()=>{});
    await unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;});
  }
}
