import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join, parse, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const aclReader=fileURLToPath(new URL('./native/darwin-acl-reader',import.meta.url));

/**
 * Trusted-directory boundary, NOT a sandbox against concurrent same-user code.
 * Node has no public openat/renameat/unlinkat API. Path checks cannot stop an
 * actor who can rename an ancestor between this check and a later operation.
 *
 * Supported: Linux POSIX ACL/mode filesystems and macOS local filesystems, with
 * root and the effective uid trusted. Every ancestor must be owned by one of
 * those identities and prohibit other users from replacing the next entry.
 * Linux sticky shared directories are allowed when each child has a trusted
 * owner. macOS shared-writable directories are rejected even when sticky, and
 * a bundled native reader rejects allow ACLs and native query failures on an
 * opened directory descriptor, root-down before descending or creating.
 * Filesystems must enforce the checked local uid/mode/ACL permissions, without
 * independent server-side or administrative grants bypassing those permissions.
 * All same-uid processes (including scanners) must be trusted.
 * Windows ACL trust cannot be established here and is rejected before mutation.
 * Rechecks below detect some mistakes; they do not eliminate TOCTOU races.
 */
function assertTrustedDirectory(entry,directory,uid) {
  if(!entry.isDirectory())throw new Error(`Output ancestor is not a directory: ${directory}`);
  const protectedSticky=process.platform==='linux'&&(entry.mode&0o1000)!==0;
  if(![0,uid].includes(entry.uid)||((entry.mode&0o022)!==0&&!protectedSticky)){
    throw new Error(`Untrusted output directory: ${directory}; use root/current-user owned ancestors without group/other write access (or a sticky shared directory with trusted owned children).`);
  }
}

function readDirectoryAcl(fd) {
  return new Promise((resolve,reject)=>{
    let child,finished=false,bytes=0,stderrBytes=0,stdout='';
    const timer=setTimeout(()=>finish(new Error('Native ACL helper timed out')),5000);
    function finish(error) {
      if(finished)return;
      finished=true;clearTimeout(timer);
      if(error){
        child?.kill('SIGKILL');child?.stdout?.destroy();child?.stderr?.destroy();
        reject(error);
      }else resolve();
    }
    try{
      child=spawn(aclReader,[],{stdio:['ignore','pipe','pipe',fd],env:{},shell:false});
    }catch(error){finish(error);return;}
    child.once('error',finish);
    child.once('close',(code,signal)=>{
      if(code!==0||signal||stderrBytes||stdout!=='SEC_HUB_ACL_OK\n')finish(new Error('Native ACL helper rejected the directory or returned an invalid result'));
      else finish();
    });
    for(const [name,stream]of [['stdout',child.stdout],['stderr',child.stderr]]){
      stream.on('data',chunk=>{
        bytes+=chunk.length;
        if(bytes>4096){finish(new Error('Native ACL helper output limit exceeded'));return;}
        if(name==='stdout')stdout+=chunk.toString('utf8');
        else stderrBytes+=chunk.length;
      });
      stream.once('error',finish);
    }
  });
}

async function assertDirectoryAcl(directory,uid) {
  if(process.platform!=='darwin')return;
  if(!['arm64','x64'].includes(process.arch))throw new Error('Unsupported macOS architecture for native directory ACL inspection.');
  let handle;
  try{
    handle=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    assertTrustedDirectory(await handle.stat(),directory,uid);
    await readDirectoryAcl(handle.fd);
  }catch(error){throw new Error(`Cannot inspect directory ACL: ${directory}; ${error.message}`,{cause:error});}
  finally{
    await handle?.close();
  }
}

async function walkDirectory(directory,create=false,mode=0o700) {
  if(!['darwin','linux'].includes(process.platform)||typeof process.geteuid!=='function'){
    throw new Error('Unsupported safe-io platform: directory ACL trust cannot be verified; use a supported POSIX filesystem with trusted ancestors.');
  }
  if(create&&(!Number.isInteger(mode)||mode<0||mode>0o7777||(mode&0o022)!==0)){
    throw new Error('Unsafe directory mode: new output directories must not grant group/other write access.');
  }
  const uid=process.geteuid();
  const absolute=resolve(directory),root=parse(absolute).root;
  let current=root;
  assertTrustedDirectory(await lstat(root),root,uid);
  await assertDirectoryAcl(root,uid);
  for(const component of absolute.slice(root.length).split(sep).filter(Boolean)){
    current=join(current,component);
    let entry;
    try{entry=await lstat(current);}catch(error){
      if(error.code!=='ENOENT'||!create)throw error;
      try{await mkdir(current,{mode});}catch(createError){if(createError.code!=='EEXIST')throw createError;}
      entry=await lstat(current);
    }
    if(entry.isSymbolicLink()){
      const systemAlias=process.platform==='darwin'&&entry.uid===0&&['/var','/tmp'].includes(current)&&(await realpath(current))===`/private${current}`;
      if(!systemAlias)throw new Error(`Refusing symbolic link output directory: ${current}`);
      // Validate /private and its child too, then continue on the canonical path.
      current=await walkDirectory(`/private${current}`);
    }else {
      assertTrustedDirectory(entry,current,uid);
      await assertDirectoryAcl(current,uid);
    }
  }
  // Preserve canonical casing on case-insensitive filesystems for callers that
  // compare containment. This pathname lookup relies on the same trust boundary.
  return realpath(current);
}

export function assertSafeDirectory(directory) { return walkDirectory(directory); }
export function ensureSafeDirectory(directory,{mode=0o700}={}) { return walkDirectory(directory,true,mode); }

/** Replace the final entry atomically within the trusted-directory boundary above. */
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
