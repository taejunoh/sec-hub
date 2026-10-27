import test from 'node:test';
import assert from 'node:assert/strict';
import {open,mkdtemp,writeFile,appendFile,rm,rename,link} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {safeRead} from '../src/agents/validation.mjs';
const scratch=resolve('../../work');
async function fixture(t){const root=await mkdtemp(join(scratch,'agent-read-test-')),file=join(root,'data');await writeFile(file,'small');t.after(()=>rm(root,{recursive:true,force:true}));return {root,file};}
test('stable regular files read through the exact byte limit',async t=>{const {file}=await fixture(t);assert.equal((await safeRead(file,5)).toString(),'small');await assert.rejects(safeRead(file,4),/oversized/i);});
test('a file growing after its size checks never causes more than limit plus one bytes to be read',async t=>{
  const {file}=await fixture(t),probe=await open(file,'r'),prototype=Object.getPrototypeOf(probe);await probe.close();
  const readFile=prototype.readFile,read=prototype.read;let grown=false,bytesRead=0;
  // Real descriptor I/O is retained. Append immediately before the first actual
  // read, after all pre-read stat checks, and measure bytes returned by I/O.
  const grow=async()=>{if(!grown){grown=true;await appendFile(file,Buffer.alloc(65536));}};
  prototype.readFile=async function(...args){await grow();const result=await readFile.apply(this,args);bytesRead+=result.length;return result;};
  prototype.read=async function(...args){await grow();const result=await read.apply(this,args);bytesRead+=result.bytesRead;return result;};
  try{await assert.rejects(safeRead(file,16),/changed|oversized/i);assert.ok(bytesRead>0&&bytesRead<=17,`reader consumed ${bytesRead} bytes for a 16-byte limit`);}finally{prototype.readFile=readFile;prototype.read=read;}
});
test('replacement of the directory entry during a descriptor read is refused',async t=>{
  const {file}=await fixture(t),probe=await open(file,'r'),prototype=Object.getPrototypeOf(probe);await probe.close();const stat=prototype.stat;let replaced=false;
  prototype.stat=async function(...args){const result=await stat.apply(this,args);if(!replaced){replaced=true;await rename(file,`${file}.old`);await writeFile(file,'small');}return result;};
  try{await assert.rejects(safeRead(file,16),/changed|unsafe/i);}finally{prototype.stat=stat;}
});
test('hardlinked regular files are refused',async t=>{const {file}=await fixture(t);await link(file,`${file}.link`);await assert.rejects(safeRead(file),/unsafe/i);});
