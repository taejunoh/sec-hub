import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdir, mkdtemp, writeFile, rm} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {main} from '../src/cli.mjs';
import {importBridge} from '../src/bridges.mjs';
import {compareRuns} from '../src/compare.mjs';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const scratch=path.resolve(repo,'../../work/cli-bridge-compare-remediation');
const finding=(severity='high',tag='a',changes={})=>({toolId:'osv',ruleId:'SAME',title:'Same identity',severity,location:{},verification:'candidate',evidence:{tag},...changes});
const run=(id,findings)=>({schemaVersion:1,id,startedAt:'2026-10-27T00:00:00Z',endedAt:'2026-10-27T00:01:00Z',target:{path:'/repo'},status:'completed',provenance:{kind:'aggregate',sourceRuns:[{id:`source-${id}`}]},tools:[{id:'osv',status:'completed',selected:true,findings}],findings});

// Regression: filtering must not change a pointer into the original imported array.
test('bridge rawRef retains original native record indices across rejected records',async t=>{
 await mkdir(scratch,{recursive:true});const temp=await mkdtemp(path.join(scratch,'bridge-'));t.after(()=>rm(temp,{recursive:true,force:true}));
 const common={title:'Fixture',description:'Fixture',claimed_root_cause:'Fixture',trace:[{kind:'entrypoint',file:'src/app.js',line:1,scope:'fixture',description:'Fixture'}],evidence:[{file:'src/app.js',line:1,description:'Fixture'}]};
 const candidate=fingerprint=>({...common,verdict:'needs_validation',fingerprint,blockers:['Fixture'],validation_plan:{}});
 const rejected={...common,verdict:'rejected',fingerprint:'REJECTED',reason:'Fixture'};
 const {claimed_root_cause,...confirmedCommon}=common;
 const confirmed={...confirmedCommon,verdict:'confirmed',fingerprint:'CONFIRMED-1',root_cause:'Fixture',intended_behavior:'Fixture',conditions:[],execution:{attacker_perspective:'User',payloads:['request'],instructions:['Send request'],observed_result:'Fixture'},remediation:{strategy:'Fixture'},severity:{likelihood:{score:'high',reason:'Fixture'},impact:{score:'high',reason:'Fixture'},overall_severity:'high'},confidence:{score:'high',reason:'Fixture'}};
 const records=[rejected,confirmed,rejected,candidate('CANDIDATE-3')];const file=path.join(temp,'native.json');await writeFile(file,JSON.stringify(records));
 const imported=await importBridge('cloudflare',file,'/repo');
 assert.equal(imported.tools[0].artifacts.rejected,2);
 assert.deepEqual(imported.findings.map(f=>f.rawRef.index).sort(),[1,3]);
 for(const f of imported.findings)assert.deepEqual(f.evidence.native,records[f.rawRef.index]);
});

test('command help flags only apply before the first literal delimiter',async()=>{
 const invoke=async args=>{let stdout='',stderr='';const code=await main(args,{stdout:{write:s=>stdout+=s},stderr:{write:s=>stderr+=s}});return {code,stdout,stderr};};
 for(const args of [['--help'],['-h'],['help'],['scan','--help'],['scan','-h'],['scan','--help','--','x']]){
  const result=await invoke(args);assert.equal(result.code,0,JSON.stringify(args));assert.match(result.stdout,/Usage:/);
 }
 for(const literal of ['--help','-h']){
  // report's missing absolute path avoids executing scanners or relying on cwd names.
  const result=await invoke(['report','--',`/sec-hub-missing/${literal}`]);assert.equal(result.code,2);assert.doesNotMatch(result.stdout,/Usage:/);
  const direct=await invoke(['report','--',literal,'extra']);assert.equal(direct.code,2);assert.doesNotMatch(direct.stdout,/Usage:/);
 }
 const scanLiteral=await invoke(['scan','--','--help','extra']);assert.equal(scanLiteral.code,2);assert.doesNotMatch(scanLiteral.stdout,/Usage:/);
 const malformed=await invoke(['report','--unexpected']);assert.equal(malformed.code,2);assert.match(malformed.stderr,/Unknown option/);
});

test('matching preserves frozen bytes for duplicate, mixed-severity, provenance and permutation fixtures',()=>{
 const fixtures=[
  [[finding('high','z'),finding('high','a'),finding('low','lo')],[finding('high','a'),finding('high','b'),finding('critical','hi')]],
  [[finding('high','a'),finding('high','a'),finding('unknown','u')],[finding('high','a'),finding('low','b')]],
  [[],[finding('high','new')]],[[finding('low','old')],[]],
 ];
 let seed=711;const next=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};const severities=['critical','high','medium','low','info','unknown'];
 for(let k=0;k<80;k++){
  const sides=Array.from({length:2},()=>Array.from({length:next()%15},()=>finding(severities[next()%6],String(next()%5),{rawRef:{index:next()%3}})));
  fixtures.push(sides);
 }
 const hash=createHash('sha256');
 for(const [before,after] of fixtures){
  const base=run('before',before),current=run('after',after),saved=JSON.stringify([base,current]);const result=JSON.stringify(compareRuns(base,current));hash.update(result+'\n');
  const permutedBase=run('before',[...before].reverse()),permutedCurrent=run('after',[...after].reverse());assert.equal(JSON.stringify(compareRuns(permutedBase,permutedCurrent)),result);
  assert.equal(JSON.stringify([base,current]),saved);
 }
 // Frozen from the original comparator before replacement, including entry IDs.
 assert.equal(hash.digest('hex'),'7dcaba202e9a9f9404007043f81cdcc16d3ee973ddbed81120f8c13153e612a4');
});

test('large same-identity disjoint-evidence comparison completes in a bounded child',()=>{
 const script=`import assert from 'node:assert/strict';import {compareRuns} from ${JSON.stringify(new URL('../src/compare.mjs',import.meta.url).href)};
 const make=(side)=>{const findings=Array.from({length:60000},(_,i)=>({toolId:'osv',ruleId:'SAME',title:'Same identity',severity:'low',location:{},evidence:{side,i}}));return {schemaVersion:1,id:side,startedAt:'2026-10-27T00:00:00Z',endedAt:'2026-10-27T00:01:00Z',target:{path:'/repo'},status:'completed',tools:[{id:'osv',status:'completed',selected:true,findings}],findings};};
 const out=compareRuns(make('before'),make('after'));assert.deepEqual(out.counts,{new:0,regressed:0,existing:60000,resolved:0,unobserved:0});assert.equal(out.entries.length,60000);assert.equal(out.entries[0].identityMethod,'weak');console.log('bounded comparison complete');`;
 const result=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
 assert.equal(result.error,undefined,`child failed: ${result.error?.message}; ${result.stderr}`);assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/bounded comparison complete/);
});
