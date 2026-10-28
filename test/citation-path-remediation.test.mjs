import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { access } from 'node:fs/promises';
import { loadCloudflareContracts } from '../src/agents/cloudflare-prompts.mjs';
import { preparePlan } from '../src/agents/supervised-validation.mjs';
import { cloudflareSourceRoot } from './helpers/cloudflare-source.mjs';

const skillRoot=cloudflareSourceRoot();
let available=true;try{await access(resolve(skillRoot,'skills/security-audit/SKILL.md'));}catch{available=false;}
const c=available?await loadCloudflareContracts(skillRoot):null;
function fixture(path='src/app.js'){
  const inputs=[{path,lines:2}],loc={file:path,line:1,description:'Caller input reaches the return boundary.'};
  const block='ATTACK-CLASSES.md#Injection',refs={surface:`${path}#run`,boundary:`${path}#caller`,subsystem:'profile/quick/all-in-scope-subsystems',attack_class:block};
  const reason=`The source boundary is visible (${path}:1).`;
  const plan={architecture:reason,source_objects:[{kind:'surface',label:'Caller',ref:refs.surface,evidence:[loc]},{kind:'boundary',label:'Return',ref:refs.boundary,evidence:[loc]}],companion_selection:c.companions.map(file=>({file,selected:false,reason,evidence:[loc]})),units:[{canonical_refs:refs,surface:'Caller',boundary:'Return',subsystem:'All source',attack_class:'Injection',starting_paths:[path],ordinary_attack_class_block:block,selected_companion_blocks:[],excluded_blocks:c.catalog.filter(b=>b.ref!==block).map(b=>({block:b.ref,reason})),grounding:[loc],priority:1,priority_reason:reason}],assignments:[{id:'hunter-1',unit_refs:[refs],relation:reason,evidence:[loc]}]};
  return {inputs,plan};
}
const fields={architecture:(p,r)=>p.architecture=r,exclusion:(p,r)=>p.units[0].excluded_blocks[0].reason=r,priority:(p,r)=>p.units[0].priority_reason=r,companion:(p,r)=>p.companion_selection[0].reason=r,assignment:(p,r)=>p.assignments[0].relation=r,grouped:(p,r)=>{p.exclusion_catalog=[{id:'all',blocks:p.units[0].excluded_blocks.map(e=>e.block),reason:r}];p.units[0].excluded_blocks=[{ref:'all'}];}};
for(const [field,set]of Object.entries(fields))test(`production ${field} reasons reject non-retained complete citation paths`,{skip:!available},()=>{
  for(const bad of ['unretained/src/app.js:1','/outside/src/app.js:1','../src/app.js:1','./src/app.js:1','src/../src/app.js:1','src/app.js?copy=src/app.js:1','src/app.js:1?copy','%2Fsrc/app.js:1','src%2Fapp.js:1','missing.js:1'])for(const mixed of [false,true]){
    const {inputs,plan}=fixture();set(plan,`${mixed?'Valid src/app.js:1; ':''}Invalid ${bad}.`);
    assert.throws(()=>preparePlan(plan,c,inputs,10),/citation|ground|source|reason/i,`${field}: ${bad}, mixed=${mixed}`);
  }
});
test('production exact citation matching preserves canonical coverage and punctuation in retained paths',{skip:!available},()=>{
  for(const path of ['src/app.js','src/my app.js','src/app(copy).js','src/my app (copy).js','Dockerfile']){
    const {inputs,plan}=fixture(path),state=preparePlan(plan,c,inputs,10);
    assert.equal(state.ledger.length,1);assert.deepEqual(state.ledger[0].canonical_refs,plan.units[0].canonical_refs);
    assert.equal(state.ledger[0].planning_grounding[0].file,path);
  }
});
test('production paths with spaces and parentheses reject prefixed citation paths',{skip:!available},()=>{
  for(const path of ['src/my app.js','src/app(copy).js','src/my app (copy).js'])for(const set of Object.values(fields))for(const prefix of ['unretained/','/outside/','../']){
    const {inputs,plan}=fixture(path);set(plan,`Valid ${path}:1; invalid ${prefix}${path}:1.`);
    assert.throws(()=>preparePlan(plan,c,inputs,10),/citation|ground|source|reason/i);
  }
});
test('production reason citations enforce line bounds even alongside a valid citation',{skip:!available},()=>{
  for(const set of Object.values(fields))for(const line of [0,3,999,'1-3','1–999']){
    const {inputs,plan}=fixture();set(plan,`src/app.js:1 and src/app.js:${line}.`);
    assert.throws(()=>preparePlan(plan,c,inputs,10),/line|citation|reason/i);
  }
});
test('paired evidence permits normal prose without requiring inline citations',{skip:!available},()=>{
  const {inputs,plan}=fixture();for(const field of ['priority','companion','assignment'])fields[field](plan,'Caller input has priority; ratio 2:1 is descriptive prose.');
  assert.equal(preparePlan(plan,c,inputs,10).ledger.length,1);
});
test('production citations preserve native line ranges and lists',{skip:!available},()=>{
  for(const suffix of ['1-2','1–2','1—2','1,2','1–2,2']){
    const {inputs,plan}=fixture();for(const set of Object.values(fields).slice(0,-1))set(plan,`Source src/app.js:${suffix}.`);
    assert.equal(preparePlan(plan,c,inputs,10).ledger.length,1);
  }
});
test('required citation prose can discuss RFC identifiers and numeric ratios',{skip:!available},()=>{
  for(const path of ['src/app.js','Dockerfile']){
    const {inputs,plan}=fixture(path);for(const field of ['architecture','exclusion'])fields[field](plan,`Source ${path}:1 discusses RFC:7231 and ratio 2:1.`);
    assert.equal(preparePlan(plan,c,inputs,10).ledger.length,1);
  }
});
test('production retained bare filenames cannot hide invalid citations behind suffixes',{skip:!available},()=>{
  for(const path of ['Dockerfile','my Dockerfile'])for(const set of Object.values(fields))for(const suffix of ['999','999?copy','999x','1?copy','1x']){
    const bad=`${path}:${suffix}`,{inputs,plan}=fixture(path);set(plan,`${path}:1 plus ${bad}.`);
    assert.throws(()=>preparePlan(plan,c,inputs,10),/line|citation|reason/i,bad);
  }
});
