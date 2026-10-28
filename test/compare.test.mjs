import test from 'node:test';
import assert from 'node:assert/strict';
import {compareRuns} from '../src/compare.mjs';
import {normalizeFindings} from '../src/reports.mjs';
const finding=(changes={})=>({toolId:'osv',ruleId:'CVE-1',title:'Issue',severity:'high',location:{path:'a.lock',package:'npm:a',version:'1'},verification:'candidate',...changes});
const run=(findings=[],changes={})=>({schemaVersion:1,id:'run',startedAt:'2026-10-27T00:00:00Z',endedAt:'2026-10-27T00:01:00Z',target:{path:'/repo'},status:'completed',tools:[{id:'osv',status:'completed',selected:true,findings}],findings,...changes});
test('occurrences, escalation, decrease and candidate provenance',()=>{
 const f=finding(); const c=compareRuns(run([f]),run([f,f])); assert.equal(c.counts.new,1); assert.equal(c.counts.existing,1);assert.equal(c.gate.exitCode,1);assert.equal(c.entries.find(e=>e.category==='new').after.verification,'candidate');
 for(const [before,after,category] of [['low','high','regressed'],['high','low','existing'],['unknown','high','regressed'],['high','unknown','regressed']]) assert.equal(compareRuns(run([finding({severity:before})]),run([finding({severity:after})])).entries[0].category,category);
});
test('leaf lineage preserves separate lockfiles and rejects top-level tampering',()=>{
 const leaves=[finding(),finding({location:{path:'b.lock',package:'npm:a',version:'1'}})];const grouped=normalizeFindings(leaves); const r=run(grouped);assert.equal(compareRuns(r,run([])).counts.resolved,2);assert.throws(()=>compareRuns({...r,findings:[]},r),/findings|multiset/i);
});
test('global failure prevents resolution despite complete local tool coverage',()=>{
 const b=run([finding()]);const c=run([],{status:'partial',tools:[{id:'osv',status:'completed',selected:true,findings:[]},{id:'skillspector',selected:true,status:'failed',findings:[]}]});const out=compareRuns(b,c);assert.equal(out.counts.resolved,0);assert.equal(out.counts.unobserved,1);assert.ok(out.entries[0].reasons.includes('current:run-partial'));assert.equal(out.status,'incomplete');assert.equal(out.gate.exitCode,2);assert.equal(compareRuns(b,run()).counts.resolved,1);
 for(const status of ['skipped','failed','timed_out','cancelled','imported'])assert.equal(compareRuns(b,run([],{tools:[{id:'osv',selected:true,status,findings:[]}]})).counts.unobserved,1);
 assert.equal(compareRuns(b,run([],{tools:[]})).status,'incomplete');
});
test('weak paths and native fingerprints',()=>{
 const weak=finding({location:{path:'../outside'}});assert.equal(compareRuns(run([weak]),run([])).counts.unobserved,1);
 const a=finding({toolId:'cloudflare',location:{path:'/repo/x',line:1},evidence:{native:{fingerprint:'fp'}}});const b={...a,location:{path:'x',line:99}};
 const cf=f=>run(f,{tools:[{id:'cloudflare',status:'completed',selected:true,execution:{mode:'official-security-audit-skill'},findings:f}]});assert.equal(compareRuns(cf([a]),cf([b])).counts.existing,1);assert.equal(compareRuns(cf([a]),cf([])).counts.unobserved,1);
 const src=finding({location:{path:'x',line:1}});const shift=finding({location:{path:'x',line:2}});assert.equal(compareRuns(run([src]),run([shift])).counts.new,1);
});
test('scope, selection, validation and gate',()=>{
 assert.throws(()=>compareRuns(run(),run([],{target:{path:'/other'}})),/target/i);assert.throws(()=>compareRuns(run(),run(),{failOn:'bad'}),/failOn/i);
 assert.throws(()=>compareRuns(run(),run([],{tools:[{id:'osv',selected:false,status:'completed',findings:[]}]})),/selected/i);
 const p=finding({toolId:'php2shell',location:{url:'https://example.test'}});const php=f=>run(f,{tools:[{id:'php2shell',status:'completed',selected:true,findings:f}]});assert.equal(compareRuns(php([p]),php([])).counts.unobserved,1);
 const u=run([finding({severity:'unknown'})]);assert.equal(compareRuns(run(),u).gate.exitCode,2);assert.equal(compareRuns(run(),u,{failOn:'any'}).gate.exitCode,1);assert.equal(compareRuns(run(),u,{failOn:'none'}).gate.exitCode,0);assert.equal(compareRuns(u,u).gate.exitCode,0);
});
test('determinism and immutability',()=>{
 const a=run([finding(),finding({title:'Second',severity:'low'})]); const saved=structuredClone(a);const b=structuredClone(a);b.findings.reverse();b.tools[0].findings.reverse();assert.deepEqual(compareRuns(a,b),compareRuns(b,a));assert.deepEqual(a,saved);
});
test('leaf own severity survives grouped maximum and matching pairs preserve occurrence content',()=>{
 const lo=finding({severity:'low'}),hi=finding({severity:'critical'});const grouped=normalizeFindings([lo,hi]);const out=compareRuns(run(grouped),run([lo]));assert.equal(out.entries.find(e=>e.category==='existing').before.severity,'low');assert.equal(out.entries.find(e=>e.category==='resolved').before.severity,'critical');
 const now=compareRuns(run([lo,hi]),run([hi,finding({severity:'medium'})]));assert.equal(now.counts.existing,1);assert.equal(now.counts.regressed,1);
});
test('known scan contracts, revisions and versions, incompatible source/pin/mode and unknown scope',()=>{
 const f=finding();const a=run([f]);a.target.revision='old';a.tools[0].version='1';const b=run([]);b.target={path:'/repo/./',revision:'new'};b.tools[0].version='2';const good=compareRuns(a,b);assert.equal(good.counts.resolved,1);assert.equal(good.gate.exitCode,0);assert.equal(good.notices.length,1);assert.equal(good.current.target.revision,'new');
 for(const mutation of [t=>t.source='other',t=>t.execution={mode:'other'},t=>t.execution={sourceCommit:'new'}]){const c=run([]);mutation(c.tools[0]);const out=compareRuns(a,c);assert.equal(out.counts.unobserved,1);assert.equal(out.status,'incomplete');}
 for(const id of ['unknown-tool','anthropic']){const tool={id,status:'completed',selected:true,findings:[]};assert.equal(compareRuns(run([],{tools:[tool]}),run([],{tools:[tool]})).status,'incomplete');}
 const anthro={id:'anthropic',status:'completed',selected:true,findings:[],execution:{mode:'official-claude-code-vuln-scan',limitations:['Static source review only; no Docker/ASAN harness']}};assert.equal(compareRuns(run([],{tools:[anthro]}),run([],{tools:[anthro]})).status,'complete');
 for(const execution of [{partial:true},{complete:false},{coverage:'partial'},{limitations:['Quick profile is partial coverage.']}]){const tools=[{id:'osv',status:'completed',selected:true,findings:[],execution}];assert.equal(compareRuns(run([],{tools}),run([],{tools})).status,'incomplete');}
});
test('selection ambiguity and invalid finding/tool inputs fail conservatively',()=>{
 const skipped={id:'osv',status:'skipped',findings:[]};assert.equal(compareRuns(run([],{tools:[skipped]}),run([],{tools:[skipped]})).status,'incomplete');
 const off={...skipped,selected:false};assert.deepEqual(compareRuns(run([],{tools:[off]}),run([],{tools:[off]})).coverage,[]);
 for(const tools of [[{id:'osv',status:'wat',findings:[]}],[{id:'osv',status:'completed',findings:[]},{id:'osv',status:'completed',findings:[]}],[{id:'osv',status:'completed',findings:[finding({toolId:'foreign'})]}]])assert.throws(()=>compareRuns(run([],{tools}),run()),/tool|status/i);
 let deep=finding();for(let i=0;i<18;i++)deep={...finding(),sourceRecords:[deep]};assert.throws(()=>compareRuns(run([deep]),run()),/depth/i);
 for(const changes of [{verificationPassed:false},{pendingIntegrations:['anthropic']},{status:'failed'}])assert.equal(compareRuns(run(),run([] ,changes)).gate.exitCode,2);
});
test('cross-tool identity stays separate and lexical/key ordering is deterministic',()=>{
 const fs=[finding(),finding({toolId:'skillspector'})],tools=fs.map(f=>({id:f.toolId,status:'completed',selected:true,findings:[f]}));const a=run(fs,{tools});const b=structuredClone(a);b.tools.reverse();b.findings.reverse();b.tools[0].findings[0]=Object.fromEntries(Object.entries(b.tools[0].findings[0]).reverse());assert.deepEqual(compareRuns(a,b),compareRuns(a,a));assert.equal(new Set(compareRuns(a,b).entries.map(e=>e.identity)).size,2);
 const dep=finding(),changed=finding({location:{...dep.location,version:'2'}});assert.equal(compareRuns(run([dep]),run([changed])).counts.new,1);
 const aliased=finding({ruleId:'GHSA-new',vulnerabilityId:'GHSA-new',aliases:['CVE-1']});assert.equal(compareRuns(run([dep]),run([aliased])).counts.new,1);
 const out=compareRuns(run(),run([finding({severity:'critical'})],{status:'partial'}));assert.equal(out.gate.violations.length,1);assert.equal(out.gate.exitCode,2);
});
test('declared unknown scope and mode do not establish resolution coverage',()=>{
 for(const execution of [{scope:'unknown'},{mode:'unrecognized-scanner-mode'}]){const tool={id:'osv',status:'completed',selected:true,findings:[],execution};assert.equal(compareRuns(run([],{tools:[tool]}),run([],{tools:[tool]})).status,'incomplete');}
});

test('review regressions: explicit incomplete metadata and uncertain disappearance cannot pass',()=>{
 for(const execution of [{coverage:'incomplete'},{status:'blocked'},{coverage:{status:'partial'}},{coverage:{status:'deferred'}},{mode:'static-source'}]){
  const b=run([finding()]);b.tools[0].execution=execution;const c=run([]);c.tools[0].execution=execution;
  const result=compareRuns(b,c);assert.equal(result.counts.unobserved,1);assert.equal(result.gate.exitCode,2);
 }
 const weak=finding({location:{}});const result=compareRuns(run([weak]),run(),{failOn:'none'});assert.equal(result.counts.unobserved,1);assert.equal(result.status,'incomplete');assert.equal(result.gate.exitCode,2);
});
test('review regression: saved v1 snapshots require valid timestamps',()=>{
 for(const field of ['startedAt','endedAt'])for(const value of [undefined,'','bad-date',42]){
  const invalid=run();invalid[field]=value;assert.throws(()=>compareRuns(invalid,run()),/startedAt|endedAt|timestamp/i);
 }
});
test('identity v1 frozen tuples, baseline coverage gap reasons and aggregate provenance',async()=>{
 const {createHash}=await import('node:crypto');const hash=tuple=>createHash('sha256').update(JSON.stringify(tuple)).digest('hex');
 const weak=finding({location:{path:'../outside'}});assert.equal(compareRuns(run(),run([weak])).entries[0].identity,hash([1,'osv','weak','CVE-1','Issue']));
 const dep=finding();assert.equal(compareRuns(run(),run([dep])).entries[0].identity,hash([1,'osv','dependency','npm:a','1','CVE-1','a.lock']));
 const base=run([],{status:'failed',provenance:{kind:'aggregate',sourceRuns:[{id:'original',status:'failed'}]},tools:[{id:'osv',selected:true,status:'failed',findings:[]}]});const current=run([dep],{provenance:{kind:'aggregate',sourceRuns:[{id:'retry',status:'completed'}]}});const snapshot=structuredClone(base.provenance);const result=compareRuns(base,current);assert.ok(result.entries[0].reasons.includes('baseline:tool-failed'));assert.deepEqual(result.baseline.provenance,snapshot);assert.deepEqual(result.current.provenance,current.provenance);result.baseline.provenance.sourceRuns[0].id='mutated';assert.deepEqual(base.provenance,snapshot);
});
