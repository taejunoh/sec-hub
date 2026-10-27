import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { getAdapter } from '../src/adapters/index.mjs';
import { normalizeFindings, writeReports } from '../src/reports.mjs';

const ids=['osv','skillspector','codex-security','open-code-review','php2shell'];
const hash=value=>createHash('sha256').update(value).digest('hex');
async function fileHashes(directory,prefix=''){
  const result={};for(const entry of await readdir(path.join(directory,prefix),{withFileTypes:true})){const relative=path.join(prefix,entry.name);if(entry.isDirectory())Object.assign(result,await fileHashes(directory,relative));else result[relative]=hash(await readFile(path.join(directory,relative)));}return result;
}
async function setup(){
  const root=await mkdtemp(path.join(tmpdir(),'sec-aggregate-')),target=path.join(root,'target'),original=path.join(root,'initial'),retry=path.join(root,'retry'),out=path.join(root,'aggregate');
  await cp(new URL('./fixtures/live-five/',import.meta.url),target,{recursive:true});
  const originalRun={schemaVersion:1,id:'initial-id',startedAt:'2026-10-27T00:00:00.000Z',endedAt:'2026-10-27T00:01:00.000Z',target:{path:target,revision:'a'.repeat(40),dirty:false},status:'partial',tools:[],findings:[]};
  const retryRun={...structuredClone(originalRun),id:'retry-id',startedAt:'2026-10-27T00:02:00.000Z',endedAt:'2026-10-27T00:03:00.000Z',status:'completed',tools:[],findings:[]};
  for(const [directory,run,isRetry] of [[original,originalRun,false],[retry,retryRun,true]]){
    for(const id of ids){
      const selected=!isRetry||id==='open-code-review',status=selected?(id==='open-code-review'&&!isRetry?'failed':'completed'):'skipped';
      const record={id,name:id,source:getAdapter(id).source,selected,status,findings:[]};
      if(!selected){record.reason='Not selected';run.tools.push(record);continue;}
      const artifactDir=path.join(directory,'raw',id);await mkdir(artifactDir,{recursive:true});
      let payload=id==='php2shell'?{patch_status:'potentially_vulnerable',php_version:'8.1.2',reason:'Header fixture',exit_code:1}:JSON.parse(await readFile(new URL(`./fixtures/adapters/${{'codex-security':'codex','open-code-review':'ocr'}[id]??id}-positive.json`,import.meta.url),'utf8'));
      if(status==='failed')payload={status:'completed_with_warnings',comments:[],summary:{budget_exceeded:true},warnings:[{type:'token_budget_reached',file:'server.mjs',message:'next-file estimate exceeds budget 20000'}]};
      const stdout=id==='php2shell'?JSON.stringify(payload):'';
      await writeFile(path.join(artifactDir,'stdout.txt'),stdout);await writeFile(path.join(artifactDir,'stderr.txt'),'');
      if(id!=='php2shell')await writeFile(path.join(artifactDir,id==='codex-security'?'findings.json':'native.json'),JSON.stringify(payload));
      record.artifacts={stdout:path.join(artifactDir,'stdout.txt'),stderr:path.join(artifactDir,'stderr.txt')};record.exitCode=id==='php2shell'?1:0;record.startedAt=run.startedAt;record.endedAt=run.endedAt;
      if(status==='completed')record.findings=normalizeFindings(await getAdapter(id).parse({artifactDir,stdout,exitCode:record.exitCode,target}));
      else record.reason='Open Code Review: native scan incomplete';
      run.tools.push(record);run.findings.push(...record.findings);
    }
    await writeReports(run,directory);
  }
  const snapshot=await fileHashes(target);
  const evidence={fixturePath:target,runStatus:'partial',targetHashes:{before:snapshot,after:snapshot},targetChanges:{added:[],removed:[],changed:[]},tools:originalRun.tools.map(({id,selected,status,findings})=>({id,selected,status,findings:findings.length})),artifactHashes:await fileHashes(original)};
  await writeFile(path.join(original,'verification-commands.json'),JSON.stringify(evidence));
  return{root,target,original,retry,out,evidence,originalRun,retryRun};
}
async function combine(options){const module=await import('../scripts/combine-verified-runs.mjs');return module.combineVerifiedRuns(options);}

test('combiner preserves initial failure history and builds five completed records with source provenance',async()=>{
  const data=await setup(),before=await readFile(path.join(data.original,'run.json'),'utf8');
  await combine(data);
  const combined=JSON.parse(await readFile(path.join(data.out,'run.json'),'utf8'));
  assert.equal(combined.status,'completed');assert.equal(combined.tools.length,5);assert.ok(combined.tools.every(tool=>tool.status==='completed'));
  assert.notEqual(combined.id,'initial-id');assert.notEqual(combined.id,'retry-id');
  assert.equal(combined.provenance.kind,'aggregate');assert.equal(combined.provenance.retry.previousRecord.status,'failed');
  assert.deepEqual(combined.provenance.sourceRuns.map(source=>source.id),['initial-id','retry-id']);
  assert.equal(combined.tools.find(tool=>tool.id==='open-code-review').provenance.sourceRunId,'retry-id');
  assert.equal(combined.tools.find(tool=>tool.id==='osv').provenance.sourceRunId,'initial-id');
  assert.equal(combined.findings.length,5);assert.ok(combined.findings.every(finding=>path.isAbsolute(finding.rawRef)));
  assert.equal(await readFile(path.join(data.original,'run.json'),'utf8'),before);
});

test('combiner refuses source-byte mismatch failed retry and unrecognized target files',async()=>{
  for(const mutation of ['changed','failed','unknown','artifact','revision','selection','missing-hash','target-output']){
    const data=await setup();
    if(mutation==='changed')await writeFile(path.join(data.target,'server.mjs'),'changed');
    if(mutation==='unknown')await writeFile(path.join(data.target,'unknown-metadata'),'unknown');
    if(mutation==='revision'){data.retryRun.target.revision='b'.repeat(40);await writeReports(data.retryRun,data.retry);}
    if(mutation==='selection'){data.retryRun.tools.find(tool=>tool.id==='osv').selected=true;await writeReports(data.retryRun,data.retry);}
    if(mutation==='missing-hash'){delete data.evidence.artifactHashes['raw/osv/native.json'];await writeFile(path.join(data.original,'verification-commands.json'),JSON.stringify(data.evidence));}
    if(mutation==='target-output')data.out=path.join(data.target,'new-output');
    if(mutation==='artifact')await writeFile(path.join(data.original,'raw','osv','native.json'),'{}');
    if(mutation==='failed'){data.retryRun.tools.find(tool=>tool.id==='open-code-review').status='failed';await writeReports(data.retryRun,data.retry);}
    await assert.rejects(combine(data),/hash|target|retry|artifact/i);
  }
});
