import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, writeFile, access } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
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
  const sourceBytes = [await fileHashes(data.original), await fileHashes(data.retry)];
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
  assert.deepEqual([await fileHashes(data.original), await fileHashes(data.retry)], sourceBytes);
  assert.deepEqual(combined.provenance.sourceRuns.map(source => source.sha256), sourceBytes.map(files => files['run.json']));
  assert.deepEqual(combined.provenance.artifactHashEvidence.retry, sourceBytes[1]);
  for (const finding of combined.findings) {
    const directory = finding.toolId === 'open-code-review' ? data.retry : data.original;
    const name = finding.toolId === 'php2shell' ? 'stdout.txt' : finding.toolId === 'codex-security' ? 'findings.json' : 'native.json';
    assert.equal(finding.rawRef, path.join(directory, 'raw', finding.toolId, name));
  }
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

// Interpose only at filesystem boundaries in an isolated child. Reads and writes
// still use real files; the hook makes each mutation deterministic.
async function combineDuringMutation(data, mutation) {
  const source = `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    const data = JSON.parse(process.argv[1]), mutation = JSON.parse(process.argv[2]);
    const realOpen = fs.open;
    let triggered = false, readBytes = 0;
    fs.open = async function(file, ...args) {
      const handle = await realOpen.call(this, file, ...args);
      if (String(file) !== mutation.file) return handle;
      const realStat = handle.stat.bind(handle), realRead = handle.read.bind(handle), realReadFile = handle.readFile.bind(handle), realClose = handle.close.bind(handle);
      handle.stat = async (...args) => {
        const info = await realStat(...args);
        if (!triggered && mutation.kind === 'grow') {
          triggered = true;
          await fs.appendFile(file, Buffer.alloc(21 * 1024 * 1024, 32));
        }
        return info;
      };
      handle.read = async (...args) => { const result = await realRead(...args); readBytes += result.bytesRead; return result; };
      handle.readFile = async (...args) => { const result = await realReadFile(...args); readBytes += result.length; return result; };
      handle.close = async () => {
        await realClose();
        if (!triggered && mutation.kind === 'replace' && new Error().stack.includes('verifyNative')) {
          triggered = true;
          await fs.writeFile(mutation.destination, '{}');
        }
      };
      return handle;
    };
    syncBuiltinESMExports();
    const { combineVerifiedRuns } = await import(${JSON.stringify(new URL('../scripts/combine-verified-runs.mjs',import.meta.url).href)});
    let error = null;
    try { await combineVerifiedRuns(data); } catch (caught) { error = caught.message; }
    console.log(JSON.stringify({ error, triggered, readBytes }));
  `;
  const result = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', source, JSON.stringify(data), JSON.stringify(mutation)]);
  return JSON.parse(result.stdout);
}

test('combiner bounds reads when an already opened regular file grows after stat', async () => {
  const data = await setup();
  const result = await combineDuringMutation(data, { kind: 'grow', file: path.join(data.original, 'run.json') });
  assert.equal(result.triggered, true);
  assert.ok(result.error, 'growing input must be rejected');
  assert.ok(result.readBytes <= 20 * 1024 * 1024 + 1, `read ${result.readBytes} bytes after a stale stat`);
  await assert.rejects(access(data.out), { code: 'ENOENT' });
});

for (const source of ['original', 'retry']) {
  for (const artifact of ['run.json', 'raw/open-code-review/native.json']) {
    test(`combiner rejects changed ${source} ${artifact} before publishing hashes`, async () => {
      const data = await setup();
      const file = path.join(data[source], 'raw', source === 'original' ? 'osv' : 'open-code-review', 'native.json');
      const result = await combineDuringMutation(data, { kind: 'replace', file, destination: path.join(data[source], artifact) });
      assert.equal(result.triggered, true);
      assert.ok(result.error, `${source} ${artifact} changed after validation but aggregate was published`);
      await assert.rejects(access(data.out), { code: 'ENOENT' });
    });
  }
}
