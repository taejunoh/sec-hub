import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, realpath, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const cli=path.join(root,'bin/sec-hub.mjs');
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const fixture=(id,findings=[],changes={})=>({schemaVersion:1,id,startedAt:'2026-01-01T00:00:00.000Z',endedAt:'2026-01-01T00:01:00.000Z',target:{path:'/synthetic/repo'},status:'completed',tools:[{id:'osv',selected:true,status:'completed',findings}],findings,...changes});
const finding=(severity='high')=>({toolId:'osv',ruleId:'SYNTHETIC',title:'Synthetic advisory',severity,location:{path:'package-lock.json',package:'npm:synthetic',version:'1.0.0'},verification:'candidate'});
async function setup(t){const temp=await mkdtemp(path.join(tmpdir(),'sec-hub-compare-cli-'));t.after(()=>rm(temp,{recursive:true,force:true}));return temp;}
async function save(temp,name,value){const file=path.join(temp,name);await writeFile(file,JSON.stringify(value));return file;}
function invoke(args,options={}){
 const env={...process.env,PATH:'',...options.env};
 const result=spawnSync(process.execPath,[...(options.preload?['--import',options.preload]:[]),cli,...args],{cwd:root,encoding:'utf8',env});
 return {code:result.status,stdout:result.stdout,stderr:result.stderr,error:result.error};
}

test('compare prints canonical full JSON and applies high, any, and none thresholds',async t=>{
 const temp=await setup(t);const base=await save(temp,'base.json',fixture('base'));
 const currentDir=path.join(temp,'current');await mkdir(currentDir);await writeFile(path.join(currentDir,'run.json'),JSON.stringify(fixture('current',[finding('high')])));
 const high=invoke(['compare',base,currentDir]);assert.equal(high.code,1,high.stderr);const result=JSON.parse(high.stdout);assert.equal(result.kind,'sec-hub.comparison');assert.equal(result.entries[0].after.verification,'candidate');
 assert.equal(invoke(['compare',base,currentDir,'--fail-on=any']).code,1);
 assert.equal(invoke(['compare',base,currentDir,'--fail-on','none']).code,0);
 assert.equal(high.stdout,JSON.stringify(stable(result))+'\n');
 const existing=await save(temp,'existing.json',fixture('existing',[finding('critical')]));
 assert.equal(invoke(['compare',existing,existing]).code,0);
 const low=await save(temp,'low.json',fixture('low',[finding('low')]));const highCurrent=await save(temp,'high-current.json',fixture('high',[finding('high')]));
 assert.equal(invoke(['compare',low,highCurrent]).code,1);
 const unknown=await save(temp,'unknown.json',fixture('unknown',[finding('unknown')]));
 assert.equal(invoke(['compare',base,unknown]).code,2);assert.equal(invoke(['compare',base,unknown,'--fail-on','none']).code,0);
 const incomplete=await save(temp,'incomplete.json',fixture('incomplete',[],{status:'partial'}));
 assert.equal(invoke(['compare',base,incomplete,'--fail-on','none']).code,2);
});

test('help documents separate scan/report and compare exit-code meanings',()=>{
 const help=invoke(['--help']);assert.equal(help.code,0);assert.match(help.stdout,/Scan\/report exit codes: 0 complete\/no findings; 1 complete\/findings; 2 incomplete\/error\./);assert.match(help.stdout,/Compare exit codes: 0 complete\/gate pass; 1 complete\/gate violation; 2 invalid input, incomplete scope, or relevant unknown severity\./);
});

test('compare accepts file or artifact directory inputs and writes same JSON to a new report directory',async t=>{
 const temp=await setup(t);const baseDir=path.join(temp,'base');await mkdir(baseDir);await writeFile(path.join(baseDir,'run.json'),JSON.stringify(fixture('base')));
 const current=await save(temp,'current.json',fixture('current',[finding('low')]));const out=path.join(temp,'artifacts');
 const result=invoke(['compare',baseDir,current,'--out',out]);assert.equal(result.code,0,result.stderr);
 const stdout=JSON.parse(result.stdout);assert.equal(stdout.inputs.baseline.file,await realpath(path.join(baseDir,'run.json')));assert.equal(stdout.inputs.current.file,await realpath(current));
 const disk=JSON.parse(await readFile(path.join(out,'comparison.json'),'utf8'));assert.deepEqual(disk,stdout);
 assert.equal(typeof (await readFile(path.join(out,'comparison.html'),'utf8')),'string');
});

test('compare rejects malformed, mismatched, occupied, missing and malformed-option invocations with code 2',async t=>{
 const temp=await setup(t);const good=await save(temp,'good.json',fixture('good'));const malformed=path.join(temp,'bad.json');await writeFile(malformed,'{');
 assert.equal(invoke(['compare',malformed,good]).code,2);
 assert.equal(invoke(['compare',good,await save(temp,'mismatch.json',fixture('other',[],{target:{path:'/other'}}))]).code,2);
 assert.equal(invoke(['compare',good,good,'--out',good]).code,2);
 for(const args of [['compare',good],['compare',good,good,'--fail-on','bogus'],['compare',good,good,'--fail-on','high','--fail-on','low'],['compare',good,good,'--unexpected'],['compare',good,good,'--out']])assert.equal(invoke(args).code,2,args.join(' '));
});

test('compare is offline and does not spawn tools or access network',async t=>{
 const temp=await setup(t);const base=await save(temp,'base.json',fixture('base'));const current=await save(temp,'current.json',fixture('current',[finding('low')]));
 const tripwire=path.join(temp,'tripwire.mjs');await writeFile(tripwire,`import cp from 'node:child_process';\nimport net from 'node:net';\nimport http from 'node:http';\nimport https from 'node:https';\nimport tls from 'node:tls';\nimport {syncBuiltinESMExports} from 'node:module';\nconst deny=()=>{throw new Error('TRIPWIRE external operation');};\nfor(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[name]=deny;\nfor(const name of ['connect','createConnection'])net[name]=deny;\nfor(const name of ['request','get'])http[name]=deny;\nfor(const name of ['request','get'])https[name]=deny;\ntls.connect=deny;\nsyncBuiltinESMExports();\nglobalThis.fetch=deny;\n`);
 const result=invoke(['compare',base,current],{preload:tripwire,env:{OSV_SCANNER_API_KEY:'',ANTHROPIC_API_KEY:'',OPENAI_API_KEY:''}});assert.equal(result.code,0,result.stderr);assert.equal(result.error,undefined);
});
