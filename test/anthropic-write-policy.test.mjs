import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {claudeArgs} from '../src/agents/invocation.mjs';
import {filePermissionDecision} from './helpers/claude-file-permissions.mjs';
const opts={skillRoot:'/official vendor',model:'fixture'},cfg={artifactDir:'/raw artifacts'},copy='/stage with spaces/target';
const inputs=[{path:'source.mjs'},{path:'nested/other source.mjs'}];
// Returning inert Write(path) selectors must deny the two intended writes.
test('v3 production permissions allow exactly two native Write outputs through scoped Edit rules',()=>{
  const args=claudeArgs(copy,opts,cfg,inputs);
  for(const file of ['VULN-FINDINGS.json','VULN-FINDINGS.md'])assert.equal(filePermissionDecision(args,'Write',`${copy}/${file}`),'allow',file);
  for(const file of ['OTHER.json','nested/VULN-FINDINGS.json','vuln-findings.json','VULN-FINDINGS.json.bak'])assert.equal(filePermissionDecision(args,'Write',`${copy}/${file}`),'no-allow',file);
  for(const path of ['/stage with spaces/sibling/VULN-FINDINGS.json','/ambient/file'])assert.equal(filePermissionDecision(args,'Write',path),'no-allow',path);
  for(const path of [`${copy}/source.mjs`,`${copy}/nested/other source.mjs`,'/stage with spaces/runner/anthropic-plugin/skills/vuln-scan/SKILL.md','/official vendor/.claude/skills/vuln-scan/SKILL.md','/raw artifacts/execution-manifest.json'])assert.equal(filePermissionDecision(args,'Write',path),'path-deny',path);
  assert.equal(filePermissionDecision(args,'Read',`${process.env.HOME}/.claude/credentials.json`),'path-deny');
  assert.equal(filePermissionDecision(args,'Read','/raw artifacts/native-events.jsonl'),'path-deny');
  assert.equal(filePermissionDecision(args,'Read',`${copy}/source.mjs`),'allow');
  for(const tool of ['Edit','NotebookEdit','Bash','Agent','Task','WebFetch','WebSearch'])assert.equal(filePermissionDecision(args,tool,`${copy}/VULN-FINDINGS.json`),'tool-deny',tool);
  const allow=args[args.indexOf('--allowedTools')+1].split(',');assert.equal(allow.some(rule=>rule==='Edit'||rule==='Write'||rule.startsWith('Write(')),false);
  assert.deepEqual(allow.filter(rule=>rule.startsWith('Edit(')),['Edit(//stage with spaces/target/VULN-FINDINGS.json)','Edit(//stage with spaces/target/VULN-FINDINGS.md)']);
});
test('v3 explicit copied-input deny wins over the output allow on a filename collision',()=>{
  const args=claudeArgs(copy,opts,cfg,[...inputs,{path:'VULN-FINDINGS.json'}]);
  assert.equal(filePermissionDecision(args,'Write',`${copy}/VULN-FINDINGS.json`),'path-deny');
  assert.equal(filePermissionDecision(args,'Write',`${copy}/VULN-FINDINGS.md`),'allow');
});
test('v1 and v2 argv prompt and settings remain byte-identical to recorded pre-v3 controls',async()=>{
  const fixture=JSON.parse(await readFile(new URL('./fixtures/anthropic-registration/invocation-v1-v2.json',import.meta.url),'utf8'));
  const saved=process.env.HOME;process.env.HOME=fixture.home;
  try{for(const c of fixture.controls){const actual=claudeArgs(c.copy,c.options,c.cfg,c.inputs,c.version);assert.deepEqual(actual,c.args,`${c.version} ${c.copy}`);assert.equal(filePermissionDecision(actual,'Write',`${c.copy}/VULN-FINDINGS.json`),'no-allow');}}finally{process.env.HOME=saved;}
});
test('v3 differs from registered v2 only in the scoped file-write rule category',()=>{
  const old=claudeArgs(copy,opts,cfg,inputs,2),current=claudeArgs(copy,opts,cfg,inputs,3);
  const expected=old.map(arg=>arg.replaceAll('Write(','Edit('));assert.deepEqual(current,expected);
  assert.equal(current[current.indexOf('--tools')+1],'Skill,Read,Glob,Grep,Write');
  assert.equal(current[current.indexOf('--disallowedTools')+1],'Bash,Agent,Task,Edit,NotebookEdit,WebFetch,WebSearch');
});
test('v3 rejects unsupported versions and metacharacter paths before invocation',()=>{
  for(const version of [0,4,'3',null,true])assert.throws(()=>claudeArgs(copy,opts,cfg,inputs,version),/policy version/);
  for(const path of ['/stage/*/target','/stage/target[1]','/stage/target,other'])assert.throws(()=>claudeArgs(path,opts,cfg,inputs,3),/metacharacters/);
});
