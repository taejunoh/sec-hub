import test from 'node:test';
import assert from 'node:assert/strict';
import { runProcess } from '../src/processes.mjs';
import { redactValue } from '../src/redaction.mjs';
import { inspectTerminalOutcome } from '../src/agents/native-errors.mjs';

test('release022 #5 structured HTTP 429 falls back to rate_limit without overriding meaningful classifications', () => {
  assert.equal(inspectTerminalOutcome('codex', [{type:'error',error:{status:429}}],1).category,'rate_limit');
  for (const [code, category] of [['usage_limit_reached','usage_limit'],['authentication_error','auth_expired'],['permission_denied','permission_denied']]) {
    assert.equal(inspectTerminalOutcome('codex',[{type:'error',error:{status:429,code}}],1).category,category);
  }
  assert.equal(inspectTerminalOutcome('codex',[{type:'error',error:{status:500}}],1).category,'backend_error');
});

test('release022 #32 capped output never discloses a retained known secret prefix', async () => {
  const token='abcdefgh12345678';
  const result=await runProcess({command:process.execPath,args:['-e','process.stdout.write(process.env.API_TOKEN)']},{env:{...process.env,API_TOKEN:token},maxOutputBytes:12});
  assert.equal(result.status,'failed');
  assert.match(result.reason,/12 byte limit/);
  assert.equal(result.stdout,'');
  assert.equal(result.stderr,'');
  const plain=await runProcess({command:process.execPath,args:['-e','console.log("ordinary diagnostic")']},{env:{...process.env,API_TOKEN:token},maxOutputBytes:100});
  assert.equal(plain.stdout,'ordinary diagnostic\n');
  const secret=await runProcess({command:process.execPath,args:['-e','process.stdout.write(process.env.API_TOKEN)']},{env:{...process.env,API_TOKEN:token},maxOutputBytes:100});
  assert.equal(secret.stdout,'[REDACTED]');
});

test('release022 #34 object key redaction preserves collisions, suffix keys, nesting, and __proto__ safely', () => {
  const source=JSON.parse('{"abcdefgh":1,"[REDACTED]":2,"[REDACTED]#2":3,"ijklmnop":4,"__proto__":{"abcdefgh":"ijklmnop"},"nested":[{"abcdefgh":5,"[REDACTED]":6}]}');
  const result=redactValue(source,{API_KEY:'abcdefgh',API_TOKEN:'ijklmnop'});
  assert.equal(Object.keys(result).length,6);
  assert.deepEqual(Object.values(result).slice(0,4),[1,2,3,4]);
  assert.equal(Object.hasOwn(result,'__proto__'),true);
  assert.equal(Object.getPrototypeOf(result),Object.prototype);
  assert.equal(Object.keys(result.nested[0]).length,2);
  assert.deepEqual(Object.values(result.nested[0]),[5,6]);
  assert.doesNotMatch(JSON.stringify(result),/abcdefgh|ijklmnop/);
  assert.deepEqual(result,redactValue(source,{API_KEY:'abcdefgh',API_TOKEN:'ijklmnop'}));
  assert.deepEqual(redactValue({safe:1}),{safe:1});
});
