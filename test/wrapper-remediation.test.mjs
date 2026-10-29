import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { run } from '../src/agents/native-wrapper.mjs';

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const codexWrapper = join(repo, 'src/adapters/codex-wrapper.mjs');

function child(command, args, options = {}) {
  const processChild = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  let stdout = '', stderr = '';
  processChild.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  processChild.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { processChild.kill('SIGKILL'); reject(new Error('wrapper fixture timed out')); }, 5000);
    processChild.once('error', error => { clearTimeout(timer); reject(error); });
    processChild.once('close', exitCode => { clearTimeout(timer); resolve({ exitCode, stdout, stderr }); });
  });
}

async function codexFixture(t, mode) {
  const root = await mkdtemp(join(tmpdir(), 'sec-wrapper-remediation-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifactDir = join(root, mode);
  await mkdir(artifactDir);
  const fake = join(root, 'fake.mjs');
  await writeFile(fake, `
    import { mkdir, writeFile } from 'node:fs/promises';
    import { join } from 'node:path';
    const args = process.argv.slice(2);
    await writeFile(process.env.CALLS, args[0] + '\\n', { flag: 'a' });
    if (args[0] === 'scan') {
      const results = args[args.indexOf('--output-dir') + 1];
      await mkdir(results);
      await writeFile(join(results, 'native-evidence.json'), '{"kept":true}');
      await writeFile(process.env.RESULTS_PATH, results);
    } else await writeFile(args[args.indexOf('--output') + 1], '{}');
  `);
  const preload = join(root, `${mode}-preload.mjs`);
  const patch = mode === 'cancel'
    ? `const original=fs.mkdtemp;fs.mkdtemp=async(...args)=>{const value=await original(...args);process.emit('SIGTERM');return value;};`
    : `fs.cp=async(source)=>{await fs.stat(source);throw Object.assign(new Error('synthetic traversal ENOENT'),{code:'ENOENT'});};`;
  await writeFile(preload, `import fs from 'node:fs/promises';import {syncBuiltinESMExports} from 'node:module';${patch}syncBuiltinESMExports();`);
  const args = ['--import', preload, codexWrapper, JSON.stringify({ command: process.execPath, args: [fake], artifactDir, target: '/synthetic/target' })];
  const result = await child(process.execPath, args, { env: { ...process.env, TMPDIR: root, CALLS: join(artifactDir, 'calls'), RESULTS_PATH: join(artifactDir, 'results-path') } });
  return { ...result, root, artifactDir, calls: await readFile(join(artifactDir, 'calls'), 'utf8').catch(() => ''), resultsPath: await readFile(join(artifactDir, 'results-path'), 'utf8').catch(() => '') };
}

test('Codex wrapper honors cancellation before launching scan', async t => {
  const result = await codexFixture(t, 'cancel');
  assert.equal(result.exitCode, 143, result.stderr);
  assert.equal(result.calls, '');
});

test('Codex wrapper retains private results when copy reports ENOENT for an existing source', async t => {
  const result = await codexFixture(t, 'copy');
  assert.equal(result.exitCode, 2, result.stderr);
  assert.match(result.stderr, /private temporary results retained at (.+)\./);
  const temporary = result.stderr.match(/private temporary results retained at (.+)\./)[1];
  const results = result.resultsPath.trim();
  assert.equal(dirname(results), temporary);
  assert.equal((await stat(temporary)).mode & 0o777, 0o700);
  assert.equal(await readFile(join(results, 'native-evidence.json'), 'utf8'), '{"kept":true}');
  assert.deepEqual(result.calls.trim().split('\n'), ['scan', 'export']);
});

test('native wrapper decodes split UTF-8 event bytes consistently with retained JSON', async t => {
  const root = await mkdtemp(join(tmpdir(), 'sec-native-utf8-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifactDir = join(root, 'artifacts');
  await mkdir(artifactDir);
  const fake = join(root, 'split-event.mjs');
  await writeFile(fake, `const data=Buffer.from('{"name":"한","kind":"event"}\\n');const at=data.indexOf(0xed);process.stdout.write(data.subarray(0,at+1));setTimeout(()=>process.stdout.write(data.subarray(at+1)),20);`);
  const live = [];
  const result = await run(process.execPath, [fake], { cwd: root, env: process.env, artifactDir, onEvent: event => live.push(event) });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(live, [JSON.parse(result.stdout.trim())]);
  assert.equal(live[0].name, '한');
});

test('native wrapper cleans staging after manifest publication fails and reports original error', async t => {
  const root = await mkdtemp(join(tmpdir(), 'sec-native-cleanup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const loader = join(root, 'loader.mjs');
  const wrapper = pathToFileURL(join(repo, 'src/agents/native-wrapper.mjs')).href;
  await mkdir(join(root, 'target'));
  await mkdir(join(root, 'artifacts'));
  await mkdir(join(root, 'work'));
  await writeFile(loader, `
    import { fileURLToPath, pathToFileURL } from 'node:url';
    const stubs = new Map();
    function stub(name, source) { const u=pathToFileURL(new URL(name, import.meta.url).pathname).href; stubs.set(u,source); }
    stub('./safe-stub.mjs', 'export async function ensureSafeDirectory(){};export async function assertSafeDirectory(){return ensureSafeDirectory()};export async function atomicWriteFile(){throw new Error("Synthetic manifest publication failure")}');
    stub('./config-stub.mjs', 'export function validateAgentOptions(){return {}};');
    stub('./validation-stub.mjs', 'export const PINS={anthropic:"pin"},SOURCES={anthropic:"source"},OUTPUTS={anthropic:[]};export function nativeOptions(){return {workRoot:process.env.TEST_WORK,skillRoot:"/synthetic",model:"synthetic"}};export async function safeRead(){return Buffer.from("{}")}export function sha256(){return "hash"}export async function sourceManifest(path){return [{path:"fixture.txt",lines:1,sha256:"hash"}]}export async function copySources(source,copy){const fs=await import("node:fs/promises");const p=await import("node:path");await fs.mkdir(copy);await fs.writeFile(p.join(copy,"fixture.txt"),"synthetic")}export function sameInputs(){return true}export function inspectNativeEvents(){return {reasons:[]}}export function verifyCloudflareRecords(){return []}export async function verifySourcePin(){return []}export async function runOfficialValidators(){return []}export function parseAnthropicDocument(){return {}}');
    stub('./invocation-stub.mjs', 'export function cloudflarePrompt(){return ""};export function codexArgs(){return []};export function claudeArgs(){return []}');
    export async function resolve(specifier, context, nextResolve) {
      const target = specifier === '../safe-io.mjs' ? './safe-stub.mjs' : specifier === '../config.mjs' ? './config-stub.mjs' : specifier === './validation.mjs' ? './validation-stub.mjs' : specifier === './invocation.mjs' ? './invocation-stub.mjs' : null;
      if(target){const u=pathToFileURL(new URL(target,import.meta.url).pathname).href;return {url:u,shortCircuit:true};}
      return nextResolve(specifier,context);
    }
    export async function load(url,context,nextLoad){if(stubs.has(url))return {format:'module',source:stubs.get(url),shortCircuit:true};return nextLoad(url,context)}
  `);
  const result = await child(process.execPath, ['--experimental-loader', loader, fileURLToPath(new URL(wrapper)), JSON.stringify({ id: 'anthropic', command: '/synthetic-no-provider', args: [], target: join(root, 'target'), artifactDir: join(root, 'artifacts') })], { env: { ...process.env, TEST_WORK: join(root, 'work') } });
  assert.equal(result.exitCode, 2, result.stderr);
  assert.match(result.stderr, /Synthetic manifest publication failure/);
  assert.deepEqual(await readdir(join(root, 'work')), []);
});
