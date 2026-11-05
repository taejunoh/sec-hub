import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';

test('Cloudflare doctor rejects unsupported Codex sandbox backend while Anthropic check is unchanged', async () => {
  registerHooks({
    resolve(specifier, context, next) {
      if (specifier === '../processes.mjs' && context.parentURL?.includes('/src/agents/index.mjs')) return { url: 'fixture:processes', shortCircuit: true };
      if (specifier === '../config.mjs' && context.parentURL?.includes('/src/agents/index.mjs')) return { url: 'fixture:config', shortCircuit: true };
      if (specifier === './validation.mjs' && context.parentURL?.includes('/src/agents/index.mjs')) return { url: 'fixture:validation', shortCircuit: true };
      if (specifier === './codex-sandbox.mjs' && context.parentURL?.includes('/src/agents/index.mjs')) return { url: 'fixture:sandbox', shortCircuit: true };
      return next(specifier, context);
    },
    load(url, context, next) {
      if (url === 'fixture:processes') return { format: 'module', shortCircuit: true, source: `export async function runProcess(){return {status:'completed',stdout:'codex-cli 0.154.0',stderr:''}}` };
      if (url === 'fixture:config') return { format: 'module', shortCircuit: true, source: 'export function validateAgentOptions(_id,value){return value}' };
      if (url === 'fixture:validation') return { format: 'module', shortCircuit: true, source: `export const SOURCES={cloudflare:'fixture',anthropic:'fixture'};export function nativeOptions(_id,value){return value};export async function verifySourcePin(){};export async function validateNativeExecution(){return {findings:[]}};export async function finalizeNativeExecution(){return {execution:{}}}` };
      if (url === 'fixture:sandbox') return { format: 'module', shortCircuit: true, source: `export function assertSandboxBackend(version){if(!/^codex-cli 0\\.164\\.0(?:\\s|$)/.test(version))throw new Error('Restricted Codex sandbox requires macOS codex-cli 0.164.0; refusing legacy fallback')}` };
      return next(url, context);
    },
  });
  const { nativeAgentAdapters } = await import('../src/agents/index.mjs?doctor-compat');
  const context = id => ({ config: { tools: { [id]: { command: `/fake/${id}`, args: [], agentOptions: {} } } } });
  const cloudflare = await nativeAgentAdapters.find(adapter => adapter.id === 'cloudflare').check(context('cloudflare'));
  assert.equal(cloudflare.available, false);
  assert.match(cloudflare.reason, /macOS codex-cli 0\.164\.0/);
  const anthropic = await nativeAgentAdapters.find(adapter => adapter.id === 'anthropic').check(context('anthropic'));
  assert.equal(anthropic.available, true);
  assert.equal(anthropic.version, 'codex-cli 0.154.0');
});
