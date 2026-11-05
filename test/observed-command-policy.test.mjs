import test from 'node:test';
import assert from 'node:assert/strict';
import { assertObservedPolicy } from '../src/agents/supervised-validation.mjs';

const expected = { context: { target: '/copy', runner: '/runner' }, readFiles: [], readCommands: [] };
test('command events without a usable command fail closed', () => {
  for (const command of [undefined, null, '', 42]) {
    assert.throws(() => assertObservedPolicy({ type: 'item.started', item: { type: 'command_execution', command } }, expected), /source-only command policy/);
  }
});
test('command events accept scoped reads and reject outside reads', () => {
  assert.doesNotThrow(() => assertObservedPolicy({ type: 'item.started', item: { type: 'command_execution', command: 'cat /copy/file' } }, expected));
  assert.throws(() => assertObservedPolicy({ type: 'item.started', item: { type: 'command_execution', command: 'cat /outside/canary' } }, expected), /source-only command policy/);
});
