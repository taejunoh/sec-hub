import test from 'node:test';
import assert from 'node:assert/strict';
import { assertObservedPolicy } from '../src/agents/supervised-validation.mjs';

const expected = {
  context: { target: '/copy', runner: '/runner' },
  readFiles: ['/pinned/SKILL.md'],
  readCommands: ["cat '/pinned/SKILL.md'"]
};
const event = command => ({ type: 'item.started', item: { type: 'command_execution', command } });

test('supervised Cloudflare readers accept absolute target and explicitly pinned paths', () => {
  for (const command of [
    "rg --files '/copy'",
    "rg -n '' '/copy/package.json'",
    "sed -n '1,120p' '/copy/package.json'",
    "rg -n '' '/pinned/SKILL.md'"
  ]) assert.doesNotThrow(() => assertObservedPolicy(event(command), expected), command);
});

test('supervised Cloudflare readers reject relative paths and implicit roots', () => {
  for (const command of [
    'rg --files',
    'rg --files .',
    'ls',
    'cat package.json',
    "rg -n '' package.json",
    "sed -n '1,120p' package.json",
    "cat '/pinned/OTHER.md'"
  ]) assert.throws(() => assertObservedPolicy(event(command), expected), /source-only command policy/, command);
});

test('supervised Cloudflare readers reject escapes, shell composition, preprocessors, redirection and executors', () => {
  for (const command of [
    "cat '/copy/../etc/passwd'",
    "rg --files '/copy' | head",
    "rg --files '/copy' && ls '/copy'",
    "rg --files '/copy' > files.txt",
    'rg --files $(pwd)',
    'rg --files `pwd`',
    "cd '/copy' && ls",
    "node -e 'console.log(1)'"
  ]) assert.throws(() => assertObservedPolicy(event(command), expected), /source-only command policy/, command);
});
