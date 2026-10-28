import test from 'node:test';
import assert from 'node:assert/strict';
import { messages, translate } from '../src/web/i18n.mjs';

test('both locales cover the same app keys with nonempty translations', () => {
  assert.deepEqual(Object.keys(messages.ko).sort(), Object.keys(messages.en).sort());
  for (const locale of ['ko', 'en']) for (const value of Object.values(messages[locale])) assert.equal(typeof value === 'string' && value.length > 0, true);
  assert.equal(translate('en', '자료 목록'), 'Artifacts');
  assert.equal(translate('ko', '자료 목록'), '자료 목록');
});

test('unsupported locales and missing keys fall back deterministically without altering raw payloads', () => {
  assert.equal(translate('xx', '자료 목록'), '자료 목록');
  assert.equal(translate('en', 'raw/<img src=x>'), 'raw/<img src=x>');
  assert.equal(translate('__proto__', '자료 목록'), '자료 목록');
  assert.equal(translate('en', 'toString'), 'toString');
  assert.equal(translate('en', '{count}개 저장 행', { count: 140 }), '140 saved rows');
});
