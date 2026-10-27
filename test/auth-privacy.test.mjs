import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanVerificationLog } from '../scripts/live-verify-redaction.mjs';

test('verification log redaction preserves JSON while masking synthetic identity and credential values', () => {
  const source = JSON.stringify({
    account_id: 'synthetic-account-123456',
    email: 'person@example.invalid',
    access_token: 'synthetic-access-token-value',
    refresh_token: 'synthetic-refresh-token-value',
    jwt: 'eyJabcdefghijk.eyJabcdefghijk.signaturepayload123456',
    authorization: 'Bearer synthetic-bearer-token-value',
    api_key: 'sk-ant-syntheticabcdefghijklmnop',
  });
  const result = cleanVerificationLog(source);
  const parsed = JSON.parse(result);
  assert.deepEqual(Object.keys(parsed), ['account_id', 'email', 'access_token', 'refresh_token', 'jwt', 'authorization', 'api_key']);
  assert.equal(parsed.account_id, '[REDACTED_ID]');
  assert.equal(parsed.email, '[REDACTED_EMAIL]');
  assert.equal(parsed.access_token, '[REDACTED_CREDENTIAL]');
  assert.equal(parsed.refresh_token, '[REDACTED_CREDENTIAL]');
  assert.equal(parsed.jwt, '[REDACTED_JWT]');
  assert.equal(parsed.authorization, 'Bearer [REDACTED_CREDENTIAL]');
  assert.equal(parsed.api_key, '[REDACTED_CREDENTIAL]');
  assert.doesNotMatch(result, /synthetic|person@example/);
});

test('verification log redaction masks opaque credentials in single-quoted and backtick formats', () => {
  const source = "access_token='syntheticopaquevalue' {'api_key': 'syntheticopaquevalue'} `client_secret`=`syntheticopaquevalue`";
  const result = cleanVerificationLog(source);
  assert.equal(result, "access_token='[REDACTED_CREDENTIAL]' {'api_key': '[REDACTED_CREDENTIAL]'} `client_secret`=`[REDACTED_CREDENTIAL]`");
  assert.doesNotMatch(result, /syntheticopaquevalue/);
});
