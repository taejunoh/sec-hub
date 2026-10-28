import test from 'node:test';
import assert from 'node:assert/strict';
import { createExecutionSession, validateExecutionRequest } from '../src/dashboard/execution-policy.mjs';

// Removing any of the distinct security checks would admit one of these requests.
test('execution policy requires exact loopback authority and independent bearer/CSRF secrets', () => {
  const session = createExecutionSession();
  assert.match(session.token, /^[a-f0-9]{64}$/);
  assert.match(session.csrfToken, /^[a-f0-9]{64}$/);
  assert.notEqual(session.token, session.csrfToken);
  assert.notEqual(session.token, createExecutionSession().token);
  const headers = ['Host', '127.0.0.1:1234', 'Authorization', `Bearer ${session.token}`, 'Origin', 'http://127.0.0.1:1234', 'X-Sec-Hub-CSRF', session.csrfToken];
  const request = (rawHeaders, method = 'POST') => ({ rawHeaders, method });
  assert.doesNotThrow(() => validateExecutionRequest(request(headers), 1234, session));
  for (const rawHeaders of [
    headers.filter((_, index) => index < 2 || index > 3),
    headers.map(value => value === `Bearer ${session.token}` ? `Bearer ${'0'.repeat(64)}` : value),
    headers.map(value => value === `Bearer ${session.token}` ? 'Basic stale' : value),
  ]) assert.throws(() => validateExecutionRequest(request(rawHeaders), 1234, session), { code: 'unauthorized', statusCode: 401 });
  for (const bad of [
    headers.map(value => value === '127.0.0.1:1234' ? 'localhost:1234' : value),
    headers.map(value => value === 'http://127.0.0.1:1234' ? 'null' : value),
    headers.filter((_, index) => index < 4 || index > 5),
    headers.map(value => value === session.csrfToken ? '0'.repeat(64) : value),
    [...headers, 'Authorization', `Bearer ${session.token}`],
    [...headers, 'Origin', 'http://127.0.0.1:1234'],
    [...headers, 'X-Sec-Hub-CSRF', session.csrfToken],
    [...headers, 'Sec-Fetch-Site', 'none'],
  ]) assert.throws(() => validateExecutionRequest(request(bad), 1234, session), { code: 'forbidden', statusCode: 403 });
  assert.doesNotThrow(() => validateExecutionRequest(request(headers.slice(0, 4), 'GET'), 1234, session));
  assert.throws(() => validateExecutionRequest(request([...headers, 'X-Sec-Hub-CSRF', session.csrfToken], 'GET'), 1234, session), { code: 'forbidden' });
});
