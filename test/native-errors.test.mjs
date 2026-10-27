import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectTerminalOutcome } from '../src/agents/native-errors.mjs';

test('a provider terminal success is backend success when the process exits cleanly', () => {
  const result = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'success', is_error: false, permission_denials: [] }
  ], 0);

  assert.deepEqual(result, { ok: true, category: 'success' });
});

test('Claude success subtype with an API error marker is a safe backend failure', () => {
  const result = inspectTerminalOutcome('anthropic', [
    { type: 'assistant', error: 'authentication failed for a private account', is_api_error_message: true },
    { type: 'result', subtype: 'success', is_error: true, terminal_reason: 'api_error' }
  ], 0);

  assert.equal(result.ok, false);
  assert.equal(result.category, 'backend_error');
  assert.doesNotMatch(result.reason, /private account|authentication failed/i);
});

test('weekly usage quota is distinct from a transient rate limit and preserves an explicit reset', () => {
  const weekly = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'error', is_error: true, error: {
      type: 'usage_limit_reached', message: 'Weekly usage limit reached; resets at 2026-10-29T10:00:00Z',
      status: 429, reset_at: '2026-10-29T10:00:00Z'
    } }
  ], 1);
  const transient = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'error', is_error: true, error: {
      type: 'rate_limit_error', message: 'Too many requests', status: 429
    } }
  ], 1);

  assert.deepEqual(weekly, {
    ok: false,
    category: 'usage_limit',
    reason: 'The provider usage allowance is exhausted.',
    statusCode: 429,
    retryAt: '2026-10-29T10:00:00.000Z'
  });
  assert.equal(transient.category, 'rate_limit');
  assert.equal(transient.retryAt, undefined);
});

test('Codex model_not_found is reported as unavailable without exposing its server message', () => {
  const result = inspectTerminalOutcome('codex', [
    { type: 'error', message: JSON.stringify({
      type: 'error', status: 400,
      error: { type: 'invalid_request_error', message: 'private org detail', code: 'model_not_found' }
    }) },
    { type: 'turn.failed', error: { message: 'model_not_found' } }
  ], 1);

  assert.equal(result.category, 'model_unavailable');
  assert.equal(result.statusCode, 400);
  assert.doesNotMatch(result.reason, /private org detail/i);
});

test('permission denials and process failure contradict a terminal success', () => {
  const denied = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'success', is_error: false, permission_denials: ['Bash'] }
  ], 0);
  const crashed = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'success', is_error: false, permission_denials: [] }
  ], 2);

  assert.equal(denied.category, 'permission_denied');
  assert.equal(denied.ok, false);
  assert.equal(crashed.category, 'backend_error');
  assert.equal(crashed.ok, false);
  assert.equal(inspectTerminalOutcome('anthropic', [
    { type: 'assistant', permission_denials: ['stale/non-terminal denial'] },
    { type: 'result', subtype: 'success', is_error: false, permission_denials: [] }
  ], 0).ok, true);
});

test('known native failure categories are normalized and unknown or missing terminals never pass', () => {
  const cases = [
    [[{ type: 'turn.failed', error: { code: 'authentication_error', message: 'expired' } }], 1, 'auth_expired'],
    [[{ type: 'turn.failed', error: { code: 'permission_denied' } }], 1, 'permission_denied'],
    [[{ type: 'turn.failed', error: { code: 'budget_exceeded' } }], 1, 'budget_exceeded'],
    [[{ type: 'result', subtype: 'error_max_turns', is_error: true }], 1, 'turn_limit'],
    [[{ type: 'turn.failed', error: { code: 'cancelled' } }], 1, 'cancelled'],
    [[{ type: 'turn.failed', error: { code: 'unknown_internal_failure' } }], 1, 'backend_error'],
    [[{ type: 'notice', message: 'work may have ended' }], 0, 'missing_terminal'],
    [[], 0, 'missing_terminal']
  ];

  for (const [events, exitCode, category] of cases) {
    const result = inspectTerminalOutcome('codex', events, exitCode);
    assert.equal(result.ok, false);
    assert.equal(result.category, category);
  }
});

test('retry time is accepted only from explicit structured reset fields', () => {
  const result = inspectTerminalOutcome('anthropic', [
    { type: 'result', subtype: 'error', is_error: true,
      error: { type: 'rate_limit_error', message: 'Try again after 2099-01-01T00:00:00Z' } }
  ], 1);

  assert.equal(result.retryAt, undefined);
});

test('ordinary source, tool, and assistant payload fields cannot classify a successful provider turn', () => {
  const source = { code: 'permission_denied', type: 'authentication_error', subtype: 'usage_limit_reached',
    status: 403, reset_at: '2099-01-01T00:00:00Z', error: { code: 'budget_exceeded' } };
  const payloads = [
    { type: 'item.completed', item: { type: 'mcp_tool_call', arguments: source, result: source } },
    { type: 'assistant', message: { content: [{ type: 'tool_use', input: source }] } },
    { type: 'user', message: { content: [{ type: 'tool_result', is_error: true, content: JSON.stringify(source) }] } },
    { type: 'assistant', message: { content: [{ type: 'text', text: JSON.stringify(source) }] } }
  ];
  assert.deepEqual(inspectTerminalOutcome('codex', [
    { type: 'item.completed', item: { type: 'tool_result', result: { code: 'permission_denied' } } },
    { type: 'turn.completed' }
  ], 0), { ok: true, category: 'success' });
  for (const terminal of [{ type: 'turn.completed' }, { type: 'result', subtype: 'success', is_error: false, result: source }]) {
    assert.deepEqual(inspectTerminalOutcome('codex', [...payloads, terminal], 0), { ok: true, category: 'success' });
  }
});

test('handled intermediate provider errors cannot overshadow final success', () => {
  const events = [
    { type: 'error', message: JSON.stringify({ error: { code: 'permission_denied' }, status: 403 }) },
    { type: 'assistant', is_api_error_message: true, error: { type: 'rate_limit_error', status: 429 } },
    { type: 'turn.failed', error: { code: 'authentication_error' } },
    { type: 'turn.completed' }
  ];
  assert.deepEqual(inspectTerminalOutcome('codex', events, 0), { ok: true, category: 'success' });
  assert.equal(inspectTerminalOutcome('codex', events, 2).ok, false);
});

test('failure classification reads provider error envelopes without traversing quoted payloads', () => {
  const events = [
    { type: 'item.completed', item: { result: { code: 'permission_denied', status: 403 } } },
    { type: 'turn.failed', error: { code: 'transport_error', details: { code: 'authentication_error' } } }
  ];
  const result = inspectTerminalOutcome('codex', events, 1);
  assert.equal(result.category, 'backend_error');
  assert.equal(result.statusCode, undefined);
});

test('real final policy, transport, and tool-process failures remain failures', () => {
  for (const code of ['content_policy_violation', 'transport_error', 'tool_process_failed']) {
    const result = inspectTerminalOutcome('codex', [
      { type: 'turn.failed', error: { code } }
    ], 1);
    assert.equal(result.ok, false);
    assert.equal(result.category, 'backend_error');
  }
  assert.equal(inspectTerminalOutcome('codex', [
    { type: 'turn.completed' }, { type: 'turn.failed', error: { code: 'permission_denied' } }
  ], 0).category, 'permission_denied');
});

test('malformed or absent terminal metadata cannot borrow classifications from source content', () => {
  const payload = { type: 'assistant', message: { code: 'permission_denied', status: 403 } };
  for (const events of [[payload], [payload, { type: 'result', subtype: 'unexpected', result: { code: 'authentication_error' } }]]) {
    assert.deepEqual(inspectTerminalOutcome('anthropic', events, 0), {
      ok: false, category: 'missing_terminal', reason: 'The provider did not report a recognized terminal outcome.'
    });
  }
});


test('a recovered turn cannot supply stale diagnostics to a later failed turn', () => {
  const result = inspectTerminalOutcome('codex', [
    { type: 'error', error: { code: 'usage_limit_reached', status: 429 } },
    { type: 'turn.completed' },
    { type: 'turn.failed', error: { code: 'authentication_error', status: 401 } }
  ], 1);
  assert.equal(result.category, 'auth_expired');
  assert.equal(result.statusCode, 401);
});
