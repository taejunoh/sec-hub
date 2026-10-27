const REASONS = {
  success: undefined,
  auth_expired: 'The provider authentication session has expired.',
  usage_limit: 'The provider usage allowance is exhausted.',
  rate_limit: 'The provider is temporarily rate limiting requests.',
  model_unavailable: 'The requested model is unavailable.',
  permission_denied: 'The provider denied a required permission.',
  budget_exceeded: 'The provider execution budget was exceeded.',
  turn_limit: 'The provider turn limit was reached.',
  cancelled: 'The provider operation was cancelled.',
  backend_error: 'The provider operation failed.',
  missing_terminal: 'The provider did not report a recognized terminal outcome.'
};

const TERMINAL_TYPES = new Set([
  'result', 'turn.completed', 'turn.failed', 'response.completed',
  'response.failed', 'thread.completed', 'thread.failed', 'error'
]);

function parseJsonString(value) {
  if (typeof value !== 'string' || !value.trim().startsWith('{')) return undefined;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function collect(events) {
  const strings = [];
  const statuses = [];
  const resets = [];
  const terminals = [];
  let hasPermissionDenials = false;
  const seen = new Set();

  function visit(value, depth = 0, inErrorContext = false, inTerminalContext = false) {
    if (depth > 8 || value == null) return;
    if (typeof value === 'string') {
      if (inErrorContext) strings.push(value);
      const parsed = parseJsonString(value);
      if (parsed) visit(parsed, depth + 1, inErrorContext, inTerminalContext);
      return;
    }
    if (typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const child of value) visit(child, depth + 1, inErrorContext, inTerminalContext);
      return;
    }

    const objectErrorContext = inErrorContext || value.is_api_error_message === true;
    for (const [key, child] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase().replaceAll('-', '_');
      if (['status', 'status_code', 'api_error_status'].includes(normalizedKey)) {
        const status = Number(child);
        if (Number.isInteger(status) && status >= 100 && status <= 599) statuses.push(status);
      }
      if (['reset_at', 'resetat', 'reset_time', 'retry_at', 'retryat'].includes(normalizedKey) && typeof child === 'string') {
        resets.push(child);
      }
      if (inTerminalContext && normalizedKey === 'permission_denials' && Array.isArray(child) && child.length > 0) {
        hasPermissionDenials = true;
      }
      if (['code', 'type', 'subtype', 'terminal_reason'].includes(normalizedKey) && typeof child === 'string') {
        strings.push(child);
      }
      const childIsError = objectErrorContext
        || ['error', 'errors', 'cause'].includes(normalizedKey);
      if (normalizedKey === 'message' && childIsError && typeof child === 'string') strings.push(child);
      visit(child, depth + 1, childIsError, inTerminalContext);
    }
  }

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    const type = typeof event.type === 'string' ? event.type.toLowerCase() : '';
    const subtype = typeof event.subtype === 'string' ? event.subtype.toLowerCase() : '';
    if (TERMINAL_TYPES.has(type) || (type === 'result' && subtype)) terminals.push(event);
    const isErrorTerminal = type.endsWith('.failed') || type === 'error'
      || subtype.startsWith('error') || event.is_error === true;
    visit(event, 0, isErrorTerminal, terminals.includes(event));
  }

  return { strings, statuses, resets, terminals, hasPermissionDenials };
}

function categoryFor(strings) {
  const text = strings.join('\n').toLowerCase();
  if (/usage_limit_reached|usage[ _-]+limit|weekly.{0,40}limit|quota.{0,40}(?:exceed|reach|exhaust)|(?:exceed|reach|exhaust).{0,40}quota/.test(text)) return 'usage_limit';
  if (/auth(?:entication)?[ _-]*(?:session[ _-]*)?expir|oauth.{0,40}expir|token.{0,30}expir|authentication_error/.test(text)) return 'auth_expired';
  if (/permission_denied|permission[ _-]+denied|not authorized|forbidden/.test(text)) return 'permission_denied';
  if (/budget_exceeded|budget.{0,30}(?:exceed|limit)|max_budget/.test(text)) return 'budget_exceeded';
  if (/error_max_turns|turn_limit|maximum.{0,20}turns|turn.{0,20}limit/.test(text)) return 'turn_limit';
  if (/cancelled|canceled|request_aborted/.test(text)) return 'cancelled';
  if (/model_not_found|model.{0,30}unavailable|overloaded_error|model_overloaded/.test(text)) return 'model_unavailable';
  if (/rate_limit_error|rate[ _-]+limit|too many requests|http.?429/.test(text)) return 'rate_limit';
  return undefined;
}

function parseRetryAt(values) {
  for (const value of values) {
    const milliseconds = Date.parse(value);
    if (Number.isFinite(milliseconds)) return new Date(milliseconds).toISOString();
  }
  return undefined;
}

function outcome(category, { statusCode, retryAt } = {}) {
  return {
    ok: category === 'success',
    category,
    ...(REASONS[category] ? { reason: REASONS[category] } : {}),
    ...(statusCode ? { statusCode } : {}),
    ...(retryAt ? { retryAt } : {})
  };
}

export function inspectTerminalOutcome(toolId, events, exitCode) {
  // toolId is part of the public contract so callers can pass the native tool
  // identity; classification relies on provider event fields, not tool labels.
  void toolId;
  const data = collect(Array.isArray(events) ? events : []);
  const statusCode = data.statuses[0];
  const retryAt = parseRetryAt(data.resets);
  const classified = categoryFor(data.strings);
  if (classified) return outcome(classified, { statusCode, retryAt });

  const terminal = data.terminals.at(-1);
  if (!terminal) return outcome('missing_terminal', { statusCode, retryAt });

  const terminalType = String(terminal.type ?? '').toLowerCase();
  const terminalSubtype = String(terminal.subtype ?? '').toLowerCase();
  const isSuccess = (terminalType === 'result' && terminalSubtype === 'success')
    || terminalType === 'turn.completed'
    || terminalType === 'response.completed'
    || terminalType === 'thread.completed';

  if (data.hasPermissionDenials) return outcome('permission_denied', { statusCode, retryAt });
  if (terminal.is_error === true || terminal.terminal_reason === 'api_error') {
    return outcome('backend_error', { statusCode, retryAt });
  }
  if (isSuccess && (exitCode == null || exitCode === 0)) return outcome('success');
  if (isSuccess && exitCode !== 0) return outcome('backend_error', { statusCode, retryAt });
  if (terminalType.endsWith('.failed') || terminalType === 'error'
    || terminalSubtype.startsWith('error')) return outcome('backend_error', { statusCode, retryAt });
  return outcome('missing_terminal', { statusCode, retryAt });
}
