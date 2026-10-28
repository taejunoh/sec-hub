import { randomBytes, timingSafeEqual } from 'node:crypto';

export class ExecutionPolicyError extends Error {
  constructor(code, statusCode) { super(code); this.code = code; this.statusCode = statusCode; }
}
const reject = (code = 'forbidden', status = 403) => { throw new ExecutionPolicyError(code, status); };
function values(request, name) {
  const found = [];
  for (let index = 0; index < (request.rawHeaders?.length ?? 0); index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name) found.push(request.rawHeaders[index + 1]);
  }
  return found;
}
function single(request, name, expected) {
  const headers = values(request, name);
  if (headers.length !== 1 || headers[0] !== expected) reject();
}
function secretMatches(actual, expected) {
  if (typeof actual !== 'string' || !/^[a-f0-9]{64}$/.test(actual)) return false;
  return timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
export function createExecutionSession() {
  return Object.freeze({ token: randomBytes(32).toString('hex'), csrfToken: randomBytes(32).toString('hex') });
}
export function validateExecutionRequest(request, port, session) {
  single(request, 'host', `127.0.0.1:${port}`);
  const authorization = values(request, 'authorization');
  if (authorization.length > 1) reject();
  if (authorization.length !== 1 || !authorization[0].startsWith('Bearer ') || !secretMatches(authorization[0].slice(7), session.token)) reject('unauthorized', 401);
  if (values(request, 'origin').length > 1 || values(request, 'x-sec-hub-csrf').length > 1) reject();
  const sites = values(request, 'sec-fetch-site');
  if (sites.length > 1 || (sites.length === 1 && sites[0] !== 'same-origin')) reject();
  if (request.method === 'POST') {
    single(request, 'origin', `http://127.0.0.1:${port}`);
    const csrf = values(request, 'x-sec-hub-csrf');
    if (csrf.length !== 1 || !secretMatches(csrf[0], session.csrfToken)) reject();
  }
}

/** Reject before reading; bound every accepted body independently of its declaration. */
export function readExecutionJson(request) {
  const contentTypes = values(request, 'content-type');
  if (contentTypes.length !== 1 || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentTypes[0])) reject('invalid_request', 400);
  if (values(request, 'content-encoding').length) reject('invalid_request', 400);
  const lengths = values(request, 'content-length');
  if (lengths.length > 1 || (lengths.length && !/^\d+$/.test(lengths[0]))) reject('invalid_request', 400);
  if (lengths.length && Number(lengths[0]) > 4096) reject('body_too_large', 413);
  return new Promise((resolve, rejectBody) => {
    let size = 0;
    let settled = false;
    const chunks = [];
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      request.off('data', onData); request.off('end', onEnd); request.off('error', onError); request.off('aborted', onAborted);
      if (error) { request.pause(); rejectBody(error); } else resolve(value);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > 4096) { finish(new ExecutionPolicyError('body_too_large', 413)); return; }
      chunks.push(chunk);
    };
    const onEnd = () => {
      let value;
      try { value = JSON.parse(Buffer.concat(chunks, size).toString('utf8')); } catch { finish(new ExecutionPolicyError('invalid_request', 400)); return; }
      if (!value || typeof value !== 'object' || Array.isArray(value)) { finish(new ExecutionPolicyError('invalid_request', 400)); return; }
      finish(null, value);
    };
    const onError = () => finish(new ExecutionPolicyError('invalid_request', 400));
    const onAborted = () => finish(new ExecutionPolicyError('invalid_request', 400));
    const deadline = setTimeout(() => finish(new ExecutionPolicyError('body_timeout', 408)), 5000);
    request.on('data', onData); request.once('end', onEnd); request.once('error', onError); request.once('aborted', onAborted);
  });
}
