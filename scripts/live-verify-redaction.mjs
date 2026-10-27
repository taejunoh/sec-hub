import { createRedactor } from '../src/redaction.mjs';

const inheritedSecrets = createRedactor();
const accountId = /((?:"?(?:account|organization|workspace)[_-]?id"?\s*:\s*"?|\b(?:account|organization|workspace)[_-]?id\s*[=:]\s*"?))([^"'\s,;}]+)("?)/gi;

/** Redact common identity and credential values in verification command logs. */
export function cleanVerificationLog(value) {
  return inheritedSecrets(String(value))
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(accountId, '$1[REDACTED_ID]$3')
    .replace(/((?:"?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret)"?\s*[:=]\s*"?|\bBearer\s+))([^"'`\s,;}]+)("?)/gi, '$1[REDACTED_CREDENTIAL]$3')
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '[REDACTED_JWT]')
    .replace(/\b(?:sk-(?:ant|proj|live)-|ghp_|github_pat_)[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_CREDENTIAL]');
}
