import { isAbsolute, resolve } from 'node:path';

// Path selection only: hook-based tests must control when production imports load.
export function cloudflareSourceRoot() {
  const configured = process.env.SEC_HUB_TEST_CLOUDFLARE_ROOT;
  if (configured !== undefined) {
    if (!isAbsolute(configured)) throw new Error('SEC_HUB_TEST_CLOUDFLARE_ROOT must be absolute');
    return resolve(configured);
  }
  return resolve('../../work/tools/cloudflare-security-audit');
}
