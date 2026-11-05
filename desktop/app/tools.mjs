import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';

const lock = JSON.parse(await readFile(new URL('./osv-lock.json', import.meta.url), 'utf8'));
const catalog = [
  { id: 'osv', ai: false, setup: { install: 'https://google.github.io/osv-scanner/installation/' } },
  { id: 'skillspector', ai: false, setup: { install: 'https://github.com/NVIDIA/skillspector' } },
  { id: 'codex-security', ai: true, setup: { install: 'https://github.com/openai/codex-security' } },
  { id: 'open-code-review', ai: true, setup: { install: 'https://github.com/alibaba/open-code-review' } },
  { id: 'php2shell', ai: false, setup: { install: 'https://github.com/openai/php2shell-checker' } },
  { id: 'cloudflare', ai: true, setup: { install: 'https://github.com/cloudflare/security-audit-skill' } },
  { id: 'anthropic', ai: true, setup: { install: 'https://github.com/anthropics/defending-code-reference-harness' } },
];

export async function verifiedOSV(resources) {
  const pin = lock.targets[`${process.platform}-${process.arch}`];
  if (!resources || !pin) return null;
  const candidate = join(resources, 'tools', 'osv', pin.filename);
  let handle;
  try {
    const named = await lstat(candidate, { bigint: true });
    if (!named.isFile() || named.size !== BigInt(pin.size) || await realpath(candidate) !== candidate) return null;
    handle = await open(candidate, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size !== BigInt(pin.size) || before.dev !== named.dev || before.ino !== named.ino) return null;
    const hash = createHash('sha256');
    for await (const data of handle.createReadStream({ autoClose: false, end: pin.size - 1 })) hash.update(data);
    const after = await handle.stat({ bigint: true });
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) return null;
    return hash.digest('hex') === pin.sha256 ? candidate : null;
  } catch { return null; }
  finally { await handle?.close(); }
}

export async function inspectDesktopTools(resources) {
  const osv = await verifiedOSV(resources);
  return catalog.map((tool) => tool.id === 'osv'
    ? { ...tool, installation: osv ? 'installed' : 'missing', ...(osv ? { command: osv, setup: undefined } : {}) }
    : { ...tool, installation: 'unknown' });
}
