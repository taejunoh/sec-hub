import { constants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, delimiter, dirname, isAbsolute, join, relative, sep } from 'node:path';
import { parseConfig } from '../config.mjs';
import { PINS, nativeOptions, safeRead } from '../agents/validation.mjs';
import { runProcess } from '../processes.mjs';
import { assertSafeDirectory } from '../safe-io.mjs';

export const desktopToolIds = Object.freeze(['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell', 'cloudflare', 'anthropic']);
const wrappers = new Set(['codex-security', 'cloudflare', 'anthropic']);
const nodeName = (name, platform) => name.toLowerCase() === (platform === 'win32' ? 'node.exe' : 'node');

export function containsPath(parent, child) {
  if (!parent || !child) return false;
  const value = relative(parent, child);
  return !isAbsolute(value) && value !== '..' && !value.startsWith(`..${sep}`);
}

export async function readDesktopConfig(filename) {
  if (typeof filename !== 'string' || !isAbsolute(filename) || !/\.json$/i.test(filename)) throw new Error('Invalid config file');
  const path = join(await assertSafeDirectory(dirname(filename)), basename(filename));
  if (!(await lstat(path)).isFile()) throw new Error('Invalid config file');
  const config = parseConfig(JSON.parse((await safeRead(path, 256 * 1024)).toString('utf8')));
  if (Object.keys(config.tools).some(id => !desktopToolIds.includes(id))) throw new Error('Unknown desktop tool');
  return { path, config };
}

async function trustedFile(requested, excluded) {
  if (!isAbsolute(requested) || excluded.some(root => containsPath(root, requested))) return null;
  try {
    const path = await realpath(requested);
    if (excluded.some(root => containsPath(root, path))) return null;
    const parent = await assertSafeDirectory(dirname(path));
    const canonical = join(parent, basename(path));
    const info = await lstat(canonical);
    if (!info.isFile() || (process.geteuid && (![0, process.geteuid()].includes(info.uid) || (info.mode & 0o022) !== 0))) return null;
    return canonical;
  } catch { return null; }
}

async function executable(requested, excluded, platform) {
  if (platform === 'win32' && !/\.exe$/i.test(requested)) return null;
  const path = await trustedFile(requested, excluded);
  if (!path || (platform === 'win32' && !/\.exe$/i.test(path))) return null;
  try {
    await access(path, constants.X_OK);
    return path;
  } catch { return null; }
}

export async function validateDesktopNodePath(requested, excluded) {
  if (typeof requested !== 'string' || !nodeName(basename(requested), process.platform)) return null;
  const path = await executable(requested, excluded, process.platform);
  return path && nodeName(basename(path), process.platform) ? path : null;
}

export async function verifyDesktopNode(command, signal) {
  const result = await runProcess({ command, args: ['--version'] }, { signal, timeoutMs: 5_000, maxOutputBytes: 1024 });
  return result.status === 'completed' && Number(/^v([0-9]+)\.[0-9]+\.[0-9]+$/.exec(result.stdout.trim())?.[1]) >= 22;
}

function installDirectories(platform, env) {
  const home = homedir();
  const defaults = platform === 'win32'
    ? [env.ProgramFiles && join(env.ProgramFiles, 'nodejs'), env.LOCALAPPDATA && join(env.LOCALAPPDATA, 'Programs', 'nodejs'), join(home, '.local', 'bin')]
    : [join(home, '.local', 'bin'), join(home, 'bin'), '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin'];
  return [...new Set([...(env.PATH ?? env.Path ?? '').split(delimiter), ...defaults].filter(path => path && isAbsolute(path)))];
}

async function findCommand(command, directories, excluded, platform) {
  if (isAbsolute(command)) return executable(command, excluded, platform);
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(command)) return null;
  const filename = platform === 'win32' && !/\.exe$/i.test(command) ? `${command}.exe` : command;
  for (const directory of directories) {
    const found = await executable(join(directory, filename), excluded, platform);
    if (found) return found;
  }
  return null;
}

const unavailable = (tool, unavailableReason, installation = tool.installation) => ({ ...tool, command: undefined, installation, unavailableReason });

export async function inspectDesktopTooling(baseTools, {
  config, configPath, nodePath, targetPath, runsRoot, platform = process.platform, env = process.env,
} = {}) {
  const excluded = [targetPath, runsRoot].filter(Boolean);
  const directories = installDirectories(platform, env);
  const configured = config?.tools ?? {};
  const runtime = async () => {
    if (nodePath) return validateDesktopNodePath(nodePath, excluded);
    const candidate = await findCommand('node', directories, excluded, platform);
    return candidate && nodeName(basename(candidate), platform) ? candidate : null;
  };
  let node;
  return Promise.all(baseTools.map(async tool => {
    const { id } = tool;
    if (id === 'cloudflare' && platform !== 'darwin' || id === 'anthropic' && platform === 'win32') return unavailable(tool, 'platform_unsupported');
    if (id === 'osv' && tool.command) return tool;

    const entry = configured[id];
    if (entry && excluded.some(root => containsPath(root, configPath))) return unavailable(tool, 'configuration_invalid');
    if (!entry && id !== 'skillspector') return unavailable(tool, id === 'osv' ? 'executable_missing' : 'config_required');
    const command = await findCommand(entry?.command ?? 'skillspector', directories, excluded, platform);
    if (!command) return unavailable(tool, 'executable_missing', 'missing');
    const args = [...(entry?.args ?? [])];
    for (let i = 0; i < args.length; i++) {
      if (!isAbsolute(args[i])) continue;
      if (excluded.some(root => containsPath(root, args[i]))) return unavailable(tool, 'configuration_invalid');
      const canonical = await realpath(args[i]).catch(() => null);
      if (canonical && excluded.some(root => containsPath(root, canonical))) return unavailable(tool, 'configuration_invalid');
    }

    if (id === 'php2shell' || Object.hasOwn(PINS, id) && args.length) {
      // The PHP checker and native-agent CLI script form take a single fixed
      // script prefix. Arbitrary flags could alter the native isolation policy.
      const script = args.length === 1 && await trustedFile(args[0], excluded);
      if (!nodeName(basename(command), platform) || !script ||
          (id === 'php2shell' ? basename(script) !== 'phpcheck.js' : id === 'cloudflare' || !/\.[cm]?js$/i.test(script))) {
        return unavailable(tool, 'configuration_invalid');
      }
      args[0] = script;
    }
    if (Object.hasOwn(PINS, id)) {
      try {
        const options = nativeOptions(id, entry.agentOptions);
        if (options.revision !== PINS[id]) return unavailable(tool, 'configuration_invalid');
        const skill = await assertSafeDirectory(options.skillRoot);
        if ([skill, options.workRoot].some(path => excluded.some(root => containsPath(root, path) || containsPath(path, root)))) {
          return unavailable(tool, 'configuration_invalid');
        }
      } catch { return unavailable(tool, 'configuration_invalid'); }
    }

    const nodeExecutable = wrappers.has(id) ? await (node ??= runtime()) : null;
    if (wrappers.has(id) && !nodeExecutable) return unavailable(tool, 'node_required', 'installed');
    return { ...tool, ...entry, args, command, installation: 'installed', ...(nodeExecutable ? { nodeExecutable } : {}) };
  }));
}
