import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { win32 } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const helper = fileURLToPath(new URL('./native/windows-safe-io.exe', import.meta.url));
const drivePath = /^[a-z]:[\\/]/i;
const device = /^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])$/i;

function safeComponent(name) {
  return name.length > 0 && name.length <= 255 && name.isWellFormed() && !/[ .]$/.test(name) &&
    !/[<>:"/\\|?*\u0000-\u001f]/.test(name) && !device.test(name.split('.')[0].trimEnd());
}

function checkedPath(path) {
  const absolute = win32.resolve(path);
  const parts = (drivePath.test(path) ? path.slice(3) : path).split(/[\\/]+/).filter(Boolean);
  if (/^[\\/]{2}/.test(path) || !drivePath.test(absolute) ||
      parts.some(name => name !== '.' && name !== '..' && !safeComponent(name)) ||
      absolute.slice(3).split('\\').filter(Boolean).some(name => !safeComponent(name))) {
    throw new Error('Unsafe Windows path: ACL trust requires a local drive path without device names, streams, or ambiguous components.');
  }
  return absolute;
}

// The explicit end frame distinguishes a completed stream from a closed pipe
// after cancellation, a failed producer, or the parent process disappearing.
async function* frames(content) {
  const input = typeof content === 'string' || ArrayBuffer.isView(content) ? [content] : content;
  for await (const chunk of input) {
    const bytes = typeof chunk === 'string' ? Buffer.from(chunk) :
      Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    for (let offset = 0; offset < bytes.length; offset += 64 * 1024) {
      const data = bytes.subarray(offset, offset + 64 * 1024);
      const length = Buffer.alloc(4);
      length.writeUInt32LE(data.length);
      yield length;
      yield data;
    }
  }
  yield Buffer.alloc(4);
}

async function nativeOperation(args, { write = false, content } = {}) {
  const child = spawn(helper, args, {
    shell: false, windowsHide: true, cwd: win32.dirname(helper), env: {},
    stdio: [write ? 'pipe' : 'ignore', 'pipe', 'pipe'],
  });
  let overflow = false, bytes = 0, stdout = '', stderr = '', spawnError, streamError;
  const timer = !write && setTimeout(() => {
    spawnError = new Error('Windows ACL helper timed out');
    child.kill();
  }, 15_000);
  const close = new Promise(resolve => {
    child.once('error', error => { spawnError = error; });
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  for (const [name, stream] of [['stdout', child.stdout], ['stderr', child.stderr]]) {
    stream.setEncoding('utf8');
    stream.on('data', chunk => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > 128 * 1024) { overflow = true; child.kill(); return; }
      if (name === 'stdout') stdout += chunk;
      else stderr += chunk;
    });
  }
  const transmit = write && pipeline(Readable.from((async function* () {
    try { yield* frames(content); }
    catch (error) { streamError = error; throw error; }
  })()), child.stdin).catch(error => error);
  const [{ code, signal }, pipeError] = await Promise.all([close, transmit]);
  clearTimeout(timer);
  if (spawnError?.code === 'ENOENT') {
    throw new Error('Windows ACL helper is unavailable. Use a Windows build with the native safe I/O helper.', { cause: spawnError });
  }
  if (spawnError) throw new Error('Windows ACL helper failed to run.', { cause: spawnError });
  if (streamError) throw streamError;
  if (overflow || code !== 0 || signal || stderr) {
    throw new Error('Windows ACL safe I/O rejected the operation: ' + (stderr.trim() || 'native helper failed'));
  }
  if (pipeError) throw pipeError;
  if (write) {
    if (stdout !== 'SEC_HUB_WRITE_OK\n') throw new Error('Windows ACL helper returned an invalid write result.');
    return;
  }
  if (!stdout.startsWith('SEC_HUB_PATH:') || !stdout.endsWith('\n')) {
    throw new Error('Windows ACL helper returned an invalid directory.');
  }
  const path = stdout.slice('SEC_HUB_PATH:'.length, -1);
  if (!drivePath.test(path)) throw new Error('Windows ACL helper returned an invalid directory.');
  return checkedPath(path);
}

export function walkWindowsDirectory(directory, create) {
  return nativeOperation([create ? 'ensure' : 'check', checkedPath(directory)]);
}

export function atomicWriteWindowsFile(file, content) {
  const absolute = checkedPath(file);
  const name = win32.basename(file);
  if (!safeComponent(name) || name !== win32.basename(absolute)) throw new Error('Unsafe Windows output file name.');
  return nativeOperation(['write', win32.dirname(absolute), name, '.sec-hub-' + randomUUID() + '.tmp'], { write: true, content });
}
