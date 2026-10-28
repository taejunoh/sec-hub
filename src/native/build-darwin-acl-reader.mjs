// Maintainer-only build. The CLI never invokes this script or a compiler.
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'darwin') throw new Error('Build the universal macOS ACL reader on macOS with Xcode command-line tools.');
if (process.argv.length > 3) throw new Error('Usage: node build-darwin-acl-reader.mjs [output-file]');
const source = fileURLToPath(new URL('./darwin-acl-reader.c', import.meta.url));
const output = process.argv[2] ? resolve(process.argv[2]) : fileURLToPath(new URL('./darwin-acl-reader', import.meta.url));
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`${command}: ${result.error?.message || result.stderr || result.stdout}`);
  return result.stdout.trim();
}
const compiler = run('/usr/bin/xcrun', ['--find', 'clang']);
const sdk = run('/usr/bin/xcrun', ['--sdk', 'macosx', '--show-sdk-path']);
const flags = ['-arch', 'arm64', '-arch', 'x86_64', '-isysroot', sdk,
  '-mmacosx-version-min=11.0', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
  '-fstack-protector-strong', '-Wl,-no_adhoc_codesign'];
run(compiler, [...flags, source, '-o', output]);
run('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', '--identifier', 'org.sec-hub.darwin-acl-reader', output]);
run('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', output]);
console.log(JSON.stringify({ source, output, compiler, compilerVersion: run(compiler, ['--version']), sdk, flags,
  architectures: run('/usr/bin/lipo', ['-archs', output]),
  sourceSha256: createHash('sha256').update(await readFile(source)).digest('hex'),
  binarySha256: createHash('sha256').update(await readFile(output)).digest('hex'),
}, null, 2));
