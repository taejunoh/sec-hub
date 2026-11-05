// Maintainer-only build. The CLI never invokes this script or a compiler.
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rename, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'darwin') throw new Error('Build the universal macOS ACL reader on macOS with Xcode command-line tools.');
if (process.argv.length > 3) throw new Error('Usage: node build-darwin-acl-reader.mjs [output-file]');
const source = fileURLToPath(new URL('./darwin-acl-reader.c', import.meta.url));
const output = process.argv[2] ? resolve(process.argv[2]) : fileURLToPath(new URL('./darwin-acl-reader', import.meta.url));
const developerDir = process.env.DEVELOPER_DIR || '/Library/Developer/CommandLineTools';
const env = { DEVELOPER_DIR: developerDir, PATH: '/usr/bin:/bin', LC_ALL: 'C' };

function run(command, args, includeStderr = false) {
  const result = spawnSync(command, args, { env, encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`${command}: ${result.error?.message || result.stderr || result.stdout}`);
  return (includeStderr ? `${result.stdout}${result.stderr}` : result.stdout).trim();
}

const pinned = 'Apple clang clang-2100.3.34.2, Apple ld-27037.1 and macOS SDK 27.0 (26A425)';
let compiler, compilerVersion, linker, linkerVersion, sdk, sdkVersion, sdkBuildVersion;
try {
  const xcrun = '/usr/bin/xcrun';
  compiler = run(xcrun, ['--find', 'clang']);
  compilerVersion = run(compiler, ['--version']);
  linker = run(xcrun, ['--find', 'ld']);
  linkerVersion = run(linker, ['-v'], true).split('\n')[0];
  sdk = run(xcrun, ['--sdk', 'macosx', '--show-sdk-path']);
  sdkVersion = run(xcrun, ['--sdk', 'macosx', '--show-sdk-version']);
  sdkBuildVersion = run(xcrun, ['--sdk', 'macosx', '--show-sdk-build-version']);
} catch (error) {
  throw new Error(`Build requires the pinned Apple toolchain (${pinned}) at ${developerDir}. ${error.message}`);
}
if (!compilerVersion.startsWith('Apple clang version 21.0.0 (clang-2100.3.34.2)\n') ||
    linkerVersion !== '@(#)PROGRAM:ld PROJECT:ld-27037.1' || sdkVersion !== '27.0' || sdkBuildVersion !== '26A425') {
  throw new Error(`Build requires the pinned Apple toolchain (${pinned}). Found ${compilerVersion.split('\n')[0]}, ${linkerVersion} and SDK ${sdkVersion} (${sdkBuildVersion}) at ${developerDir}.`);
}

const flags = ['-arch', 'arm64', '-arch', 'x86_64', '-isysroot', sdk, `--ld-path=${linker}`,
  '-mmacosx-version-min=11.0', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
  '-fstack-protector-strong', '-Wl,-no_adhoc_codesign'];

const staging = await mkdtemp(join(dirname(output), '.darwin-acl-reader-'));
try {
  // The linker includes the output basename when deriving Mach-O UUIDs.
  const executable = join(staging, 'darwin-acl-reader');
  run(compiler, [...flags, source, '-o', executable]);
  run('/usr/bin/codesign', ['--force', '--sign', '-', '--timestamp=none', '--identifier', 'org.sec-hub.darwin-acl-reader', executable]);
  run('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', executable]);
  const architectures = run('/usr/bin/lipo', ['-archs', executable]);
  if (architectures !== 'x86_64 arm64') throw new Error(`Unexpected ACL reader architectures: ${architectures}`);
  const sourceSha256 = createHash('sha256').update(await readFile(source)).digest('hex');
  const binarySha256 = createHash('sha256').update(await readFile(executable)).digest('hex');
  await rename(executable, output);
  console.log(JSON.stringify({ source, output, developerDir, compiler, compilerVersion, linker, linkerVersion,
    sdk, sdkVersion, sdkBuildVersion, flags, architectures, sourceSha256, binarySha256 }, null, 2));
} finally {
  await rm(staging, { recursive: true, force: true });
}
