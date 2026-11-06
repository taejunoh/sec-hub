import { createHash } from 'node:crypto';
import { constants, createReadStream, createWriteStream } from 'node:fs';
import { access, chmod, copyFile, cp, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, rmdir, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appFiles = ['package.json', 'main.cjs', 'controller.mjs', 'policy.mjs', 'preload.cjs', 'tools.mjs', 'osv-lock.json', 'smoke.mjs'];
const licenseFiles = ['LICENSE', 'LICENSES.chromium.html'];
const macArchitectures = new Map([['darwin-arm64', 'arm64'], ['darwin-x64', 'x86_64']]);
const supported = new Set([...macArchitectures.keys(), 'win32-x64']);
const hostTarget = process.platform + '-' + process.arch;
const json = value => `${JSON.stringify(value, null, 2)}\n`;
const slash = value => value.split(path.sep).join('/');
const inside = (root, value) => { const rel = path.relative(root, value); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); };

async function hashFile(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}
export async function verifyArchive(filename, expected) {
  const info = await stat(filename);
  const sha256 = await hashFile(filename);
  if (sha256 !== expected.sha256) throw new Error(`Runtime archive SHA-256 mismatch: ${path.basename(filename)}`);
  if (info.size !== expected.size) throw new Error(`Runtime archive size mismatch: ${path.basename(filename)}`);
  return { sha256, size: info.size };
}
async function resolvedFuture(filename) {
  try { return await realpath(filename); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const parent = path.dirname(filename);
    if (parent === filename) throw error;
    return path.join(await resolvedFuture(parent), path.basename(filename));
  }
}
function assertOutsideSource(actualRoot, filename) {
  if (inside(actualRoot, filename)) throw new Error('Generated output and runtime cache must be outside the source repository');
  if (inside(filename, actualRoot)) throw new Error('Output and cache cannot contain the source repository');
}
export async function validatePaths({ repository: root, out, cache }) {
  if (!path.isAbsolute(out ?? '') || !path.isAbsolute(cache ?? '')) throw new Error('--out and --cache must be absolute paths');
  const actualRoot = await realpath(root);
  for (const filename of [out, cache]) assertOutsideSource(actualRoot, await resolvedFuture(filename));
}
export function platformLayout(base, target) {
  if (!supported.has(target)) throw new Error(`Unsupported desktop target: ${target}`);
  const application = path.join(base, macArchitectures.has(target) ? 'Sec Hub.app' : 'Sec Hub');
  return macArchitectures.has(target)
    ? { application, executable: path.join(application, 'Contents/MacOS/SecHub'), resources: path.join(application, 'Contents/Resources') }
    : { application, executable: path.join(application, 'Sec Hub.exe'), resources: path.join(application, 'resources') };
}
async function regularFile(filename) {
  const info = await lstat(filename);
  if (info.isSymbolicLink()) throw new Error(`Symbolic source path is forbidden: ${filename}`);
  if (!info.isFile()) throw new Error(`Expected regular file: ${filename}`);
  return info;
}
async function sourceTree(root, { jsonOnly = false } = {}) {
  const info = await lstat(root);
  if (info.isSymbolicLink()) throw new Error(`Symbolic source directory is forbidden: ${root}`);
  if (!info.isDirectory()) throw new Error(`Expected source directory: ${root}`);
  const files = [];
  for (const entry of (await readdir(root)).sort()) {
    const filename = path.join(root, entry); const entryInfo = await lstat(filename);
    if (entryInfo.isSymbolicLink()) throw new Error(`Symbolic source path is forbidden: ${filename}`);
    if (entryInfo.isDirectory()) files.push(...await sourceTree(filename, { jsonOnly }));
    else if (entryInfo.isFile() && (!jsonOnly || entry.endsWith('.json'))) files.push(filename);
    else if (!entryInfo.isFile()) throw new Error(`Unsupported source entry: ${filename}`);
  }
  return files;
}
export async function stagePayload({ repository: root, resources }) {
  const app = path.join(root, 'desktop/app');
  for (const directory of [path.join(root, 'desktop'), app]) {
    const info = await lstat(directory);
    if (info.isSymbolicLink()) throw new Error(`Symbolic source directory is forbidden: ${directory}`);
    if (!info.isDirectory()) throw new Error(`Expected source directory: ${directory}`);
  }
  // Exact entrypoints plus JSON-only synthetic samples. No tests, scratch, examples or config.
  const sources = [];
  for (const name of appFiles) {
    const filename = path.join(app, name);
    try { await regularFile(filename); sources.push([filename, path.join('app', name)]); }
    catch (error) { if (error.code === 'ENOENT' && !['package.json', 'main.cjs'].includes(name)) continue; throw error; }
  }
  try { for (const filename of await sourceTree(path.join(app, 'sample'), { jsonOnly: true })) sources.push([filename, path.join('app', path.relative(app, filename))]); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await regularFile(path.join(root, 'package.json'));
  sources.push([path.join(root, 'package.json'), path.join('core', 'package.json')]);
  for (const filename of await sourceTree(path.join(root, 'src'))) {
    const relative = path.relative(root, filename);
    if (slash(relative) !== 'src/native/windows-safe-io.exe') sources.push([filename, path.join('core', relative)]);
  }
  for (const [source, relative] of sources) {
    const destination = path.join(resources, relative);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination); await chmod(destination, (await stat(source)).mode & 0o777);
    if (await hashFile(source) !== await hashFile(destination)) throw new Error(`Staged payload changed: ${relative}`);
  }
  return { files: (await inventory(resources)).filter(file => file.path.startsWith('app/') || file.path.startsWith('core/')), allowlist: { app: [...appFiles, 'sample/**/*.json'], core: ['package.json', 'src/**'] } };
}
export async function validateRuntime(root, target) {
  if (!supported.has(target)) throw new Error(`Unsupported desktop target: ${target}`);
  for (const name of licenseFiles) await regularFile(path.join(root, name));
  const executable = macArchitectures.has(target) ? 'Electron.app/Contents/MacOS/Electron' : 'electron.exe';
  const filename = path.join(root, executable);
  await regularFile(filename);
  if (macArchitectures.has(target)) await verifyMacArchitecture(filename, target);
}
async function verifyMacArchitecture(filename, target) {
  const { stdout } = await run('/usr/bin/lipo', ['-archs', filename]);
  const expected = macArchitectures.get(target);
  if (stdout.trim() !== expected) throw new Error('Unexpected Mach-O architecture in ' + path.basename(filename) + ': expected ' + expected + ', found ' + stdout.trim());
}
async function run(command, args, { cwd = repository, quiet = false } = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (command === '/usr/bin/ditto') { delete env.DITTONORSRC; delete env.DITTO_TEST_OPTIONS; }
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; if (!quiet) process.stderr.write(chunk); });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`${command} exited ${code}: ${stderr.slice(-4000)}`)));
  });
}
async function inventory(root, relative = '') {
  const files = [];
  for (const name of (await readdir(path.join(root, relative))).sort()) {
    const rel = path.join(relative, name); const filename = path.join(root, rel); const info = await lstat(filename);
    if (info.isDirectory()) files.push(...await inventory(root, rel));
    else if (info.isSymbolicLink()) {
      const { readlink } = await import('node:fs/promises'); const target = await readlink(filename);
      if (!inside(root, path.resolve(path.dirname(filename), target))) throw new Error(`Escaping runtime symlink: ${rel}`);
      files.push({ path: slash(rel), type: 'symlink', target, mode: (info.mode & 0o777).toString(8) });
    } else if (info.isFile()) files.push({ path: slash(rel), type: 'file', size: info.size, mode: (info.mode & 0o777).toString(8), sha256: await hashFile(filename) });
    else throw new Error(`Unsupported package entry: ${rel}`);
  }
  return files;
}
async function gitState() {
  const commit = (await run('git', ['rev-parse', 'HEAD'])).stdout.trim();
  const status = (await run('git', ['status', '--porcelain', '--untracked-files=all'])).stdout;
  return { commit, dirty: status.length > 0, status };
}
function psLiteral(value) { return `'${value.replaceAll("'", "''")}'`; }
async function nativeTemporary(prefix) {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), prefix));
  if (process.platform !== 'win32') await chmod(directory, 0o700);
  return await realpath(directory);
}
async function extractArchive(archive, destination) {
  if (process.platform === 'darwin') await run('/usr/bin/ditto', ['-x', '-k', '--rsrc', '--extattr', '--acl', '--qtn', archive, destination]);
  else await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath ${psLiteral(archive)} -DestinationPath ${psLiteral(destination)}`]);
}
async function packMac(application, archive) {
  await run('/usr/bin/ditto', ['-c', '-k', '--rsrc', '--extattr', '--acl', '--qtn', '--sequesterRsrc', '--keepParent', application, archive]);
}
function canBuildIntelOnAppleSilicon(target, allowMacCrossArch) {
  return allowMacCrossArch === true && hostTarget === 'darwin-arm64' && target === 'darwin-x64';
}
export async function packAndVerify({ application, archive, target, expectedFiles, developerId, notarized = false, allowMacCrossArch = false }) {
  if (hostTarget !== target && !canBuildIntelOnAppleSilicon(target, allowMacCrossArch)) throw new Error('Verify archives on the native target');
  if (macArchitectures.has(target)) await packMac(application, archive);
  else await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Compress-Archive -LiteralPath ${psLiteral(application)} -DestinationPath ${psLiteral(archive)} -CompressionLevel Optimal`]);
  const directory = await nativeTemporary('sec-hub-desktop-roundtrip-');
  try {
    await extractArchive(archive, directory);
    const layout = platformLayout(directory, target);
    const files = await inventory(layout.application);
    if (json(files) !== json(expectedFiles)) throw new Error('Extracted archive inventory differs from the final signed file inventory');
    // This is verification only: never strip metadata or re-sign extracted bytes.
    let signatureLog = '';
    if (macArchitectures.has(target)) {
      const result = await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', layout.application]);
      signatureLog = result.stdout + result.stderr;
    }
    if (developerId) signatureLog += await verifyMacDeveloperSignature(layout.application, developerId.teamId);
    if (notarized) {
      const ticket = await run('/usr/bin/xcrun', ['stapler', 'validate', layout.application]);
      const assessment = await run('/usr/sbin/spctl', ['--assess', '--type', 'execute', '--verbose=4', layout.application]);
      if (!/source=Notarized Developer ID/.test(assessment.stdout + assessment.stderr)) throw new Error('Gatekeeper did not identify a notarized Developer ID app');
      signatureLog += ticket.stdout + ticket.stderr + assessment.stdout + assessment.stderr;
    }
    const verification = { status: 'passed', nativeTemporaryExtraction: true, postExtractionMutations: false, inventoryFiles: files.length, inventorySha256: createHash('sha256').update(json(files)).digest('hex'), macStrictSignature: macArchitectures.has(target), ...(developerId && { macDeveloperId: true, macStapledTicket: notarized, macGatekeeper: notarized }), authoritativeDeliverable: 'ZIP verified after fresh extraction in native temporary storage; out/package is a convenience copy derived from that ZIP and may acquire local filesystem metadata' };
    return { directory, application: layout.application, files, verification, signatureLog };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}
async function obtainPinnedFile(cache, pin) {
  await mkdir(cache, { recursive: true });
  const archive = path.join(cache, pin.filename);
  try { await access(archive); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const temporary = `${archive}.${process.pid}.download`;
    try {
      const response = await fetch(pin.url, { signal: AbortSignal.timeout(180000) });
      if (!response.ok || !response.body || !response.url.startsWith('https://')) throw new Error(`Official download failed: ${response.status}`);
      await pipeline(Readable.fromWeb(response.body), async function* (chunks) {
        let size = 0;
        for await (const chunk of chunks) {
          size += chunk.length;
          if (size > pin.size) throw new Error('Official download exceeds pinned size');
          yield chunk;
        }
      }, createWriteStream(temporary, { flags: 'wx' }));
      await verifyArchive(temporary, pin); await rename(temporary, archive);
    } finally { await rm(temporary, { force: true }); }
  }
  await verifyArchive(archive, pin);
  return archive;
}
async function obtainRuntime(cache, pin) {
  const archive = await obtainPinnedFile(cache, pin);
  // Always extract the verified ZIP afresh; a pre-extracted cache is not trusted provenance.
  const extracted = await mkdtemp(path.join(cache, '.verified-extract-'));
  try {
    await extractArchive(archive, extracted);
    return extracted;
  } catch (error) { await rm(extracted, { recursive: true, force: true }); throw error; }
}
async function stageOSV(resources, cache, target) {
  const lock = JSON.parse(await readFile(path.join(repository, 'desktop/app/osv-lock.json'), 'utf8'));
  const binary = lock.targets[target];
  const directory = path.join(resources, 'tools', 'osv');
  await mkdir(directory, { recursive: true });
  for (const pin of [binary, lock.license]) {
    const source = await obtainPinnedFile(path.join(cache, 'osv', lock.version), pin);
    const destination = path.join(directory, pin.filename);
    await copyFile(source, destination);
    await chmod(destination, pin === binary ? 0o755 : 0o644);
    await verifyArchive(destination, pin);
    if (pin === binary && macArchitectures.has(target)) await verifyMacArchitecture(destination, target);
  }
  return { version: lock.version, release: lock.release, checksums: lock.checksums, binary, license: lock.license };
}
async function stageWindowsSafeIO(resources, stage) {
  const source = path.join(repository, 'src/native/windows-safe-io.c');
  const output = path.join(resources, 'core/src/native/windows-safe-io.exe');
  await run('cl.exe', ['/nologo', '/std:c17', '/MT', '/W4', '/WX', '/O2', '/DUNICODE', '/D_UNICODE',
    source, `/Fo${path.join(stage, 'windows-safe-io.obj')}`, `/Fe${output}`, 'advapi32.lib'], { cwd: stage });
  await regularFile(output);
  return { path: slash(path.relative(resources, output)), sha256: await hashFile(output) };
}
async function setPlist(plist, key, value) {
  await run('/usr/libexec/PlistBuddy', ['-c', `Set :${key} ${value}`, plist]);
}
export async function prepareMacSigning(application) {
  // Codesign rejects FinderInfo added by bundle-aware copying. This is newly
  // assembled output only; quarantine and all other security metadata are preserved.
  await run('/usr/bin/xattr', ['-dr', 'com.apple.FinderInfo', application]);
}
export async function rebrandMac(application, version) {
  const contents = path.join(application, 'Contents'); const plist = path.join(contents, 'Info.plist');
  await rename(path.join(contents, 'MacOS/Electron'), path.join(contents, 'MacOS/SecHub'));
  for (const [key, value] of Object.entries({ CFBundleExecutable: 'SecHub', CFBundleIdentifier: 'org.sechub.desktop', CFBundleName: 'Sec Hub', CFBundleDisplayName: 'Sec Hub', CFBundleShortVersionString: version, CFBundleVersion: version })) await setPlist(plist, key, value);
  // This integrity record describes upstream's removed default_app.asar, not our plain app folder.
  await run('/usr/libexec/PlistBuddy', ['-c', 'Delete :ElectronAsarIntegrity', plist]);
  const frameworks = path.join(contents, 'Frameworks');
  for (const name of await readdir(frameworks)) {
    if (!name.startsWith('Electron Helper') || !name.endsWith('.app')) continue;
    const oldName = name.slice(0, -4); const newName = oldName.replace('Electron', 'Sec Hub');
    const helper = path.join(frameworks, name); const helperPlist = path.join(helper, 'Contents/Info.plist');
    await rename(path.join(helper, 'Contents/MacOS', oldName), path.join(helper, 'Contents/MacOS', newName));
    await run('/usr/libexec/PlistBuddy', ['-c', `Add :CFBundleExecutable string ${newName}`, helperPlist]); await setPlist(helperPlist, 'CFBundleName', newName);
    const suffix = oldName === 'Electron Helper' ? '' : `.${oldName.match(/\(([^)]+)\)/)?.[1]?.toLowerCase() ?? 'utility'}`;
    await setPlist(helperPlist, 'CFBundleIdentifier', `org.sechub.desktop.helper${suffix}`);
    await rename(helper, path.join(frameworks, `${newName}.app`));
  }
}
const developerIdName = /^Developer ID Application: .+ \(([A-Z0-9]{10})\)$/;
const machOMagic = new Set([0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe]);

async function macDeveloperIdentity(identity) {
  const { stdout } = await run('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning']);
  const matches = stdout.split('\n').flatMap(line => {
    const match = line.match(/^\s*\d+\) ([A-F0-9]{40}) "([^"]+)"$/);
    if (!match) return [];
    const [, fingerprint, name] = match;
    const team = name.match(developerIdName);
    return team && (fingerprint === identity.toUpperCase() || name === identity) ? [{ fingerprint, name, teamId: team[1] }] : [];
  });
  if (matches.length !== 1) throw new Error('Select exactly one valid Developer ID Application identity in the Keychain');
  return matches[0];
}

async function macNativeCode(directory) {
  const native = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) native.push(...await macNativeCode(filename));
    if (!entry.isFile()) continue;
    const handle = await open(filename, 'r');
    try {
      const prefix = Buffer.alloc(4);
      if ((await handle.read(prefix, 0, 4, 0)).bytesRead === 4 && machOMagic.has(prefix.readUInt32BE())) native.push(filename);
    } finally { await handle.close(); }
  }
  return native;
}

async function macSigningPlan(application) {
  const frameworksDirectory = path.join(application, 'Contents', 'Frameworks');
  const entries = await readdir(frameworksDirectory, { withFileTypes: true });
  const bundleExecutables = new Set([path.join(application, 'Contents', 'MacOS', 'SecHub')]);
  const bundles = [];
  for (const entry of entries.filter(entry => entry.isDirectory())) {
    const bundle = path.join(frameworksDirectory, entry.name);
    if (entry.name.endsWith('.app')) {
      const executable = (await run('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', path.join(bundle, 'Contents', 'Info.plist')])).stdout.trim();
      bundleExecutables.add(path.join(bundle, 'Contents', 'MacOS', executable));
      const jit = ['Sec Hub Helper.app', 'Sec Hub Helper (Renderer).app', 'Sec Hub Helper (GPU).app'].includes(entry.name);
      bundles.push({ filename: bundle, jit });
    } else if (entry.name.endsWith('.framework')) {
      const versions = path.join(bundle, 'Versions');
      for (const version of (await readdir(versions, { withFileTypes: true })).filter(entry => entry.isDirectory())) {
        const filename = path.join(versions, version.name);
        bundleExecutables.add(path.join(filename, path.basename(entry.name, '.framework')));
        bundles.push({ filename });
      }
    }
  }
  const standalone = (await macNativeCode(application)).filter(filename => !bundleExecutables.has(filename));
  return [...standalone.map(filename => ({ filename })), ...bundles];
}

async function signMacCode(filename, identity, entitlements) {
  const args = ['--force', '--timestamp', '--options', 'runtime', '--sign', identity.fingerprint];
  if (entitlements) args.push('--entitlements', entitlements);
  await run('/usr/bin/codesign', [...args, filename]);
}

async function verifyMacDeveloperSignature(filename, teamId) {
  const requirement = `anchor apple generic and certificate leaf[subject.OU] = "${teamId}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`;
  await run('/usr/bin/codesign', ['--verify', '--all-architectures', '--strict', '-R', `=${requirement}`, filename]);
  const result = await run('/usr/bin/codesign', ['--display', '--verbose=4', filename], { quiet: true });
  const details = result.stdout + result.stderr;
  if (!/^CodeDirectory .* flags=0x[0-9a-f]+\([^)]*\bruntime\b/m.test(details) || !/^Timestamp=.+/m.test(details)) {
    throw new Error(`Developer ID signature lacks hardened runtime or a secure timestamp: ${filename}`);
  }
  return details;
}

export async function withMacBuildOutput(out, buildIn) {
  const requested = path.resolve(out);
  const parent = await resolvedFuture(path.dirname(requested));
  const destination = path.join(parent, path.basename(requested));
  assertOutsideSource(await realpath(repository), destination);
  await mkdir(parent, { recursive: true });
  if (await realpath(parent) !== parent) throw new Error('--out parent changed before staging');
  const existing = await lstat(destination).catch(error => {
    if (error.code !== 'ENOENT') throw error;
  });
  if (existing && (!existing.isDirectory() || (await readdir(destination)).length)) {
    throw new Error('--out must be an empty real directory; existing deliverables are never replaced');
  }
  // Work on the output volume so the entire directory can be published
  // atomically. POSIX rename refuses a symlink or nonempty destination.
  const directory = await mkdtemp(path.join(parent, '.sec-hub-desktop-output-'));
  let result;
  try {
    result = await buildIn(directory);
  } catch (error) {
    try { await rmdir(directory); }
    catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') {
        throw new Error(`${error.message}\nBuild checkpoint retained at ${directory}`, { cause: error });
      }
    }
    throw error;
  }
  try {
    if (await realpath(parent) !== parent) throw new Error('--out parent changed during packaging');
    await rename(directory, destination);
  } catch (error) {
    throw new Error(`Could not publish --out without replacing existing entries. Staged files are at ${directory}. ${error.message}`, { cause: error });
  }
  return { result, destination };
}

async function copyVerifiedArchive(source, destination, expected) {
  await copyFile(source, destination, constants.COPYFILE_EXCL);
  await verifyArchive(destination, expected);
}

async function notarizeMac(application, stage, out, profile) {
  // Retain the exact submitted bytes and identifier until the final ZIP has
  // passed every check. A timeout must not require re-signing or re-uploading.
  const submissionZip = path.join(stage, 'notarization-input.zip');
  const receipt = path.join(out, 'notarization-submission.json');
  await packMac(application, submissionZip);
  const archive = { filename: path.basename(submissionZip), size: (await stat(submissionZip)).size, sha256: await hashFile(submissionZip) };
  await copyVerifiedArchive(submissionZip, path.join(out, archive.filename), archive);
  const args = ['--keychain-profile', profile, '--output-format', 'json'];
  const upload = await run('/usr/bin/xcrun', ['notarytool', 'submit', submissionZip, ...args]);
  const { id } = JSON.parse(upload.stdout);
  if (typeof id !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id)) throw new Error('Apple notarization upload returned an invalid submission ID');
  await writeFile(receipt, json({ id, archive }));
  process.stderr.write(`Apple notarization submission: ${id} (checkpoint: ${out})\n`);
  const completion = await run('/usr/bin/xcrun', ['notarytool', 'wait', id, ...args, '--timeout', '60m']);
  const { status } = JSON.parse(completion.stdout);
  await writeFile(receipt, json({ id, status, archive }));
  if (status !== 'Accepted') {
    if (status === 'Invalid' || status === 'Rejected') {
      const log = await run('/usr/bin/xcrun', ['notarytool', 'log', id, ...args]);
      await writeFile(path.join(out, 'notarization-error.json'), log.stdout);
    }
    throw new Error(`Apple notarization status: ${status} (${id})`);
  }
  await run('/usr/bin/xcrun', ['stapler', 'staple', application]);
  return { id, status };
}

export async function build({ target, out, cache, allowDirty = false, macSignIdentity, notaryProfile, allowMacCrossArch = false }) {
  if (!supported.has(target)) throw new Error(`Unsupported desktop target: ${target}`);
  if (!macArchitectures.has(target) && (macSignIdentity !== undefined || notaryProfile !== undefined)) throw new Error('Developer ID signing and notarization options apply only to macOS');
  if (macSignIdentity !== undefined && !developerIdName.test(macSignIdentity) && !/^[a-f0-9]{40}$/i.test(macSignIdentity)) throw new Error('Use a Developer ID Application name or SHA-1 fingerprint');
  if (notaryProfile !== undefined && (!macSignIdentity || typeof notaryProfile !== 'string' || !notaryProfile.trim())) throw new Error('Notarization requires a Developer ID Application identity and a nonempty Keychain profile');
  const crossArch = canBuildIntelOnAppleSilicon(target, allowMacCrossArch);
  if (allowMacCrossArch && !crossArch) throw new Error('--allow-mac-cross-arch applies only when building Intel macOS packages on Apple silicon');
  if (hostTarget !== target && !crossArch) throw new Error('Build on the native target OS and architecture');
  await validatePaths({ repository, out, cache });
  const source = await gitState();
  if (source.dirty && !allowDirty) throw new Error('Final packages require a clean Git checkout; --allow-dirty labels a development package');
  const buildIn = directory => buildPackage({ target, out: directory, cache, allowDirty, macSignIdentity, notaryProfile, allowMacCrossArch, source });
  let result;
  let destination = out;
  if (macArchitectures.has(target)) {
    ({ result, destination } = await withMacBuildOutput(out, buildIn));
  } else {
    await mkdir(out, { recursive: true });
    if ((await readdir(out)).length) throw new Error('--out must be an empty directory; existing deliverables are never replaced');
    result = await buildIn(out);
  }
  return { ...result, archive: path.join(destination, result.archive), manifest: path.join(destination, result.manifest), executable: path.join(destination, result.executable), application: path.join(destination, result.application) };
}

async function buildPackage({ target, out, cache, allowDirty, macSignIdentity, notaryProfile, allowMacCrossArch, source }) {
  const developerId = macSignIdentity ? await macDeveloperIdentity(macSignIdentity) : undefined;
  if (notaryProfile) await run('/usr/bin/xcrun', ['notarytool', 'history', '--keychain-profile', notaryProfile, '--output-format', 'json']);
  const lock = JSON.parse(await readFile(path.join(repository, 'desktop/runtime-lock.json'), 'utf8'));
  const pin = lock.targets[target];
  const extracted = await obtainRuntime(cache, pin);
  // Documents/cloud-backed directories can attach FinderInfo during packaging.
  // Assemble and validate on private native temporary storage instead.
  const stage = await nativeTemporary('sec-hub-desktop-stage-');
  let roundtrip;
  try {
    await validateRuntime(extracted, target);
    const layout = platformLayout(stage, target);
    if (macArchitectures.has(target)) await run('/usr/bin/ditto', [path.join(extracted, 'Electron.app'), layout.application]);
    else await cp(extracted, layout.application, { recursive: true, dereference: false });
    const appVersion = JSON.parse(await readFile(path.join(repository, 'desktop/app/package.json'), 'utf8')).version;
    if (!/^\d+\.\d+\.\d+$/.test(appVersion)) throw new Error('Unexpected desktop version');
    if (macArchitectures.has(target)) await rebrandMac(layout.application, appVersion);
    else {
      await rename(path.join(layout.application, 'electron.exe'), layout.executable);
      try { await rename(path.join(layout.application, 'electron_wer.dll'), path.join(layout.application, 'Sec Hub_wer.dll')); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    await rm(path.join(layout.resources, 'default_app.asar'), { force: true });
    const payload = await stagePayload({ repository, resources: layout.resources });
    const appMetadata = JSON.parse(await readFile(path.join(layout.resources, 'app/package.json'), 'utf8'));
    const coreMetadata = JSON.parse(await readFile(path.join(layout.resources, 'core/package.json'), 'utf8'));
    if (appMetadata.version !== appVersion || !/^\d+\.\d+\.\d+$/.test(coreMetadata.version)) throw new Error('Unexpected app/core payload version');
    const bundledTools = { osv: await stageOSV(layout.resources, cache, target) };
    const windowsSafeIO = target === 'win32-x64' ? await stageWindowsSafeIO(layout.resources, stage) : undefined;
    const licenses = [];
    for (const name of licenseFiles) {
      const destination = path.join(layout.resources, 'licenses/electron', name);
      await mkdir(path.dirname(destination), { recursive: true }); await copyFile(path.join(extracted, name), destination);
      licenses.push({ path: slash(path.relative(layout.application, destination)), size: (await stat(destination)).size, sha256: await hashFile(destination) });
    }
    const label = allowDirty ? 'development' : 'prerelease';
    const signing = macArchitectures.has(target)
      ? { kind: 'ad-hoc', identity: '-', applePublisherSigned: false, notarized: false, removedBuildMetadata: ['com.apple.FinderInfo'] }
      : { kind: 'no-sec-hub-publisher-signature', publisherSigned: false, vendorRuntimeSignature: 'preserved-if-present' };
    if (developerId) Object.assign(signing, { kind: 'developer-id', identity: developerId.name, teamId: developerId.teamId, applePublisherSigned: true, hardenedRuntime: true, notarized: undefined });
    const metadata = { schemaVersion: 1, application: 'Sec Hub', appVersion: appMetadata.version, coreVersion: coreMetadata.version, target, label, source, runtime: { electron: lock.electron, node: lock.node, officialArchive: pin }, payload, licenses, bundledTools, windowsSafeIO, signing };
    const bundledScanner = path.join(layout.resources, 'tools', 'osv', bundledTools.osv.binary.filename);
    let signatureLog = '';
    if (developerId) {
      // Keep standalone Mach-O files in the bundle's native-code directory.
      // Preserve the fixed core lookup with an internal, sealed symlink.
      const macOS = path.dirname(layout.executable);
      const scanner = path.join(macOS, path.basename(bundledScanner));
      const reader = path.join(layout.resources, 'core', 'src', 'native', 'darwin-acl-reader');
      const nativeReader = path.join(macOS, path.basename(reader));
      await rename(bundledScanner, scanner);
      await rename(reader, nativeReader);
      await symlink(path.relative(path.dirname(reader), nativeReader), reader);
      await prepareMacSigning(layout.application);
      const jit = path.join(repository, 'desktop', 'mac-jit.entitlements.plist');
      for (const item of await macSigningPlan(layout.application)) {
        await signMacCode(item.filename, developerId, item.jit ? jit : undefined);
        signatureLog += await verifyMacDeveloperSignature(item.filename, developerId.teamId);
      }
      bundledTools.osv.packagedBinary = { path: slash(path.relative(layout.application, scanner)), size: (await stat(scanner)).size, sha256: await hashFile(scanner) };
      await writeFile(path.join(layout.resources, 'desktop-build.json'), json(metadata));
      await signMacCode(layout.application, developerId, jit);
      signatureLog += await verifyMacDeveloperSignature(layout.application, developerId.teamId);
    } else {
      await writeFile(path.join(layout.resources, 'desktop-build.json'), json(metadata));
      if (macArchitectures.has(target)) {
        await prepareMacSigning(layout.application);
        await run('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', layout.application]);
      }
      await verifyArchive(bundledScanner, bundledTools.osv.binary);
    }
    if (macArchitectures.has(target)) {
      const verification = await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', layout.application]);
      await writeFile(path.join(out, 'codesign-verification.log'), signatureLog + verification.stdout + verification.stderr);
    }
    const notarization = notaryProfile ? await notarizeMac(layout.application, stage, out, notaryProfile) : undefined;
    if (developerId) {
      signing.notarized = Boolean(notarization);
      if (notarization) signing.notarization = notarization;
    }
    const finalSource = await gitState();
    if (finalSource.commit !== source.commit || finalSource.status !== source.status) throw new Error('Source checkout changed during packaging; rebuild from frozen source');
    const files = await inventory(layout.application);
    const basename = `sec-hub-desktop-${appMetadata.version}-${target}-${developerId ? (notarization ? 'notarized-' : 'developer-id-') : ''}${label}`;
    const archive = path.join(out, `${basename}.zip`);
    const stagingArchive = macArchitectures.has(target) ? path.join(stage, path.basename(archive)) : archive;
    roundtrip = await packAndVerify({ application: layout.application, archive: stagingArchive, target, expectedFiles: files, developerId, notarized: Boolean(notarization), allowMacCrossArch });
    const archiveMetadata = { filename: path.basename(archive), size: (await stat(stagingArchive)).size, sha256: await hashFile(stagingArchive) };
    await writeFile(path.join(out, 'archive-verification.json'), json(roundtrip.verification));
    if (macArchitectures.has(target)) await writeFile(path.join(out, 'archive-codesign-verification.log'), roundtrip.signatureLog);
    // CI and local smoke launch files freshly extracted from the deliverable.
    const outputStage = path.join(out, 'package');
    if (macArchitectures.has(target)) await run('/usr/bin/ditto', [roundtrip.directory, outputStage]);
    else await cp(roundtrip.directory, outputStage, { recursive: true, dereference: false });
    const outputLayout = platformLayout(outputStage, target);
    if (json(await inventory(outputLayout.application)) !== json(files)) throw new Error('Convenience package copy differs from the verified archive inventory');
    if (stagingArchive !== archive) await copyVerifiedArchive(stagingArchive, archive, archiveMetadata);
    const manifest = { ...metadata, createdAt: new Date().toISOString(), executable: slash(path.relative(out, outputLayout.executable)), application: slash(path.relative(out, outputLayout.application)), finalFiles: roundtrip.files, finalFilesSha256: roundtrip.verification.inventorySha256, archiveVerification: roundtrip.verification, archive: archiveMetadata };
    const manifestPath = path.join(out, `${basename}.manifest.json`);
    await writeFile(manifestPath, json(manifest));
    await writeFile(path.join(out, 'SHA256SUMS.txt'), `${manifest.archive.sha256}  ${path.basename(archive)}\n${await hashFile(manifestPath)}  ${path.basename(manifestPath)}\n`);
    if (notarization) await rm(path.join(out, 'notarization-input.zip'));
    return { archive: path.basename(archive), manifest: path.basename(manifestPath), executable: manifest.executable, application: manifest.application, label, source: source.commit };
  } finally {
    await Promise.all([extracted, stage, roundtrip?.directory].filter(Boolean).map(directory => rm(directory, { recursive: true, force: true })));
  }
}
function argumentsFor(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--allow-dirty') options.allowDirty = true;
    else if (argv[i] === '--allow-mac-cross-arch') options.allowMacCrossArch = true;
    else if (argv[i] === '--mac-sign-identity' && argv[i + 1]) options.macSignIdentity = argv[++i];
    else if (argv[i] === '--notary-profile' && argv[i + 1]) options.notaryProfile = argv[++i];
    else if (['--target', '--out', '--cache'].includes(argv[i]) && argv[i + 1]) options[argv[i].slice(2)] = argv[++i];
    else throw new Error(`Unknown or incomplete argument: ${argv[i]}`);
  }
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  build(argumentsFor(process.argv.slice(2))).then(result => process.stdout.write(json(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
