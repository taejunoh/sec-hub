import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, chmod, copyFile, cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appFiles = ['package.json', 'main.cjs', 'controller.mjs', 'policy.mjs', 'smoke.mjs'];
const licenseFiles = ['LICENSE', 'LICENSES.chromium.html'];
const supported = new Set(['darwin-arm64', 'win32-x64']);
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
export async function validatePaths({ repository: root, out, cache }) {
  if (!path.isAbsolute(out ?? '') || !path.isAbsolute(cache ?? '')) throw new Error('--out and --cache must be absolute paths');
  const actualRoot = await realpath(root);
  for (const filename of [out, cache]) {
    if (inside(actualRoot, await resolvedFuture(filename))) throw new Error('Generated output and runtime cache must be outside the source repository');
    if (inside(await resolvedFuture(filename), actualRoot)) throw new Error('Output and cache cannot contain the source repository');
  }
}
export function platformLayout(base, target) {
  if (!supported.has(target)) throw new Error(`Unsupported desktop target: ${target}`);
  const application = path.join(base, target === 'darwin-arm64' ? 'Sec Hub.app' : 'Sec Hub');
  return target === 'darwin-arm64'
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
  for (const filename of await sourceTree(path.join(root, 'src'))) sources.push([filename, path.join('core', path.relative(root, filename))]);
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
  const executable = target === 'darwin-arm64' ? 'Electron.app/Contents/MacOS/Electron' : 'electron.exe';
  await regularFile(path.join(root, executable));
}
async function run(command, args, { cwd = repository } = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (command === '/usr/bin/ditto') { delete env.DITTONORSRC; delete env.DITTO_TEST_OPTIONS; }
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; process.stderr.write(chunk); });
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
export async function packAndVerify({ application, archive, target, expectedFiles }) {
  if (`${process.platform}-${process.arch}` !== target) throw new Error('Verify archives on the native target');
  if (target === 'darwin-arm64') await run('/usr/bin/ditto', ['-c', '-k', '--rsrc', '--extattr', '--acl', '--qtn', '--sequesterRsrc', '--keepParent', application, archive]);
  else await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Compress-Archive -LiteralPath ${psLiteral(application)} -DestinationPath ${psLiteral(archive)} -CompressionLevel Optimal`]);
  const directory = await nativeTemporary('sec-hub-desktop-roundtrip-');
  try {
    await extractArchive(archive, directory);
    const layout = platformLayout(directory, target);
    const files = await inventory(layout.application);
    if (json(files) !== json(expectedFiles)) throw new Error('Extracted archive inventory differs from the final signed file inventory');
    // This is verification only: never strip metadata or re-sign extracted bytes.
    let signatureLog = '';
    if (target === 'darwin-arm64') {
      const result = await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', layout.application]);
      signatureLog = result.stdout + result.stderr;
    }
    const verification = { status: 'passed', nativeTemporaryExtraction: true, postExtractionMutations: false, inventoryFiles: files.length, inventorySha256: createHash('sha256').update(json(files)).digest('hex'), macStrictSignature: target === 'darwin-arm64', authoritativeDeliverable: 'ZIP verified after fresh extraction in native temporary storage; out/package is a convenience copy derived from that ZIP and may acquire local filesystem metadata' };
    return { directory, application: layout.application, files, verification, signatureLog };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}
async function obtainRuntime(cache, pin) {
  await mkdir(cache, { recursive: true });
  const archive = path.join(cache, pin.filename);
  try { await access(archive); } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const temporary = `${archive}.${process.pid}.download`;
    try {
      const response = await fetch(pin.url, { signal: AbortSignal.timeout(180000) });
      if (!response.ok || !response.body) throw new Error(`Official runtime download failed: ${response.status}`);
      await pipeline(Readable.fromWeb(response.body), createWriteStream(temporary, { flags: 'wx' }));
      await verifyArchive(temporary, pin); await rename(temporary, archive);
    } finally { await rm(temporary, { force: true }); }
  }
  await verifyArchive(archive, pin);
  // Always extract the verified ZIP afresh; a pre-extracted cache is not trusted provenance.
  const extracted = await mkdtemp(path.join(cache, '.verified-extract-'));
  try {
    await extractArchive(archive, extracted);
    return extracted;
  } catch (error) { await rm(extracted, { recursive: true, force: true }); throw error; }
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
export async function build({ target, out, cache, allowDirty = false }) {
  if (!supported.has(target)) throw new Error(`Unsupported desktop target: ${target}`);
  if (`${process.platform}-${process.arch}` !== target) throw new Error('Build on the native target OS and architecture');
  await validatePaths({ repository, out, cache });
  const source = await gitState();
  if (source.dirty && !allowDirty) throw new Error('Final packages require a clean Git checkout; --allow-dirty labels a development package');
  await mkdir(out, { recursive: true });
  if ((await readdir(out)).length) throw new Error('--out must be an empty directory; existing deliverables are never replaced');
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
    if (target === 'darwin-arm64') await run('/usr/bin/ditto', [path.join(extracted, 'Electron.app'), layout.application]);
    else await cp(extracted, layout.application, { recursive: true, dereference: false });
    if (target === 'darwin-arm64') await rebrandMac(layout.application, '0.1.0');
    else {
      await rename(path.join(layout.application, 'electron.exe'), layout.executable);
      try { await rename(path.join(layout.application, 'electron_wer.dll'), path.join(layout.application, 'Sec Hub_wer.dll')); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    await rm(path.join(layout.resources, 'default_app.asar'), { force: true });
    const payload = await stagePayload({ repository, resources: layout.resources });
    const appMetadata = JSON.parse(await readFile(path.join(layout.resources, 'app/package.json'), 'utf8'));
    const coreMetadata = JSON.parse(await readFile(path.join(layout.resources, 'core/package.json'), 'utf8'));
    if (appMetadata.version !== '0.1.0' || coreMetadata.version !== '0.3.0') throw new Error('Unexpected app/core payload version');
    const licenses = [];
    for (const name of licenseFiles) {
      const destination = path.join(layout.resources, 'licenses/electron', name);
      await mkdir(path.dirname(destination), { recursive: true }); await copyFile(path.join(extracted, name), destination);
      licenses.push({ path: slash(path.relative(layout.application, destination)), size: (await stat(destination)).size, sha256: await hashFile(destination) });
    }
    const label = allowDirty ? 'development' : 'prerelease';
    const metadata = { schemaVersion: 1, application: 'Sec Hub', appVersion: appMetadata.version, coreVersion: coreMetadata.version, target, label, source, runtime: { electron: lock.electron, node: lock.node, officialArchive: pin }, payload, licenses, signing: target === 'darwin-arm64' ? { kind: 'ad-hoc', identity: '-', applePublisherSigned: false, notarized: false, removedBuildMetadata: ['com.apple.FinderInfo'] } : { kind: 'no-sec-hub-publisher-signature', publisherSigned: false, vendorRuntimeSignature: 'preserved-if-present' } };
    await writeFile(path.join(layout.resources, 'desktop-build.json'), json(metadata));
    if (target === 'darwin-arm64') {
      await prepareMacSigning(layout.application);
      await run('/usr/bin/codesign', ['--force', '--deep', '--sign', '-', layout.application]);
      const verification = await run('/usr/bin/codesign', ['--verify', '--deep', '--strict', '--verbose=2', layout.application]);
      await writeFile(path.join(out, 'codesign-verification.log'), verification.stdout + verification.stderr);
    }
    const finalSource = await gitState();
    if (finalSource.commit !== source.commit || finalSource.status !== source.status) throw new Error('Source checkout changed during packaging; rebuild from frozen source');
    const files = await inventory(layout.application);
    const basename = `sec-hub-desktop-${appMetadata.version}-${target}-${label}`;
    const archive = path.join(out, `${basename}.zip`);
    roundtrip = await packAndVerify({ application: layout.application, archive, target, expectedFiles: files });
    await writeFile(path.join(out, 'archive-verification.json'), json(roundtrip.verification));
    if (target === 'darwin-arm64') await writeFile(path.join(out, 'archive-codesign-verification.log'), roundtrip.signatureLog);
    // CI and local smoke launch files freshly extracted from the deliverable.
    const outputStage = path.join(out, 'package');
    if (target === 'darwin-arm64') await run('/usr/bin/ditto', [roundtrip.directory, outputStage]);
    else await cp(roundtrip.directory, outputStage, { recursive: true, dereference: false });
    const outputLayout = platformLayout(outputStage, target);
    if (json(await inventory(outputLayout.application)) !== json(files)) throw new Error('Convenience package copy differs from the verified archive inventory');
    const manifest = { ...metadata, createdAt: new Date().toISOString(), executable: slash(path.relative(out, outputLayout.executable)), application: slash(path.relative(out, outputLayout.application)), finalFiles: roundtrip.files, finalFilesSha256: roundtrip.verification.inventorySha256, archiveVerification: roundtrip.verification, archive: { filename: path.basename(archive), size: (await stat(archive)).size, sha256: await hashFile(archive) } };
    const manifestPath = path.join(out, `${basename}.manifest.json`);
    await writeFile(manifestPath, json(manifest));
    await writeFile(path.join(out, 'SHA256SUMS.txt'), `${manifest.archive.sha256}  ${path.basename(archive)}\n${await hashFile(manifestPath)}  ${path.basename(manifestPath)}\n`);
    return { archive, manifest: manifestPath, executable: outputLayout.executable, application: outputLayout.application, label, source: source.commit };
  } finally {
    await Promise.all([extracted, stage, roundtrip?.directory].filter(Boolean).map(directory => rm(directory, { recursive: true, force: true })));
  }
}
function argumentsFor(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--allow-dirty') options.allowDirty = true;
    else if (['--target', '--out', '--cache'].includes(argv[i]) && argv[i + 1]) options[argv[i].slice(2)] = argv[++i];
    else throw new Error(`Unknown or incomplete argument: ${argv[i]}`);
  }
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  build(argumentsFor(process.argv.slice(2))).then(result => process.stdout.write(json(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
