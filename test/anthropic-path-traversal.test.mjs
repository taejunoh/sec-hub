import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { get } from 'node:http';
import { mkdtemp, mkdir, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const originalRootLiteral = "'/srv/example-public-documents'";
const baselineHash = '8ac2b1f2e25e2fb2f4cd8972f07dcf1c8f9eccd743f143b80e1c1e3b9997774f';
const secret = 'SYNTHETIC_F001_OUTSIDE_MARKER_20261029\n';
const ordinary = 'SYNTHETIC_F001_PUBLIC_DOCUMENT\n';
const welcome = 'SYNTHETIC_F001_WELCOME\n';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function request(server, path) {
  return new Promise((resolve, reject) => {
    const req = get({ hostname: '127.0.0.1', port: server.address().port, path, agent: false }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(2000, () => req.destroy(new Error('Loopback document request timed out')));
    req.on('error', reject);
  });
}

async function startCopy(sourceUrl, label, directory, documentRoot, servers, sources) {
  // Only text is read at the original location. Execute solely this private copy.
  const source = await readFile(sourceUrl, 'utf8');
  assert.equal(source.split(originalRootLiteral).length - 1, 1, 'one exact root literal for adaptation');
  const replacement = JSON.stringify(documentRoot);
  const adapted = source.replace(originalRootLiteral, replacement);
  const modulePath = join(directory, `${label}-server.mjs`);
  await writeFile(modulePath, adapted, { mode: 0o600 });
  sources[label] = {
    sourcePath: sourceUrl.pathname,
    sourceSha256: sha256(source),
    adaptedPath: modulePath,
    adaptedSha256: sha256(adapted),
    adaptation: { kind: 'exact-documentRoot-literal-only', from: originalRootLiteral, to: replacement, replacements: 1 },
  };
  const module = await import(pathToFileURL(modulePath).href);
  assert.equal(typeof module.handleDocument, 'function');
  assert.equal(typeof module.createDocumentServer, 'function');
  const server = module.createDocumentServer();
  servers.push(server);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  sources[label].address = server.address();
  return server;
}

// Removing filename validation must fail the traversal cases; removing no-follow
// opening must fail the external and internal final-component symlink cases.
test('F-001 isolated HTTP disclosure control and fixed-counterpart regression', { timeout: 15000 }, async (t) => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'sec-hub-f001-')));
  const documentRoot = join(directory, 'public');
  const servers = [];
  const sources = {};
  const observations = [];
  const receipt = {
    schema: 'sec-hub.anthropic-f001-http-regression.v1',
    finding: { id: 'F-001', nativeRunId: '40c1b129-c830-47a6-93fd-808e360102bb', sourceRevision: '471e8622a2fa6b32aae45808ee29c49e2426c92f', historicalClassification: 'candidate' },
    scope: 'Dynamic confirmation only of isolated synthetic handler copies; no deployed endpoint claim.',
    runtime: { executable: process.execPath, version: process.version, platform: process.platform, arch: process.arch },
    temporaryDirectory: directory,
    temporaryDirectoryMode: (await stat(directory)).mode & 0o777,
    sources,
    observations,
    constraints: { providerCalls: 0, credentialReads: 0, originalModulesExecuted: false, network: '127.0.0.1 ephemeral HTTP only', configuredRootAndParents: 'trusted', platformScope: 'POSIX no-follow/nonblocking descriptor semantics; no Windows verification' },
  };
  try {
    await mkdir(documentRoot);
    await mkdir(join(directory, 'public-sibling'));
    await mkdir(join(documentRoot, 'directory'));
    await writeFile(join(documentRoot, 'note.txt'), ordinary);
    await writeFile(join(documentRoot, 'welcome.txt'), welcome);
    await writeFile(join(directory, 'secret-marker.txt'), secret);
    await writeFile(join(directory, 'public-sibling', 'secret-marker.txt'), secret);
    await symlink(join(directory, 'secret-marker.txt'), join(documentRoot, 'external-link.txt'));
    await symlink(join(directory, 'public-sibling'), join(documentRoot, 'external-directory'));
    await symlink(join(documentRoot, 'note.txt'), join(documentRoot, 'internal-link.txt'));
    const before = await startCopy(new URL('./fixtures/live-five/server.mjs', import.meta.url), 'before', directory, documentRoot, servers, sources);
    assert.equal(sources.before.sourceSha256, baselineHash, 'preserved scanner source identity');
    const after = await startCopy(new URL('./fixtures/remediated-live-five/server.mjs', import.meta.url), 'after', directory, documentRoot, servers, sources);
    const cases = [
      { id: 'valid', path: '/document?name=note.txt', before: [200, ordinary], after: [200, ordinary] },
      { id: 'default', path: '/document', before: [200, welcome], after: [200, welcome] },
      { id: 'empty-default', path: '/document?name=', before: [200, welcome], after: [200, welcome] },
      { id: 'missing', path: '/document?name=missing.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'non-document-route', path: '/other?name=../secret-marker.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'plain-traversal', path: '/document?name=../secret-marker.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'encoded-slash-traversal', path: '/document?name=..%2Fsecret-marker.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'encoded-dot-traversal', path: '/document?name=%2e%2e%2fsecret-marker.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'sibling-prefix-traversal', path: '/document?name=../public-sibling/secret-marker.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'external-file-symlink', path: '/document?name=external-link.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'external-directory-symlink', path: '/document?name=external-directory/secret-marker.txt', before: [200, secret], after: [404, 'Not found'] },
      { id: 'internal-file-symlink', path: '/document?name=internal-link.txt', before: [200, ordinary], after: [404, 'Not found'] },
      // POSIX path.join keeps a leading-slash name under root; this control
      // returns the PUBLIC document in the baseline, never an outside file.
      { id: 'absolute-leading-slash-public-control', path: '/document?name=%2Fnote.txt', before: [200, ordinary], after: [404, 'Not found'] },
      { id: 'absolute-synthetic-path-control', path: `/document?name=${encodeURIComponent(join(directory, 'secret-marker.txt'))}`, before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'backslash-traversal-control', path: '/document?name=..%5Csecret-marker.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'windows-drive-control', path: '/document?name=C%3A%5Csecret-marker.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'windows-unc-control', path: '/document?name=%5C%5Csynthetic%5Csecret-marker.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'double-encoding-control', path: '/document?name=%252e%252e%252fsecret-marker.txt', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'nul-control', path: '/document?name=note.txt%00', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'dot-control', path: '/document?name=.', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'dotdot-control', path: '/document?name=..', before: [404, 'Not found'], after: [404, 'Not found'] },
      { id: 'nonregular-directory', path: '/document?name=directory', before: [404, 'Not found'], after: [404, 'Not found'] },
    ];
    // Collect all real HTTP observations before assertions so red evidence is
    // complete even when several independent security assertions fail.
    for (const entry of cases) {
      const beforeResult = await request(before, entry.path);
      const afterResult = await request(after, entry.path);
      observations.push({
        id: entry.id, request: entry.path,
        before: { ...beforeResult, bodySha256: sha256(beforeResult.body), outsideMarkerDisclosed: beforeResult.body.includes(secret), expectedStatus: entry.before[0], expectedBody: entry.before[1] },
        after: { ...afterResult, bodySha256: sha256(afterResult.body), outsideMarkerDisclosed: afterResult.body.includes(secret), expectedStatus: entry.after[0], expectedBody: entry.after[1] },
      });
    }
    await t.test('vulnerable HTTP control discloses only expected synthetic marker cases', () => {
      for (const [index, entry] of cases.entries()) {
        assert.equal(observations[index].before.status, entry.before[0], entry.id);
        assert.equal(observations[index].before.body, entry.before[1], entry.id);
      }
    });
    for (const [index, entry] of cases.entries()) {
      await t.test(`fixed counterpart: ${entry.id}`, () => {
        const result = observations[index].after;
        assert.equal(result.outsideMarkerDisclosed, false, `${entry.id}: outside synthetic marker must never be returned`);
        assert.equal(result.status, entry.after[0], `${entry.id}: HTTP status`);
        assert.equal(result.body, entry.after[1], `${entry.id}: HTTP body`);
      });
    }
  } finally {
    await Promise.all(servers.map((server) => new Promise((resolve, reject) => {
      server.closeAllConnections();
      server.close((error) => error ? reject(error) : resolve());
    })));
    await rm(directory, { recursive: true, force: true });
    receipt.cleanup = { serversClosed: servers.every((server) => !server.listening), temporaryTreeRemoved: true };
    if (process.env.ANTHROPIC_F001_RECEIPT) {
      await writeFile(process.env.ANTHROPIC_F001_RECEIPT, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
    }
  }
});
