import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));
const source = fileURLToPath(new URL('../src/native/darwin-acl-reader.c', import.meta.url));
const native = process.platform === 'darwin' && ['arm64', 'x64'].includes(process.arch);
const compiler = native ? spawnSync('/usr/bin/xcrun', ['--find', 'clang'], { encoding: 'utf8' }).stdout?.trim() : null;
const sdk = native ? spawnSync('/usr/bin/xcrun', ['--sdk', 'macosx', '--show-sdk-path'], { encoding: 'utf8' }).stdout?.trim() : null;

// These are explicitly injected native API failures, not claims of real OS faults.
// They compile the production C main unchanged with one API call overridden.
const faults = [
  ['ACL query EIO', 'acl_get_fd_np', 'acl_t fault(int fd,acl_type_t type){(void)fd;(void)type;errno=EIO;return NULL;}'],
  ['invalid ACL', 'acl_valid', 'int fault(acl_t acl){(void)acl;errno=EINVAL;return -1;}'],
  ['iterator EIO', 'acl_get_entry', 'int fault(acl_t acl,int cursor,acl_entry_t *ace){(void)acl;(void)cursor;(void)ace;errno=EIO;return -1;}'],
  ['tag EIO', 'acl_get_tag_type', 'int fault(acl_entry_t ace,acl_tag_t *tag){(void)ace;(void)tag;errno=EIO;return -1;}'],
  ['absence fstatx EIO', 'fstatx_np', 'int fault(int fd,struct stat *s,filesec_t security){(void)fd;(void)s;(void)security;errno=EIO;return -1;}'],
  ['absence property EIO', 'filesec_query_property', 'int fault(filesec_t security,filesec_property_t key,int *present){(void)security;(void)key;(void)present;errno=EIO;return -1;}'],
];
test('native helper rejects injected query, malformed ACL and absence-confirmation errors', { skip: !compiler }, async t => {
  const temp = await fs.mkdtemp(join(tmpdir(), 'sec-hub-acl-fault-'));
  const directory = join(temp, 'directory'); await fs.mkdir(directory);
  const handle = await fs.open(directory, 'r');
  try {
    for (const [label, api, implementation] of faults) {
      await t.test(label, async () => {
        const empty = label.startsWith('absence ');
        spawnSync('/bin/chmod', ['-N', directory]);
        if (!empty) {
          const acl = spawnSync('/bin/chmod', ['+a', 'everyone deny delete', directory], { encoding: 'utf8' });
          assert.equal(acl.status, 0, acl.stderr);
        }
        const code = join(temp, 'fault.c'), executable = join(temp, 'fault');
        await fs.writeFile(code, `#include <sys/types.h>\n#include <sys/stat.h>\n#include <sys/acl.h>\n#include <fcntl.h>\n#include <errno.h>\n#include <stdio.h>\n${implementation}\n#define ${api} fault\n#include ${JSON.stringify(source)}\n`);
        const built = spawnSync(compiler, ['-isysroot', sdk, '-std=c11', '-Wall', '-Wextra', '-Werror', code, '-o', executable], { encoding: 'utf8', timeout: 30000 });
        assert.equal(built.status, 0, built.stderr);
        const result = spawnSync(executable, [], { stdio: ['ignore', 'pipe', 'pipe', handle.fd], encoding: 'utf8', timeout: 5000, env: {} });
        assert.equal(result.status, 2, result.error?.message || result.stderr);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /ACL/);
      });
    }
  } finally {
    await handle.close();spawnSync('/bin/chmod', ['-RN', temp]);await fs.rm(temp, { recursive: true, force: true });
  }
});

test('packed package includes native source/build/binary and writes without PATH tools or compilation', { skip: !native }, async () => {
  const temp = await fs.mkdtemp(join(tmpdir(), 'sec-hub-acl-package-'));
  try {
    const packed = spawnSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', temp], {
      cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024,
    });
    assert.equal(packed.status, 0, packed.stderr);
    const [metadata] = JSON.parse(packed.stdout);
    for (const path of ['src/native/darwin-acl-reader', 'src/native/darwin-acl-reader.c', 'src/native/build-darwin-acl-reader.mjs']) {
      assert.ok(metadata.files.some(file => file.path === path), `missing packaged ${path}`);
    }
    const unpacked = join(temp, 'unpacked'); await fs.mkdir(unpacked);
    const extracted = spawnSync('/usr/bin/tar', ['-xzf', join(temp, metadata.filename), '-C', unpacked], { encoding: 'utf8' });
    assert.equal(extracted.status, 0, extracted.stderr);
    const binary = join(unpacked, 'package/src/native/darwin-acl-reader');
    assert.ok((await fs.stat(binary)).mode & 0o111);
    assert.deepEqual(await fs.readFile(binary), await fs.readFile(join(root, 'src/native/darwin-acl-reader')));
    const module = resolve(unpacked, 'package/src/safe-io.mjs'), output = join(temp, 'output');
    const code = `import {pathToFileURL} from 'node:url';import {readFile} from 'node:fs/promises';const safe=await import(pathToFileURL(process.argv[1]).href);await safe.ensureSafeDirectory(process.argv[2]);await safe.atomicWriteFile(process.argv[2]+'/report','packed write');process.stdout.write(await readFile(process.argv[2]+'/report','utf8'));`;
    const ran = spawnSync(process.execPath, ['--input-type=module', '-e', code, module, output], {
      encoding: 'utf8', timeout: 10000, env: { PATH: '/does-not-exist' },
    });
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(ran.stdout, 'packed write');
  } finally { await fs.rm(temp, { recursive: true, force: true }); }
});
