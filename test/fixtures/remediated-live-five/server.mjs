// Hardened synthetic counterpart, outside scanner baselines and shipped runtime.
// Execute only private test copies. POSIX no-follow semantics are required;
// configured documentRoot and its parent directories are trusted configuration.
import { createServer } from 'node:http';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';

const documentRoot = '/srv/example-public-documents';

export async function handleDocument(request, response) {
  const url = new URL(request.url, 'http://fixture.invalid');
  if (url.pathname !== '/document') {
    response.writeHead(404);
    response.end('Not found');
    return;
  }
  const filename = url.searchParams.get('name') || 'welcome.txt';
  // URLSearchParams already decodes once. Accept a single basename only.
  if (filename === '.' || filename === '..' || /[\\/\0]/.test(filename) || /^[a-z]:/i.test(filename)
      || !(constants.O_NOFOLLOW > 0) || !(constants.O_NONBLOCK > 0)) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }
  const requestedPath = join(documentRoot, filename);
  try {
    let file;
    let document;
    try {
      // No realpath/open race: reject the final symlink during descriptor open.
      // Nonblocking open also allows a FIFO to be rejected by fstat promptly.
      file = await open(requestedPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      if (!(await file.stat()).isFile()) throw new Error('Document is not a regular file');
      document = await file.readFile();
    } finally {
      await file?.close();
    }
    response.writeHead(200, { 'Content-Type': 'text/plain' });
    response.end(document);
  } catch {
    response.writeHead(404);
    response.end('Not found');
  }
}

// Export only: nothing listens and no files are read by importing this module.
export const createDocumentServer = () => createServer(handleDocument);
