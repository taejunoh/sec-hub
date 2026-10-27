// Synthetic security-review input. Never run, install, or deploy this fixture.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const documentRoot = '/srv/example-public-documents';

export async function handleDocument(request, response) {
  const url = new URL(request.url, 'http://fixture.invalid');
  if (url.pathname !== '/document') {
    response.writeHead(404);
    response.end('Not found');
    return;
  }
  // The filename crosses a trust boundary without containment validation.
  const filename = url.searchParams.get('name') || 'welcome.txt';
  const requestedPath = join(documentRoot, filename);
  try {
    const document = await readFile(requestedPath);
    response.writeHead(200, { 'Content-Type': 'text/plain' });
    response.end(document);
  } catch {
    response.writeHead(404);
    response.end('Not found');
  }
}

// Export only: nothing listens and no files are read by importing this module.
export const createDocumentServer = () => createServer(handleDocument);
