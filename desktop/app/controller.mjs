import { isOwnedUrl, browserUrl } from './policy.mjs';

const INVALID_RESULTS = 'This folder has no readable saved results. Choose a folder containing canonical run.json or comparison.json files. Your previous results remain open.';

/** Own every server, including a server which resolves after a close request. */
export function createViewerController({ sampleRuns, startDashboard, inspectDashboard, show, notify }) {
  let current = null;
  let closing = false;
  let queue = Promise.resolve();
  let closePromise;
  let pendingAbort;
  const owned = new Set();
  const enqueue = (operation) => {
    const result = queue.then(operation);
    queue = result.catch(() => {});
    return result;
  };
  const release = async (server) => {
    if (!owned.has(server)) return;
    await server.close();
    owned.delete(server);
  };

  function change(runs, example) {
    if (closing) return Promise.resolve(false);
    return enqueue(async () => {
      if (closing) return false;
      const abort = new AbortController(); pendingAbort = abort;
      let server;
      const previous = current;
      let showing = false;
      try {
        // Deliberately construct this object: executionConfig is never accepted.
        server = await startDashboard({ runs, port: 0, signal: abort.signal });
        owned.add(server);
        if (!isOwnedUrl(server.url, server.url)) throw Error('invalid server origin');
        if (closing) { await release(server); return false; }
        const catalog = await inspectDashboard(server.url);
        if (!Number.isSafeInteger(catalog.readyCount) || catalog.readyCount < 1) throw Error('empty catalog');
        if (closing) { await release(server); return false; }
        const candidate = { url: server.url, example, server };
        showing = true;
        await show({ url: candidate.url, example });
        if (closing) { await release(server); return false; }
        current = candidate;
        if (previous) await release(previous.server);
        return true;
      } catch {
        if (server && server !== current?.server) await release(server);
        if (showing && previous && !closing) await show({ url: previous.url, example: previous.example });
        if (!closing) await notify(INVALID_RESULTS);
        return false;
      } finally {
        if (pendingAbort === abort) pendingAbort = null;
      }
    });
  }

  return {
    get current() { return current ? { url: current.url, example: current.example } : null; },
    showExample: () => change(sampleRuns, true),
    showFolder: (runs) => change(runs, false),
    close() {
      if (closePromise) return closePromise;
      closing = true;
      pendingAbort?.abort();
      closePromise = enqueue(async () => {
        const results = await Promise.allSettled([...owned].map(release));
        current = null;
        const failure = results.find((result) => result.status === 'rejected');
        if (failure) throw failure.reason;
      });
      return closePromise;
    },
  };
}

/** No renderer-supplied path or URL enters either native action. */
export function createNativeActions({ controller, pickFolder, openExternal }) {
  let picking = false;
  return {
    async openSavedResults() {
      if (picking) return false;
      picking = true;
      try {
        const chosen = await pickFolder();
        return chosen ? await controller.showFolder(chosen) : false;
      } finally { picking = false; }
    },
    async openInBrowser() {
      const current = controller.current;
      const url = browserUrl(current?.url, current?.url);
      if (url) await openExternal(url);
    },
  };
}
