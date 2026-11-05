import { randomUUID } from 'node:crypto';
import { basename, isAbsolute, relative, sep } from 'node:path';
import { directoryIdentity } from './execution-config.mjs';
import { createJobController, ExecutionError } from './jobs.mjs';
import { redactValue } from '../redaction.mjs';

const active = (job) => job && ['running', 'cancelling'].includes(job.state);
const allowed = () => true;
const problem = (code) => ({ error: { code } });
const failure = (error) => problem(error instanceof ExecutionError ? error.code : 'internal_error');
const contains = (parent, child) => {
  const value = relative(parent, child);
  return !isAbsolute(value) && value !== '..' && !value.startsWith(`..${sep}`);
};

/** Main-process entry point. Native directory and tool inputs never come from HTTP or IPC arguments. */
export async function createDesktopScanController({ runs, pickFolder, inspectTools, confirmAI, openExternal, refreshCatalog, scan, report }) {
  const rootIdentity = await directoryIdentity(runs, true);
  const configuration = {
    runsRoot: rootIdentity.path,
    rootIdentity,
    targets: [],
    limits: { maxActiveJobs: 1, maxJobs: 20, maxJobTimeMs: 15 * 60_000, maxHistory: 20 },
  };
  const jobs = createJobController({ configuration, scan, report, inspectGit: false });
  const shutdown = new AbortController();
  let selected = null;
  let jobId = null;
  let generation = 0;
  let nativeOperation = false;
  const getJob = () => jobId ? jobs.get(jobId) : null;
  const canUse = (current) => !shutdown.signal.aborted && current();

  async function state() {
    const tools = (await inspectTools()).map(({ id, command, installation, ai, setup }) => ({
      id, installation, authentication: ai ? 'unknown' : 'not_required', selectable: Boolean(command), ai,
      ...(setup ? { setupActions: Object.keys(setup) } : {}),
    }));
    return { folderLabel: selected?.label ?? null, tools, job: getJob(), generation };
  }

  async function withNativeOperation(operation) {
    if (shutdown.signal.aborted) return problem('execution_closing');
    if (nativeOperation || active(getJob())) return problem('execution_busy');
    nativeOperation = true;
    try { return await operation(); }
    catch (error) { return failure(error); }
    finally { nativeOperation = false; }
  }

  return {
    getState: state,
    chooseFolder(current = allowed) {
      return withNativeOperation(async () => {
        const chosen = await pickFolder();
        if (!canUse(current)) return problem('forbidden');
        if (!chosen) return state();
        let identity;
        try { identity = await directoryIdentity(chosen); }
        catch { return problem('target_unavailable'); }
        if (!canUse(current)) return problem('forbidden');
        if (contains(identity.path, rootIdentity.path) || contains(rootIdentity.path, identity.path)) return problem('target_unavailable');
        const label = redactValue(basename(identity.path).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 120)) || 'Selected folder';
        selected = { id: randomUUID(), label, path: identity.path, identity };
        return state();
      });
    },
    startScan(request, current = allowed) {
      return withNativeOperation(async () => {
        if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).length !== 2
          || !Object.hasOwn(request, 'toolIds') || !Object.hasOwn(request, 'aiConsent')
          || !Array.isArray(request.toolIds) || !request.toolIds.length || request.toolIds.length > 8
          || request.toolIds.some((id) => typeof id !== 'string' || !/^[a-z0-9-]{1,32}$/.test(id))
          || new Set(request.toolIds).size !== request.toolIds.length || typeof request.aiConsent !== 'boolean') return problem('invalid_request');
        if (!selected) return problem('target_not_found');
        const available = await inspectTools();
        const tools = request.toolIds.map((id) => available.find((entry) => entry.id === id));
        if (tools.some((tool) => !tool?.command || !isAbsolute(tool.command))) return problem('tool_unavailable');
        const ai = tools.some((tool) => tool.ai);
        if (!canUse(current)) return problem('forbidden');
        if (ai && (!request.aiConsent || !await confirmAI({ folderLabel: selected.label, toolIds: tools.filter((tool) => tool.ai).map((tool) => tool.id), signal: shutdown.signal }))) return problem('ai_consent_required');
        if (!canUse(current)) return problem('forbidden');
        const config = { tools: Object.fromEntries(tools.map(({ id, command, args, scanOptions }) => [id, { command, ...(args ? { args } : {}), ...(scanOptions ? { scanOptions } : {}) }])) };
        configuration.targets[0] = { ...selected, toolIds: [...request.toolIds], ai, timeoutMs: 120_000, config };
        const job = jobs.start({ targetId: selected.id, toolIds: request.toolIds });
        jobId = job.id;
        return { job };
      });
    },
    getJob: () => ({ job: getJob() }),
    cancelScan: () => ({ job: jobId ? jobs.cancel(jobId) : null }),
    refreshResults(current = allowed) {
      if (nativeOperation) return problem('execution_busy');
      return jobs.withRefresh(async () => {
        const next = generation + 1;
        const result = await refreshCatalog(jobs.describe().jobs, next, () => canUse(current));
        if (!canUse(current)) return problem('forbidden');
        generation = next;
        return result;
      }).catch((error) => error instanceof ExecutionError ? failure(error) : problem('refresh_failed'));
    },
    openSetup(id, action, current = allowed) {
      return withNativeOperation(async () => {
        if (typeof id !== 'string' || !['install', 'sign_in'].includes(action)) return problem('setup_unavailable');
        const tool = (await inspectTools()).find((entry) => entry.id === id);
        const url = tool?.setup?.[action];
        if (!url) return problem('setup_unavailable');
        if (!canUse(current)) return problem('forbidden');
        await openExternal(url);
        return { ok: true };
      });
    },
    close() {
      shutdown.abort();
      return jobs.close();
    },
  };
}
