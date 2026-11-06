import { randomUUID } from 'node:crypto';
import { basename, isAbsolute } from 'node:path';
import { directoryIdentity } from './execution-config.mjs';
import { createJobController, ExecutionError } from './jobs.mjs';
import { redactValue } from '../redaction.mjs';
import { containsPath, desktopToolIds, readDesktopConfig, validateDesktopNodePath, verifyDesktopNode } from './desktop-tooling.mjs';

const active = (job) => job && ['running', 'cancelling'].includes(job.state);
const allowed = () => true;
const problem = (code) => ({ error: { code } });
const failure = (error) => problem(error instanceof ExecutionError ? error.code : 'internal_error');
const labelFor = (path, fallback) => redactValue(basename(path).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 120)) || fallback;
const configuredTools = new Set(desktopToolIds);

function phpEndpoint(value) {
  if (typeof value !== 'string' || value.length > 2048 || !/^https?:\/\//i.test(value) || /[\x00-\x20\x7f\\?#]/.test(value)) return null;
  try {
    const parsed = new URL(value);
    return parsed.username || parsed.password ? null : parsed.href;
  } catch { return null; }
}

/** Main-process entry point. Executable paths and configuration never come from HTTP or IPC arguments. */
export async function createDesktopScanController({
  runs, pickFolder, pickConfig, pickNode, inspectTools, confirmAI, openExternal, refreshCatalog, scan, report,
}) {
  const rootIdentity = await directoryIdentity(runs, true);
  const configuration = {
    runsRoot: rootIdentity.path,
    rootIdentity,
    targets: [],
    limits: { maxActiveJobs: 1, maxJobs: 20, maxJobTimeMs: 150 * 60_000, maxHistory: 20 },
  };
  const jobs = createJobController({ configuration, scan, report, inspectGit: false, allowAnthropic: true });
  const shutdown = new AbortController();
  let selected = null;
  let selectedConfig = null;
  let selectedNode = null;
  let jobId = null;
  let generation = 0;
  let nativeOperation = false;
  const getJob = () => jobId ? jobs.get(jobId) : null;
  const canUse = (current) => !shutdown.signal.aborted && current();

  const toolOptions = () => inspectTools({
    config: selectedConfig?.config, configPath: selectedConfig?.path, nodePath: selectedNode,
    targetPath: selected?.path, runsRoot: rootIdentity.path,
  });
  const excluded = () => [selected?.path, rootIdentity.path].filter(Boolean);

  async function state() {
    const tools = (await toolOptions()).map(({ id, command, installation, ai, setup, unavailableReason }) => ({
      id, installation, authentication: ai ? 'unknown' : 'not_required', selectable: Boolean(command), ai,
      ...(setup ? { setupActions: Object.keys(setup) } : {}),
      ...(unavailableReason ? { unavailableReason } : {}),
    }));
    return { folderLabel: selected?.label ?? null, configLabel: selectedConfig?.label ?? null, nodeConfigured: Boolean(selectedNode), tools, job: getJob(), generation };
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
        if (containsPath(identity.path, rootIdentity.path) || containsPath(rootIdentity.path, identity.path)) return problem('target_unavailable');
        selected = { id: randomUUID(), label: labelFor(identity.path, 'Selected folder'), path: identity.path, identity };
        return state();
      });
    },
    chooseConfig(current = allowed) {
      return withNativeOperation(async () => {
        const chosen = await pickConfig();
        if (!canUse(current)) return problem('forbidden');
        if (!chosen) return state();
        let config;
        try { config = await readDesktopConfig(chosen); }
        catch { return problem('config_unavailable'); }
        if (!canUse(current)) return problem('forbidden');
        if (excluded().some(root => containsPath(root, config.path))) return problem('config_unavailable');
        selectedConfig = { ...config, label: labelFor(config.path, 'Selected configuration') };
        return state();
      });
    },
    chooseNode(current = allowed) {
      return withNativeOperation(async () => {
        const chosen = await pickNode();
        if (!canUse(current)) return problem('forbidden');
        if (!chosen) return state();
        const command = await validateDesktopNodePath(chosen, excluded());
        if (!canUse(current)) return problem('forbidden');
        if (!command) return problem('node_unavailable');
        selectedNode = command;
        return state();
      });
    },
    startScan(request, current = allowed) {
      return withNativeOperation(async () => {
        if (!request || typeof request !== 'object' || Array.isArray(request)
          || Object.keys(request).some(key => !['toolIds', 'aiConsent', 'phpUrl'].includes(key))
          || !Object.hasOwn(request, 'toolIds') || !Object.hasOwn(request, 'aiConsent')
          || !Array.isArray(request.toolIds) || !request.toolIds.length || request.toolIds.length > desktopToolIds.length
          || request.toolIds.some(id => !configuredTools.has(id))
          || new Set(request.toolIds).size !== request.toolIds.length || typeof request.aiConsent !== 'boolean') return problem('invalid_request');
        if (!selected) return problem('target_not_found');
        let url;
        if (request.toolIds.includes('php2shell')) {
          if (!Object.hasOwn(request, 'phpUrl') || request.phpUrl === '') return problem('php_url_required');
          url = phpEndpoint(request.phpUrl);
          if (!url) return problem('invalid_php_url');
        } else if (Object.hasOwn(request, 'phpUrl')) return problem('invalid_request');
        const available = await toolOptions();
        const tools = request.toolIds.map((id) => available.find((entry) => entry.id === id));
        if (tools.some((tool) => !tool?.command || !isAbsolute(tool.command))) return problem('tool_unavailable');
        const ai = tools.some((tool) => tool.ai);
        if (!canUse(current)) return problem('forbidden');
        if (ai && (!request.aiConsent || !await confirmAI({ folderLabel: selected.label, toolIds: tools.filter((tool) => tool.ai).map((tool) => tool.id), signal: shutdown.signal }))) return problem('ai_consent_required');
        if (!canUse(current)) return problem('forbidden');
        const nodeExecutable = tools.find(tool => tool.nodeExecutable)?.nodeExecutable;
        if (nodeExecutable && !await verifyDesktopNode(nodeExecutable, shutdown.signal)) return problem('node_unavailable');
        if (!canUse(current)) return problem('forbidden');
        const config = { tools: Object.fromEntries(tools.map(({ id, command, args, scanOptions, agentOptions }) => [
          id, { command, ...(args ? { args } : {}), ...(scanOptions ? { scanOptions } : {}), ...(agentOptions ? { agentOptions } : {}) },
        ])) };
        configuration.targets[0] = { ...selected, toolIds: [...request.toolIds], ai, timeoutMs: (ai ? 35 : 2) * 60_000, config, url, nodeExecutable };
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
        const tool = (await toolOptions()).find((entry) => entry.id === id);
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
