import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const scanFields = {
  'codex-security': { auth: ['chatgpt','api-key','auto'], model: 'string', effort: ['low','medium','high','xhigh'], maxCost: 'positive', maxTimeMinutes: 'positive' },
  'open-code-review': { provider: 'string', model: 'string', maxTokensBudget: 'integer', concurrency: 'integer', timeoutMinutes: 'integer', noPlan: 'boolean', noDedup: 'boolean', noSummary: 'boolean' },
};

export function validateScanOptions(id, value) {
  if (value === undefined) return {};
  const fields = scanFields[id];
  if (!fields || !value || Array.isArray(value) || typeof value !== 'object') throw new Error(`Config ${id}.scanOptions must be a supported options object`);
  for (const [key, item] of Object.entries(value)) {
    const type = fields[key];
    const valid = Array.isArray(type) ? type.includes(item)
      : type === 'string' ? typeof item === 'string' && item.trim().length > 0 && !item.includes('\0') && !item.startsWith('-')
      : type === 'boolean' ? typeof item === 'boolean'
      : type === 'integer' ? Number.isSafeInteger(item) && item > 0
      : type === 'positive' ? typeof item === 'number' && Number.isFinite(item) && item > 0 : false;
    if (!valid) throw new Error(`Invalid config ${id}.scanOptions.${key}`);
  }
  return { ...value };
}

export async function loadConfig(file) {
  if (!file) return {tools:{}};
  let value;
  try { value=JSON.parse(await readFile(resolve(file),'utf8')); }
  catch (error) { throw new Error(`Cannot read explicit config: ${error.message}`); }
  if (!value || Array.isArray(value) || typeof value!=='object' || Object.keys(value).some(key=>key!=='tools')) throw new Error('Config must contain only a tools object');
  if (!value.tools || Array.isArray(value.tools) || typeof value.tools!=='object') throw new Error('Config tools must be an object');
  const tools={};
  for (const [id, entry] of Object.entries(value.tools)) {
    if (!/^[a-z0-9-]+$/.test(id) || !entry || Array.isArray(entry) || typeof entry!=='object') throw new Error('Invalid tool configuration');
    if (Object.keys(entry).some(key=>!['command','args','scanOptions'].includes(key))) throw new Error(`Unknown config setting for ${id}`);
    if (typeof entry.command!=='string' || !entry.command.trim() || entry.command.includes('\0')) throw new Error(`Config ${id}.command must be an executable`);
    if (entry.args!==undefined && (!Array.isArray(entry.args) || entry.args.some(arg=>typeof arg!=='string' || arg.includes('\0')))) throw new Error(`Config ${id}.args must be a string array`);
    validateScanOptions(id,entry.scanOptions);
    tools[id]={command:entry.command,args:entry.args??[],...(entry.scanOptions===undefined?{}:{scanOptions:{...entry.scanOptions}})};
  }
  return {tools};
}
