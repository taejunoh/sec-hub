import { readFile } from 'node:fs/promises';
import { resolve, isAbsolute, normalize } from 'node:path';

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


const agentFields = {
  cloudflare: { strategy:['native-collab','supervised-codex-workers'], preparationFrom:'preparationManifest', preparationSha256:'sha256', skillRoot:'absolute', revision:'revision', model:'string', workRoot:'absolute', effort:['low','medium','high','xhigh'], profile:['quick'], maxAgents:'agents' },
  anthropic: { skillRoot:'absolute', revision:'revision', model:'string', workRoot:'absolute', maxTurns:'integer', maxBudgetUsd:'positive', mode:['vuln-scan'], single:'true', noScore:'true' },
};
export function validateAgentOptions(id, value) {
  if (value === undefined) return {};
  const fields=agentFields[id];
  if (!fields || !value || Array.isArray(value) || typeof value!=='object') throw new Error('Config '+id+'.agentOptions must be a supported options object');
  for (const [key,item] of Object.entries(value)) {
    const type=fields[key];
    const clean=typeof item==='string' && item.trim().length>0 && !/[\x00-\x1f\x7f]/.test(item) && !item.startsWith('-');
    const valid=Array.isArray(type)?type.includes(item)
      :type==='preparationManifest'?clean && item===item.trim() && isAbsolute(item) && normalize(item)===item && item.endsWith('/raw/cloudflare/execution-manifest.json')
      :type==='sha256'?typeof item==='string' && /^[a-f0-9]{64}$/.test(item)
      :type==='absolute'?clean && isAbsolute(item)
      :type==='revision'?typeof item==='string' && /^[a-f0-9]{40}$/.test(item)
      :type==='string'?clean
      :type==='integer'?Number.isSafeInteger(item) && item>0
      :type==='agents'?Number.isSafeInteger(item) && item>=7
      :type==='positive'?typeof item==='number' && Number.isFinite(item) && item>0
      :type==='true'?item===true:false;
    if(!valid)throw new Error('Invalid config '+id+'.agentOptions.'+key);
  }
  if((value.preparationFrom!==undefined)!==(value.preparationSha256!==undefined))throw new Error('Invalid config '+id+'.agentOptions: preparationFrom and preparationSha256 are required together');
  if(value.preparationFrom!==undefined && value.strategy!=='supervised-codex-workers')throw new Error('Invalid config '+id+'.agentOptions.preparationFrom: requires supervised-codex-workers');
  return {...value};
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
    if (Object.keys(entry).some(key=>!['command','args','scanOptions','agentOptions'].includes(key))) throw new Error(`Unknown config setting for ${id}`);
    if (typeof entry.command!=='string' || !entry.command.trim() || entry.command.includes('\0')) throw new Error(`Config ${id}.command must be an executable`);
    if (entry.args!==undefined && (!Array.isArray(entry.args) || entry.args.some(arg=>typeof arg!=='string' || arg.includes('\0')))) throw new Error(`Config ${id}.args must be a string array`);
    validateScanOptions(id,entry.scanOptions);
    validateAgentOptions(id,entry.agentOptions);
    tools[id]={command:entry.command,args:entry.args??[],...(entry.scanOptions===undefined?{}:{scanOptions:{...entry.scanOptions}}),...(entry.agentOptions===undefined?{}:{agentOptions:{...entry.agentOptions}})};
  }
  return {tools};
}
