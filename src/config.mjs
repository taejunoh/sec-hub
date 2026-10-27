import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

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
    if (Object.keys(entry).some(key=>!['command','args'].includes(key))) throw new Error(`Unknown config setting for ${id}`);
    if (typeof entry.command!=='string' || !entry.command.trim() || entry.command.includes('\0')) throw new Error(`Config ${id}.command must be an executable`);
    if (entry.args!==undefined && (!Array.isArray(entry.args) || entry.args.some(arg=>typeof arg!=='string' || arg.includes('\0')))) throw new Error(`Config ${id}.args must be a string array`);
    tools[id]={command:entry.command,args:entry.args??[]};
  }
  return {tools};
}
