import { readFile, stat } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { loadConfig } from './config.mjs';
import { runScan, doctor, exitCodeForRun, prepareRunDirectory, createRedactor } from './runner.mjs';

const HELP=`Sec Hub 0.1.1 — local security scanner orchestration

Usage:
  sec-hub doctor [target] [--json] [--config file] [--ai]
  sec-hub scan <target> [--ai] [--tools ids] [--url https://host]
               [--timeout seconds] [--out directory] [--config file]
  sec-hub report <run-directory-or-run.json>
  sec-hub bridge <cloudflare|anthropic> [--out directory]
  sec-hub import <cloudflare|anthropic> <file> [--target path] [--out directory]
  sec-hub --help | --version

Basic scan selects osv and skillspector. AI scanners require --ai and
explicit executable configuration. PHP checks require an explicit HTTP(S) URL.
Use doctor to see prerequisites and install guidance; no tools are installed.
Reports include JSON, HTML and SARIF. --out must be an empty directory.
Exit codes: 0 complete/no findings; 1 complete/findings; 2 incomplete/error.
`;
const optionsByCommand={doctor:['json','config','ai'],scan:['ai','tools','url','timeout','out','config'],report:[],bridge:['out'],import:['target','out']};
function parseArgs(args,allowed){
  const positional=[],options={};let literal=false;
  for(let i=0;i<args.length;i++){
    const arg=args[i];if(arg==='--'&&!literal){literal=true;continue;}
    if(!literal&&arg.startsWith('-')){
      if(!arg.startsWith('--'))throw new Error(`Unknown option: ${arg}`);
      const [key,...rest]=arg.slice(2).split('=');if(!allowed.includes(key))throw new Error(`Unknown option: --${key}`);
      if(Object.hasOwn(options,key))throw new Error(`Duplicate option: --${key}`);
      if(['json','ai'].includes(key)){if(rest.length)throw new Error(`--${key} takes no value`);options[key]=true;}
      else {const value=rest.length?rest.join('='):args[++i];if(value===undefined||value.startsWith('--')||!value)throw new Error(`--${key} requires a value`);options[key]=value;}
    }else positional.push(arg);
  }
  return {positional,options};
}
function expectCount(values,min,max=min){if(values.length<min||values.length>max)throw new Error('Invalid arguments. Run sec-hub --help for usage.');}
function validateRun(run){
  const statuses=['completed','partial','failed'],toolStatuses=['completed','failed','timed_out','cancelled','skipped','imported'];
  if(!run||run.schemaVersion!==1||typeof run.id!=='string'||!run.id||typeof run.startedAt!=='string'||typeof run.endedAt!=='string'||!run.target||typeof run.target.path!=='string'||!statuses.includes(run.status)||!Array.isArray(run.tools)||!Array.isArray(run.findings)||run.tools.some(tool=>!tool||typeof tool.id!=='string'||!toolStatuses.includes(tool.status)||!Array.isArray(tool.findings)))throw new Error('Invalid saved run: expected canonical schema version 1');
  return run;
}
export async function main(argv,{stdout=process.stdout,stderr=process.stderr}={}){
  const say=value=>stdout.write(String(value)+'\n');
  try{
    if(Number(process.versions.node.split('.')[0])<22)throw new Error('Node.js 22 or newer is required');
    if(!argv.length||argv[0]==='--help'||argv[0]==='-h'||argv[0]==='help'){say(HELP);return 0;}
    if(argv[0]==='--version'||argv[0]==='-v'){say('0.1.1');return 0;}
    const [command,...args]=argv;if(!Object.hasOwn(optionsByCommand,command))throw new Error(`Unknown command: ${command}`);
    if(args.includes('--help')){say(HELP);return 0;}
    const {positional,options}=parseArgs(args,optionsByCommand[command]);
    if(command==='doctor'){
      expectCount(positional,0,1);
      const controller=new AbortController(),cancel=()=>controller.abort();process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
      try{
        const data=await doctor({target:positional[0],config:await loadConfig(options.config),ai:options.ai,signal:controller.signal});
        if(options.json)say(JSON.stringify(data,null,2));else{say(`Node ${data.node}; target ${data.target}`);for(const tool of data.tools){say(`${tool.available?'ready':'unavailable'}  ${tool.id}: ${tool.reason??tool.version??tool.name}`);if(!tool.available&&tool.install)say(`  Install: ${typeof tool.install==='string'?tool.install:JSON.stringify(tool.install)}`);}}
        return controller.signal.aborted?2:0;
      }finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
    }
    if(command==='report'){
      expectCount(positional,1);let input=resolve(positional[0]);if((await stat(input)).isDirectory())input=join(input,'run.json');
      const run=validateRun(JSON.parse(await readFile(input,'utf8')));
      const {writeReports}=await import('./reports.mjs');const paths=await writeReports(run,dirname(input));say(JSON.stringify({id:run.id,status:run.status,...paths},null,2));return exitCodeForRun(run);
    }
    if(command==='bridge'){
      expectCount(positional,1);const {exportBridge}=await import('./bridges.mjs');const directory=await prepareRunDirectory(options.out);say(JSON.stringify(await exportBridge(positional[0],directory),null,2));return 0;
    }
    if(command==='import'){
      expectCount(positional,2);const {importBridge}=await import('./bridges.mjs');const {writeReports}=await import('./reports.mjs');
      const run=await importBridge(positional[0],resolve(positional[1]),resolve(options.target??process.cwd()));const directory=await prepareRunDirectory(options.out);const paths=await writeReports(run,directory);say(JSON.stringify({id:run.id,status:run.status,...paths},null,2));return exitCodeForRun(run);
    }
    expectCount(positional,1);const config=await loadConfig(options.config);
    const timeout=options.timeout===undefined?120:Number(options.timeout);if(!Number.isFinite(timeout)||timeout<=0||timeout>86400)throw new Error('--timeout must be between 0 and 86400 seconds');
    let tools;if(options.tools!==undefined){tools=options.tools.split(',');if(tools.some(id=>!id||id.trim()!==id))throw new Error('--tools requires comma-separated tool IDs');}
    const controller=new AbortController();const cancel=()=>controller.abort();process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
    try{
      const run=await runScan({target:positional[0],ai:options.ai,tools,url:options.url,timeoutMs:timeout*1000,out:options.out,config,signal:controller.signal});
      const {writeReports}=await import('./reports.mjs');const paths=await writeReports(run,run.directory);say(JSON.stringify({id:run.id,status:run.status,findings:run.findings.length,...paths},null,2));return exitCodeForRun(run);
    }finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
  }catch(error){stderr.write(`sec-hub: ${createRedactor()(error.message)}\n`);return 2;}
}
