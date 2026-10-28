import { readFile, stat } from 'node:fs/promises';
import { resolve, join, dirname, isAbsolute } from 'node:path';
import { createRedactor, redactValue } from './redaction.mjs';

const VERSION='0.2.4';
const HELP=`Sec Hub ${VERSION} — local security scanner orchestration

Usage:
  sec-hub doctor [target] [--json] [--config file] [--ai]
  sec-hub scan <target> [--ai] [--tools ids] [--url https://host]
               [--timeout seconds] [--out directory] [--config file]
  sec-hub report <run-directory-or-run.json>
  sec-hub compare BASE CURRENT [--fail-on critical|high|medium|low|info|any|none] [--out NEWDIR]
  sec-hub serve --runs ABS_ROOT [--port 0]
  sec-hub bridge <cloudflare|anthropic> [--out directory]
  sec-hub import <cloudflare|anthropic> <file> [--target path] [--out directory]
  sec-hub --help | --version

Basic scan selects osv and skillspector. AI scanners require --ai and
explicit executable configuration. Cloudflare and Anthropic additionally require
explicit --tools selection. PHP checks require an explicit HTTP(S) URL.
Use doctor to see prerequisites and install guidance; no tools are installed.
Reports include JSON, HTML and SARIF. --out must be an empty directory.
Compare reads two saved runs offline and prints the complete comparison JSON. Its default gate fails on new or regressed high/critical findings; --fail-on may select another severity, any, or none. Incomplete coverage or an unknown relevant severity returns 2.
Scan/report exit codes: 0 complete/no findings; 1 complete/findings; 2 incomplete/error.
Compare exit codes: 0 complete/gate pass; 1 complete/gate violation; 2 invalid input, incomplete scope, or relevant unknown severity.
Serve opens a read-only dashboard on 127.0.0.1. --runs must be an absolute directory; --port is a decimal integer from 0 to 65535 (default 0).
`;
const optionsByCommand={doctor:['json','config','ai'],scan:['ai','tools','url','timeout','out','config'],report:[],compare:['fail-on','out'],serve:['runs','port'],bridge:['out'],import:['target','out']};
const failOnValues=new Set(['critical','high','medium','low','info','any','none']);
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
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
    if(argv[0]==='--version'||argv[0]==='-v'){say(VERSION);return 0;}
    const [command,...args]=argv;if(!Object.hasOwn(optionsByCommand,command))throw new Error(`Unknown command: ${command}`);
    const delimiter=args.indexOf('--');
    if(args.slice(0,delimiter<0?args.length:delimiter).some(arg=>arg==='--help'||arg==='-h')){say(HELP);return 0;}
    const {positional,options}=parseArgs(args,optionsByCommand[command]);
    if(command==='serve'){
      expectCount(positional,0);
      const runs=options.runs;
      if(!runs)throw new Error('serve requires --runs ABS_ROOT');
      if(!isAbsolute(runs))throw new Error('--runs must be an absolute directory path');
      const rootInfo=await stat(runs);
      if(!rootInfo.isDirectory())throw new Error('--runs must point to a directory');
      const portText=options.port??'0';
      if(!/^\d+$/.test(portText)||!Number.isSafeInteger(Number(portText))||Number(portText)>65535)throw new Error('--port must be a decimal integer from 0 to 65535');
      const controller=new AbortController(),cancel=()=>controller.abort();
      process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
      try{
        const {startDashboard}=await import('./dashboard/server.mjs');
        const dashboard=await startDashboard({runs,port:Number(portText),signal:controller.signal});
        say(JSON.stringify({event:'listening',url:dashboard.url,readOnly:true}));
        await dashboard.closed;
        return 0;
      }catch{
        stderr.write('sec-hub: Dashboard server failed.\n');
        return 2;
      }finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
    }
    if(command==='doctor'){
      expectCount(positional,0,1);
      const controller=new AbortController(),cancel=()=>controller.abort();process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
      try{
        const [{doctor},{loadConfig}]=await Promise.all([import('./runner.mjs'),import('./config.mjs')]);
        const data=await doctor({target:positional[0],config:await loadConfig(options.config),ai:options.ai,signal:controller.signal});
        if(options.json)say(JSON.stringify(data,null,2));else{say(`Node ${data.node}; target ${data.target}`);for(const tool of data.tools){say(`${tool.available?'ready':'unavailable'}  ${tool.id}: ${tool.reason??tool.version??tool.name}`);if(!tool.available&&tool.install)say(`  Install: ${typeof tool.install==='string'?tool.install:JSON.stringify(tool.install)}`);}}
        return controller.signal.aborted?2:0;
      }finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
    }
    if(command==='report'){
      expectCount(positional,1);let input=resolve(positional[0]);if((await stat(input)).isDirectory())input=join(input,'run.json');
      const run=validateRun(JSON.parse(await readFile(input,'utf8')));
      const [{writeReports},{exitCodeForRun}]=await Promise.all([import('./reports.mjs'),import('./runner.mjs')]);const paths=await writeReports(run,dirname(input));say(JSON.stringify({id:run.id,status:run.status,...paths},null,2));return exitCodeForRun(run);
    }
    if(command==='compare'){
      expectCount(positional,2);
      const failOn=options['fail-on']??'high';if(!failOnValues.has(failOn))throw new Error('--fail-on must be critical, high, medium, low, info, any, or none');
      const [{readComparisonRun,writeComparisonReports},{compareRuns}]=await Promise.all([import('./comparison-io.mjs'),import('./compare.mjs')]);
      const [baseline,current]=await Promise.all(positional.map(readComparisonRun));
      const compared=compareRuns(baseline.run,current.run,{failOn});
      const result=redactValue({...compared,inputs:{baseline:{file:baseline.file,sha256:baseline.sha256},current:{file:current.file,sha256:current.sha256}}});
      if(options.out!==undefined)await writeComparisonReports(result,resolve(options.out),{inputs:[baseline,current]});
      say(JSON.stringify(stable(result)));
      return result.gate.exitCode;
    }
    if(command==='bridge'){
      expectCount(positional,1);const [{exportBridge},{prepareRunDirectory}]=await Promise.all([import('./bridges.mjs'),import('./runner.mjs')]);const directory=await prepareRunDirectory(options.out);say(JSON.stringify(await exportBridge(positional[0],directory),null,2));return 0;
    }
    if(command==='import'){
      expectCount(positional,2);const [{importBridge},{writeReports},{prepareRunDirectory,exitCodeForRun}]=await Promise.all([import('./bridges.mjs'),import('./reports.mjs'),import('./runner.mjs')]);
      const run=await importBridge(positional[0],resolve(positional[1]),resolve(options.target??process.cwd()));const directory=await prepareRunDirectory(options.out);const paths=await writeReports(run,directory);say(JSON.stringify({id:run.id,status:run.status,...paths},null,2));return exitCodeForRun(run);
    }
    expectCount(positional,1);const [{loadConfig},{runScan,exitCodeForRun}]=await Promise.all([import('./config.mjs'),import('./runner.mjs')]);const config=await loadConfig(options.config);
    const timeout=options.timeout===undefined?120:Number(options.timeout);if(!Number.isFinite(timeout)||timeout<=0||timeout>86400)throw new Error('--timeout must be between 0 and 86400 seconds');
    let tools;if(options.tools!==undefined){tools=options.tools.split(',');if(tools.some(id=>!id||id.trim()!==id))throw new Error('--tools requires comma-separated tool IDs');}
    const controller=new AbortController();const cancel=()=>controller.abort();process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
    try{
      const run=await runScan({target:positional[0],ai:options.ai,tools,url:options.url,timeoutMs:timeout*1000,out:options.out,config,signal:controller.signal});
      const {writeReports}=await import('./reports.mjs');const paths=await writeReports(run,run.directory);say(JSON.stringify({id:run.id,status:run.status,findings:run.findings.length,...paths},null,2));return exitCodeForRun(run);
    }finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
  }catch(error){stderr.write(`sec-hub: ${createRedactor()(error.message)}\n`);return 2;}
}
