import { createHash } from 'node:crypto';
import path from 'node:path';
import { normalizeFindings } from './reports.mjs';

const order = (a,b) => a < b ? -1 : a > b ? 1 : 0;
const rank = {critical:5,high:4,medium:3,low:2,info:1,unknown:0};
const toolStatuses = new Set(['completed','failed','skipped','timed_out','cancelled','imported']);
const canonical = value => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort(order).map(k=>[k,canonical(value[k])]));
  return value;
};
const key = value => JSON.stringify(canonical(value));
const digest = value => createHash('sha256').update(key(value)).digest('hex');
const clean = finding => { const {sources,sourceRecords,...rest}=finding; return canonical(rest); };
const nonempty = x => typeof x==='string' && x.trim().length>0;

function leaves(findings, owner) {
  if (!Array.isArray(findings)) throw new TypeError('findings must be arrays');
  const result=[];
  function visit(f,depth){
    if(depth>16)throw new TypeError('sourceRecords exceeds maximum depth');
    if(!f||typeof f!=='object'||Array.isArray(f))throw new TypeError('finding must be an object');
    if(owner && f.toolId!==owner)throw new TypeError('foreign finding toolId');
    if(f.sourceRecords!==undefined&&!Array.isArray(f.sourceRecords))throw new TypeError('sourceRecords must be an array');
    if(f.sourceRecords?.length){for(const child of f.sourceRecords)visit(child,depth+1);return;}
    if(result.length>=100000)throw new TypeError('findings exceeds maximum leaves');
    result.push(clean(normalizeFindings([f])[0]));
  }
  for(const f of findings)visit(f,0);
  return result;
}
function validate(run) {
  if(!run||run.schemaVersion!==1||!nonempty(run.id)||!['completed','partial','failed'].includes(run.status))throw new TypeError('Invalid v1 run or run status');
  for(const field of ['startedAt','endedAt'])if(!nonempty(run[field])||!Number.isFinite(Date.parse(run[field])))throw new TypeError(`run.${field} must be a valid timestamp`);
  if(!run.target||!nonempty(run.target.path)||!path.posix.isAbsolute(run.target.path)||/[\0\r\n]/.test(run.target.path))throw new TypeError('run target must be an absolute saved path');
  if(!Array.isArray(run.tools))throw new TypeError('run.tools must be an array');
  const tools=new Map(), findings=[];
  for(const t of run.tools){
    if(!t||!nonempty(t.id)||tools.has(t.id)||!toolStatuses.has(t.status))throw new TypeError('Invalid or duplicate tool/status');
    if(t.selected!==undefined&&typeof t.selected!=='boolean')throw new TypeError('tool.selected must be boolean');
    const fs=leaves(t.findings,t.id);
    if(t.selected===false&&(t.status!=='skipped'||t.execution!==undefined||fs.length))throw new TypeError('Unselected tool cannot have execution or findings');
    tools.set(t.id,t);findings.push(...fs);
    if(findings.length>100000)throw new TypeError('findings exceeds maximum leaves');
  }
  const top=leaves(run.findings);
  if(key(top.map(key).sort(order))!==key(findings.map(key).sort(order)))throw new TypeError('run.findings leaf multiset differs from tool findings');
  return {run,tools,findings,target:path.posix.resolve('/',run.target.path)};
}
function locationPath(value,target){
  if(!nonempty(value))return {value:null,unsafe:false};
  const input=value.replaceAll('\\','/');
  const normalized=path.posix.normalize(input);
  if(path.posix.isAbsolute(normalized)){
    const rel=path.posix.relative(target,normalized);
    return {value:rel||'.',unsafe:rel==='..'||rel.startsWith('../')};
  }
  return {value:normalized,unsafe:normalized==='..'||normalized.startsWith('../')};
}
function identity(f,target){
  const loc=f.location??{},p=locationPath(loc.path,target);
  let method,tuple;
  if(p.unsafe){method='weak';tuple=[f.ruleId,f.title];}
  else if(f.toolId==='cloudflare'&&nonempty(f.evidence?.native?.fingerprint)){method='native';tuple=[f.evidence.native.fingerprint,p.value];}
  else if(nonempty(loc.package)&&nonempty(loc.version)){method='dependency';tuple=[loc.package,loc.version,f.vulnerabilityId||f.ruleId,p.value];}
  else if(p.value||nonempty(loc.url)){method='location';tuple=[f.ruleId,p.value,loc.line||null,loc.url||null];}
  else{method='weak';tuple=[f.ruleId,f.title];}
  return {identity:digest([1,f.toolId,method,...tuple]),identityMethod:method,weak:method==='weak',finding:f,content:key(f)};
}
function selected(t){return !!t&&(t.selected===true||(t.selected===undefined&&t.status!=='skipped'));}
function coverageSide(t){return t?canonical({status:t.status,selected:t.selected??(t.status==='skipped'?null:true),...(t.source?{source:t.source}:{}),...(t.version?{version:t.version}:{}),...(t.execution?{execution:t.execution}:{})}):null;}
function incompleteMetadata(value,depth=0){
  if(!value||typeof value!=='object'||depth>16)return false;
  const incomplete=new Set(['partial','incomplete','failed','blocked','deferred','cancelled','timed_out','unknown']);
  return Object.entries(value).some(([field,child])=>
    (['complete','isComplete','is_complete','coverageComplete'].includes(field)&&child===false)||
    (field==='partial'&&child===true)||
    (['status','coverage','scope','completeness','coverageStatus','scopeStatus'].includes(field)&&typeof child==='string'&&incomplete.has(child.toLowerCase()))||
    (child&&typeof child==='object'&&incompleteMetadata(child,depth+1)));
}
function limitations(t){
  if(!t)return ['missing-tool'];
  const reasons=[];
  if(t.selected===undefined&&t.status==='skipped')reasons.push('ambiguous-legacy-selection');
  if(!selected(t))reasons.push('tool-not-selected');
  if(t.status!=='completed')reasons.push(`tool-${t.status}`);
  const e=t.execution??{},mode=e.mode??e.executionMode;
  if(t.id==='php2shell')reasons.push('endpoint-scope-unverifiable');
  else if(t.id==='cloudflare')reasons.push(['official-security-audit-skill','supervised-official-security-audit-skill'].includes(mode)?'quick-profile-partial-coverage':'unknown-scan-contract');
  else if(t.id==='anthropic'){if(mode!=='official-claude-code-vuln-scan')reasons.push('unknown-scan-contract');}
  else if(!['osv','skillspector','codex-security','open-code-review'].includes(t.id))reasons.push('unknown-scan-contract');
  else if(mode!==undefined)reasons.push('unknown-scan-contract');
  if(e.scope==='unknown'||e.coverage==='unknown')reasons.push('unknown-scan-scope');
  if(incompleteMetadata(e)||(Array.isArray(e.limitations)&&e.limitations.some(s=>/partial coverage|incomplete coverage/i.test(s))))reasons.push('explicit-incomplete-coverage');
  return reasons;
}
function conflicts(a,b){
  if(!a||!b)return [];
  const result=[];
  for(const [label,av,bv] of [['source',a.source,b.source],['source',a.execution?.source,b.execution?.source],['mode',a.execution?.mode??a.execution?.executionMode,b.execution?.mode??b.execution?.executionMode],['pin',a.execution?.sourceCommit??a.execution?.revision,b.execution?.sourceCommit??b.execution?.revision]])if(av!==bv&&(av!==undefined||bv!==undefined))result.push(`incompatible-${label}`);
  return result;
}
/** Compare saved v1 claims using exact, versioned identities. New means newly observed,
 * not proven introduced. Advisory alias/version changes and fallback line shifts can
 * produce new and disappeared entries. No native claim is authenticated here. */
export function compareRuns(baseRun,currentRun,{failOn='high'}={}){
  if(!['critical','high','medium','low','info','any','none'].includes(failOn))throw new TypeError('Invalid failOn');
  const base=validate(baseRun),current=validate(currentRun);
  if(base.target!==current.target)throw new TypeError('Comparison target paths differ');
  const ids=new Set([...base.tools.keys(),...current.tools.keys()].filter(id=>selected(base.tools.get(id))||selected(current.tools.get(id))||base.tools.get(id)?.selected===undefined||current.tools.get(id)?.selected===undefined));
  for(const f of [...base.findings,...current.findings])ids.add(f.toolId);
  // Explicitly unselected, empty skipped records do not create requirements.
  for(const id of [...ids])if([base.tools.get(id),current.tools.get(id)].every(t=>!t||(t.selected===false&&t.status==='skipped')))ids.delete(id);
  const coverage=[...ids].sort(order).map(toolId=>{const a=base.tools.get(toolId),b=current.tools.get(toolId);return {toolId,baseline:coverageSide(a),current:coverageSide(b),reasons:[...new Set([...limitations(a).map(r=>`baseline:${r}`),...limitations(b).map(r=>`current:${r}`),...conflicts(a,b)])].sort(order)};});
  const notices=[];
  for(const c of coverage){const a=base.tools.get(c.toolId),b=current.tools.get(c.toolId);if(a?.version!==b?.version&&a?.version&&b?.version)notices.push(`${c.toolId}: scanner versions differ`);if(a?.execution?.backendVersion!==b?.execution?.backendVersion&&a?.execution?.backendVersion&&b?.execution?.backendVersion)notices.push(`${c.toolId}: backend versions differ`);}
  const globalIncomplete=[baseRun,currentRun].some(r=>r.status!=='completed'||r.verificationPassed===false||r.verification?.passed===false||(Array.isArray(r.pendingIntegrations)&&r.pendingIntegrations.length));
  const groups=new Map();
  for(const [side,data] of [['before',base],['after',current]])for(const f of data.findings){const i=identity(f,data.target);if(!groups.has(i.identity))groups.set(i.identity,{before:[],after:[]});groups.get(i.identity)[side].push(i);}
  const entries=[];
  function add(category,before,after){const i=after??before;const reasons=[];if(i.weak)reasons.push('weak-identity');if(category==='new'){reasons.push('newly-observed');reasons.push(...(coverage.find(c=>c.toolId===i.finding.toolId)?.reasons.filter(r=>r.startsWith('baseline:'))??[]));}if(category==='unobserved')reasons.push(...(coverage.find(c=>c.toolId===i.finding.toolId)?.reasons??[]));if(category==='regressed')reasons.push(before.finding.severity==='unknown'||after.finding.severity==='unknown'?'severity-knownness-changed':'severity-increased');entries.push({identity:i.identity,identityMethod:i.identityMethod,category,...(before?{before:before.finding}:{}),...(after?{after:after.finding}:{}),reasons:[...new Set(reasons)].sort(order)});}
  for(const {before,after} of groups.values()){
    before.sort((a,b)=>order(a.content,b.content));after.sort((a,b)=>order(a.content,b.content));
    function pair(test){for(let i=before.length-1;i>=0;i--){const j=after.findIndex(a=>test(before[i],a));if(j<0)continue;const b=before.splice(i,1)[0],a=after.splice(j,1)[0];const bs=b.finding.severity,as=a.finding.severity;add((bs==='unknown')!==(as==='unknown')||rank[as]>rank[bs]?'regressed':'existing',b,a);}}
    pair((b,a)=>b.finding.severity===a.finding.severity&&b.content===a.content);pair((b,a)=>b.finding.severity===a.finding.severity);
    before.sort((a,b)=>rank[b.finding.severity]-rank[a.finding.severity]||order(a.content,b.content));after.sort((a,b)=>rank[b.finding.severity]-rank[a.finding.severity]||order(a.content,b.content));
    while(before.length&&after.length){const b=before.shift(),a=after.shift();add((b.finding.severity==='unknown')!==(a.finding.severity==='unknown')||rank[a.finding.severity]>rank[b.finding.severity]?'regressed':'existing',b,a);}
    for(const b of before)add(!b.weak&&coverage.find(c=>c.toolId===b.finding.toolId)?.reasons.length===0?'resolved':'unobserved',b);
    for(const a of after)add('new',undefined,a);
  }
  entries.sort((a,b)=>order(a.identity,b.identity)||order(a.category,b.category)||order(key(a),key(b)));
  const ordinals=new Map();for(const e of entries){const ordinal=(ordinals.get(e.identity)??0)+1;ordinals.set(e.identity,ordinal);e.id=`cmp-v1-${e.identity}-${ordinal}`;}
  const counts={new:0,regressed:0,existing:0,resolved:0,unobserved:0};for(const e of entries)counts[e.category]++;
  const violations=[],unknown=[];
  for(const e of entries.filter(e=>['new','regressed'].includes(e.category))){const severity=e.after.severity;if(failOn==='none')continue;if(failOn==='any'||(severity!=='unknown'&&rank[severity]>=rank[failOn]))violations.push(e.id);else if(severity==='unknown')unknown.push(e.id);}
  const status=globalIncomplete||coverage.some(c=>c.reasons.length)||entries.some(e=>e.category==='unobserved')?'incomplete':'complete';
  return {schemaVersion:1,kind:'sec-hub.comparison',identityVersion:1,baseline:{id:baseRun.id,target:canonical(baseRun.target),status:baseRun.status,...(baseRun.provenance!==undefined?{provenance:canonical(baseRun.provenance)}:{})},current:{id:currentRun.id,target:canonical(currentRun.target),status:currentRun.status,...(currentRun.provenance!==undefined?{provenance:canonical(currentRun.provenance)}:{})},status,coverage,entries,counts,notices:notices.sort(order),gate:{failOn,violations,unknown,exitCode:status==='incomplete'||unknown.length?2:violations.length?1:0}};
}
