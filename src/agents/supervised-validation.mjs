import { createRequire } from 'node:module';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { atomicWriteFile } from '../safe-io.mjs';
import { nativeOptions, PINS, SOURCES, OUTPUTS, safeRead, sha256, sourceManifest, sameInputs, verifySourcePin, runOfficialValidators } from './validation.mjs';
import { loadCloudflareContracts, buildRolePrompt, supervisedArgs, reconOutputSchema, STRATEGY, LABEL, replayPromptVersion } from './cloudflare-prompts.mjs';
const require=createRequire(import.meta.url),prevalidated=new Map();
const text=s=>typeof s==='string'&&s.trim().length>0;
const clone=x=>JSON.parse(JSON.stringify(x));
// Match the pinned ledger validator's literal JS string comparison, including
// percent-encoded prefixes. Locale collation gives a different punctuation order.
const compareCoverageIds=(a,b)=>a<b?-1:a>b?1:0;
export const stable=x=>JSON.stringify(canonical(x));
function canonical(x){return Array.isArray(x)?x.map(canonical):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;}
function exact(x,keys,label){if(!x||typeof x!=='object'||Array.isArray(x)||stable(Object.keys(x).sort())!==stable([...keys].sort()))throw new Error(`Invalid ${label} contract`);}
export function officialHelpers(c){return {ledger:require(join(c.root,'validate-coverage-ledger.cjs')),findings:require(join(c.root,'validate-findings.cjs'))};}
export function validateLocations(locations,inputs){
  if(!Array.isArray(locations)||!locations.length)throw new Error('Missing grounded source locations');
  for(const loc of locations){const input=inputs.find(x=>x.path===loc?.file);if(!input||!Number.isInteger(loc.line)||loc.line<1||loc.line>input.lines||!text(loc.description))throw new Error('Invalid source path or line bounds');}
}
function reasonCitations(reason,inputs,{rejectBare=false}={}){
  const spans=[];
  const before=ch=>ch===undefined||/[\s`"'([\]{}<>;,]/.test(ch);
  const after=s=>!s||/^[\s`"'()[\]{}<>;,:]/.test(s)||/^\.(?=$|[\s`"'()[\]{}<>;,])/.test(s);
  // Match whole retained paths literally, including spaces and parentheses.
  // A suffix of an absolute, traversal, encoded or otherwise prefixed path
  // cannot supply grounding. Never normalize or resolve citation paths.
  for(const input of inputs){
    const escaped=input.path.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    for(const m of reason.matchAll(new RegExp(`${escaped}:(\\d+(?:[-–—]\\d+)?(?:,\\d+(?:[-–—]\\d+)?)*)`,'g'))){
      if(!before(reason[m.index-1]))continue;
      if(!after(reason.slice(m.index+m[0].length)))throw new Error('Invalid inline source citation');
      if(m[1].match(/\d+/g).some(line=>+line<1||+line>input.lines))throw new Error('Invalid reason source line');
      spans.push([m.index,m.index+m[0].length]);
    }
  }
  // Inspect every remaining explicit citation, even if another one was valid.
  // Covered spans permit filenames with whitespace/delimiters without letting
  // the generic token scanner reinterpret only a suffix of those filenames.
  for(const m of reason.matchAll(/([^\s`"'()[\]{}<>;,]+):(\d+)/g)){
    if(spans.some(([a,b])=>m.index>=a&&m.index+m[0].length<=b))continue;
    const retained=inputs.some(input=>input.path===m[1]);
    if(!retained&&/^\d+$/.test(m[1]))continue;
    // In prose requiring a citation, an unknown bare label (RFC:7231, for
    // example) is ambiguous, not evidence. Only path-shaped unknown tokens
    // are rejected there. Structured paired reasons retain their preexisting
    // stricter rule for all explicit inline tokens. Exact retained bare names
    // (e.g. Dockerfile:1) must pass the full validation above; malformed suffixes
    // cannot turn a retained name into an ignored ambiguous prose label.
    if(!rejectBare&&!retained&&!/[./\\%?]/.test(m[1]))continue;
    throw new Error('Invalid inline source citation');
  }
  return spans.length;
}
function cite(reason,inputs){
  if(!text(reason))throw new Error('Missing grounded reason');
  if(!reasonCitations(reason,inputs))throw new Error('Reason lacks source file:line grounding');
}
function pairedReason(reason,locations,inputs){
  if(!text(reason))throw new Error('Missing grounded reason');
  validateLocations(locations,inputs);
  // These three adapter fields carry their source references in the SAME
  // object's required evidence/grounding array. The official workflow does not
  // require duplicating that reference inside the prose. Explicit inline
  // citations, when present, must still name real files and valid lines.
  reasonCitations(reason,inputs,{rejectBare:true});
}
function validateLedger(ledger,c){const errors=officialHelpers(c).ledger.validateDocument(ledger);if(errors.length)throw new Error(`Official coverage ledger invalid: ${errors.slice(0,3).join('; ')}`);}
export function validateRecords(records,c,inputs){
  const errors=officialHelpers(c).findings.validateDocument(records,JSON.parse(c.docs['report-schema.json']));if(errors.length)throw new Error(`Official findings invalid: ${errors.slice(0,3).join('; ')}`);
  for(const record of records){if(record.verdict==='confirmed')throw new Error('Source-only workflow cannot retain confirmed');validateLocations(record.trace,inputs);validateLocations(record.evidence,inputs);}
}
export function validateRecon(response,role,inputs){
  exact(response,['sections'],'recon');const expected=role==='recon-1c'?['entry-surfaces','transformations-copies-sinks-limits']:Array.from({length:role==='recon-1d'?7:6},(_,i)=>String(i+1));
  if(!Array.isArray(response.sections)||stable(response.sections.map(s=>s.section).sort())!==stable(expected.sort()))throw new Error('Recon omitted or duplicated required sections');
  for(const section of response.sections){exact(section,['section','facts','unknowns'],'recon section');if(!Array.isArray(section.facts)||!Array.isArray(section.unknowns)||!section.facts.length&&!section.unknowns.length||section.unknowns.some(x=>!text(x)))throw new Error('Invalid recon facts/unknowns');if(section.facts.length)validateLocations(section.facts,inputs);for(const f of section.facts)if(!text(f.text))throw new Error('Missing recon factual text');}
}
function semanticUnit(proposed,plan,c,inputs){
  const helpers=officialHelpers(c).ledger,refs=proposed.canonical_refs;
  if(!refs||refs.subsystem!=='profile/quick/all-in-scope-subsystems'||Object.keys(refs).sort().join(',')!=='attack_class,boundary,subsystem,surface')throw new Error('Invalid quick canonical references');
  // Pinned RECONNAISSANCE makes canonical refs authoritative even when display
  // labels change. Require exactly one grounded object of the same kind/ref;
  // retain the model's human labels without rewriting them.
  for(const kind of ['surface','boundary'])if(plan.source_objects.filter(o=>o.kind===kind&&o.ref===refs[kind]).length!==1)throw new Error('Canonical source reference lacks unique planner grounding');
  validateLocations(proposed.grounding,inputs);
  if(!Array.isArray(proposed.starting_paths)||!proposed.starting_paths.length||proposed.starting_paths.some(p=>!helpers.isSafeRelativePath(p)||!inputs.some(x=>x.path===p)))throw new Error('Invalid starting source path');
  const all=new Set(c.catalog.map(b=>b.ref)),selected=[proposed.ordinary_attack_class_block,...proposed.selected_companion_blocks].filter(Boolean);
  if(!Array.isArray(proposed.selected_companion_blocks)||!Array.isArray(proposed.excluded_blocks)||selected.some(b=>!all.has(b))||new Set(selected).size!==selected.length||!selected.includes(refs.attack_class))throw new Error('Invalid assignment attack-class selection');
  if(proposed.ordinary_attack_class_block!==null&&!proposed.ordinary_attack_class_block.startsWith('ATTACK-CLASSES.md#'))throw new Error('Invalid ordinary attack block');
  const attackBlock=c.catalog.find(b=>b.ref===refs.attack_class);if(![attackBlock.ref.split('#')[1],attackBlock.ref].includes(proposed.attack_class))throw new Error('Attack class label differs from exact source block');
  for(const file of new Set(proposed.selected_companion_blocks.map(b=>b.split('#')[0]))){if(!plan.companion_selection.find(s=>s.file===file)?.selected)throw new Error('Companion selected without grounded boundary map');for(const name of ['Core discipline','Universal moves','Validation rules'])if(!selected.includes(`${file}#${name}`))throw new Error('Companion selected without mandatory discipline/moves/validation');}
  const exclusions=new Set();for(const e of proposed.excluded_blocks){exact(e,['block','reason'],'excluded block');if(!all.has(e.block)||selected.includes(e.block)||exclusions.has(e.block))throw new Error('Invalid or duplicate excluded block');cite(e.reason,inputs);exclusions.add(e.block);}
  if(selected.length+exclusions.size!==all.size)throw new Error('Assignment omitted excluded official blocks');
  if(!Number.isInteger(proposed.priority)||proposed.priority<1)throw new Error('Invalid coverage priority');pairedReason(proposed.priority_reason,proposed.grounding,inputs);
  return {coverage_id:helpers.canonicalCoverageId(refs),canonical_refs:clone(refs),...Object.fromEntries(['surface','boundary','subsystem','attack_class','starting_paths','ordinary_attack_class_block','selected_companion_blocks','excluded_blocks'].map(k=>[k,clone(proposed[k])])),prior_status:'none',attempts:[],wave:1,status:'planned',agent_id:null,reviewed_paths:[],local_checks:[],result_fingerprints:[],unresolved:[],planning_grounding:clone(proposed.grounding),priority:proposed.priority,priority_reason:proposed.priority_reason};
}
export function preparePlan(plan,c,inputs,maxAgents,{requireGrouped=false}={}){
  const keys=['architecture','source_objects','companion_selection','units','assignments'];
  exact(plan,[...keys,...(Object.hasOwn(plan??{},'exclusion_catalog')?['exclusion_catalog']:[])],'planner');
  const grouped=Object.hasOwn(plan,'exclusion_catalog');if(requireGrouped&&!grouped)throw new Error('Production planner requires grouped exclusion catalog');
  if(!text(plan.architecture)||plan.architecture.split(/\s+/).length>1100||!Array.isArray(plan.source_objects)||!plan.source_objects.length||!Array.isArray(plan.units)||!plan.units.length||!Array.isArray(plan.assignments)||!plan.assignments.length)throw new Error('Invalid grounded architecture/plan');
  // The optional dictionary is transport compression only. Every unit explicitly
  // selects each model-authored reason; expand to the SAME full semantic map
  // before canonicalization and all existing coverage checks. Preserve raw JSON.
  const exclusions=new Map(),knownBlocks=new Set(c.catalog.map(b=>b.ref));
  if(grouped){
    if(!Array.isArray(plan.exclusion_catalog)||!plan.exclusion_catalog.length)throw new Error('Invalid exclusion catalog');
    for(const entry of plan.exclusion_catalog){exact(entry,['id','blocks','reason'],'exclusion catalog entry');if(typeof entry.id!=='string'||!/^[a-z][a-z0-9_-]{0,63}$/.test(entry.id)||exclusions.has(entry.id)||!Array.isArray(entry.blocks)||!entry.blocks.length||new Set(entry.blocks).size!==entry.blocks.length||entry.blocks.some(block=>!knownBlocks.has(block)))throw new Error('Invalid duplicate exclusion ID/block or unknown block');cite(entry.reason,inputs);exclusions.set(entry.id,entry.blocks.map(block=>({block,reason:entry.reason})));}
  }
  plan=clone(plan);delete plan.exclusion_catalog;
  for(const unit of plan.units){if(!Array.isArray(unit.excluded_blocks))throw new Error('Invalid unit exclusions');unit.excluded_blocks=unit.excluded_blocks.flatMap(entry=>{if(Object.hasOwn(entry??{},'ref')){exact(entry,['ref'],'exclusion reference');if(!exclusions.has(entry.ref))throw new Error('Missing exclusion reference');return clone(exclusions.get(entry.ref));}if(grouped)throw new Error('Grouped planner exclusions must use explicit references');return entry;});}
  cite(plan.architecture,inputs);const seen=new Set();
  for(const o of plan.source_objects){exact(o,['kind','label','ref','evidence'],'source object');if(!['surface','boundary'].includes(o.kind)||!text(o.label)||!text(o.ref)||seen.has(`${o.kind}:${o.label}`))throw new Error('Invalid canonical source object');seen.add(`${o.kind}:${o.label}`);validateLocations(o.evidence,inputs);const path=o.ref.split('#')[0];if(!inputs.some(i=>i.path===path)||!o.ref.includes('#')||!o.evidence.some(e=>e.file===path))throw new Error('Source object reference is not grounded in its source file');}
  if(!Array.isArray(plan.companion_selection)||stable(plan.companion_selection.map(s=>s.file).sort())!==stable(c.companions))throw new Error('Planner omitted companion selection map');
  for(const s of plan.companion_selection){exact(s,['file','selected','reason','evidence'],'companion selection');if(typeof s.selected!=='boolean')throw new Error('Invalid companion selection');pairedReason(s.reason,s.evidence,inputs);}
  const ledger=plan.units.map(p=>semanticUnit(p,plan,c,inputs)).sort((a,b)=>compareCoverageIds(a.coverage_id,b.coverage_id));validateLedger(ledger,c);
  const ids=new Set(),owners=new Set(),helper=officialHelpers(c).ledger;
  const assignments=plan.assignments.map(a=>{exact(a,['id','unit_refs','relation','evidence'],'hunter assignment');if(!helper.isSafeAgentId(a.id)||owners.has(a.id)||!a.id.startsWith('hunter-')||!Array.isArray(a.unit_refs)||!a.unit_refs.length)throw new Error('Invalid hunter owner');owners.add(a.id);pairedReason(a.relation,a.evidence,inputs);const units=a.unit_refs.map(refs=>{const id=helper.canonicalCoverageId(refs),unit=ledger.find(u=>u.coverage_id===id);if(!unit||ids.has(id))throw new Error('Duplicate or foreign hunter assignment');ids.add(id);return unit;});
    // Relationship is semantically grounded by the planner, with mechanical guard
    // against merging unrelated entry/boundary objects solely for agent budget.
    if(new Set(units.map(u=>u.canonical_refs.surface)).size>1&&new Set(units.map(u=>u.canonical_refs.boundary)).size>1)throw new Error('Hunter combines unrelated surfaces and boundaries');
    return {id:a.id,coverageIds:units.map(u=>u.coverage_id).sort(),priority:Math.min(...units.map(u=>u.priority))};
  }).sort((a,b)=>a.priority-b.priority||compareCoverageIds(a.coverageIds[0],b.coverageIds[0]));
  if(ids.size!==ledger.length)throw new Error('Planner silently omitted coverage units');
  const selected=assignments.slice(0,Math.max(0,maxAgents-7)),selectedIds=new Set(selected.flatMap(a=>a.coverageIds));
  for(const u of ledger)if(!selectedIds.has(u.coverage_id)){u.status='deferred';u.unresolved=['budget_cannot_reserve_critics_and_validation'];}
  validateLedger(ledger,c);return {plan:clone(plan),architecture:plan.architecture,ledger,assignments:selected,candidates:new Map(),records:[],hardening:[],critic:null,decisions:[]};
}
export function assignHunter(state,assignment,c){for(const id of assignment.coverageIds){const u=state.ledger.find(u=>u.coverage_id===id);if(u.status!=='planned')throw new Error('Invalid coverage state before assignment');u.status='in_progress';u.agent_id=assignment.id;}validateLedger(state.ledger,c);}
export function applyHunter(state,response,assignment,c,inputs){
  exact(response,['units','candidates','hardening','uncovered'],'hunter');if(!Array.isArray(response.units)||!Array.isArray(response.candidates)||!Array.isArray(response.hardening)||!Array.isArray(response.uncovered)||stable(response.units.map(u=>u.coverage_id).sort())!==stable(assignment.coverageIds))throw new Error('Invalid foreign, absent or duplicate hunter coverage unit');
  const next=clone(state.ledger),localCandidates=new Map();
  for(const candidate of response.candidates){if(candidate.proposed_verdict!=='needs_validation')throw new Error('Source-only candidate must propose needs_validation');const {proposed_verdict,...rest}=candidate,record={verdict:proposed_verdict,...rest};validateRecords([record],c,inputs);if(localCandidates.has(record.fingerprint)||state.candidates.has(record.fingerprint)&&stable(state.candidates.get(record.fingerprint))!==stable(candidate))throw new Error('Conflicting duplicate candidate fingerprint');localCandidates.set(record.fingerprint,candidate);}
  for(const result of response.units){exact(result,['coverage_id','disposition','reviewed_paths','checks','candidate_fingerprints','unresolved'],'hunter unit');const u=next.find(x=>x.coverage_id===result.coverage_id);if(u.agent_id!==assignment.id||u.status!=='in_progress'||!['covered','candidate','blocked'].includes(result.disposition)||!Array.isArray(result.checks)||!result.checks.length)throw new Error('Invalid hunter assignment ownership/state');
    for(const check of result.checks){exact(check,['agent_id','reviewed_paths','invariant','method','result','artifact'],'hunter check');if(check.agent_id!==assignment.id||check.method!=='source'||check.artifact!==null)throw new Error('Invalid source check owner or artifact');for(const p of check.reviewed_paths??[])if(!inputs.some(i=>i.path===p))throw new Error('Invalid reviewed source path');}
    Object.assign(u,{status:result.disposition,reviewed_paths:result.reviewed_paths,local_checks:result.checks,result_fingerprints:result.candidate_fingerprints,unresolved:result.unresolved,hardening:clone(response.hardening)});
    for(const fp of result.candidate_fingerprints)if(!localCandidates.has(fp))throw new Error('Candidate unit fingerprint lacks own candidate');
  }
  for(const fp of localCandidates.keys())if(!response.units.some(u=>u.candidate_fingerprints.includes(fp)))throw new Error('Candidate lacks linked owned unit');
  for(const note of response.hardening){cite(note,inputs);}
  // The native uncovered interface lacks canonical refs. No generic guessed unit
  // may be invented; a fresh counted planner is needed before any continuation.
  if(response.uncovered.length)throw new Error('Hunter uncovered new units require counted grounded planning; run incomplete');
  validateLedger(next,c);state.ledger=next;for(const [fp,record]of localCandidates)state.candidates.set(fp,record);state.hardening.push(...response.hardening);
}
export function applyCritic(state,response,c,inputs){
  exact(response,['missing_units','reassign_ids','resolved_prior_leads','stop'],'critic');if(!Array.isArray(response.missing_units)||!Array.isArray(response.reassign_ids)||!Array.isArray(response.resolved_prior_leads)||typeof response.stop!=='boolean'||response.stop&&(response.missing_units.length||response.reassign_ids.length))throw new Error('Invalid critic response');
  state.critic=clone(response);
  if(response.resolved_prior_leads.length)throw new Error('Critic resolved absent prior leads');
  if(response.reassign_ids.length)throw new Error('Critic reassignment lacks native source-backed reason; counted planner required; incomplete');
  for(const gap of response.missing_units){exact(gap,['surface','boundary','subsystem','attack_class','starting_paths','selected_companion_blocks','excluded_blocks','reason'],'critic missing unit');cite(gap.reason,inputs);const surfaces=state.plan.source_objects.filter(o=>o.kind==='surface'&&(o.label===gap.surface||o.ref===gap.surface)),boundaries=state.plan.source_objects.filter(o=>o.kind==='boundary'&&(o.label===gap.boundary||o.ref===gap.boundary)),blocks=c.catalog.filter(b=>b.ref===gap.attack_class||b.ref.split('#')[1]===gap.attack_class);if(surfaces.length!==1||boundaries.length!==1||blocks.length!==1)throw new Error('Critic missing unique canonical identity grounding; incomplete');const [surface]=surfaces,[boundary]=boundaries,[block]=blocks;
    const proposed={...gap,canonical_refs:{surface:surface.ref,boundary:boundary.ref,subsystem:'profile/quick/all-in-scope-subsystems',attack_class:block.ref},ordinary_attack_class_block:block.file==='ATTACK-CLASSES.md'?block.ref:null,grounding:[...surface.evidence,...boundary.evidence],priority:1,priority_reason:gap.reason},u=semanticUnit(proposed,state.plan,c,inputs);
    if(state.ledger.some(x=>x.coverage_id===u.coverage_id))throw new Error('Critic proposed duplicate canonical unit');u.status='deferred';u.unresolved=['quick_profile_final_critic',gap.reason];state.ledger.push(u);
  }
  state.ledger.sort((a,b)=>compareCoverageIds(a.coverage_id,b.coverage_id));validateLedger(state.ledger,c);
}
export function applyVerifier(state,response,fingerprint,c,inputs,agentId){
  exact(response,['decision','record'],'verifier');if(!['needs_validation','rejected'].includes(response.decision)||response.record?.verdict!==response.decision||response.record.fingerprint!==fingerprint||!state.candidates.has(fingerprint))throw new Error('Invalid independent verifier fingerprint/decision');validateRecords([response.record],c,inputs);
  if(state.records.some(r=>r.fingerprint===fingerprint))throw new Error('Duplicate final independent verdict');
  state.records.push(clone(response.record));state.records.sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint));state.decisions.push({fingerprint,agentId,decision:response.decision});
  for(const u of state.ledger.filter(u=>u.result_fingerprints.includes(fingerprint))){u.independent_decisions??=[];u.independent_decisions.push({fingerprint,agent_id:agentId,decision:response.decision});}
  validateLedger(state.ledger,c);
}
export function renderSupervisedReports(state,metadata){
  const records=state?.records??[],ledger=state?.ledger??[],unvalidated=[...(state?.candidates?.keys()??[])].filter(fp=>!records.some(r=>r.fingerprint===fp)),needs=records.filter(r=>r.verdict==='needs_validation'),counts=Object.fromEntries(['covered','candidate','blocked','deferred','out_of_scope','not_applicable','planned','in_progress'].map(s=>[s,ledger.filter(u=>u.status===s).length]));
  const lines=r=>r.trace.map(l=>`${l.file}:${l.line} (${l.kind}) ${l.description}`).join('; '),table=needs.length?'| Title | Trace | Blocker | Local plan | Owner-observed deployment plan |\n| --- | --- | --- | --- | --- |\n'+needs.map(r=>[r.title,lines(r),r.blockers.join('; '),r.validation_plan.local??'Not applicable',r.validation_plan.deployment??'Not applicable'].map(s=>String(s).replaceAll('|','\\|').replaceAll('\n',' ')).join(' | ')).map(s=>'| '+s+' |').join('\n'):'No independently retained needs_validation records.';
  const pending=unvalidated.length?unvalidated.map(fp=>`- ${fp}: ${ledger.filter(u=>u.result_fingerprints.includes(fp)).map(u=>u.coverage_id).join(', ')}`).join('\n'):'None.';
  const report=`# ${LABEL}\n\nAdapted delegation strategy; no vendor certification is claimed.\n\nProfile: quick. This is a partial pass. Scope: all ${metadata.scope_paths.length} retained source files. Source ref: ${metadata.source_ref}. Execution: sandboxed-source-and-local-only; this adapter performed source review only and no target-controlled execution, installation, deployment probing or patches. Prior runs: none supplied. Agents spent ${metadata.budget.spent} of ${metadata.budget.max_agents}; baseline reserved minimum8. Status: ${metadata.run_status}${metadata.incomplete_reason?`; ${metadata.incomplete_reason}`:''}.\n\n## Security posture\n\n${records.length} independently decided records; ${unvalidated.length} unvalidated ledger candidates. Source-only review cannot establish a confirmed vulnerability or deployment posture.\n\n## Confirmed findings\n\n| Severity | Title | Boundary | Observed result |\n| --- | --- | --- | --- |\n\nNone: target execution was not authorized.\n\n## NEEDS VALIDATION\n\n${table}\n\n## Unvalidated ledger candidates (not findings)\n\n${pending}\n\n## Hardening notes\n\n${(state?.hardening??[]).map(n=>'- '+n).join('\n')||'None returned.'}\n\n## Positive source patterns\n\n${ledger.filter(u=>u.status==='covered').flatMap(u=>u.local_checks.map(check=>'- '+check.result)).join('\n')||'No positive source pattern retained.'}\n\n## Coverage\n\n${JSON.stringify(counts)}\n\nDeferred/out-of-scope units:\n${ledger.filter(u=>['deferred','out_of_scope','blocked'].includes(u.status)).map(u=>`- ${u.coverage_id}: ${u.unresolved.join('; ')}`).join('\n')||'None.'}\n\nFinal critic:\n\n\`\`\`json\n${JSON.stringify(state?.critic??null,null,2)}\n\`\`\`\n\nExplicit exclusions:\n${ledger.flatMap(u=>u.excluded_blocks.map(e=>`- ${u.coverage_id}: ${e.block}: ${e.reason}`)).join('\n')||'No coverage map established.'}\n`;
  const unresolved=needs.map(r=>`## ${r.title}\n\nFingerprint: ${r.fingerprint}\n\nClaimed root cause: ${r.claimed_root_cause}\n\nTrace: ${lines(r)}\n\nEvidence:\n${r.evidence.map(e=>`- ${e.file}:${e.line}: ${e.description}`).join('\n')}\n\nExact blockers:\n${r.blockers.map(b=>'- '+b).join('\n')}\n\n${r.validation_plan.local?`Bounded local plan: ${r.validation_plan.local}\n\n`:''}${r.validation_plan.deployment?`Owner-observed deployment plan: ${r.validation_plan.deployment}\n\n`:''}`).join('\n');
  const provenance=metadata.preparation?`## Preparation provenance\n\nReused ${metadata.preparation.charged_agents} successful native preparation role completions from ${metadata.preparation.source_manifest} (SHA256 ${metadata.preparation.source_manifest_sha256}). The source run remains ${metadata.preparation.source_status}; its host sorting failure is not promoted to audit completion. This run spawned ${metadata.budget.new_agents} fresh downstream native processes and charges ${metadata.budget.spent} cumulative invocations, including the five reused roles. No preparation model call was simulated or repeated.\n\n`:'';
  return {'REPORT.md':provenance?report.replace('## Security posture',provenance+'## Security posture'):report,'FINDINGS-DETAIL.md':'# Confirmed finding details\n\nNo confirmed medium, high or critical records. Source-only review did not execute target code.\n','NEEDS-VALIDATION.md':`# Needs validation\n\n${unresolved||'No independently retained unresolved records.\n'}\n## Unvalidated ledger candidates (not findings)\n\n${pending}\n`};
}

function shellCommand(command){
  if(!/^\/(?:bin|usr\/bin)\/(?:zsh|bash|sh) -l?c /.test(command))return command;
  // Codex renders argv using POSIX shell quoting, not JSON string quoting.
  // Decode only literal words and exactly one known shell -c argument. No
  // evaluation or shell execution occurs; the decoded command must still pass
  // the independent bounded-reader grammar below.
  const words=[];let word='',quote=null,started=false;
  for(let i=0;i<command.length;i++){
    const ch=command[i];if(/[\x00-\x1f\x7f]/.test(ch))return command;
    if(quote==="'"){if(ch==="'")quote=null;else word+=ch;continue;}
    if(quote==='"'){
      if(ch==='"'){quote=null;continue;}
      if(ch==='\\'){const next=command[++i];if(next===undefined)return command;if('\\"$`'.includes(next))word+=next;else word+='\\'+next;continue;}
      if(ch==='$'||ch==='`')return command;word+=ch;continue;
    }
    if(ch==="'"||ch==='"'){quote=ch;started=true;continue;}
    if(ch==='\\'){const next=command[++i];if(next===undefined||/[\x00-\x1f\x7f]/.test(next))return command;word+=next;started=true;continue;}
    if(/[;&|<>`$]/.test(ch))return command;
    if(/\s/.test(ch)){if(started){words.push(word);word='';started=false;}continue;}
    word+=ch;started=true;
  }
  if(quote)return command;if(started)words.push(word);
  return words.length===3&&/^\/(?:bin|usr\/bin)\/(?:zsh|bash|sh)$/.test(words[0])&&['-c','-lc'].includes(words[1])?words[2]:command;
}
function sourceReader(command,expected){
  // A deliberately small literal shell grammar, without expansion, redirection,
  // command composition, executors or source-controlled helper programs.
  const words=[];let word='',quote=null,started=false;
  for(let i=0;i<command.length;i++){const ch=command[i];if(/[\n\r\0]/.test(ch))return false;if(quote){if(ch===quote){quote=null;continue;}if(quote==='"'&&(ch==='$'||ch==='`'||ch==='\\'))return false;word+=ch;continue;}if(ch==='"'||ch==="'"){quote=ch;started=true;continue;}if(/[;&|<>`$\\]/.test(ch))return false;if(/\s/.test(ch)){if(started){words.push(word);word='';started=false;}continue;}word+=ch;started=true;}
  if(quote)return false;if(started)words.push(word);const tool=words.shift();if(!['cat','rg','sed','head','tail','wc','ls'].includes(tool))return false;
  const confined=p=>{if(!p||/[\x00-\x1f*?\[\]{}~]/.test(p))return false;const absolute=resolve(expected.context.runner??'/',p),rel=relative(expected.context.target,absolute);return rel===''||!rel.startsWith('..')&&!isAbsolute(rel)||expected.readFiles.includes(absolute);};
  const safeCount=value=>/^\d+$/.test(value??'')&&Number.isSafeInteger(Number(value));
  if(tool==='sed')return words[0]==='-n'&&/^\d+(?:,\d+)?p$/.test(words[1]??'')&&words.length>2&&words.slice(2).every(p=>!p.startsWith('-')&&confined(p));
  const paths=[];let pattern=tool!=='rg',files=false;
  for(let i=0;i<words.length;i++){const w=words[i];if(w==='--'){if(tool==='rg'&&!pattern&&!files){if(++i>=words.length)return false;pattern=true;}paths.push(...words.slice(i+1));break;}
    if(w.startsWith('-')){if(tool==='rg'){if(w==='--files'){files=true;continue;}if(['-e','--regexp'].includes(w)){if(!words[++i])return false;pattern=true;continue;}if(['--glob','-g','--max-count','-m'].includes(w)){if(!words[++i])return false;continue;}if(!['-n','--line-number','-l','--files-with-matches','-i','-s','-F','--fixed-strings','--hidden','--no-ignore','--count','-c','-U','--multiline'].includes(w))return false;}
      else if(tool==='head'&&/^-\d+$/.test(w)){if(!safeCount(w.slice(1)))return false;}
      else if(['head','tail'].includes(tool)&&['-n','-c'].includes(w)){if(!safeCount(words[++i]))return false;}
      else if(!({cat:['-n','-b'],wc:['-l','-c','-w'],ls:['-l','-a','-la','-al','-R'],head:[],tail:[]}[tool]??[]).includes(w))return false;
      continue;
    }
    if(tool==='rg'&&!pattern&&!files){pattern=true;continue;}paths.push(w);
  }
  return paths.length>0&&paths.every(confined);
}
export function assertObservedPolicy(event,expected){
  if(!['item.started','item.updated','item.completed'].includes(event.type)||!event.item)return;
  const item=event.item;
  const policyError=message=>{const error=new Error(message);error.fatalPolicy=true;return error;};
  if(!['reasoning','command_execution','agent_message'].includes(item.type))throw policyError('Nested delegation or unsupported native tool is prohibited');
  if(item.type==='command_execution'&&item.command&&!expected.readCommands.includes(shellCommand(item.command))&&!sourceReader(shellCommand(item.command),expected))throw policyError('Native source-only command policy violation');
}
export function inspectRoleEvidence(events,record,expected,c){
  const starts=events.filter(e=>e.type==='thread.started'),completed=events.filter(e=>e.type==='item.completed').map(e=>e.item),messages=completed.filter(i=>i?.type==='agent_message');
  // Evaluate all observed tool intent before terminal classification. A failed
  // turn must never disguise a forbidden attempted read or executor as retryable.
  for(const event of events)assertObservedPolicy(event,expected);
  if(record.exitCode!==0||record.interrupted||record.outputLimitExceeded||events.some(e=>['error','turn.failed'].includes(e.type))||events.filter(e=>e.type==='turn.completed').length!==1||starts.length!==1||!text(starts[0].thread_id))throw new Error('Native role did not complete successfully');
  if(completed.some(i=>!['reasoning','command_execution','agent_message'].includes(i?.type)))throw new Error('Nested delegation or unsupported native tool is prohibited');
  const commands=completed.filter(i=>i?.type==='command_execution');
  for(let i=0;i<expected.readFiles.length;i++){const read=commands[i],expectedOutput=c.docs[relative(c.root,expected.readFiles[i])];if(!read||shellCommand(read.command??'')!==expected.readCommands[i]||read.status!=='completed'||read.exit_code!==0||read.aggregated_output!==expectedOutput)throw new Error('Native first pinned instruction read differs');}
  // Read-only CLI sandbox plus prompt restrictions; recorded command stream must
  // contain only bounded source readers. Reject shell composition and executors.
  for(const command of commands.slice(expected.readFiles.length))if(!sourceReader(shellCommand(command.command??''),expected))throw new Error('Native source-only command policy violation');
  if(!messages.length||!text(messages.at(-1).text))throw new Error('Native final agent_message missing');let response;try{response=JSON.parse(messages.at(-1).text);}catch{throw new Error('Invalid strict native final JSON; no repairs permitted');}
  if(!response||typeof response!=='object'||Array.isArray(response))throw new Error('Native response must be JSON object');
  return {response,threadId:starts[0].thread_id,finalText:messages.at(-1).text};
}

export async function validateSupervisedCloudflare(ctx){
  const cfg=ctx.config?.tools?.cloudflare,options=nativeOptions('cloudflare',cfg?.agentOptions),manifestBytes=await safeRead(join(ctx.artifactDir,'execution-manifest.json')),m=JSON.parse(manifestBytes),reasons=[];
  if(options.strategy!==STRATEGY||m.schema!=='sec-hub.native-agent/v1'||m.id!=='cloudflare'||m.strategy!==STRATEGY||m.source!==SOURCES.cloudflare||m.sourceCommit!==PINS.cloudflare||resolve(m.target??'')!==resolve(ctx.target)||m.model!==options.model||m.backend!=='codex'||m.mode!=='supervised-official-security-audit-skill'||!Array.isArray(m.roles)||m.roles.length>options.maxAgents||!Array.isArray(m.inputs)||!m.inputs.length)throw new Error('Invalid supervised native manifest/configuration');
  if(m.invocation?.command!==cfg.command||!sameInputs(m.invocation.args,cfg.args??[])||!isAbsolute(m.nativeNodeExecutable??'')||Number.parseInt(m.nativeNodeVersion)<22||!text(m.backendVersion))throw new Error('Native supervised backend configuration differs');
  const promptVersion=replayPromptVersion(m);
  const pin=await verifySourcePin('cloudflare',options);if(!sameInputs(pin,m.instructions))throw new Error('Pinned instructions differ');
  if(!sameInputs(await sourceManifest(ctx.target),m.inputs)||!sameInputs(m.inputs,m.copyBefore)||!sameInputs(m.inputs,m.copyAfter)||!sameInputs(m.inputs,m.originalAfter))throw new Error('Source preservation failed');
  const c=await loadCloudflareContracts(options.skillRoot),hashes={};
  if(!Array.isArray(m.retainedFiles)||new Set(m.retainedFiles).size!==m.retainedFiles.length||OUTPUTS.cloudflare.some(f=>!m.retainedFiles.includes(f)))throw new Error('Invalid retained evidence file list');
  for(const name of m.retainedFiles){if(!officialHelpers(c).ledger.isSafeRelativePath(name))throw new Error('Invalid evidence path');hashes[name]=sha256(await safeRead(join(ctx.artifactDir,name)));}
  const sealed=m.finalRetainedHashes??m.preRedactionHashes;if(!sealed||stable(hashes)!==stable(sealed))throw new Error('Retained supervised evidence hashes differ');
  let preparation=null;
  if(options.preparationFrom||m.preparation){if(!options.preparationFrom||!m.preparation)throw new Error('Preparation configuration and receipt must match');const {validateCloudflarePreparation}=await import('./cloudflare-preparation.mjs');preparation=await validateCloudflarePreparation(m.preparation,{...ctx,nativeNodeExecutable:m.nativeNodeExecutable,nativeNodeVersion:m.nativeNodeVersion},options);if(m.backendVersion!==preparation.receipt.backendVersion)throw new Error('Native preparation backend version differs');for(const file of preparation.retainedFiles)if(!m.retainedFiles.includes(file))throw new Error('Preparation snapshot is missing from retained evidence');}
  const charged=preparation?.receipt.chargedAgents??0;if(charged+m.roles.length>options.maxAgents)throw new Error('Cumulative preparation budget exceeded');
  const threads=new Set(preparation?.threadIds??[]),recon=preparation?preparation.recon.map((response,i)=>({role:['recon-1a','recon-1b','recon-1c','recon-1d'][i],response})):[],hunterRecords=[],verifierRecords=[];let state=preparation?.state??null,plannerSeen=!!preparation,criticSeen=false,lastPhase=preparation?1:-1,hunterWaveLedger=null;
  const phases={'recon-1a':0,'recon-1b':0,'recon-1c':0,'recon-1d':0,planner:1,hunter:2,critic:3,verifier:4};
  for(const r of m.roles){
    const phase=phases[r.role];if(phase===undefined||phase<lastPhase)throw new Error('Supervised phase order differs');lastPhase=phase;
    if(preparation&&(phase<2||preparation.receipt.roles.some(old=>[old.agentId,old.ownerId].includes(r.agentId)||[old.agentId,old.ownerId].includes(r.ownerId))))throw new Error('Preparation continuation must use fresh downstream role identities only');
    if(!officialHelpers(c).ledger.isSafeAgentId(r.agentId)||!Number.isInteger(r.pid)||r.pid<1||!Number.isFinite(Date.parse(r.startedAt))||!Number.isFinite(Date.parse(r.endedAt))||Date.parse(r.endedAt)<Date.parse(r.startedAt))throw new Error('Invalid native process evidence');
    const base=`roles/${r.agentId}`;for(const name of ['prompt.txt','events.jsonl','stderr.log','response.json'])if(!m.retainedFiles.includes(`${base}/${name}`))throw new Error('Native role evidence missing');
    let context={role:r.role,agentId:r.ownerId??r.agentId,target:m.copyTarget,runner:m.runner};
    if(r.role.startsWith('recon-')){if(recon.some(x=>x.role===r.role))throw new Error('Duplicate baseline recon');}
    else if(r.role==='planner'){if(recon.length!==4||plannerSeen)throw new Error('Planner phase order invalid');plannerSeen=true;context.recon=[...recon].sort((a,b)=>a.role.localeCompare(b.role)).map(x=>x.response);}
    else {if(!state)throw new Error('Missing grounded planner');context={...context,architecture:state.architecture,ledger:clone(state.ledger),plan:state.plan,fingerprints:[...state.candidates.keys()].sort()};
      if(r.role==='hunter'){if(criticSeen)throw new Error('Hunter after critic');const a=state.assignments.find(a=>a.id===r.ownerId);if(!a||hunterRecords.some(x=>x.ownerId===r.ownerId))throw new Error('Foreign/duplicate hunter assignment');if(!hunterRecords.length){for(const assignment of state.assignments)assignHunter(state,assignment,c);hunterWaveLedger=clone(state.ledger);}context.ledger=clone(hunterWaveLedger);context.units=context.ledger.filter(u=>a.coverageIds.includes(u.coverage_id));hunterRecords.push(r);}
      if(r.role==='critic'){if(criticSeen||hunterRecords.length!==state.assignments.length)throw new Error('Exactly one critic must follow every hunter');criticSeen=true;}
      if(r.role==='verifier'){if(!criticSeen||!state.candidates.has(r.fingerprint))throw new Error('Verifier phase/fingerprint invalid');context.candidate=state.candidates.get(r.fingerprint);context.units=state.ledger.filter(u=>u.result_fingerprints.includes(r.fingerprint));context.checks=context.units.flatMap(u=>u.local_checks);verifierRecords.push(r);}
    }
    const expected=buildRolePrompt(c,context,promptVersion),schema=reconOutputSchema(r.role),schemaFile=schema?`${base}/output-schema.json`:null,schemaText=schema?JSON.stringify(schema,null,2)+'\n':null;
    if(schema){const schemaMeta={file:schemaFile,sha256:sha256(schemaText),bytes:Buffer.byteLength(schemaText)};if(stable(r.outputSchema)!==stable(schemaMeta)||!m.retainedFiles.includes(schemaFile)||(await safeRead(resolve(ctx.artifactDir,schemaFile))).toString()!==schemaText)throw new Error('Native recon output schema differs from trusted contract');}else if(r.outputSchema!==undefined)throw new Error('Unexpected output schema on non-recon role');
    const args=[...(cfg.args??[]),...supervisedArgs(m.runner,options,m.nativeNodeExecutable,schemaFile?resolve(ctx.artifactDir,schemaFile):null)];
    if(r.command!==cfg.command||stable(r.args)!==stable(args)||r.cwd!==m.runner||r.promptSha256!==sha256(expected.prompt)||r.promptBytes!==Buffer.byteLength(expected.prompt)||stable(r.sourceBlocks)!==stable(expected.sourceBlocks)||(await safeRead(join(ctx.artifactDir,base,'prompt.txt'))).toString()!==expected.prompt)throw new Error(`Native ${r.role} invocation/prompt differs from trusted reconstruction`);
    let events;try{events=(await safeRead(join(ctx.artifactDir,base,'events.jsonl'))).toString().split('\n').filter(x=>x.trim()).map(x=>JSON.parse(x));}catch{throw new Error('Invalid native JSONL evidence');}const starts=events.filter(e=>e.type==='thread.started');
    if(starts.length===1){if(threads.has(starts[0].thread_id)||r.threadId!==starts[0].thread_id)throw new Error('Native fresh thread reuse/identity violation');threads.add(starts[0].thread_id);}
    const rawFinal=events.filter(e=>e.type==='item.completed'&&e.item?.type==='agent_message').at(-1)?.item.text;
    if((await safeRead(join(ctx.artifactDir,base,'response.json'))).toString()!==(typeof rawFinal==='string'?rawFinal:'null'))throw new Error('Native final message differs from retained exact response');
    let proof;try{proof=inspectRoleEvidence(events,r,expected,c);}catch(error){if(r.accepted!==false)throw error;if(r.role!=='verifier'||error.fatalPolicy)reasons.push(error.message);continue;}
    if(r.accepted===false){if(r.role!=='verifier')reasons.push(r.failure??'Rejected native role');continue;}
    if(r.role.startsWith('recon-')){validateRecon(proof.response,r.role,m.inputs);recon.push({role:r.role,response:proof.response});}
    if(r.role==='planner')state=preparePlan(proof.response,c,m.inputs,options.maxAgents,{requireGrouped:true});
    if(r.role==='hunter')applyHunter(state,proof.response,state.assignments.find(a=>a.id===r.ownerId),c,m.inputs);
    if(r.role==='critic')applyCritic(state,proof.response,c,m.inputs);
    if(r.role==='verifier')applyVerifier(state,proof.response,r.fingerprint,c,m.inputs,r.ownerId);
  }
  // Concurrent recon/hunter intervals must finish before the next phase starts.
  const timedRoles=[...(preparation?.receipt.roles??[]),...m.roles];
  for(let phase=1;phase<=4;phase++){const before=timedRoles.filter(r=>phases[r.role]<phase),after=m.roles.filter(r=>phases[r.role]===phase);if(before.length&&after.some(r=>Date.parse(r.startedAt)<Math.max(...before.map(x=>Date.parse(x.endedAt)))))throw new Error('Native process phase order overlap');}
  if(recon.length!==4||!plannerSeen||!state||!criticSeen||!hunterRecords.length||state.records.length!==state.candidates.size)reasons.push('Mandatory supervised graph or independent dispositions incomplete');
  const ledger=JSON.parse(await safeRead(join(ctx.artifactDir,'coverage-ledger.json'))),records=JSON.parse(await safeRead(join(ctx.artifactDir,'findings.json'))),metadata=JSON.parse(await safeRead(join(ctx.artifactDir,'run-metadata.json')));
  if(state&&(stable(ledger)!==stable(state.ledger)||stable(records)!==stable(state.records)||(await safeRead(join(ctx.artifactDir,'architecture.md'))).toString()!==state.architecture))throw new Error('Parent canonical artifacts differ from unchanged native decisions/ledger replay');
  validateRecords(records,c,m.inputs);const validators=await runOfficialValidators(options,ctx.artifactDir);if(validators.some(v=>v.exitCode!==0))reasons.push('Official validator failed');
  if(metadata.profile!=='quick'||metadata.execution_policy!=='sandboxed-source-and-local-only'||metadata.budget?.spent!==charged+m.roles.length||metadata.budget?.max_agents!==options.maxAgents||metadata.run_status!=='complete')reasons.push('Official metadata incomplete');
  if(preparation){const expected={source_manifest:m.preparation.sourceManifestPath,source_manifest_sha256:m.preparation.sourceManifestSha256,source_status:m.preparation.sourceStatus,charged_agents:charged};if(stable(metadata.preparation)!==stable(expected)||metadata.budget.reused_agents!==charged||metadata.budget.new_agents!==m.roles.length)throw new Error('Preparation provenance or cumulative budget metadata differs');}else if(metadata.preparation!==undefined)throw new Error('Unexpected preparation metadata');
  if(metadata.repo!==resolve(ctx.target)||metadata.target!==m.copyTarget||metadata.strategy!==STRATEGY||metadata.source_ref!==`sha256:${sha256(JSON.stringify(m.inputs))}`||stable(metadata.scope_paths)!==stable(m.inputs.map(i=>i.path))||stable(metadata.prior_run_paths)!=='[]'||metadata.budget?.planned_minimum!==8||stable(metadata.shared_file_owners)!==stable(Object.fromEntries(OUTPUTS.cloudflare.map(f=>[f,'trusted-supervisor'])))||state&&stable(metadata.selected_companion_files)!==stable(state.plan.companion_selection.filter(s=>s.selected).map(s=>s.file)))throw new Error('Official run metadata differs from reconstructed source/scope/ownership');
  for(const [name,expected]of Object.entries(renderSupervisedReports(state,metadata)))if((await safeRead(join(ctx.artifactDir,name))).toString()!==expected)throw new Error('Deterministic report differs from final evidence');
  if(ctx.exitCode!==0||m.status!=='complete')reasons.push(...(m.reasons?.length?m.reasons:['Supervised wrapper incomplete']));
  const findings=records.filter(r=>r.verdict!=='rejected').map(r=>({toolId:'cloudflare',ruleId:r.fingerprint,title:r.title,description:r.description,severity:'unknown',verification:'candidate',location:{path:r.trace[0].file,line:r.trace[0].line},evidence:{native:r,dynamicVerification:'not-performed'},rawRef:join(ctx.artifactDir,'findings.json')}));
  const execution={mode:'supervised-official-security-audit-skill',strategy:STRATEGY,label:LABEL,adapted:true,backend:'codex',sourceCommit:PINS.cloudflare,source:SOURCES.cloudflare,model:m.model,backendVersion:m.backendVersion,manifestPath:join(ctx.artifactDir,'execution-manifest.json'),dynamicVerification:'not-performed',limitations:['Adapted agent-neutral delegation; no vendor certification.','Source-only; target execution was not authorized.','Quick profile is partial coverage.','Global AGENTS may remain model-visible; explicit developer role authority overrides conflicting directives and auto skill instructions are suppressed.'],nativeEvidence:{roles:m.roles.map(r=>({role:r.role,agentId:r.agentId,pid:r.pid,threadId:r.threadId,accepted:r.accepted})),spawnCount:m.roles.length,chargedAgentCount:charged+m.roles.length,reusedPreparationAgents:charged,preparation:m.preparation??null,independentRecords:state?.decisions??[],redactedNativeProvenance:!!m.finalRetainedHashes},validators,retainedHashes:hashes,hashScope:m.finalRetainedHashes?'retained bytes after redaction':'native retained bytes before redaction',sourcePreserved:true};
  if(reasons.length){const error=new Error(`cloudflare: supervised workflow incomplete: ${[...new Set(reasons)].join('; ')}`);error.findings=findings;error.execution=execution;throw error;}
  if(!m.finalRetainedHashes)prevalidated.set(resolve(ctx.artifactDir),sha256(manifestBytes));return {findings,execution};
}
export async function finalizeSupervisedCloudflare(ctx){
  const file=join(ctx.artifactDir,'execution-manifest.json'),bytes=await safeRead(file);if(prevalidated.get(resolve(ctx.artifactDir))!==sha256(bytes))throw new Error('Supervised execution was not validated before redaction or manifest changed');
  const m=JSON.parse(bytes),hashes={};for(const name of m.retainedFiles)hashes[name]=sha256(await safeRead(join(ctx.artifactDir,name)));m.finalRetainedHashes=hashes;m.finalHashScope='retained bytes after redaction; native provenance may be redacted';
  await atomicWriteFile(file,JSON.stringify(m,null,2)+'\n');prevalidated.delete(resolve(ctx.artifactDir));return validateSupervisedCloudflare(ctx);
}
