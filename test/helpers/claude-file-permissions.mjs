// Synthetic boundary evaluator, not a native end-to-end permissions test.
// Contract: official https://code.claude.com/docs/en/permissions and
// https://code.claude.com/docs/en/agent-sdk/permissions; installed Claude
// 2.1.292 SHA256 97a01e5bc74a199e67189435d0331ea3a24eac2e07db4b76d9148c5b0386138f.
// Write.checkPermissions -> shared edit category (offset 187584570); scoped
// Qge selector (offset 187337674, 239B, SHA256
// 74f0f5db0d06e7c26e6e38603474f4f0fa85e979ca4e89264e77de96c566f4b1)
// requires toolName Edit AND defined ruleContent, excluding bare Edit.
// Models only our exact absolute and subtree selectors; no native execution.
const rules=text=>(text??'').split(',').filter(Boolean).map(value=>{const match=/^([^()]+)(?:\((.*)\))?$/.exec(value);if(!match)throw new Error('Unsupported synthetic permission rule');return {tool:match[1],content:match[2]};});
const value=(args,flag)=>args[args.indexOf(flag)+1];
const matches=(pattern,path)=>{
  if(!pattern.startsWith('//')||!path.startsWith('/'))throw new Error('Only absolute synthetic permission rules supported');
  const literal=pattern.slice(1);return literal.endsWith('/**')?path.startsWith(literal.slice(0,-2)):path===literal;
};
export function filePermissionDecision(args,tool,path){
  const deny=rules(value(args,'--disallowedTools')),tools=value(args,'--tools').split(',');
  if(!tools.includes(tool)||deny.some(rule=>rule.tool===tool&&rule.content===undefined))return 'tool-deny';
  const settings=JSON.parse(value(args,'--settings')),category=tool==='Write'?'Edit':tool;
  const scoped=entries=>entries.filter(rule=>rule.tool===category&&rule.content!==undefined);
  if(scoped([...deny,...rules((settings.permissions?.deny??[]).join(','))]).some(rule=>matches(rule.content,path)))return 'path-deny';
  return scoped(rules(value(args,'--allowedTools'))).some(rule=>matches(rule.content,path))?'allow':'no-allow';
}
