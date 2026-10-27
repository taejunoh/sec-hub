/** Redact known inherited secret values; this is not a general secret detector. */
export function createRedactor(env=process.env) {
  const values=Object.entries(env)
    .filter(([key,value])=>/TOKEN|SECRET|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL/i.test(key)&&typeof value==='string'&&value.length>=8)
    .flatMap(([,value])=>[value,JSON.stringify(value).slice(1,-1),encodeURIComponent(value)]);
  const secrets=[...new Set(values)].sort((a,b)=>b.length-a.length);
  return text=>secrets.reduce((value,secret)=>value.split(secret).join('[REDACTED]'),String(text));
}

export function redactValue(value,env=process.env) {
  const redact=createRedactor(env);
  const visit=item=>{
    if(typeof item==='string')return redact(item);
    if(Array.isArray(item))return item.map(visit);
    if(item&&typeof item==='object')return Object.fromEntries(Object.entries(item).map(([key,entry])=>[redact(key),visit(entry)]));
    return item;
  };
  return visit(value);
}
