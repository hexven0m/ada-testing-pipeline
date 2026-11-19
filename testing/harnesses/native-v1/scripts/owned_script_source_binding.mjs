/** Independently bind parsed source from the current owned main document.
 * Only used when response-body retrieval did not produce a hash. A known
 * mismatch never falls back. This does not execute, wrap or replace a detector.
 */
import {createHash} from 'node:crypto';
const paths={'headless.js':'/static/detections/headless.js',preload:'/static/js/user-agent-spoof.js'};
export async function bindOwnedScriptSources({send,scripts,contexts,mainFrame,origin,expected,hashes,methods,waitMs=2500}) {
  const names=Object.keys(paths);
  for(const name of names){
    if(!/^[a-f0-9]{64}$/.test(expected[name]||''))throw Error('detector-source-unverified');
    if(hashes[name]&&hashes[name]!==expected[name])throw Error('detector-source-unverified');
    if(hashes[name])methods[name]='network-response-body';
  }
  const main=[...contexts.entries()].filter(([,ctx])=>ctx.frameId===mainFrame&&ctx.isDefault===true);
  if(main.length!==1||typeof main[0][1].uniqueId!=='string'||!main[0][1].uniqueId)throw Error('detector-source-unverified');
  const [contextId,context]=main[0];
  const selected=new Map();
  function live(){
    const now=contexts.get(contextId);
    if(!now||now.uniqueId!==context.uniqueId||now.frameId!==mainFrame||now.isDefault!==true)throw Error('detector-source-unverified');
    for(const [name,scriptId] of selected){const rows=candidates(name);if(rows.length!==1||rows[0].scriptId!==scriptId)throw Error('detector-source-unverified');}
  }
  const missing=names.filter(name=>!hashes[name]);
  if(!missing.length){live();return {uniqueContextId:context.uniqueId};}
  function candidates(name){return scripts.filter(item=>item.url===origin+paths[name]&&
    typeof item.scriptId==='string'&&item.scriptId.length>0&&item.scriptId.length<=128&&
    item.executionContextId===contextId&&contexts.get(item.executionContextId)?.frameId===mainFrame&&contexts.get(item.executionContextId)?.isDefault===true);}
  let enabled=false;
  try{
    await send('Debugger.enable');enabled=true;
    const deadline=Date.now()+waitMs;
    while(missing.some(name=>candidates(name).length===0)&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,25));
    for(const name of missing){
      const rows=candidates(name);
      if(rows.length!==1)throw Error('detector-source-unverified');
      selected.set(name,rows[0].scriptId);live();
      const result=await send('Debugger.getScriptSource',{scriptId:rows[0].scriptId});
      live();
      if(typeof result.scriptSource!=='string'||Buffer.byteLength(result.scriptSource)>262144)throw Error('detector-source-unverified');
      const digest=createHash('sha256').update(result.scriptSource).digest('hex');
      if(digest!==expected[name])throw Error('detector-source-unverified');
      hashes[name]=digest;methods[name]='executed-main-document-script';
    }
  }finally{if(enabled)await send('Debugger.disable');}
  live();
  return {uniqueContextId:context.uniqueId};
}
