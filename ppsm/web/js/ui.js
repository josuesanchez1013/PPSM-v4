"use strict";
/* ---------------- classification banner ---------------- */
const CB=["UNCLASSIFIED u","CUI cui","CONFIDENTIAL c","SECRET s","SECRET//NOFORN s",
  "SECRET//SI//NOFORN s","TOP SECRET ts","TOP SECRET//SI/TK//NOFORN sci",
  "TOP SECRET//HCS/SI/TK//ORCON/NOFORN sci"];
let cbi=0;
function bannerClassFor(t){t=(t||"").toUpperCase();
  if(/\/\/.*\b(SI|TK|HCS|KDK|G\b)|\/\/SAR|SCI/.test(t)) return "sci";
  if(t.startsWith("TOP SECRET")) return "ts";
  if(t.startsWith("SECRET")) return "s";
  if(t.startsWith("CONFIDENTIAL")) return "c";
  if(t.startsWith("CUI")) return "cui";
  return "u";}
function setBanner(text){ text=text||"UNCLASSIFIED";
  $("classbar").textContent=text; $("classbar").className="classbar "+bannerClassFor(text); }
$("classbar").onclick=()=>{cbi=(cbi+1)%CB.length;const cls=CB[cbi].split(" ").pop();
  const txt=CB[cbi].slice(0, CB[cbi].length-cls.length-1);
  setBanner(txt); $("m_docclass").value=txt; };
$("m_docclass").addEventListener("change",()=>setBanner($("m_docclass").value||"UNCLASSIFIED"));
$("m_env").addEventListener("change",()=>{
  $("m_env_other").style.display = $("m_env").value==="Other" ? "block" : "none";
  if($("m_env").value==="Other") $("m_env_other").focus();
});

/* init */
const clsOpts='<option value="">— select —</option>'+
  CLASS.filter(Boolean).map(c=>`<option value="${esc(c)}">${esc(c)}</option>`).join("");
$("m_class").innerHTML=clsOpts;
$("m_docclass").innerHTML=clsOpts;
$("m_docclass").value="UNCLASSIFIED"; setBanner("UNCLASSIFIED");
const dl=document.createElement("datalist"); dl.id="clslist";
dl.innerHTML=CLASS.filter(Boolean).map(c=>`<option value="${esc(c)}">`).join("");
document.body.appendChild(dl);
const dle=document.createElement("datalist"); dle.id="enclist"; document.body.appendChild(dle);
bulkControl();
$("fField").innerHTML='<option value="">in any field</option>'+
  COLS.map(c=>`<option value="${c[0]}">${esc(c[1])}</option>`).join("");
document.addEventListener("keydown",e=>{ if(e.key==="Escape"){ $("stModal").hidden=true; $("errModal").hidden=true; } });
$("errClose").onclick=()=>$("errModal").hidden=true;
$("errModal").addEventListener("click",e=>{ if(e.target===$("errModal")) $("errModal").hidden=true; });

/* ---------------- v2 wiring ---------------- */
$("cfgApply").onclick=applySettings;
$("cfgReset").onclick=resetSettings;
$("expEmassXlsx").onclick=exportEmassXlsx;
$("expEmassCsv").onclick=exportEmassCsv;
$("expProfile").onclick=exportProfile;
$("impProfileBtn").onclick=()=>$("profileFile").click();
$("profileFile").onchange=e=>{ const f=e.target.files[0]; if(f) importProfile(f); e.target.value=""; };

(function(){
  const box=$("enrichOpts"); if(!box) return;
  const DEFAULT_ON=["boundary","dataService","data","appName","emassType","srcPoint","dstPoint",
                    "vpn","srcHost","dstHost","enclave","collector","classification"];
  box.innerHTML=ENRICH_FIELDS.map(([k,label])=>
    `<label class="opt"><input type="checkbox" data-enrich="${k}" ${DEFAULT_ON.indexOf(k)>=0?"checked":""}><span>${esc(label)}</span></label>`
  ).join("");
})();
$("enrichRun").onclick=runAutoFill;
/* One button for the whole post-import pass, so the common path is a single
   click rather than four. */
/* The system name is only used for filenames and the export header, so infer
   a sensible one rather than blocking on it. */
function autoSystemName(){
  const el=$("m_system");
  if(!el || el.value.trim()) return;
  const doms={};
  ROWS.forEach(r=>[r.srcHost,r.dstHost].forEach(h=>{
    if(!h) return;
    const parts=String(h).split(".");
    if(parts.length>1){ const d=parts.slice(1).join("."); doms[d]=(doms[d]||0)+1; }
  }));
  const best=Object.entries(doms).sort((a,b)=>b[1]-a[1])[0];
  if(best){ el.value=best[0].split(".")[0].toUpperCase(); return; }
  const encl=[...new Set(ROWS.map(r=>r.enclave).filter(Boolean))];
  if(encl.length===1) el.value=encl[0];
}

function finishRegister(quiet){
  if(!ROWS.length){
    if(!quiet) flash("Nothing to finish yet — import your collection folder first.","warn");
    return;
  }
  autoSystemName();
  const steps=[];
  try{
    const learned=applyHostmap(true);
    if(learned) steps.push(learned+" hostname"+(learned===1?"":"s")+" resolved");
  }catch(e){}
  try{
    const x=crossReference(ROWS);
    const bits=[];
    if(x.filledSrc)  bits.push(x.filledSrc+" source"+(x.filledSrc===1?"":"s")+" resolved from traffic");
    if(x.filledPort) bits.push(x.filledPort+" source port"+(x.filledPort===1?"":"s")+" filled");
    if(x.filledRef)  bits.push(x.filledRef+" flow"+(x.filledRef===1?"":"s")+" matched to a rule");
    if(x.absorbed)   bits.push(x.absorbed+" discovered service"+(x.absorbed===1?"":"s")+" folded into the traffic that used "+(x.absorbed===1?"it":"them"));
    if(bits.length) steps.push(bits.join(" · "));
  }catch(e){}
  try{
    const fixed=repairLegacyBoundaries(ROWS);
    const counts=enrichRows(ROWS, null, false);
    const filled=Object.values(counts).reduce((a,b)=>a+b,0);
    if(filled) steps.push(filled+" field"+(filled===1?"":"s")+" filled in");
    if(fixed)  steps.push(fixed+" boundary tag"+(fixed===1?"":"s")+" updated");
  }catch(e){}
  let before=ROWS.length;
  try{
    const ex=excludeEphemeral(ROWS);
    if(ex.dropped) steps.push(ex.dropped+" ephemeral-destination row"+(ex.dropped===1?"":"s")+" removed");
    if(ex.blanked) steps.push(ex.blanked+" ephemeral source port"+(ex.blanked===1?"":"s")+" cleared");
  }catch(e){}
  try{ dedupeRows(); }catch(e){}
  try{
    if(CFG.consolidatePorts!==false){
      const cz=consolidateRows(ROWS);
      if(cz.collapsed) steps.push(cz.collapsed+" row"+(cz.collapsed===1?"":"s")+
        " consolidated into "+cz.into+" by port");
    }
  }catch(e){}
  const removed=before-ROWS.length;
  if(removed) steps.push(removed+" duplicate"+(removed===1?"":"s")+" merged");
  render();
  try{ renderEndpoints(); }catch(e){}
  try{ renderPpsmChecks(); }catch(e){}
  try{ if(ROWS.length) renderDiagram(); }catch(e){}
  try{ if(ROWS.length && $("dgCanvas")) $("dgCanvas").scrollIntoView===undefined; }catch(e){}
  const st=(function(){ try{ return endpointStats(buildEndpoints()); }catch(e){ return null; } })();
  const outstanding=(function(){ try{
    return runPpsmChecks(ROWS).filter(i=>i.severity==="high").reduce((a,b)=>a+b.count,0);
  }catch(e){ return 0; } })();
  const tail = st ? (" · "+st.pct+"% of internal systems named") : "";
  if(quiet && !steps.length) return;
  flash((steps.length?steps.join(" · "):"Nothing further to derive")+tail+
        (outstanding?" · "+outstanding+" item"+(outstanding===1?"":"s")+" still to fix, see Review Checks":" · review checks clear"),
        outstanding?"warn":"ok");
}
$("finishBtn").onclick=finishRegister;


$("chkRun").onclick=renderPpsmChecks;
$("chkExport").onclick=exportChecksCsv;
$("covRun").onclick=renderCoverage;
$("diffLoad").onclick=()=>$("diffFile").click();
$("diffFile").onchange=e=>{ loadPreviousRegister(e.target.files); e.target.value=""; };
$("diffExport").onclick=exportDiffCsv;
$("diffApply").onclick=applyDiffStatus;
$("covExport").onclick=exportCoverageCsv;
if($("chkScope")) $("chkScope").addEventListener("change",renderPpsmChecks);
$("epRefresh").onclick=renderEndpoints;
$("epResolve").onclick=()=>applyHostmap(false);
$("epImport").onclick=()=>$("epFile").click();
/* "Load Host Inventory" goes through the same reader as the ingest box, so a
   DNS zone, a Windows DNS export (CSV, TXT or Excel), an AD export, a hosts
   file, a .nessus scan or a filled-in work list are all read the same way,
   several at once; the resolution summary is shown when they are in. */
$("epFile").onchange=e=>{ const fs=[...e.target.files]; if(!fs.length) return;
  EP_IMPORT_PENDING=true;
  handleFiles(fs); e.target.value=""; };
$("epExport").onclick=exportEndpointsCsv;
$("epExportUn").onclick=exportUnnamedCsv;
$("epExportMap").onclick=exportHostmap;
["epScope","epUnnamed"].forEach(id=>{ const el=$(id); if(el) el.addEventListener("change",renderEndpoints); });

$("dgGen").onclick=renderDiagram;
$("dgSvg").onclick=exportDiagramSvg;
$("dgPng").onclick=exportDiagramPng;
$("dgPrint").onclick=printDiagram;
["dgMode","dgGroup","dgScope","dgTheme","dgMaxEdges","dgPortCount","dgWidth","dgRowH",
 "dgShowPorts","dgShowCounts","dgTitle"].forEach(id=>{
  const el=$(id); if(el) el.addEventListener("change",()=>{ if(ROWS.length) renderDiagram(); });
});
if($("fCollector")) $("fCollector").addEventListener("change",()=>{PAGE=1;render();});
applyColumnVisibility();

$("m_date").value=new Date().toISOString().slice(0,10);
render();
