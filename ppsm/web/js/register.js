"use strict";
/* ---------------- row model ---------------- */
function blank(o={}){
  return Object.assign({
    id:++rid, enclave:"",src:"",dest:"",proto:"",srcPort:"",dstPort:"",dataService:"",banner:"",
    direction:"",boundary:"",isaRef:"",data:"",classification:"",justification:"",
    assurance:"",status:"New",cal:"",collector:"",srcZone:"",dstZone:"",
    srcHost:"",dstHost:"",
    emassType:"",srcLoc:"",dstLoc:"",srcPoint:"",dstPoint:"",vpn:"",vpnType:"",appName:"",
    calRef:"",registryId:"",subPath:"",
    pkts:"",bytes:"",notes:"",origin:"manual"
  },o);
}

/* ---------------- render ---------------- */
/* opts may be plain strings, or {value,label} pairs so the cell stores a short
   code while the dropdown still reads in full. Storing the label was putting
   an em dash into the data, which Excel renders as "?" on many systems. */
function sel(field,val,opts){
  return `<select data-f="${field}">`+opts.map(o=>{
    const v = (o && typeof o==="object") ? o.value : o;
    const l = (o && typeof o==="object") ? o.label : o;
    return `<option value="${esc(v)}"${v===val?" selected":""}>${esc(l)}</option>`;
  }).join("")+`</select>`;
}
let PAGE=1;
function pageSize(){ return +$("pgSize").value; } // 0 = all
/* Addresses to leave out of the register: exact addresses, networks in CIDR,
   hostnames, or a wildcard such as scanner*. A row goes if either end matches,
   because a scanner is worth excluding whichever direction it appears in. */
function excludeList(){
  return String(($("fExclude")||{}).value||"")
    .split(/[,;\s]+/).map(s=>s.trim()).filter(Boolean);
}
function matchesExclusion(r, list){
  if(!list.length) return false;
  const ends=[r.src, r.dest, r.srcHost, r.dstHost].filter(Boolean);
  for(const raw of list){
    const p=raw.toLowerCase();
    for(const e of ends){
      const v=String(e).toLowerCase();
      if(p.indexOf("/")>0){ if(isIP(e) && inCidr(e,raw)) return true; continue; }
      if(p.indexOf("*")>=0){
        const re=new RegExp("^"+p.replace(/[.+^${}()|[\]\\]/g,"\\$&").replace(/\*/g,".*")+"$");
        if(re.test(v)) return true;
        continue;
      }
      if(v===p) return true;
      // a bare short name also matches the full name it belongs to
      if(v.indexOf(".")>0 && v.split(".")[0]===p) return true;
    }
  }
  return false;
}

function getFiltered(){
  const q=$("fSearch").value.trim().toLowerCase();
  const ex=excludeList();
  const fe=$("fEnclave").value, fb=$("fBoundary").value, fo=$("fOrigin").value, ff=$("fField").value;
  const fc=$("fCollector")?$("fCollector").value:"";
  return ROWS.filter(r=>{
    if(matchesExclusion(r, ex)) return false;
    if(fe && r.enclave!==fe) return false;
    if(fb && r.boundary!==fb) return false;
    if(fo && r.origin!==fo) return false;
    if(fc && r.collector!==fc) return false;
    if(q){
      const hay = ff ? String(r[ff]==null?"":r[ff]).toLowerCase()
                     : COLS.map(c=>r[c[0]]).join(" \u0001 ").toLowerCase(); // every field
      if(!hay.includes(q)) return false;
    }
    return true;
  });
}
function fillFilter(id, values, allLabel){
  const el=$(id); const cur=el.value;
  const uniq=[...new Set(values.filter(Boolean))].sort();
  el.innerHTML=`<option value="">${esc(allLabel)}</option>`+uniq.map(o=>`<option value="${esc(o)}">${esc(o)}</option>`).join("");
  el.value=cur;
}
function render(){
  fillFilter("fEnclave", ROWS.map(r=>r.enclave), "All enclaves");
  fillFilter("fBoundary", ROWS.map(r=>r.boundary), "All boundaries");
  fillFilter("fOrigin", ROWS.map(r=>r.origin), "All sources");
  fillFilter("fCollector", ROWS.map(r=>r.collector), "All collectors");
  var _cl=$("colllist"); if(_cl) _cl.innerHTML=[...new Set(ROWS.map(r=>r.collector).filter(Boolean))]
    .map(e=>`<option value="${esc(e)}">`).join("");
  var _hl=$("hostlist");
  if(_hl){ const names=new Set([...HOSTMAP.values()].map(h=>h.name));
    ROWS.forEach(r=>{ if(r.srcHost)names.add(r.srcHost); if(r.dstHost)names.add(r.dstHost); });
    _hl.innerHTML=[...names].filter(Boolean).sort().map(e=>`<option value="${esc(e)}">`).join(""); }
  $("enclist").innerHTML=[...new Set(ROWS.map(r=>r.enclave).filter(Boolean))].map(e=>`<option value="${esc(e)}">`).join("");

  const filtered=getFiltered(), ps=pageSize(), total=filtered.length;
  const pages = ps===0?1:Math.max(1,Math.ceil(total/ps));
  if(PAGE>pages) PAGE=pages; if(PAGE<1) PAGE=1;
  const start = ps===0?0:(PAGE-1)*ps, end = ps===0?total:Math.min(total,start+ps);
  const view = filtered.slice(start,end);

  const tb=$("tbody"); tb.innerHTML="";
  const frag=document.createDocumentFragment();
  view.forEach((r,i)=>{
    const crosses=FLAGGED(r.boundary);
    const tr=document.createElement("tr");
    tr.className=(SELECTED.has(r.id)?"selected ":"")+(crosses?"crosses":(r.boundary==="Internal only"?"internal":"")); tr.dataset.id=r.id;
    tr.innerHTML=`
      <td class="selcell"><input type="checkbox" class="rowsel" data-id="${r.id}" ${SELECTED.has(r.id)?"checked":""}></td>
      <td class="rownum">${start+i+1}</td>
      <td class="mono"><input data-f="enclave" list="enclist" value="${esc(r.enclave)}" title="${esc(r.enclave)}" style="min-width:152px" placeholder="—"></td>
      <td class="mono"><input data-f="src" value="${esc(r.src)}" title="${esc(r.src)}" placeholder="—" style="min-width:152px"></td>
      <td><input data-f="srcHost" list="hostlist" value="${esc(r.srcHost)}" title="${esc(r.srcHost)}" placeholder="—" style="min-width:196px"></td>
      <td class="mono"><input data-f="dest" value="${esc(r.dest)}" title="${esc(r.dest)}" placeholder="—" style="min-width:152px"></td>
      <td><input data-f="dstHost" list="hostlist" value="${esc(r.dstHost)}" title="${esc(r.dstHost)}" placeholder="—" style="min-width:196px"></td>
      <td class="mono"><input data-f="proto" value="${esc(r.proto)}" style="min-width:64px"></td>
      <td class="mono"><input data-f="srcPort" value="${esc(r.srcPort)}" style="min-width:96px" placeholder="—"></td>
      <td class="mono"><input data-f="dstPort" value="${esc(r.dstPort)}" style="min-width:76px"></td>
      <td><input data-f="dataService" value="${esc(r.dataService)}" title="${esc(r.dataService)}" style="min-width:150px"></td>
      <td><input data-f="banner" value="${esc(r.banner)}" title="${esc(r.banner)}" style="min-width:170px" placeholder="—"></td>
      <td>${sel("direction",r.direction,DIRECTION)}</td>
      <td>${sel("boundary",r.boundary,boundaryList())}</td>
      <td><input data-f="isaRef" value="${esc(r.isaRef)}" placeholder="ISA / agreement ref" style="min-width:170px"></td>
      <td><input data-f="data" value="${esc(r.data)}" title="${esc(r.data)}" style="min-width:310px" placeholder="data crossing"></td>
      <td><input data-f="classification" list="clslist" value="${esc(r.classification)}" placeholder="e.g. SECRET//NOFORN" style="min-width:150px"></td>
      <td><textarea data-f="justification" rows="2" class="just" placeholder="full engineering / mission justification">${esc(r.justification)}</textarea></td>
      <td>${sel("assurance",r.assurance,ASSURANCE_LIST.concat(
        ASSURANCE_LEGACY.filter(a=>a&&a===r.assurance).map(a=>({value:a,label:a+" (legacy)"}))))}</td>
      <td>${sel("status",r.status,STATUS)}</td>
      <td>${sel("cal",r.cal,CAL)}</td>
      <td class="mono"><input data-f="collector" list="colllist" value="${esc(r.collector)}" placeholder="—" style="min-width:130px"></td>
      <td class="mono"><input data-f="srcZone" value="${esc(r.srcZone)}" title="${esc(r.srcZone)}" style="min-width:120px" placeholder="—" style="width:88px"></td>
      <td class="mono"><input data-f="dstZone" value="${esc(r.dstZone)}" title="${esc(r.dstZone)}" style="min-width:120px" placeholder="—" style="width:88px"></td>
      <td class="mono"><input data-f="pkts" value="${esc(r.pkts)}" title="${esc(r.pkts)}" style="min-width:92px" placeholder="—" style="width:64px"></td>
      <td class="mono"><input data-f="bytes" value="${esc(r.bytes)}" title="${esc(r.bytes)}" style="min-width:100px" placeholder="—" style="width:78px"></td>
      <td><input data-f="notes" value="${esc(r.notes)}" title="${esc(r.notes)}" style="min-width:330px" placeholder="—" style="min-width:130px"></td>
      <td class="mono"><span class="badge-bnd">${esc(r.origin)}</span></td>
      <td class="act"><button title="delete" data-del="${r.id}">×</button></td>`;
    frag.appendChild(tr);
  });
  tb.appendChild(frag);

  const cross=ROWS.filter(r=>FLAGGED(r.boundary)).length;
  $("empty").style.display=ROWS.length?"none":"block";
  $("count").innerHTML=`${ROWS.length} entries · ${total} shown · <b>${cross}</b> cross a boundary`;
  if($("exCount")){
    const ex=excludeList();
    const n=ex.length ? ROWS.filter(r=>matchesExclusion(r,ex)).length : 0;
    $("exCount").innerHTML = n ? `<b>${n}</b> hidden` : (ex.length ? "none match" : "");
  }
  $("pgInfo").textContent = total?`Showing ${start+1}–${end} of ${total}`:"No matching rows";
  $("pgNum").textContent = `${PAGE} / ${pages}`;
  // select-all reflects the filtered set; bulk target reflects selection vs filter
  const selInFiltered=filtered.filter(r=>SELECTED.has(r.id)).length;
  const sa=$("selAll");
  sa.checked = filtered.length>0 && selInFiltered===filtered.length;
  sa.indeterminate = selInFiltered>0 && selInFiltered<filtered.length;
  updateBulkTarget();
  applyColumnVisibility();
}
function refreshEndpoints(){ try{ renderEndpoints(); }catch(e){} }
function updateBulkTarget(){
  if(SELECTED.size>0){ $("bulkN").textContent=SELECTED.size; $("bulkTarget").textContent="selected"; }
  else { $("bulkN").textContent=getFiltered().length; $("bulkTarget").textContent="filtered"; }
}

/* ---------------- events ---------------- */
$("tbody").addEventListener("input",e=>{
  const f=e.target.dataset.f; if(!f) return;
  const id=+e.target.closest("tr").dataset.id;
  const row=ROWS.find(r=>r.id===id); if(!row) return;
  row[f]=e.target.value;
  if(f==="boundary"){ render(); } // re-tag highlight
});
$("tbody").addEventListener("change",e=>{
  if(e.target.classList.contains("rowsel")){
    const id=+e.target.dataset.id;
    if(e.target.checked) SELECTED.add(id); else SELECTED.delete(id);
    const tr=e.target.closest("tr"); tr.classList.toggle("selected",e.target.checked);
    updateBulkTarget();
    // keep the header select-all box in sync
    const filtered=getFiltered(); const inSel=filtered.filter(r=>SELECTED.has(r.id)).length;
    const sa=$("selAll"); sa.checked=filtered.length>0&&inSel===filtered.length; sa.indeterminate=inSel>0&&inSel<filtered.length;
    return;
  }
  const f=e.target.dataset.f; if(!f) return;
  const id=+e.target.closest("tr").dataset.id;
  const row=ROWS.find(r=>r.id===id); if(row){row[f]=e.target.value; if(f==="boundary")render();}
});
$("selAll").addEventListener("change",()=>{
  const filtered=getFiltered();
  if($("selAll").checked) filtered.forEach(r=>SELECTED.add(r.id));
  else filtered.forEach(r=>SELECTED.delete(r.id));
  render();
});
$("tbody").addEventListener("click",e=>{
  const del=e.target.dataset.del;
  if(del){ROWS=ROWS.filter(r=>r.id!==+del); SELECTED.delete(+del); render();}
});

/* ---------------- filter / paginate / bulk ---------------- */
function bulkControl(){
  const f=$("bulkField").value;
  const lists={boundary:BOUNDARIES,direction:DIRECTION,assurance:ASSURANCE,status:STATUS,cal:CAL,
               vpn:["Yes","No"], vpnType:[""].concat([...new Set(EMASS_VPNTYPE)])};
  let html;
  if(f==="boundary") lists.boundary=boundaryList();
  if(f==="assurance") lists.assurance=ASSURANCE;
  if(lists[f]) html=`<select class="t" id="bulkVal" style="flex:1;min-width:210px">`+
    lists[f].map(o=>{
      const v=(o&&typeof o==="object")?o.value:o, l=(o&&typeof o==="object")?o.label:o;
      return `<option value="${esc(v)}">${esc(l)}</option>`;
    }).join("")+`</select>`;
  else if(f==="classification") html=`<input class="t" id="bulkVal" list="clslist" placeholder="e.g. SECRET//NOFORN" style="flex:1;min-width:160px">`;
  else if(f==="enclave") html=`<input class="t" id="bulkVal" list="enclist" placeholder="enclave name" style="flex:1;min-width:160px">`;
  else if(f==="collector") html=`<input class="t" id="bulkVal" list="colllist" placeholder="collector / source host" style="flex:1;min-width:160px">`;
  else if(f==="srcPort") html=`<input class="t" id="bulkVal" placeholder="e.g. 1024-65535" style="flex:1;min-width:160px">`;
  else if(f==="srcLoc"||f==="dstLoc") html=`<input class="t" id="bulkVal" placeholder="e.g. Bldg 1234, Peterson SFB, CO — or a cloud provider" style="flex:1;min-width:220px">`;
  else html=`<input class="t" id="bulkVal" placeholder="value to set" style="flex:1;min-width:160px">`;
  $("bulkValWrap").innerHTML=html;
}
$("bulkField").addEventListener("change",bulkControl);
$("fSearch").addEventListener("input",()=>{PAGE=1;render();});
["fField","fEnclave","fBoundary","fOrigin","pgSize"].forEach(id=>$(id).addEventListener("change",()=>{PAGE=1;render();}));
if($("fExclude")) $("fExclude").addEventListener("input", ()=>{ PAGE=1; render(); });
if($("fExRemove")) $("fExRemove").onclick=()=>{
  const ex=excludeList();
  if(!ex.length) return flash("Nothing to remove — put an address in the box first.","warn");
  const doomed=ROWS.filter(r=>matchesExclusion(r,ex));
  if(!doomed.length) return flash("Nothing matches those addresses.","warn");
  if(!confirm("Remove "+doomed.length+" row"+(doomed.length===1?"":"s")+" from the register for good?\n\n"+
              "This cannot be undone, though the rows come back if you import the same files again.")) return;
  const gone=new Set(doomed);
  ROWS=ROWS.filter(r=>!gone.has(r));
  SELECTED.clear();
  $("fExclude").value="";
  render();
  flash(doomed.length+" row"+(doomed.length===1?"":"s")+" removed.","ok");
};
$("fClear").onclick=()=>{$("fSearch").value="";$("fField").value="";$("fEnclave").value="";$("fBoundary").value="";$("fOrigin").value="";PAGE=1;render();};
$("pgFirst").onclick=()=>{PAGE=1;render();};
$("pgPrev").onclick=()=>{PAGE--;render();};
$("pgNext").onclick=()=>{PAGE++;render();};
$("pgLast").onclick=()=>{PAGE=1e9;render();};
$("bulkApply").onclick=()=>{
  const fe=$("bulkField"); const f=fe.value, v=$("bulkVal").value;
  const label=fe.options[fe.selectedIndex].textContent;
  const usingSel=SELECTED.size>0;
  const targets=usingSel ? ROWS.filter(r=>SELECTED.has(r.id)) : getFiltered();
  const msg=$("bulkMsg");
  if(!targets.length){ msg.textContent="No rows selected or matching the filter."; msg.className="bulkmsg warn"; return; }
  targets.forEach(r=>{ r[f]=v; });
  render();
  const where=usingSel?"selected":"filtered";
  msg.textContent=`✓ ${label} = "${v||"(blank)"}" applied to ${targets.length} ${where} row(s)`;
  msg.className="bulkmsg ok";
  flash(`Bulk update: ${label} = "${v||"(blank)"}" on ${targets.length} ${where} row(s).`,"ok");
};
$("bulkClearSel").onclick=()=>{ SELECTED.clear(); render(); $("bulkMsg").textContent=""; };
$("addRow").onclick=()=>{ROWS.push(blank()); PAGE=1e9; render();
  const tb=$("tbody"); const inp=tb.lastElementChild&&tb.lastElementChild.querySelector("input"); if(inp) inp.focus();};
$("clearAll").onclick=()=>{ if(ROWS.length && confirm("Remove all "+ROWS.length+" entries?")){ROWS=[];SELECTED.clear();render();}};
/* ---------------- dedupe ----------------
   Two rows are the same registration when they describe the same flow:
   same source, same destination, same protocol, same destination port(s).
   Everything else (direction as seen from one side or the other, enclave
   filled in by one source and not the other, the origin tool, counters) is
   detail about the same flow, not a reason to keep two lines. Rules and
   observations are still kept apart.

   Pass 1 — exact duplicates. Rows with the same key are collapsed into the
   most complete one; blank fields on the kept row are filled from the rows
   that go, and the origin tools are merged.

   Pass 2 — contained rows. After Consolidate, a row may carry
   "80; 443" and sources "10.1.1.5; 10.1.1.6". A plain "10.1.1.5 -> 443"
   row says nothing that line does not already say, so it goes too. A row
   with no source at all (a bare listener) is contained by any observed
   flow to the same port.

   Hostnames and addresses are compared case-insensitively, trailing dots
   and whitespace ignored, so "SRV01.lan." and "srv01.lan" match. */
function dedupeRows(){
  const nz   = v => String(v==null?"":v).trim().toLowerCase().replace(/\.+$/,"");
  const list = v => { const out=new Set();
    String(v==null?"":v).split(/[;,]/).forEach(x=>{ const t=nz(x); if(t) out.add(t); }); return out; };
  const basis= r => String(r.origin||"").indexOf("firewall-rule")>=0 ? "rule" : "seen";
  const srcOf= r => r.src || r.srcHost || "";
  const dstOf= r => r.dest || r.dstHost || "";
  const subset=(a,b)=>{ for(const x of a) if(!b.has(x)) return false; return true; };
  const union =(arr)=>{ const out=[]; const seen=new Set();
    arr.forEach(v=>String(v||"").split(/,\s*/).forEach(t=>{ t=t.trim(); if(t&&!seen.has(t)){seen.add(t);out.push(t);} }));
    return out.join(", "); };
  // fill blanks on keep from gone, merge origin; counters add up
  const absorb=(keep,gone)=>{
    Object.keys(gone).forEach(k=>{
      if(k==="id"||k==="origin"||k==="notes"||k==="pkts"||k==="bytes") return;
      if((keep[k]==null||keep[k]==="") && gone[k]!=null && gone[k]!=="") keep[k]=gone[k];
    });
    keep.origin=union([keep.origin,gone.origin]);
    if(+gone.pkts)  keep.pkts =String((+keep.pkts||0)+(+gone.pkts));
    if(+gone.bytes) keep.bytes=String((+keep.bytes||0)+(+gone.bytes));
    if(gone.notes && String(keep.notes||"").indexOf(gone.notes)<0)
      keep.notes = keep.notes ? keep.notes+" · "+gone.notes : gone.notes;
  };

  // ---- pass 1: identical flows
  const groups=new Map();
  for(const r of ROWS){
    const ports=[...list(r.dstPort)].sort().join(";");
    const srcs =[...list(srcOf(r))].sort().join(";");
    const k=[basis(r), srcs, nz(dstOf(r)), nz(r.proto), ports].join("|");
    if(!groups.has(k)) groups.set(k,[]);
    groups.get(k).push(r);
  }
  const gone=new Set();
  groups.forEach(g=>{
    if(g.length<2) return;
    const keep=g.slice().sort((a,b)=>cells(b)-cells(a))[0];
    g.forEach(r=>{ if(r!==keep){ absorb(keep,r); gone.add(r); } });
  });
  let out=ROWS.filter(r=>!gone.has(r));

  // ---- pass 2: rows contained by a wider row (same dest + proto + basis)
  const byDest=new Map();
  out.forEach(r=>{ const k=[basis(r),nz(dstOf(r)),nz(r.proto)].join("|");
    if(!byDest.has(k)) byDest.set(k,[]); byDest.get(k).push(r); });
  byDest.forEach(g=>{
    if(g.length<2) return;
    const info=g.map(r=>({r, ports:list(r.dstPort), srcs:list(srcOf(r))}));
    // widest rows first so a narrow row is absorbed by the widest match
    info.sort((a,b)=>(b.ports.size+b.srcs.size)-(a.ports.size+a.srcs.size));
    for(let i=0;i<info.length;i++){
      const a=info[i]; if(gone.has(a.r)) continue;
      for(let j=i+1;j<info.length;j++){
        const b=info[j]; if(gone.has(b.r)) continue;
        if(b.ports.size===0) continue;                       // nothing to compare
        const wider = a.ports.size>b.ports.size || a.srcs.size>b.srcs.size;
        if(!wider) continue;
        if(!subset(b.ports,a.ports)) continue;
        if(!subset(b.srcs,a.srcs)) continue;                 // empty source ⊆ anything
        absorb(a.r,b.r); gone.add(b.r);
      }
    }
  });
  out=out.filter(r=>!gone.has(r));

  const removed=ROWS.length-out.length; ROWS=out;
  const live=new Set(ROWS.map(r=>r.id)); [...SELECTED].forEach(id=>{ if(!live.has(id)) SELECTED.delete(id); });
  return removed;
}
$("consolidate").onclick=()=>{
  const c=consolidateRows(ROWS); render();
  flash(c.collapsed ? (c.collapsed+" row"+(c.collapsed===1?"":"s")+" consolidated into "+c.into+
        ". Like ports and like sources are joined with semicolons.")
       : "Nothing to consolidate — no rows share a source/destination or a service.",
       c.collapsed?"ok":"warn");
};
$("dedupe").onclick=()=>{
  const removed=dedupeRows(); render();
  if(removed) flash(`Removed ${removed} duplicate row(s).`,"ok");
  else flash("No duplicates found.","ok");
};

/* ---------------- ingest ---------------- */
const drop=$("drop");
drop.onclick=()=>$("file").click();
$("file").onchange=e=>{ handleFiles(e.target.files); e.target.value=""; };  // reset so the same file can be re-selected

// Stop the browser from opening/navigating to a file dropped ANYWHERE on the page
["dragenter","dragover","drop"].forEach(ev=>window.addEventListener(ev,e=>e.preventDefault(),false));
drop.addEventListener("dragenter",()=>drop.classList.add("over"));
drop.addEventListener("dragover",()=>drop.classList.add("over"));
drop.addEventListener("dragleave",()=>drop.classList.remove("over"));
// One drop handler on the window catches drops on the box and anywhere else (forgiving)
window.addEventListener("drop",e=>{
  e.preventDefault(); drop.classList.remove("over");
  const dt=e.dataTransfer; if(!dt) return;
  let files = dt.files && dt.files.length ? dt.files : null;
  if(!files && dt.items){ files=[...dt.items].filter(i=>i.kind==="file").map(i=>i.getAsFile()).filter(Boolean); }
  if(files && files.length) handleFiles(files);
  else logFile("(drop)","note",0,"No file detected in that drop — use the click-to-browse button instead.");
});

// Decode file bytes with encoding detection (handles UTF-16 from PowerShell '>' redirection, BOMs)
function decodeBytes(buf){
  try{
    const b=new Uint8Array(buf);
    if(b.length>=2 && b[0]===0xFF && b[1]===0xFE) return new TextDecoder("utf-16le").decode(b.subarray(2));
    if(b.length>=2 && b[0]===0xFE && b[1]===0xFF) return new TextDecoder("utf-16be").decode(b.subarray(2));
    if(b.length>=3 && b[0]===0xEF && b[1]===0xBB && b[2]===0xBF) return new TextDecoder("utf-8").decode(b.subarray(3));
    // no BOM: sniff for UTF-16 by counting null bytes near the start
    let nul=0; const lim=Math.min(b.length,400);
    for(let i=0;i<lim;i++) if(b[i]===0) nul++;
    if(lim>0 && nul>lim*0.2) return new TextDecoder("utf-16le").decode(b);
    return new TextDecoder("utf-8").decode(b);
  }catch(e){ try{ return new TextDecoder().decode(new Uint8Array(buf)); }catch(_){ return ""; } }
}

let EP_IMPORT_PENDING=false;
/* When set, handleFiles parses files but hands the rows to this object
   instead of the register — used by "Compare with previous register". */
let DIFF_CAPTURE=null;
function handleFiles(files){
  const arr=[...files];
  if(!arr.length){ logFile("(no file)","note",0,"Nothing received."); return; }
  let pending=arr.length; const fails=[];
  const done=()=>{
    if(--pending>0) return;
    if(DIFF_CAPTURE){ const c=DIFF_CAPTURE; DIFF_CAPTURE=null; try{ c.done(c.rows, c.kinds); }catch(e){ flash("Compare failed: "+e.message,"warn"); } return; }
    const loud=EP_IMPORT_PENDING; EP_IMPORT_PENDING=false;   // "Load Host Inventory" wants the summary shown
    try{
      if(CFG.autoResolveHosts || loud) applyHostmap(!loud);
      if(CFG.autoEnrich) enrichRows(ROWS, null, false);
      if(CFG.autoFinish!==false && ROWS.length) finishRegister(true);
    }catch(e){}
    render();
    if(typeof renderEndpoints==="function") renderEndpoints();
    if(fails.length) showImportErrors(fails);
  };
  arr.forEach(f=>{
    const rd=new FileReader();
    rd.onload=()=>{
      let res, text="";
      const bytes = new Uint8Array(rd.result);
      const isPdf = bytes.length>4 && bytes[0]===0x25 && bytes[1]===0x50 && bytes[2]===0x44 && bytes[3]===0x46;
      const isCap = isPcapMagic(bytes) || /\.(pcap|pcapng|cap)$/i.test(f.name);
      const isZip = bytes.length>4 && bytes[0]===0x50 && bytes[1]===0x4b && bytes[2]===0x03 && bytes[3]===0x04;
      const isXlsx = isZip && (/\.(xlsx|xlsm)$/i.test(f.name) || (function(){
        try{ return zipEntries(bytes).entries.has("xl/workbook.xml"); }catch(e){ return false; } })());
      if(isXlsx){
        /* every sheet goes through the normal readers as CSV, so an Excel copy
           of anything the tool already understands is understood too */
        try{
          const book=readXlsx(bytes);
          let rows=[], kinds=[], notes=[], seenN=0, namesN=0;
          book.sheets.forEach(sh=>{
            const csv=sheetToCsv(sh.rows);
            if(!csv.trim()) return;
            // an eMASS workbook names its data tab "PPSM Info" or "PPSM"
            if(!text) text=csv;
            const r=parseFile(f.name.replace(/\.(xlsx|xlsm)$/i,".csv"), csv);
            if(r && (r.rows.length || r.seen)){
              rows=rows.concat(r.rows);
              seenN+=r.seen||0; namesN+=r.names||0;
              kinds.push(r.kind + (book.sheets.length>1 ? " ['"+sh.name+"']" : ""));
              if(r.note) notes.push(r.note);
            }
          });
          res = (rows.length || seenN)
            ? {kind:[...new Set(kinds)].join(", ")+" (from Excel)", rows, seen:seenN, names:namesN,
               note:notes.join(" · ")}
            : {kind:"Excel", rows:[], note:"workbook read ("+book.sheets.length+" sheet"+
                (book.sheets.length===1?"":"s")+"), but no sheet held data the tool recognises"};
        }catch(err){ res={kind:"Excel",rows:[],note:"Excel read error: "+err.message}; }
      } else if(isPdf){
        try{
          const ex=extractPdfText(bytes);
          if(ex.text && ex.text.trim().length>20){
            PDF_ITEMS = ex.items || null;
            try{ res=parseFile(f.name.replace(/\.pdf$/i,".txt"), ex.text); }
            finally{ PDF_ITEMS = null; }
            res.kind=(res.kind||"text")+" (from PDF)";
            res.note=(ex.note+(res.note?" · "+res.note:""));
            if(!res.rows.length && !res.seen)
              res.note="text was recovered from the PDF, but no flow records could be read from it";
          } else {
            res={kind:"PDF",rows:[],note:ex.note};
          }
        }catch(err){ res={kind:"PDF",rows:[],note:"PDF read error: "+err.message}; }
      } else if(isCap){
        try{ res={kind:"pcap", ...parsePcapBuffer(rd.result, f.name)}; }
        catch(err){ res={kind:"error",rows:[],note:"capture parse error: "+err.message}; }
      } else {
        text = decodeBytes(rd.result);
        try{ res=parseFile(f.name, text); }
        catch(err){ res={kind:"error",rows:[],note:"parse error: "+err.message}; }
      }
      try{
        const ag=$("airgap").checked, enc=$("impEnclave").value.trim(), eph=$("ephem").value.trim();
        const coll=$("impCollector")?$("impCollector").value.trim():"";
        res.rows.forEach(r=>{
          if(!r.boundary){
            const d=deriveBoundary(r);
            // the air-gapped default only applies when nothing could be derived
            // air-gapped means it stays inside, which is Internal, not a B number
            r.boundary = d || (ag ? INTERNAL_BND : "");
          }
          if(enc && !r.enclave) r.enclave=enc;
          if(coll && !r.collector) r.collector=coll;
          if(eph && !r.srcPort && r.direction==="Inbound") r.srcPort=eph;
          // strip terminal escapes / control characters before anything downstream sees them
          for(const k in r){ if(typeof r[k]==="string") r[k]=xmlClean(r[k]).replace(/\n+/g," ").trim(); }
          normalizeEndpoints(r); normalizeBoundary(r);
        });
        // attribute wildcard listeners to the host the collector ran on
        const hh = readHostHeader(text);
        if(hh.name || hh.ip){
          res.rows.forEach(r=>{
            const wild = !r.dest || r.dest==="0.0.0.0" || r.dest==="::" || r.dest==="*";
            if(wild){
              if(hh.ip) r.dest=hh.ip;
              if(hh.name && !r.dstHost) r.dstHost=hh.name;
            }
            if(!r.collector) r.collector=hh.name||hh.ip;
          });
          if(hh.ip && hh.name) learnHost(hh.ip, hh.name, "collector");
        }
        // anything that does not look like network data never reaches the register
        const before=res.rows.length;
        res.rows=res.rows.filter(rowLooksReal);
        const dropped=before-res.rows.length;
        /* A listener bound to loopback, or a flow that stays on loopback,
           cannot leave the host and so crosses no boundary. PPSM does not
           register those, and on a fleet of Linux hosts they would otherwise
           be the bulk of the rows. */
        const loop=res.rows.filter(r=>{
          const d=r.dest, s=r.src;
          if(!d || !isLoopback(d)) return false;
          return !s || isLoopback(s);
        }).length;
        if(loop) res.rows=res.rows.filter(r=>!(r.dest && isLoopback(r.dest) && (!r.src || isLoopback(r.src))));
        /* IPv4-only environments: an IPv6 row is noise, not evidence. Set
           aside rather than dropped silently, so the count is visible. */
        let v6=0;
        if(CFG.ipv4Only!==false){
          const before6=res.rows.length;
          res.rows=res.rows.filter(r=>!(isIPv6Addr(r.src) || isIPv6Addr(r.dest)));
          v6=before6-res.rows.length;
        }
        if(dropped) res.note=(res.note?res.note+" · ":"")+dropped+
          " line"+(dropped===1?"":"s")+" ignored (not flow data)";
        if(loop) res.note=(res.note?res.note+" · ":"")+loop+
          " loopback-only service"+(loop===1?"":"s")+" skipped (cannot leave the host)";
        if(v6) res.note=(res.note?res.note+" · ":"")+v6+
          " IPv6 row"+(v6===1?"":"s")+" skipped (IPv4 only)";
        if(DIFF_CAPTURE){
          DIFF_CAPTURE.rows.push(...res.rows); DIFF_CAPTURE.kinds.push(res.kind||"");
          done(); return;
        }
        learnFromRows(res.rows);
        if(CFG.autoResolveHosts){
          res.rows.forEach(r=>{
            if(r.src && !r.srcHost && HOSTMAP.has(r.src)) r.srcHost=HOSTMAP.get(r.src).name;
            if(r.dest && !r.dstHost && HOSTMAP.has(r.dest)) r.dstHost=HOSTMAP.get(r.dest).name;
          });
        }
        if(CFG.autoEnrich) enrichRows(res.rows, null, false);
        const mres=mergeIntoRegister(res.rows); res.merged=mres.merged; render();
      }catch(err){ res.note="post-process error: "+err.message; }
      if(res.rows.length){
        const m=res.merged||0;
        const note=(res.note||"")+(m?((res.note?" · ":"")+m+" merged with flows already seen"):"");
        logFile(f.name, res.kind, res.rows.length, note);
      }
      else if(res.seen || res.names){
        // a hosts file, DNS zone, DHCP lease list or inventory export adds
        // names rather than flows — that is a successful import
        logNames(f.name, res.kind, res.seen||res.names||0, res.names||0, res.note);
      }
      else {
        const reason = (res.note && /error/i.test(res.note)) ? res.note
          : (isPdf ? ("The PDF was read, but no flow records could be recovered from it. "+
                      (res.note||"")+" If it is a scan or an image export there is no text to recover — "+
                      "go back to the original log. If it does contain a table, try selecting the text, "+
                      "pasting it into a .txt file and importing that.")
                   : diagnoseFile(f.name, text));
        /* A read-me or notes file sitting in a collection folder is not an
           import failure. Log it and move on rather than raising a popup for
           something the person never meant to import. */
        if(/looks like a document rather than captured data/.test(reason)){
          logFile(f.name, "skipped", 0, "not data — ignored");
        } else {
          logFile(f.name, "unknown", 0, reason);
          fails.push({name:f.name, reason});
        }
      }
      done();
    };
    rd.onerror=()=>{ const reason=readErrorReason(rd.error); logFile(f.name,"error",0,reason); fails.push({name:f.name,reason}); done(); };
    try{ rd.readAsArrayBuffer(f); }
    catch(err){ const reason="The browser could not start reading this file: "+err.message; logFile(f.name,"error",0,reason); fails.push({name:f.name,reason}); done(); }
  });
}

// Map a FileReader error to a plain-language cause
function readErrorReason(err){
  const n=err&&err.name;
  if(n==="NotReadableError") return "The file could not be read — it may be locked, open in another program, or you don't have permission to read it. Close it elsewhere, copy it to a local folder you own, and try again.";
  if(n==="SecurityError")    return "The browser blocked access to this file for security reasons. Copy it to a normal local folder (not a restricted/network path) and retry.";
  if(n==="NotFoundError")    return "The file was not found — it may have been moved or deleted while loading. Re-select it.";
  if(n==="AbortError")       return "Reading the file was interrupted. Try again.";
  return "The file could not be read"+(n?(" ("+n+")"):"")+". Copy it to a local folder and re-select it.";
}

// Inspect content to explain WHY a read-but-unrecognized file did not import
function diagnoseFile(name, content){
  const lower=(name||"").toLowerCase();
  const head=(content||"").slice(0,3000);
  const t=head.replace(/^\uFEFF/,"").replace(/^\s+/,"");
  if(!content || !content.trim()) return "The file is empty (0 bytes of text). Re-export the scan and confirm it saved correctly.";
  if(t.startsWith("%PDF") || /^%PDF/.test(head))
    return "This is a PDF, not a log file. A PDF stores text as page layout, so the columns of a Zeek conn.log, a NetFlow cache or a firewall connection table do not survive being printed to one. Go back to the original text: use the conn.log file itself, log the switch or firewall session to .txt, or Save As CSV from a spreadsheet. If a PDF really is all you have, select the table text, paste it into a .txt file and import that — space-aligned columns are read as well as tab-separated ones.";
  if(t.charCodeAt(0)===0x1f && t.charCodeAt(1)===0x8b)
    return "This file is gzip-compressed. Decompress it first (for example gunzip conn.log.gz or gunzip capture.pcap.gz) and import the result.";
  if(t.charCodeAt(0)===0xD0 && t.charCodeAt(1)===0xCF)
    return "This is an older binary Excel file (.xls). Open it in Excel and use File → Save As → Excel Workbook (.xlsx) or CSV, then import that.";
  if(t.charCodeAt(0)===0x50 && t.charCodeAt(1)===0x4b)
    return "This is a Zip or Office file. If it is a spreadsheet, use File → Save As → CSV. If it is an archive, extract it first and import the file inside.";
  if(/^\{\\rtf/.test(t))
    return "This is an RTF document. Open it and save as plain text (.txt), then import that.";
  if(/[\x00-\x08\x0E-\x1F]/.test(head.slice(0,800)))
    return "This looks like a binary file that isn't a recognized capture. pcap/pcapng ARE supported — but .db, .zip and Excel files are not. If this is a capture, confirm it isn't gzip-compressed (.pcap.gz): decompress it first.";
  if(/^<!doctype html|^<html/i.test(t)) return "This is an HTML report, not scan data. In Tenable/ACAS use Export → Nessus (.nessus) — not the HTML or PDF report.";
  /* Prose first: a document with plenty of words and almost no addresses is
     not a failed scan, it is just not data. */
  {
    const words=(head.match(/[A-Za-z]{3,}/g)||[]).length;
    const ips=(head.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)||[]).length;
    const lines=(head.match(/^.+$/mg)||[]).length;
    if(words>80 && ips<Math.max(3, lines*0.15))
      return "This looks like a document rather than captured data \u2014 mostly prose, with almost no addresses or ports in it. If you meant to import a log or a scan, export that from the tool that produced it. README and instruction files are not data sources.";
  }
  if(/^\s*\d{1,3}(\.\d{1,3}){3}\s+[A-Za-z]/m.test(head))
    return "This looks like a hosts file, but no usable entries were read. Each line needs an IP address followed by a hostname, for example '10.20.30.15 sql01.range.mil'. Loopback and localhost lines are skipped on purpose.";
  if(/\bIN\s+(A|AAAA|SOA|NS)\b/i.test(head))
    return "This looks like a DNS zone file, but no A or AAAA records were read. The tool needs address records, for example 'sql01 IN A 10.20.30.15'. If the file only holds CNAME, MX or NS records there are no addresses to learn.";
  if(/^\s*lease\s/mi.test(head))
    return "This looks like a DHCP lease file, but no client hostnames were found. Only leases carrying a client-hostname entry can be used.";
  if(/id\.orig_h|#fields|#separator/.test(head))
    return "This looks like a Zeek log, but no complete flow records could be read from it. Zeek conn.log needs the id.orig_h, id.orig_p, id.resp_h, id.resp_p and proto columns present. If the file has been through a PDF, an email body or a Word document the columns may have been re-wrapped — re-export the original conn.log.";
  if(/<nmaprun/i.test(head)) return "Recognized as nmap XML, but no open ports were found (all ports closed/filtered, or the scan is empty). Re-run with service detection, e.g. nmap -sS -sV -oX.";
  if(lower.endsWith(".nessus") || /<NessusClientData|<ReportHost/i.test(head)){
    if(!/<NessusClientData/i.test(head)) return "This .nessus file is missing its expected <NessusClientData_v2> root — it may be truncated or a different XML. Re-export from Tenable/ACAS as Export → Nessus.";
    return "Recognized as a Nessus/ACAS file, but no listening ports/services were found — it may contain only host-level findings, or be an empty report.";
  }
  if(/^<\?xml|^<\w+[\s>]/.test(t)) return "This is XML, but not a recognized nmap (-oX) or Nessus (.nessus) export. Confirm the scan was saved in one of those formats (the root tag should be <nmaprun> or <NessusClientData_v2>).";
  if(/,/.test(head) && /\r?\n/.test(head))
    return "This looks like CSV, but no port/service column was found. Include a header row with at least a 'Port' (or 'Destination Port') column — optionally Protocol, Service, and Source/Destination IP. (A Tenable CSV export works if it has a Port column.)";
  if(/\b(tcp|udp|listen|listening|estab)\b/i.test(head))
    return "This looks like connection text, but it didn't match a known netstat/ss layout. Use Windows 'netstat -ano', or Linux 'ss -tupna' / 'netstat -antup' output.";
  return "The file was read, but its format wasn't recognized. Supported: nmap XML (-oX), Nessus .nessus XML, Windows netstat -ano, Linux ss/netstat text, or CSV with a port column.";
}

function showImportErrors(fails){
  $("errBody").innerHTML =
    `<div class="st-summary bad">✗ ${fails.length} file${fails.length>1?"s":""} could not be imported</div>`+
    fails.map(f=>`<div class="err-item"><div class="err-name">${esc(f.name||"(dropped item)")}</div><div class="err-reason">${esc(f.reason)}</div></div>`).join("")+
    `<div class="err-foot"><b>Supported formats:</b> pcap / pcapng captures · Cisco <code>show conn</code> · NetFlow cache (table/csv) · Zeek <code>conn.log</code> · <code>pfirewall.log</code> · iptables/UFW · ASA syslog · tcpdump text · nmap XML (<code>-oX</code>) · Nessus/ACAS <code>.nessus</code> · Windows <code>netstat -ano</code> · Linux <code>ss -tupna</code> · CSV with a port column.<br>`+
    `<b>Quick check:</b> open the file in a text editor — a valid <code>.nessus</code> starts with <code>&lt;?xml</code> then <code>&lt;NessusClientData_v2&gt;</code>; nmap XML starts with <code>&lt;nmaprun&gt;</code>.</div>`;
  $("errModal").hidden=false;
}
function logNames(name,kind,seen,learned,note){
  const row=document.createElement("div"); row.className="logrow";
  const detail = learned ? (learned+" name"+(learned===1?"":"s")+" learned"+
                            (seen>learned ? " · "+(seen-learned)+" already known" : ""))
                         : (seen+" record"+(seen===1?"":"s")+" read — all already known");
  // what the parser added beyond the counts: aliases, the zone it qualified under, a warning
  const extra=String(note||"").split(/\s+·\s+/).filter(p=>/alias|qualified|zone|no addresses|neighbour/i.test(p));
  row.innerHTML=`<span class="tag ok">${esc(kind)}</span><span class="fn">${esc(name)}</span>
    <span class="det">${esc(detail+(extra.length?" · "+extra.join(" · "):""))}</span>`;
  $("loglist").prepend(row);
}
function logFile(name,kind,n,note){
  if(!name && !n && (kind==="note"||kind==="info")){
    // a message, not a file: show it as one
    const row=document.createElement("div"); row.className="logrow logmsg";
    // same shape as every other log row, so the list stays uniform
    row.innerHTML=`<span class="tag ${kind==="info"?"ok":"warn"}">${kind==="info"?"done":"note"}</span>`+
      `<span class="fn"></span>`+
      `<span class="det" style="flex:1;text-align:left">${esc(note||"")}</span>`;
    $("loglist").prepend(row);
    return;
  }
  const row=document.createElement("div"); row.className="logrow";
  const tag = n>0?'<span class="tag ok">'+kind+'</span>'
    : (kind==="unknown"||kind==="error")?'<span class="tag err">'+kind+'</span>'
    :'<span class="tag warn">'+kind+'</span>';
  row.innerHTML=`${tag}<span class="fn">${esc(name)}</span>
    <span class="det">${n} entr${n===1?"y":"ies"}${note?" · "+esc(note):""}</span>`;
  $("loglist").prepend(row);
}
function flash(msg,kind){logFile("",kind==="ok"?"info":"note",0,msg);
  const r=$("loglist").firstChild; if(r){r.querySelector(".tag").className="tag "+(kind==="ok"?"ok":(kind||"warn"));
    r.querySelector(".tag").textContent=kind==="ok"?"done":"note";}}
