"use strict";
/* ---------------- consolidate like endpoints ----------------
   Rows that share the same source, destination, protocol, boundary and
   direction differ only by port. eMASS accepts semicolon-separated ports,
   so those collapse into one registration. Data Service and Application
   name are joined the same way, aligned to their ports. */
function consolidateRows(rows){
  rows = rows || ROWS;
  const isRule = r => String(r.origin||"").indexOf("firewall-rule")>=0;
  const uniqJoin = arr => {
    const out=[]; const seen=new Set();
    arr.forEach(v=>{ const s=String(v==null?"":v).trim();
      if(s && !seen.has(s)){ seen.add(s); out.push(s); } });
    return out.join("; ");
  };
  const key = r => [
    isRule(r) ? "rule" : "seen",
    (r.src||r.srcHost||"").toLowerCase(),
    (r.dest||r.dstHost||"").toLowerCase(),
    (r.proto||"").toUpperCase(),
    bndCode(r.boundary),
    (r.direction||"").toLowerCase(),
    (r.vpn||""), (r.vpnType||"")
  ].join("|");

  const groups=new Map();
  rows.forEach(r=>{
    const k=key(r);
    if(!groups.has(k)) groups.set(k,[]);
    groups.get(k).push(r);
  });

  const absorbed=new Set();
  let collapsed=0, into=0;
  groups.forEach(g=>{
    if(g.length<2) return;
    // a group has to span more than one port to be worth joining; if every
    // row is the same port it is a true duplicate, left to Dedupe
    const ports=[...new Set(g.map(r=>String(r.dstPort||"").trim()).filter(Boolean))];
    if(ports.length<2){
      // identical rows: keep the most complete, drop the rest
      const keep=g.slice().sort((a,b)=>cells(b)-cells(a))[0];
      g.forEach(r=>{ if(r!==keep) absorbed.add(r); });
      collapsed += g.length-1; into++;
      return;
    }
    const keep=g.slice().sort((a,b)=>cells(b)-cells(a))[0];
    /* order the rows by port number so the joined lists line up */
    const ordered=g.slice().sort((a,b)=>(+a.dstPort||0)-(+b.dstPort||0));
    keep.dstPort     = uniqJoin(ordered.map(r=>r.dstPort));
    keep.dataService = uniqJoin(ordered.map(r=>r.dataService));
    keep.appName     = uniqJoin(ordered.map(r=>r.appName));
    keep.banner      = uniqJoin(ordered.map(r=>r.banner));
    keep.srcPort     = uniqJoin(ordered.map(r=>r.srcPort)) || keep.srcPort;
    // counters add up across the collapsed ports
    let pk=0,by=0; const tools=new Set();
    ordered.forEach(r=>{ pk+=(+r.pkts||0); by+=(+r.bytes||0);
      String(r.origin||"").split(/,\s*/).filter(Boolean).forEach(t=>tools.add(t));
      if(r!==keep) absorbed.add(r); });
    if(pk) keep.pkts=String(pk);
    if(by) keep.bytes=String(by);
    keep.origin=[...tools].join(", ");
    const note=ports.length+" ports consolidated: "+ordered.map(r=>r.dstPort).join(", ");
    if(String(keep.notes||"").indexOf(" ports consolidated")<0)
      keep.notes = keep.notes ? keep.notes+" \u00b7 "+note : note;
    collapsed += g.length-1; into++;
  });

  if(absorbed.size){
    for(let i=ROWS.length-1;i>=0;i--) if(absorbed.has(ROWS[i])) ROWS.splice(i,1);
    const live=new Set(ROWS.map(r=>r.id));
    [...SELECTED].forEach(id=>{ if(!live.has(id)) SELECTED.delete(id); });
  }
  // second pass: collapse several sources that reach the same service
  const sc = CFG.consolidateSources!==false ? consolidateSources(rows) : {collapsed:0,into:0};
  return {collapsed: collapsed+sc.collapsed, into: into+sc.into};
}
function cells(r){ return Object.values(r).filter(Boolean).length; }

/* ---------------- consolidate like sources ----------------
   After ports are joined, rows that share the same destination, port,
   protocol, boundary and direction differ only by WHO connects. Several
   workstations reaching one service is one registration; the source IPs and
   names are joined with semicolons, the same way ports are. A network source
   (a CIDR) or a row with no source is left alone. */
function consolidateSources(rows){
  rows = rows || ROWS;
  const isRule = r => String(r.origin||"").indexOf("firewall-rule")>=0;
  const uniqJoin = arr => { const out=[],seen=new Set();
    arr.forEach(v=>{ const s=String(v==null?"":v).trim(); if(s&&!seen.has(s)){seen.add(s);out.push(s);} });
    return out.join("; "); };
  const key = r => [
    isRule(r)?"rule":"seen",
    (r.dest||r.dstHost||"").toLowerCase(),
    (r.dstPort||"").toLowerCase(),
    (r.proto||"").toUpperCase(),
    bndCode(r.boundary),
    (r.direction||"").toLowerCase(),
    (r.dataService||"").toLowerCase(),
    (r.vpn||""),(r.vpnType||"")
  ].join("|");

  const groups=new Map();
  rows.forEach(r=>{
    // only roll up rows that actually have a single-host source to merge
    if(!r.src && !r.srcHost) return;
    if(isCidr(r.src)) return;
    const k=key(r);
    if(!groups.has(k)) groups.set(k,[]);
    groups.get(k).push(r);
  });

  const absorbed=new Set(); let collapsed=0,into=0;
  groups.forEach(g=>{
    const srcs=[...new Set(g.map(r=>(r.src||r.srcHost||"").toLowerCase()).filter(Boolean))];
    if(srcs.length<2) return;                      // nothing to merge
    const keep=g.slice().sort((a,b)=>cells(b)-cells(a))[0];
    const ordered=g.slice().sort((a,b)=>cmpIp(a.src,b.src));
    keep.src     = uniqJoin(ordered.map(r=>r.src));
    keep.srcHost = uniqJoin(ordered.map(r=>r.srcHost));
    keep.srcPort = uniqJoin(ordered.map(r=>r.srcPort)) || keep.srcPort;
    let pk=0,by=0; const tools=new Set();
    ordered.forEach(r=>{ pk+=(+r.pkts||0); by+=(+r.bytes||0);
      String(r.origin||"").split(/,\s*/).filter(Boolean).forEach(t=>tools.add(t));
      if(r!==keep) absorbed.add(r); });
    if(pk) keep.pkts=String(pk);
    if(by) keep.bytes=String(by);
    keep.origin=[...tools].join(", ");
    const n=srcs.length+" sources consolidated";
    if(String(keep.notes||"").indexOf(" sources consolidated")<0)
      keep.notes = keep.notes ? keep.notes+" \u00b7 "+n : n;
    collapsed += g.length-1; into++;
  });
  if(absorbed.size){
    for(let i=ROWS.length-1;i>=0;i--) if(absorbed.has(ROWS[i])) ROWS.splice(i,1);
    const live=new Set(ROWS.map(r=>r.id));
    [...SELECTED].forEach(id=>{ if(!live.has(id)) SELECTED.delete(id); });
  }
  return {collapsed, into};
}
/* sort IPv4 numerically so a joined source list reads in order */
function cmpIp(a,b){
  const f=s=>{ const m=String(s||"").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    return m?((+m[1]<<24)>>>0)+(+m[2]<<16)+(+m[3]<<8)+(+m[4]):0; };
  return f(a)-f(b) || String(a||"").localeCompare(String(b||""));
}


/* ---------------- eMASS PPSM export (reading one back) ----------------
   eMASS exports registered PPSM entries as a CSV, or an .xlsx whose tab is
   named "PPSM Info" / "PPSM". Column names vary a little between eMASS
   versions, so match them loosely. Rows come in marked "Registered" so they
   are told apart from freshly collected traffic. */
function looksLikeEmassExport(header){
  const c=header.map(x=>String(x||"").trim().toLowerCase());
  const has=n=>c.some(x=>x===n||x.indexOf(n)>=0);
  // the combination that identifies an eMASS PPSM export rather than any CSV
  const port = has("port");
  const svc  = has("data service")||has("service");
  const proto= has("protocol");
  const host = has("host")||has("ip")||has("destination")||has("fqdn");
  const emassy = has("boundary")||has("connection logical")||has("ppsm")||has("data service");
  return port && proto && (svc||host) && emassy;
}

/* One end of a register row, from its address cell and its FQDN cell. Either
   cell may hold several values joined by semicolons (the template allows it),
   a hostname in the address column, an address in the FQDN column, trailing
   dots, or upper case. Returns [{ip, host}, ...] — one entry per distinct
   endpoint, addresses paired with names by position where the counts match. */
function emassEndpoints(addrCell, nameCell){
  const split=v=>String(v||"").split(/[;,\n]/).map(s=>s.trim()).filter(s=>s && !/^(n\/?a|none|-|null)$/i.test(s));
  const ips=[], names=[];
  const take=v=>{
    const s=v.replace(/\.$/,"");
    if(isCidr(s)){ ips.push(s); return; }
    const e=splitIpHost(s);
    if(e.ip) ips.push(e.ip);
    if(e.host){ const h=e.host.replace(/\.$/,""); names.push(h.indexOf(".")>0 ? h.toLowerCase() : h); }
  };
  split(addrCell).forEach(take); split(nameCell).forEach(take);
  const uniq=a=>[...new Set(a)];
  // "wsus11" and "wsus11.range2.mil" in the two cells are one host: keep the FQDN
  const fold=a=>{ const out=[]; a.forEach(n=>{
    const i=out.findIndex(o=>sameHost(o,n));
    if(i<0) out.push(n); else if(n.indexOf(".")>0 && out[i].indexOf(".")<0) out[i]=n; }); return out; };
  const A=uniq(ips), N=fold(uniq(names));
  if(!A.length && !N.length) return [{ip:"",host:""}];
  if(!A.length) return N.map(h=>({ip:"",host:h}));
  if(!N.length) return A.map(ip=>({ip,host:""}));
  if(A.length===N.length) return A.map((ip,i)=>({ip,host:N[i]}));
  // counts differ: never guess which name belongs to which address. The
  // addresses stand on their own and the names resolve through the inventory.
  return A.map(ip=>({ip,host:""})).concat(N.map(h=>({ip:"",host:h})));
}

function parseEmassExport(text){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return {rows:[],note:""};
  // find the header row: eMASS puts banners and a system block above it
  let hi=-1, hdr=null;
  for(let i=0;i<Math.min(lines.length,30);i++){
    const c=splitCsvLine(lines[i]).map(s=>s.replace(/^"|"$/g,"").trim());
    if(c.length>=4 && looksLikeEmassExport(c)){ hi=i; hdr=c.map(x=>x.toLowerCase()); break; }
  }
  if(hi<0) return {rows:[],note:""};

  const col=(...names)=>{ for(const n of names){ const i=hdr.indexOf(n); if(i>=0) return i; }
                          for(const n of names){ const i=hdr.findIndex(x=>x.indexOf(n)>=0); if(i>=0) return i; }
                          return -1; };
  const iType=col("type"), iApp=col("application/software record name","application","software record"),
        iProto=col("protocol"), iSvc=col("data service","service"), iPort=col("port"),
        iBnd=col("boundary"), iDir=col("direction"),
        iVpn=col("vpn / encrypted tunnel traffic","vpn traffic"), iVpnT=col("vpn tunnel type"),
        iSrc=col("source ip address","source ip"), iSrcN=col("source fqdn","source"),
        iSrcPt=col("connection logical source point"),
        iDst=col("destination ip address","destination ip"), iDstN=col("destination fqdn","destination"),
        iDstPt=col("connection logical destination point"),
        iSrcLoc=col("source physical location","source physical"),
        iDstLoc=col("destination physical location","destination physical"),
        iPurpose=col("purpose");

  const rows=[], seen=new Set(), coll=collNow();
  let named=0;
  lines.slice(hi+1).forEach(l=>{
    const c=splitCsvLine(l).map(s=>s.replace(/^"|"$/g,"").trim());
    if(!c.length || c.every(x=>!x)) return;
    // eMASS exports can carry several ports in one cell, separated by ;
    const portField=iPort>=0?c[iPort]:"";
    if(!portField && !(iSvc>=0&&c[iSvc])) return;              // not a data row
    // a banner or the "# of records" footer is not a row
    if(/controlled unclassified|date exported|system name|^\s*#/i.test(l)) return;

    const proto=normProto(iProto>=0?c[iProto]:"");
    /* Each end of the row is an address cell and an FQDN cell, and in a
       register kept by hand either may hold the other's content: a hostname
       where the address belongs, several sources joined by semicolons, a
       trailing dot or upper case from a copy-paste. Read every value in both
       cells, keep addresses as addresses and names as names, and give each
       distinct endpoint its own row (source consolidation joins them back
       together on the way out). */
    const srcEnds=emassEndpoints(iSrc>=0?c[iSrc]:"", iSrcN>=0?c[iSrcN]:"");
    const dstEnds=emassEndpoints(iDst>=0?c[iDst]:"", iDstN>=0?c[iDstN]:"");
    // learn names both ways
    srcEnds.concat(dstEnds).forEach(e=>{ if(e.ip && e.host && learnHost(e.ip,e.host,"emass")) named++; });

    const ports=String(portField).split(/[;,]/).map(x=>x.trim()).filter(Boolean);
    const svcs =String(iSvc>=0?c[iSvc]:"").split(/[;,]/).map(x=>x.trim());
    (ports.length?ports:[""]).forEach((port,idx)=>{
      srcEnds.forEach(se=>dstEnds.forEach(de=>{
        const key=[proto,se.ip||se.host,de.ip||de.host,port].join("|").toLowerCase();
        if(seen.has(key)) return; seen.add(key);
        rows.push(blank({
          emassType: iType>=0?c[iType]:"",
          appName: iApp>=0?c[iApp]:"",
          proto,
          dataService: svcs[idx]||svcs[0]||(iSvc>=0?c[iSvc]:""),
          dstPort: port,
          boundary: bndCode(iBnd>=0?c[iBnd]:"") || (iBnd>=0?c[iBnd]:""),
          direction: iDir>=0?c[iDir]:"",
          vpn: iVpn>=0?c[iVpn]:"", vpnType: iVpnT>=0?c[iVpnT]:"",
          src: se.ip, srcHost: se.host,
          srcLoc: iSrcLoc>=0?c[iSrcLoc]:"", srcPoint: iSrcPt>=0?c[iSrcPt]:"",
          dest: de.ip, dstHost: de.host,
          dstLoc: iDstLoc>=0?c[iDstLoc]:"", dstPoint: iDstPt>=0?c[iDstPt]:"",
          justification: iPurpose>=0?c[iPurpose]:"",
          status:"Registered",               // already in eMASS
          origin:"emass-export", collector:coll,
          notes:"from the eMASS PPSM export"
        }));
      }));
    });
  });
  return {rows, note: rows.length?("eMASS PPSM export: "+rows.length+" registered entr"+
    (rows.length===1?"y":"ies")+(named?" · "+named+" named":"")):""};
}

/* ---------------- export ---------------- */
const COLS=[["enclave","Enclave"],["src","Source IP"],["srcHost","Source Hostname"],
  ["dest","Destination IP"],["dstHost","Destination Hostname"],["proto","Protocol"],
  ["srcPort","Source Port"],["dstPort","Destination Port"],["dataService","Data Service / Application"],
  ["banner","Service / Banner"],["direction","Direction"],["boundary","Boundary Crossed"],
  ["isaRef","Interconnection / Agreement Ref"],
  ["data","Data Description"],["classification","Classification"],["justification","Mission Justification"],  ["assurance","Assurance Category"],["status","Status"],["cal","CAL Listed? (Y/N)"],
  ["collector","Collector / Source Host"],["srcZone","Source Zone/Interface"],["dstZone","Destination Zone/Interface"],
  ["calRef","CAL / VA Report Reference"],["registryId","PPSM Registry ID"],
  ["subPath","Submission Path"],
  ["appName","Application/Software Record Name"],["emassType","Type (eMASS)"],
  ["srcLoc","Source Physical Location / CSP"],["dstLoc","Destination Physical Location / CSP"],
  ["srcPoint","Connection Logical Source Point"],["dstPoint","Connection Logical Destination Point"],
  ["vpn","VPN / Encrypted Tunnel Traffic"],["vpnType","VPN Tunnel Type"],
  ["pkts","Packets"],["bytes","Bytes"],["notes","Notes"],["origin","Source Tool"]];

function envVal(){ const s=$("m_env").value; return s==="Other" ? ($("m_env_other").value.trim()||"Other") : s; }
function meta(){
  const v=id=>{ const el=$(id); return el?el.value:""; };
  return {system:$("m_system").value,version:$("m_version").value,env:envVal(),
  classification:$("m_class").value,docClass:$("m_docclass").value,desc:$("m_desc").value,
  poc:$("m_poc").value,date:$("m_date").value,
  // the eMASS template's own header block
  exportedBy:v("m_exportedby")||$("m_poc").value, exportDate:v("m_date"),
  office:v("m_office"), owner:v("m_owner"), systemId:v("m_sysid"), ditpr:v("m_ditpr"),
  pocName:v("m_pocname")||$("m_poc").value, pocPhone:v("m_pocphone"), pocEmail:v("m_pocemail"),
  reviewDate:v("m_reviewdate"), reviewedBy:v("m_reviewedby")};}

function csvCell(v){v=v==null?"":String(v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;}
$("expCsv").onclick=()=>{
  const m=meta();
  const metaCols=[["System",m.system],["Version",m.version],["Environment",m.env],["Description",m.desc]];
  const lines=[];
  // header block as leading columns repeated is unusual; instead prepend metadata rows then table
  lines.push("# PPSM Register");
  metaCols.forEach(([k,v])=>lines.push("# "+k+","+csvCell(v)));
  lines.push("# POC,"+csvCell(m.poc)+",Date,"+csvCell(m.date));
  lines.push("");
  const VC=visibleCols();
  lines.push(VC.map(c=>csvCell(asciiSafe(c[1]))).join(","));
  ROWS.forEach(r=>lines.push(VC.map(c=>csvCell(asciiSafe(r[c[0]]))).join(",")));
  download((m.system||"ppsm")+"-register.csv", lines.join("\n"), "text/csv");
};

/* everything the app holds, as one JSON object */
function sessionSnapshot(){
  return {meta:meta(),rows:ROWS,cfg:CFG,hostmap:[...HOSTMAP.entries()],
          aliases:[...ALIASES.entries()], software:[...SOFTWARE_INV.entries()]};
}
const META_FIELDS=["exportedby","office","owner","sysid","ditpr","pocname","pocphone","pocemail","reviewdate","reviewedby"];
function restoreSession(d){
  if(d.meta){$("m_system").value=d.meta.system||"";$("m_version").value=d.meta.version||"";
    const ev=d.meta.env||"";
    if(ev===""||ev==="Unclassified"||ev==="Classified"){ $("m_env").value=ev; $("m_env_other").value=""; $("m_env_other").style.display="none"; }
    else { $("m_env").value="Other"; $("m_env_other").value=ev; $("m_env_other").style.display="block"; }
    $("m_desc").value=d.meta.desc||"";
    $("m_class").value=d.meta.classification||"";
    $("m_docclass").value=d.meta.docClass||"UNCLASSIFIED"; setBanner($("m_docclass").value||"UNCLASSIFIED");
    $("m_poc").value=d.meta.poc||"";$("m_date").value=d.meta.date||"";
    META_FIELDS.forEach(k=>{ const el=$("m_"+k); const key=k==="exportedby"?"exportedBy":k==="sysid"?"systemId":k==="pocname"?"pocName":
      k==="pocphone"?"pocPhone":k==="pocemail"?"pocEmail":k==="reviewdate"?"reviewDate":k==="reviewedby"?"reviewedBy":k;
      if(el && d.meta[key]!==undefined) el.value=d.meta[key]||""; });}
  if(d.cfg) CFG=Object.assign(JSON.parse(JSON.stringify(CFG_DEFAULTS)),d.cfg);
  ROWS=(d.rows||[]).map(r=>normalizeBoundary(normalizeEndpoints(blank(r))));
  if(d.hostmap) HOSTMAP=new Map(d.hostmap);
  if(d.software) SOFTWARE_INV=new Map(d.software);
  ALIASES.clear(); if(d.aliases) d.aliases.forEach(([a,t])=>ALIASES.set(a,t));
  learnFromRows(); applyColumnVisibility(); render(); renderEndpoints();
  if(typeof renderDiagram==="function" && ROWS.length) renderDiagram();
}
$("saveJson").onclick=()=>download((meta().system||"ppsm")+"-session.json",
  JSON.stringify(sessionSnapshot(),null,2),"application/json");
$("loadJson").onclick=()=>$("jsonFile").click();
$("jsonFile").onchange=e=>{const f=e.target.files[0];if(!f)return;
  const rd=new FileReader();rd.onload=()=>{try{ restoreSession(JSON.parse(rd.result)); flash("Session loaded.","ok"); }
  catch(err){flash("Invalid session file: "+err.message,"err");}};
  rd.readAsText(f); e.target.value="";};

$("expReport").onclick=()=>{
  const m=meta(); const banner=$("classbar").textContent;
  const rowsHtml=ROWS.map((r,i)=>`<tr class="${FLAGGED(r.boundary)?'x':''}">
    <td>${i+1}</td><td>${esc(r.enclave)}</td><td>${esc(r.src)}</td><td>${esc(r.dest)}</td><td>${esc(r.proto)}</td>
    <td>${esc(r.srcPort)}</td><td>${esc(r.dstPort)}</td><td>${esc(r.dataService)}</td><td>${esc(r.banner)}</td>
    <td>${esc(r.direction)}</td><td>${esc(r.boundary)}</td><td>${esc(r.isaRef)}</td><td>${esc(r.data)}</td>
    <td>${esc(r.classification)}</td><td>${esc(r.justification)}</td>
    <td>${esc(r.assurance)}</td><td>${esc(r.status)}</td><td>${esc(r.cal)}</td></tr>`).join("");
  const html=`<!doctype html><html><head><meta charset="utf-8"><title>PPSM Register — ${esc(m.system)}</title>
  <style>body{font-family:Georgia,serif;color:#111;margin:0;padding:0}
  .b{text-align:center;font:700 11px monospace;letter-spacing:.2em;padding:5px;background:#1c5e3a;color:#fff}
  .wrap{padding:28px 34px}h1{font-size:18px;margin:0 0 2px}.sub{color:#555;font-size:12px;margin-bottom:14px}
  table{border-collapse:collapse;width:100%;font-size:9.5px;font-family:Arial,sans-serif}
  th{background:#1f2a36;color:#fff;text-align:left;padding:5px 6px;font-size:8.5px;letter-spacing:.04em}
  td{border:1px solid #ccc;padding:4px 6px;vertical-align:top}
  tr.x td{background:#fff4e0}
  .meta{font-size:12px;margin-bottom:16px;line-height:1.7}.meta b{display:inline-block;width:120px;color:#444}
  @media print{.b{-webkit-print-color-adjust:exact;print-color-adjust:exact}th,tr.x td{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  </style></head><body>
  <div class="b">${esc(banner)}</div>
  <div class="wrap">
  <h1>Ports, Protocols &amp; Services Management Register</h1>
  <div class="sub">DoDI 8551.01 data model · generated ${new Date().toISOString().slice(0,10)}</div>
  <div class="meta">
    <div><b>System / Enclave</b> ${esc(m.system)||"—"}</div>
    <div><b>Version</b> ${esc(m.version)||"—"}</div>
    <div><b>Environment</b> ${esc(m.env)||"—"}</div>
    <div><b>Classification</b> ${esc(m.classification)||"—"}</div>
    <div><b>Description</b> ${esc(m.desc)||"—"}</div>
    <div><b>POC</b> ${esc(m.poc)||"—"} &nbsp;&nbsp; <b style="width:auto">Date</b> ${esc(m.date)||"—"}</div>
    <div><b>Total entries</b> ${ROWS.length} &nbsp;&nbsp; <b style="width:auto">Boundary-crossing</b> ${ROWS.filter(r=>FLAGGED(r.boundary)).length}</div>
  </div>
  <table><thead><tr><th>#</th><th>Enclave</th><th>Source</th><th>Dest</th><th>Proto</th><th>Src Pt</th><th>Dst Pt</th><th>Data Service</th><th>Service / Banner</th>
  <th>Direction</th><th>Boundary</th><th>ISA / Agreement</th><th>Data</th><th>Class</th><th>Mission Justification</th>
  <th>Assurance</th><th>Status</th><th>CAL?</th></tr></thead><tbody>${rowsHtml}</tbody></table>
  </div>
  <div class="b">${esc(banner)}</div>
  <script>window.onload=()=>window.print()<\/script>
  </body></html>`;
  const win=window.open("","_blank");
  if(win && win.document){ win.document.write(html); win.document.close(); }
  else { download((m.system||"ppsm")+"-report.html", html, "text/html");
    flash("Popup blocked — report saved as an HTML file. Open it, then print to PDF.","warn"); }
};

/* ---------------- native .xlsx export (offline, no dependencies) ---------------- */
const CRC_TABLE=(()=>{const t=[];for(let n=0;n<256;n++){let c=n;
  for(let k=0;k<8;k++)c=c&1?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}return t;})();
function crc32(b){let c=0xFFFFFFFF;for(let i=0;i<b.length;i++)c=CRC_TABLE[(c^b[i])&0xFF]^(c>>>8);return (c^0xFFFFFFFF)>>>0;}
function colLetter(i){let s="";i++;while(i>0){const m=(i-1)%26;s=String.fromCharCode(65+m)+s;i=Math.floor((i-1)/26);}return s;}

/* Wrap bytes as DEFLATE stored blocks (BTYPE=00). This is valid deflate
   output — method 8 — so the zip looks like one Excel wrote itself, which its
   strict loader is happier with than a method-0 (stored) entry. */
function deflateStored(data){
  const out=[]; const n=data.length; let p=0;
  do{
    const len=Math.min(65535, n-p);
    const last=(p+len>=n)?1:0;
    out.push(last);                                   // BFINAL on last block, BTYPE=00
    out.push(len&255,(len>>>8)&255);
    const nlen=(~len)&0xFFFF; out.push(nlen&255,(nlen>>>8)&255);
    for(let i=0;i<len;i++) out.push(data[p+i]);
    p+=len;
  }while(p<n);
  if(n===0){ out.push(1,0,0,0xFF,0xFF); }
  return new Uint8Array(out);
}
function zipStore(files){
  const enc=new TextEncoder(), chunks=[], central=[]; let offset=0;
  const u16=n=>[n&255,(n>>>8)&255], u32=n=>[n&255,(n>>>8)&255,(n>>>16)&255,(n>>>24)&255];
  for(const f of files){
    const name=enc.encode(f.name), crc=crc32(f.data), sz=f.data.length;
    const comp=deflateStored(f.data), csz=comp.length;
    const local=[].concat(u32(0x04034b50),u16(20),u16(0),u16(8),u16(0),u16(0x21),  // method 8 = deflate
      u32(crc),u32(csz),u32(sz),u16(name.length),u16(0));
    chunks.push(new Uint8Array(local),name,comp);
    central.push({name,crc,csz,sz,offset}); offset+=local.length+name.length+csz;
  }
  const cdStart=offset; let cdSize=0;
  for(const c of central){
    const cd=[].concat(u32(0x02014b50),u16(20),u16(20),u16(0),u16(8),u16(0),u16(0x21),
      u32(c.crc),u32(c.csz),u32(c.sz),u16(c.name.length),u16(0),u16(0),u16(0),u16(0),u32(0),u32(c.offset));
    const u=new Uint8Array(cd.length+c.name.length); u.set(new Uint8Array(cd),0); u.set(c.name,cd.length);
    chunks.push(u); cdSize+=u.length;
  }
  chunks.push(new Uint8Array([].concat(u32(0x06054b50),u16(0),u16(0),
    u16(central.length),u16(central.length),u32(cdSize),u32(cdStart),u16(0))));
  let total=0; chunks.forEach(c=>total+=c.length);
  const out=new Uint8Array(total); let p=0; chunks.forEach(c=>{out.set(c,p);p+=c.length;});
  return out;
}

function buildXlsx(m, rows){
  const enc=new TextEncoder();
  const cell=(ref,val,s)=>{ const v=asciiSafe(val);
    if(v==="") return s?`<c r="${ref}" s="${s}"/>`:"";
    return `<c r="${ref}"${s?` s="${s}"`:""} t="inlineStr"><is><t xml:space="preserve">${esc(v)}</t></is></c>`; };
  const NC=COLS.length, last=rows.length+6, lastCol=colLetter(NC-1);
  let body="";
  body+=`<row r="1"><c r="A1" t="inlineStr" s="4"><is><t>${xesc("PPSM Register — "+(m.system||"")+" — verify against your Component's official sheet before submission")}</t></is></c></row>`;
  const meta=(rn,a,av,h,hv)=>`<row r="${rn}">`+cell("A"+rn,a,4)+cell("B"+rn,av,0)+cell("H"+rn,h,4)+cell("I"+rn,hv,0)+`</row>`;
  body+=meta(2,"System:",m.system,"Environment:",m.env);
  body+=meta(3,"Version:",m.version,"POC:",m.poc);
  body+=meta(4,"Description:",m.desc,"Date:",m.date);
  body+=meta(5,"Classification:",m.classification,"","");
  body+=`<row r="6">`+COLS.map((c,i)=>cell(colLetter(i)+"6",c[1],1)).join("")+`</row>`;
  rows.forEach((r,idx)=>{ const rn=idx+7; const s=FLAGGED(r.boundary)?3:2;
    body+=`<row r="${rn}">`+COLS.map((c,i)=>cell(colLetter(i)+rn, r[c[0]], s)).join("")+`</row>`; });

  const WIDTH_BY_KEY={enclave:16,src:15,srcHost:22,dest:15,dstHost:22,proto:9,srcPort:11,
    dstPort:11,dataService:20,banner:22,direction:13,boundary:26,isaRef:14,data:24,
    classification:18,justification:30,assurance:20,status:13,cal:11,collector:20,
    srcZone:14,dstZone:14,pkts:9,bytes:11,notes:26,origin:13};
  const colsXml=`<cols>`+COLS.map((c,i)=>
    `<col min="${i+1}" max="${i+1}" width="${WIDTH_BY_KEY[c[0]]||16}" customWidth="1"/>`).join("")+`</cols>`;
  const views=`<sheetViews><sheetView workbookViewId="0"><pane ySplit="6" topLeftCell="A7" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A7" sqref="A7"/></sheetView></sheetViews>`;
  const idxOf=key=>COLS.findIndex(c=>c[0]===key);
  /* Excel caps an inline list at 255 characters, so only short lists go inline. */
  const DVF=[["direction",'Inbound,Outbound,Bidirectional,Listening'],
    ["assurance",'Best Practice,Conditional,Banned,Exception,Local Service (AO),Unassigned'],
    ["status",'New,Registered,Pending VA,Pending CLSA,Exception'],["cal",'Y,N,Pending']]
    .filter(([f])=>idxOf(f)>=0)
    .filter(([,l])=>l.length<=250);
  const dv=DVF.length ? `<dataValidations count="${DVF.length}">`+DVF.map(([f,l])=>{
    const c=colLetter(idxOf(f));
    return `<dataValidation type="list" allowBlank="1" showInputMessage="1" showErrorMessage="1" sqref="${c}7:${c}${Math.max(last,7)}"><formula1>"${esc(l)}"</formula1></dataValidation>`;
  }).join("")+`</dataValidations>` : "";
  const sheet=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><dimension ref="A1:${lastCol}${last}"/>${views}<sheetFormatPr defaultRowHeight="15"/>${colsXml}<sheetData>${body}</sheetData><autoFilter ref="A6:${lastCol}6"/>${dv}</worksheet>`;

  const styles=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="3"><font><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Arial"/></font><font><b/><sz val="11"/><name val="Arial"/></font></fonts><fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F2A36"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF4E0"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFC9D2DC"/></left><right style="thin"><color rgb="FFC9D2DC"/></right><top style="thin"><color rgb="FFC9D2DC"/></top><bottom style="thin"><color rgb="FFC9D2DC"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;

  const ct=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
  const rels=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const wbxml=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="PPSM Register" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const wbrels=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;

  return zipStore([
    {name:"[Content_Types].xml", data:enc.encode(ct)},
    {name:"_rels/.rels", data:enc.encode(rels)},
    {name:"xl/workbook.xml", data:enc.encode(wbxml)},
    {name:"xl/_rels/workbook.xml.rels", data:enc.encode(wbrels)},
    {name:"xl/styles.xml", data:enc.encode(styles)},
    {name:"xl/worksheets/sheet1.xml", data:enc.encode(sheet)},
  ]);
}
$("expXlsx").onclick=()=>{
  const m=meta();
  const bytes=buildXlsx(m, ROWS);
  download((m.system||"ppsm")+"-register.xlsx", bytes,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
};

function download(name,content,type){
  const blob=new Blob([content],{type});
  if(window.navigator && window.navigator.msSaveOrOpenBlob){ // legacy Edge/IE
    window.navigator.msSaveOrOpenBlob(blob,name); return;
  }
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url; a.download=name; a.rel="noopener"; a.style.display="none";
  document.body.appendChild(a);   // Firefox requires the anchor to be in the DOM
  a.click();
  setTimeout(()=>{ document.body.removeChild(a); URL.revokeObjectURL(url); },1500);
}
