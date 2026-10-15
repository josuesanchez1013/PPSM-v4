"use strict";
/* ============================================================
   FIREPOWER / FMC REPORTS
   FMC exports a family of reports and they are not interchangeable.
   A connection event names the initiator and responder, so direction
   is settled rather than guessed. A servers report lists listening
   services. A discovery report carries hostnames and operating
   systems. This works out which one it has been handed and reads it
   accordingly, rather than treating every CSV the same.
   ============================================================ */

/* Each signature is a set of column names that only that report has.
   `need` must all be present; `any` is enough on its own. */
const FMC_REPORTS = [
  { id:"connection", label:"FMC connection events",
    need:["initiator ip","responder ip"], kind:"flows" },
  { id:"intrusion",  label:"FMC intrusion events",
    need:["source ip","destination ip"], any:["inline result","impact","classification"], kind:"flows" },
  { id:"secintel",   label:"FMC security intelligence events",
    need:["initiator ip"], any:["security intelligence category","si category"], kind:"flows" },
  { id:"servers",    label:"FMC servers report",
    need:["port"], any:["server","application protocol"], kind:"listeners" },
  { id:"hosts",      label:"FMC network discovery hosts",
    need:["ip address"], any:["netbios name","os name","host criticality"], kind:"names" },
  { id:"applications", label:"FMC applications report",
    need:["application"], any:["application protocol","business relevance","risk"], kind:"services" },
  { id:"acrules",    label:"FMC access control rules",
    need:[], any:["access control rule","rule name"], kind:"rules" },
  { id:"vpn",        label:"FMC VPN report",
    need:[], any:["vpn topology","tunnel status","peer ip","site-to-site"], kind:"tunnels" }
];

function fmcDetect(header){
  const cols = header.map(c=>String(c||"").trim().toLowerCase());
  const has = n => cols.some(c => c===n || c.indexOf(n)>=0);
  let best=null, bestScore=0;
  for(const r of FMC_REPORTS){
    if(r.need.length && !r.need.every(has)) continue;
    if(r.any && r.any.length && !r.any.some(has)) continue;
    // prefer the signature that matches the most columns
    const score = r.need.length*2 + (r.any||[]).filter(has).length;
    if(score>bestScore){ best=r; bestScore=score; }
  }
  return best;
}

/* column lookup that tolerates FMC's naming drift between versions */
function fmcCols(header){
  const cols=header.map(c=>String(c||"").trim().toLowerCase());
  return (...names)=>{
    for(const n of names){ const i=cols.indexOf(n); if(i>=0) return i; }
    for(const n of names){ const i=cols.findIndex(c=>c.indexOf(n)>=0); if(i>=0) return i; }
    return -1;
  };
}

const fmcAny = v => /^(any|any-ipv4|any-ipv6|all|n\/a|--|unknown)$/i.test(String(v||"").trim()) ? "" : String(v||"").trim();

/* ---------------- connection events ----------------
   The richest of the family: initiator and responder settle direction,
   the security zones drive the boundary, and the access control rule
   ties the flow to the line that permitted it. */
function fmcConnectionEvents(rows, header){
  const c=fmcCols(header), out=[], seen=new Set(), coll=collNow();
  const iSrc=c("initiator ip"), iDst=c("responder ip"),
        iSp =c("source port / icmp type","source port","initiator port"),
        iDp =c("destination port / icmp code","destination port","responder port"),
        iPro=c("protocol"), iApp=c("application protocol","application"),
        iAct=c("action"), iRule=c("access control rule","rule"),
        iPol=c("access control policy","policy"),
        iSz =c("security zone (initiator)","ingress security zone","initiator security zone"),
        iDz =c("security zone (responder)","egress security zone","responder security zone"),
        iIn =c("ingress interface"), iEg=c("egress interface"),
        iIb =c("initiator bytes"), iRb=c("responder bytes"),
        iIp2=c("initiator packets"), iRp=c("responder packets"),
        iCli=c("client"), iWeb=c("web application");
  rows.forEach(r=>{
    const src=fmcAny(r[iSrc]), dst=fmcAny(r[iDst]);
    if(!src && !dst) return;
    const dp=(r[iDp]||"").trim();
    const proto=(r[iPro]||"").trim().toUpperCase();
    if(!validPort(dp) && !dp) return;
    const key=[proto,src,dst,dp].join("|");
    if(seen.has(key)) return; seen.add(key);
    const act=(iAct>=0?r[iAct]:"").toLowerCase();
    const num=x=>{ const n=parseInt(String(x||"").replace(/[^\d]/g,""),10); return isNaN(n)?0:n; };
    const svc=fmcAny(iApp>=0?r[iApp]:"") || fmcAny(iCli>=0?r[iCli]:"");
    out.push(blank({
      src, dest:dst, proto,
      srcPort:(iSp>=0?(r[iSp]||"").trim():""), dstPort:dp,
      dataService: svc || guessService(dp, proto),
      banner: fmcAny(iWeb>=0?r[iWeb]:""),
      direction:"Outbound",                       // initiator -> responder
      srcZone: fmcAny(iSz>=0?r[iSz]:"") || fmcAny(iIn>=0?r[iIn]:""),
      dstZone: fmcAny(iDz>=0?r[iDz]:"") || fmcAny(iEg>=0?r[iEg]:""),
      isaRef:  fmcAny(iRule>=0?r[iRule]:""),
      status: /block|deny|reject/.test(act) ? "Blocked by policy" : "New",
      pkts: String(num(iIp2>=0?r[iIp2]:0)+num(iRp>=0?r[iRp]:0)||""),
      bytes:String(num(iIb>=0?r[iIb]:0)+num(iRb>=0?r[iRb]:0)||""),
      origin:"fmc-connection", collector:coll,
      notes:[act?("action "+act):"", fmcAny(iPol>=0?r[iPol]:"")?("policy "+fmcAny(r[iPol])):""]
             .filter(Boolean).join(" · ")
    }));
  });
  return out;
}

/* ---------------- intrusion / security intelligence events ---------------- */
function fmcEventFlows(rows, header, origin){
  const c=fmcCols(header), out=[], seen=new Set(), coll=collNow();
  const iSrc=c("source ip","initiator ip"), iDst=c("destination ip","responder ip"),
        iSp =c("source port / icmp type","source port"),
        iDp =c("destination port / icmp code","destination port"),
        iPro=c("protocol"), iMsg=c("message","security intelligence category","si category"),
        iRes=c("inline result"), iApp=c("application protocol");
  rows.forEach(r=>{
    const src=fmcAny(r[iSrc]), dst=fmcAny(r[iDst]);
    if(!src || !dst) return;
    const dp=(r[iDp]||"").trim();
    const proto=(r[iPro]||"").trim().toUpperCase();
    const key=[proto,src,dst,dp].join("|");
    if(seen.has(key)) return; seen.add(key);
    out.push(blank({
      src, dest:dst, proto, srcPort:(iSp>=0?(r[iSp]||"").trim():""), dstPort:dp,
      dataService: fmcAny(iApp>=0?r[iApp]:"") || guessService(dp,proto),
      direction:"Outbound",
      // an event is not proof of an approved service, so it never arrives as New
      status:"Flagged by sensor",
      origin, collector:coll,
      notes:[fmcAny(iMsg>=0?r[iMsg]:""), fmcAny(iRes>=0?r[iRes]:"")].filter(Boolean).join(" · ")
    }));
  });
  return out;
}

/* ---------------- servers report ----------------
   Discovered listening services: the closest thing FMC has to a
   credentialed port enumeration. */
function fmcServers(rows, header){
  const c=fmcCols(header), out=[], seen=new Set(), coll=collNow();
  const iIp=c("ip address","ip"), iPort=c("port"), iPro=c("protocol"),
        iSrv=c("server","application protocol"), iVen=c("vendor"), iVer=c("version"),
        iHits=c("hits","count");
  rows.forEach(r=>{
    const ip=fmcAny(r[iIp]); const port=(r[iPort]||"").trim();
    if(!ip || !validPort(port)) return;
    let proto=(iPro>=0?(r[iPro]||"").trim().toUpperCase():"");
    proto=normProto(proto) || "TCP";
    const key=[proto,ip,port].join("|");
    if(seen.has(key)) return; seen.add(key);
    const banner=[fmcAny(iVen>=0?r[iVen]:""), fmcAny(iVer>=0?r[iVer]:"")].filter(Boolean).join(" ");
    out.push(blank({
      dest:ip, proto, dstPort:port,
      srcPort: CFG.ephemeralRange || "1024-65535",
      dataService: fmcAny(iSrv>=0?r[iSrv]:"") || guessService(port,proto),
      banner,
      direction:"Inbound",                        // a listening service
      status:"New", origin:"fmc-servers", collector:coll,
      notes: iHits>=0 && r[iHits] ? ("hits "+r[iHits]) : ""
    }));
  });
  return out;
}

/* ---------------- network discovery hosts: a name source ---------------- */
function fmcHosts(rows, header){
  const c=fmcCols(header);
  const iIp=c("ip address","ip"), iNb=c("netbios name","host name","hostname","name"),
        iOs=c("os name","operating system"), iVen=c("os vendor"), iVer=c("os version");
  let seenN=0, learned=0;
  rows.forEach(r=>{
    const ip=fmcAny(r[iIp]); const nm=fmcAny(iNb>=0?r[iNb]:"");
    if(!ip || !nm) return;
    seenN++;
    const os=[fmcAny(iVen>=0?r[iVen]:""), fmcAny(iOs>=0?r[iOs]:""), fmcAny(iVer>=0?r[iVer]:"")]
      .filter(Boolean).join(" ");
    if(learnHost(ip, nm, "fmc-discovery", {os})) learned++;
  });
  return {names:learned, seen:seenN};
}

/* ---------------- applications report ---------------- */
function fmcApplications(rows, header){
  const c=fmcCols(header), out=[], seen=new Set(), coll=collNow();
  const iApp=c("application"), iPro=c("application protocol"),
        iIp=c("ip address","host","responder ip"), iPort=c("port","destination port");
  rows.forEach(r=>{
    const app=fmcAny(iApp>=0?r[iApp]:"");
    const ip=fmcAny(iIp>=0?r[iIp]:"");
    const port=(iPort>=0?(r[iPort]||"").trim():"");
    if(!app && !ip) return;
    if(!validPort(port)) return;                 // without a port there is nothing to register
    const key=[ip,port,app].join("|");
    if(seen.has(key)) return; seen.add(key);
    out.push(blank({
      dest:ip, dstPort:port, proto:"TCP",
      dataService: fmcAny(iPro>=0?r[iPro]:"") || app,
      appName: app, direction:"Inbound", status:"New",
      origin:"fmc-applications", collector:coll
    }));
  });
  return out;
}

/* ---------------- VPN report: candidates for B15 / B16 ---------------- */
function fmcVpn(rows, header){
  const c=fmcCols(header), out=[], coll=collNow();
  const iName=c("vpn topology","topology","name"), iPeer=c("peer ip","remote peer","peer"),
        iLocal=c("local ip","local peer"), iStat=c("tunnel status","status"),
        iType=c("tunnel type","type","ipsec");
  rows.forEach(r=>{
    const peer=fmcAny(iPeer>=0?r[iPeer]:"");
    if(!peer) return;
    out.push(blank({
      src: fmcAny(iLocal>=0?r[iLocal]:""), dest:peer,
      proto:"ESP", dataService:"ipsec-tunnel",
      direction:"Bidirectional",
      vpn:"Yes", vpnType: fmcAny(iType>=0?r[iType]:"") || "IPSEC",
      isaRef: fmcAny(iName>=0?r[iName]:""),
      status:"New", origin:"fmc-vpn", collector:coll,
      notes:"tunnel"+(iStat>=0&&r[iStat]?(" · "+r[iStat]):"")+
            " · confirm whether this is B15 (multiple AOs) or B16 (single AO)"
    }));
  });
  return out;
}

/* ---------------- the entry point ---------------- */
function parseFmcReport(text, filename){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return null;

  /* FMC prefixes exports with title and filter lines, so find the real
     header: the first row that looks like column names. */
  let hdrIdx=-1, header=null;
  for(let i=0;i<Math.min(lines.length,25);i++){
    const cols=splitCsvLine(lines[i]);
    if(cols.length<3) continue;
    const r=fmcDetect(cols);
    if(r){ hdrIdx=i; header=cols; break; }
  }
  if(hdrIdx<0) return null;
  const report=fmcDetect(header);
  if(!report) return null;

  const body=lines.slice(hdrIdx+1)
    .map(splitCsvLine)
    .filter(c=>c.length>=Math.min(3,header.length) && c.some(x=>String(x).trim()));

  let rows=[], names=null;
  switch(report.id){
    case "connection":   rows=fmcConnectionEvents(body, header); break;
    case "intrusion":    rows=fmcEventFlows(body, header, "fmc-intrusion"); break;
    case "secintel":     rows=fmcEventFlows(body, header, "fmc-secintel"); break;
    case "servers":      rows=fmcServers(body, header); break;
    case "applications": rows=fmcApplications(body, header); break;
    case "vpn":          rows=fmcVpn(body, header); break;
    case "hosts":        names=fmcHosts(body, header); break;
    case "acrules":      return null;   // handled by the access-control-policy reader
  }

  if(names) return {kind:report.label, rows:[], names:names.names, seen:names.seen,
    note: nameNote(names.seen, names.names, "discovered hosts")};

  return {kind:report.label, rows,
    note: rows.length ? (report.label+": "+rows.length+" entries")
                      : (report.label+": recognised, but no usable rows in it")};
}

/* ============================================================
   EXCEL (.xlsx) INPUT
   An .xlsx is a zip of XML parts. Read it with the same DEFLATE
   decoder the PDF reader uses, pull the shared strings and every
   sheet, and hand each sheet to the normal parsers as CSV. No
   libraries, nothing leaves the machine.
   ============================================================ */

function zipEntries(bytes){
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  // the end-of-central-directory record sits in the last 64 KB
  let eocd=-1;
  for(let i=u8.length-22; i>=Math.max(0,u8.length-66000); i--){
    if(dv.getUint32(i,true)===0x06054b50){ eocd=i; break; }
  }
  if(eocd<0) throw new Error("not a zip archive (no central directory)");
  const count = dv.getUint16(eocd+10,true);
  let p = dv.getUint32(eocd+16,true);
  const out = new Map();
  for(let n=0; n<count && p+46<=u8.length; n++){
    if(dv.getUint32(p,true)!==0x02014b50) break;
    const method = dv.getUint16(p+10,true);
    const csize  = dv.getUint32(p+20,true);
    const nlen = dv.getUint16(p+28,true), xlen=dv.getUint16(p+30,true), clen=dv.getUint16(p+32,true);
    const lho  = dv.getUint32(p+42,true);
    let name=""; for(let k=0;k<nlen;k++) name+=String.fromCharCode(u8[p+46+k]);
    out.set(name.replace(/\\/g,"/"), {method, csize, lho});
    p += 46+nlen+xlen+clen;
  }
  return {u8, dv, entries:out};
}

function zipRead(z, name){
  const e = z.entries.get(name);
  if(!e) return null;
  const {u8, dv} = z;
  if(dv.getUint32(e.lho,true)!==0x04034b50) return null;
  const nlen=dv.getUint16(e.lho+26,true), xlen=dv.getUint16(e.lho+28,true);
  const start=e.lho+30+nlen+xlen;
  const raw=u8.subarray(start, start+e.csize);
  const data = e.method===0 ? raw : (e.method===8 ? inflateRaw(raw) : null);
  if(!data) return null;
  return new TextDecoder("utf-8").decode(data);
}

function xmlUnescape(s){
  return String(s||"")
    .replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&apos;/g,"'")
    .replace(/&#x([0-9a-f]+);/gi,(m,h)=>String.fromCodePoint(parseInt(h,16)))
    .replace(/&#(\d+);/g,(m,d)=>String.fromCodePoint(+d))
    .replace(/&amp;/g,"&");
}

function colIndex(ref){
  const m=String(ref||"").match(/^([A-Z]+)/i);
  if(!m) return -1;
  let n=0; for(const ch of m[1].toUpperCase()) n=n*26+(ch.charCodeAt(0)-64);
  return n-1;
}

/* Returns {sheets:[{name, rows:[[cell,...],...]}]} */
function readXlsx(bytes){
  const z=zipEntries(bytes);
  if(!z.entries.has("xl/workbook.xml")) throw new Error("zip file is not an Excel workbook");

  // shared strings: plain <t>, or rich text split across several <r><t> runs
  const shared=[];
  const ss=zipRead(z,"xl/sharedStrings.xml");
  if(ss){
    const siRe=/<(?:\w+:)?si\b[^>]*>([\s\S]*?)<\/(?:\w+:)?si>/g; let m;
    while((m=siRe.exec(ss))){
      let txt=""; const tRe=/<(?:\w+:)?t\b[^>]*>([\s\S]*?)<\/(?:\w+:)?t>/g; let t;
      while((t=tRe.exec(m[1]))) txt+=t[1];
      shared.push(xmlUnescape(txt));
    }
  }

  // sheet names in workbook order, mapped to their parts
  const wb=zipRead(z,"xl/workbook.xml")||"";
  const rels=zipRead(z,"xl/_rels/workbook.xml.rels")||"";
  const relTarget={};
  (rels.match(/<Relationship\b[^>]*>/g)||[]).forEach(tag=>{
    const id=(tag.match(/\bId="([^"]+)"/)||[])[1], tg=(tag.match(/\bTarget="([^"]+)"/)||[])[1];
    if(id&&tg) relTarget[id]=tg.replace(/^\/?xl\//,"").replace(/^\//,"");
  });
  const order=[];
  (wb.match(/<(?:\w+:)?sheet\b[^>]*>/g)||[]).forEach(tag=>{
    const nm=xmlUnescape((tag.match(/\bname="([^"]*)"/)||[])[1]||"");
    const rid=(tag.match(/\br:id="([^"]+)"/)||tag.match(/\bid="([^"]+)"/)||[])[1];
    const tgt=relTarget[rid];
    if(tgt) order.push({name:nm, path:"xl/"+tgt});
  });
  if(!order.length){
    [...z.entries.keys()].filter(k=>/^xl\/worksheets\/sheet\d+\.xml$/.test(k)).sort()
      .forEach((k,i)=>order.push({name:"Sheet"+(i+1), path:k}));
  }

  const sheets=[];
  for(const s of order){
    const xml=zipRead(z,s.path);
    if(!xml) continue;
    const rows=[];
    const rowRe=/<(?:\w+:)?row\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?row>/g; let rm;
    while((rm=rowRe.exec(xml))){
      const rnum=+((rm[1].match(/\br="(\d+)"/)||[])[1]||rows.length+1);
      const cells=[];
      const cRe=/<(?:\w+:)?c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:\w+:)?c>)/g; let cm;
      let next=0;
      while((cm=cRe.exec(rm[2]))){
        const attrs=cm[1]||"", inner=cm[2]||"";
        const ref=(attrs.match(/\br="([A-Z]+\d+)"/i)||[])[1];
        const ci = ref ? colIndex(ref) : next;
        next = ci+1;
        const type=(attrs.match(/\bt="([^"]+)"/)||[])[1]||"";
        let val="";
        if(type==="inlineStr"){
          const tRe=/<(?:\w+:)?t\b[^>]*>([\s\S]*?)<\/(?:\w+:)?t>/g; let t;
          while((t=tRe.exec(inner))) val+=t[1];
          val=xmlUnescape(val);
        } else {
          const v=(inner.match(/<(?:\w+:)?v>([\s\S]*?)<\/(?:\w+:)?v>/)||[])[1];
          if(v!==undefined){
            if(type==="s") val=shared[+v]||"";
            else if(type==="b") val = v==="1"?"TRUE":"FALSE";
            else val=xmlUnescape(v);
          }
        }
        // whole numbers stored as floats read back as integers
        if(type!=="s" && type!=="inlineStr" && /^-?\d+\.0+$/.test(val)) val=val.replace(/\.0+$/,"");
        if(type!=="s" && type!=="inlineStr" && /^-?\d+(\.\d+)?E\+?\d+$/i.test(val))
          val=String(Math.round(Number(val)));
        cells[ci]=val;
      }
      while(rows.length < rnum-1) rows.push([]);
      rows.push(Array.from(cells, c=>c===undefined?"":c));
    }
    sheets.push({name:s.name, rows});
  }
  return {sheets};
}

/* Spreadsheets carry title and filter rows above the table. Start at the
   first row that looks like a header: most of the widest row's columns
   filled in. */
function sheetToCsv(rows){
  const filled=r=>r.filter(c=>String(c).trim()!=="").length;
  const width=Math.max(0,...rows.map(filled));
  if(width<2) return "";
  let start=0;
  for(let i=0;i<rows.length;i++){
    const f=filled(rows[i]);
    if(f>=Math.max(2, Math.ceil(width*0.5))){ start=i; break; }
  }
  return rows.slice(start)
    .filter(r=>filled(r)>0)
    .map(r=>r.map(c=>csvCell(String(c).replace(/\r?\n/g," "))).join(","))
    .join("\n");
}

/* ============================================================
   NETFLOW TOP-CONVERSATIONS REPORTS
   SolarWinds NTA, ManageEngine NetFlow Analyzer, Plixer, Stealthwatch
   and similar all export a "top N conversations" table. The column
   names differ between products; the content does not.
   ============================================================ */

/* "10.1.1.5", "host.lan (10.1.1.5)", "10.1.1.5 (host.lan)", "10.1.1.5:443" */
function convEndpoint(v){
  const s=String(v||"").trim();
  if(!s) return {ip:"",host:"",port:""};
  let m=s.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if(m) return {ip:m[1],host:"",port:m[2]};
  m=s.match(/^(.+?)\s*[\(\[]\s*(\d{1,3}(?:\.\d{1,3}){3})\s*[\)\]]$/);
  if(m) return {ip:m[2],host:isIP(m[1])?"":m[1].trim(),port:""};
  m=s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*[\(\[]\s*([^)\]]+?)\s*[\)\]]$/);
  if(m) return {ip:m[1],host:isIP(m[2])?"":m[2].trim(),port:""};
  if(isIP(s)) return {ip:s,host:"",port:""};
  return {ip:"",host:isHostname(s)?s:"",port:""};
}

/* "12.4 MB" -> bytes */
function toBytes(v){
  const s=String(v||"").trim().replace(/,/g,"");
  const m=s.match(/^([\d.]+)\s*([KMGT]?)(i?B|bytes|octets)?$/i);
  if(!m) return /^\d+$/.test(s)?s:"";
  const mult={"":1,K:1e3,M:1e6,G:1e9,T:1e12}[m[2].toUpperCase()]||1;
  return String(Math.round(parseFloat(m[1])*mult));
}

/* port from its own column, or out of an application label: "https (443/TCP)" */
function convPortProto(appVal, portVal, protoVal){
  let port=String(portVal||"").trim(), proto=String(protoVal||"").trim().toUpperCase();
  proto=normProto(proto);
  const a=String(appVal||"");
  if(!port){
    let m=a.match(/\b(\d{1,5})\s*\/\s*(TCP|UDP)\b/i) || a.match(/\b(TCP|UDP)\s*[\/:]\s*(\d{1,5})\b/i);
    if(m){
      if(/^\d/.test(m[1])){ port=m[1]; proto=proto||m[2].toUpperCase(); }
      else { proto=proto||m[1].toUpperCase(); port=m[2]; }
    }
  }
  if(!port){
    const named=(a.match(/^([a-z][\w\-]*)/i)||[])[1];
    if(named && NAMED_PORTS[named.toLowerCase()]) port=NAMED_PORTS[named.toLowerCase()];
  }
  return {port:validPort(port)?port:"", proto:proto||""};
}

function parseConversations(text){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  const pick=(cols,exact,partial,reject)=>{
    for(const n of exact){ const i=cols.findIndex(c=>c===n); if(i>=0) return i; }
    for(const n of partial){
      const i=cols.findIndex(c=>c.indexOf(n)>=0 && !(reject||[]).some(r=>c.indexOf(r)>=0));
      if(i>=0) return i;
    }
    return -1;
  };
  let hi=-1, cols=null;
  for(let i=0;i<Math.min(lines.length,30);i++){
    const c=splitCsvLine(lines[i]).map(x=>x.trim().toLowerCase());
    // our own register export is not a conversations report
    if(c.some(x=>/boundary crossed|mission justification|^enclave$/.test(x))) return {rows:[],note:""};
    const s=pick(c,["source","source ip","src ip","source address","client","client ip","endpoint 1","host a"],
                   ["source","client","endpoint 1","src"],["port","zone","interface","country"]);
    const d=pick(c,["destination","destination ip","dst ip","destination address","server","server ip","endpoint 2","host b"],
                   ["destination","server","endpoint 2","dst"],["port","zone","interface","country"]);
    const vol=c.some(x=>/byte|traffic|octet|packet|volume|conversation|% of|flows/.test(x));
    if(s>=0 && d>=0 && vol){ hi=i; cols=c; break; }
  }
  if(hi<0) return {rows:[],note:""};

  const iS =pick(cols,["source","source ip","src ip","source address","client","client ip","endpoint 1","host a"],
                 ["source","client","endpoint 1","src"],["port","zone","interface","country"]);
  const iD =pick(cols,["destination","destination ip","dst ip","destination address","server","server ip","endpoint 2","host b"],
                 ["destination","server","endpoint 2","dst"],["port","zone","interface","country"]);
  const iSP=pick(cols,["source port","src port","client port"],["source port","src port","client port"]);
  const iDP=pick(cols,["destination port","dst port","dest port","server port","port","service port"],
                 ["destination port","dst port","dest port","server port","service port"]);
  const iPR=pick(cols,["protocol","proto","ip protocol","transport"],["protocol"],["application"]);
  const iAP=pick(cols,["application","app","service","application name"],["application","service"],["port"]);
  const iBY=pick(cols,["total bytes","bytes","traffic","octets","volume","total traffic"],["byte","traffic","octet","volume"],["%","percent"]);
  const iPK=pick(cols,["packets","pkts","total packets"],["packet"],["%"]);

  const rows=[], seen=new Set(), coll=collNow();
  lines.slice(hi+1).forEach(l=>{
    const c=splitCsvLine(l);
    const a=convEndpoint(c[iS]), b=convEndpoint(c[iD]);
    if(!(a.ip||a.host) || !(b.ip||b.host)) return;
    if(/^(total|sum|other)/i.test(String(c[iS]||"").trim())) return;
    const pp=convPortProto(iAP>=0?c[iAP]:"", iDP>=0?c[iDP]:(b.port||""), iPR>=0?c[iPR]:"");
    let sport = iSP>=0 ? String(c[iSP]||"").trim() : (a.port||"");
    let src=a, dst=b, dport=pp.port;
    // with both ports known, the better-known one is the service
    if(dport && sport && validPort(sport)){
      const o=orientPair(a.ip||a.host, sport, b.ip||b.host, dport);
      if(o.dest===(a.ip||a.host)){ src=b; dst=a; }
      dport=o.dstPort; sport=o.srcPort;
    }
    const proto = pp.proto || (dport?"TCP":"");
    const key=[proto,src.ip||src.host,dst.ip||dst.host,dport].join("|");
    if(seen.has(key)) return; seen.add(key);
    if(src.ip && src.host) learnHost(src.ip, src.host, "netflow-report");
    if(dst.ip && dst.host) learnHost(dst.ip, dst.host, "netflow-report");
    rows.push(blank({
      src:src.ip, srcHost:src.host, dest:dst.ip, dstHost:dst.host,
      proto, srcPort: validPort(sport)?sport:"", dstPort:dport,
      dataService: (iAP>=0 && String(c[iAP]||"").trim() && !/^(unknown|other|-)$/i.test(c[iAP]))
                   ? String(c[iAP]).replace(/\s*\(.*\)\s*$/,"").trim().toLowerCase()
                   : guessService(dport,proto),
      direction:"Outbound", status:"New", origin:"netflow-report", collector:coll,
      bytes: iBY>=0 ? toBytes(c[iBY]) : "", pkts: iPK>=0 ? toBytes(c[iPK]) : "",
      notes: dport ? "" : "no port in the report — service could not be identified"
    }));
  });
  return {rows, note: rows.length?("top conversations: "+rows.length+" rows"):""};
}

/* ============================================================
   POSITIONED PDF TEXT
   Plain extraction loses where each piece of text sat on the page,
   and a table cannot be read without that: a wrapped cell spreads
   over several lines and interleaves with its neighbours. This walks
   the content stream tracking the graphics state and text matrix, so
   every string comes out with its page position.
   ============================================================ */
function pdfItemsFromContent(str, cmap){
  const items=[];
  const I=()=>[1,0,0,1,0,0];
  const mul=(m,n)=>[ m[0]*n[0]+m[1]*n[2], m[0]*n[1]+m[1]*n[3],
                     m[2]*n[0]+m[3]*n[2], m[2]*n[1]+m[3]*n[3],
                     m[4]*n[0]+m[5]*n[2]+n[4], m[4]*n[1]+m[5]*n[3]+n[5] ];
  let ctm=I(), stack=[], tm=I(), tlm=I(), leading=0, fsize=10, font=null;
  const ops=[];
  let i=0; const n=str.length;

  const decode=raw=>{
    if(!cmap || !cmap.size) return raw;
    let wide=!!cmap.wide;
    if(!wide){ for(const k of cmap.keys()){ if(k>0xFF){ wide=true; break; } } }
    let out="";
    if(wide){ for(let k=0;k+1<raw.length;k+=2){ const c=(raw.charCodeAt(k)<<8)|raw.charCodeAt(k+1);
                out+=cmap.has(c)?cmap.get(c):""; } }
    else { for(let k=0;k<raw.length;k++){ const c=raw.charCodeAt(k); out+=cmap.has(c)?cmap.get(c):raw[k]; } }
    return out;
  };
  const emit=raw=>{
    const s=decode(raw);
    if(!s.trim()) { tm=mul([1,0,0,1, fsize*0.5*s.length, 0], tm); return; }
    const x=ctm[0]*tm[4]+ctm[2]*tm[5]+ctm[4];
    const y=ctm[1]*tm[4]+ctm[3]*tm[5]+ctm[5];
    items.push({x, y, s, size:fsize*Math.abs(tm[3]||1)*Math.abs(ctm[3]||1)});
    // no glyph widths here, so advance by an estimate in case more text follows
    tm=mul([1,0,0,1, fsize*0.52*s.length, 0], tm);
  };
  const readStr=()=>{
    let depth=1, s=""; i++;
    while(i<n && depth>0){
      const c=str[i];
      if(c==="\\"){
        const nx=str[i+1];
        const map={n:"\n",r:"\r",t:"\t",b:"",f:"","(":"(",")":")","\\":"\\"};
        if(nx in map){ s+=map[nx]; i+=2; }
        else if(nx>="0"&&nx<="7"){ let o=""; i++; while(o.length<3&&str[i]>="0"&&str[i]<="7"){ o+=str[i]; i++; }
                                   s+=String.fromCharCode(parseInt(o,8)); }
        else i+=2;
      } else if(c==="("){ depth++; s+=c; i++; }
      else if(c===")"){ depth--; if(depth) s+=c; i++; }
      else { s+=c; i++; }
    }
    return {t:"s", v:s};
  };
  const readHex=()=>{
    let h=""; i++;
    while(i<n && str[i]!==">"){ if(/[0-9a-fA-F]/.test(str[i])) h+=str[i]; i++; }
    i++;
    let s=""; for(let k=0;k+1<h.length;k+=2) s+=String.fromCharCode(parseInt(h.substr(k,2),16));
    if(h.length%2) s+=String.fromCharCode(parseInt(h.slice(-1)+"0",16));
    return {t:"s", v:s};
  };

  const num=o=>o&&o.t==="n"?o.v:0;
  while(i<n){
    const c=str[i];
    if(/\s/.test(c)){ i++; continue; }
    if(c==="%"){ while(i<n && str[i]!=="\n" && str[i]!=="\r") i++; continue; }
    if(c==="("){ ops.push(readStr()); continue; }
    if(c==="<" && str[i+1]==="<"){ i+=2; continue; }
    if(c===">" && str[i+1]===">"){ i+=2; continue; }
    if(c==="<"){ ops.push(readHex()); continue; }
    if(c==="["){ ops.push({t:"["}); i++; continue; }
    if(c==="]"){ // close an array
      const arr=[]; while(ops.length && ops[ops.length-1].t!=="[") arr.unshift(ops.pop());
      ops.pop(); ops.push({t:"a", v:arr}); i++; continue; }
    if(c==="/"){ let nm="/"; i++; while(i<n && !/[\s\/\[\]<>()%{}]/.test(str[i])){ nm+=str[i]; i++; }
                 ops.push({t:"/", v:nm}); continue; }
    let tok=""; while(i<n && !/[\s\/\[\]<>()%{}]/.test(str[i])){ tok+=str[i]; i++; }
    if(!tok){ i++; continue; }
    if(/^[-+]?(\d+\.?\d*|\.\d+)$/.test(tok)){ ops.push({t:"n", v:parseFloat(tok)}); continue; }

    const a=ops; const L=a.length;
    switch(tok){
      case "q":  stack.push(ctm.slice()); break;
      case "Q":  if(stack.length) ctm=stack.pop(); break;
      case "cm": if(L>=6) ctm=mul([num(a[L-6]),num(a[L-5]),num(a[L-4]),num(a[L-3]),num(a[L-2]),num(a[L-1])], ctm); break;
      case "BT": tm=I(); tlm=I(); break;
      case "Tf": if(L>=1){ fsize=num(a[L-1])||fsize; if(L>=2 && a[L-2].t==="/") font=a[L-2].v; } break;
      case "TL": if(L>=1) leading=num(a[L-1]); break;
      case "Td": case "TD":
        if(L>=2){ const tx=num(a[L-2]), ty=num(a[L-1]);
          if(tok==="TD") leading=-ty;
          tlm=mul([1,0,0,1,tx,ty], tlm); tm=tlm.slice(); }
        break;
      case "Tm": if(L>=6){ tlm=[num(a[L-6]),num(a[L-5]),num(a[L-4]),num(a[L-3]),num(a[L-2]),num(a[L-1])]; tm=tlm.slice(); } break;
      case "T*": tlm=mul([1,0,0,1,0,-leading], tlm); tm=tlm.slice(); break;
      case "Tj": if(L>=1 && a[L-1].t==="s") emit(a[L-1].v); break;
      case "'":  tlm=mul([1,0,0,1,0,-leading], tlm); tm=tlm.slice();
                 if(L>=1 && a[L-1].t==="s") emit(a[L-1].v); break;
      case '"':  tlm=mul([1,0,0,1,0,-leading], tlm); tm=tlm.slice();
                 if(L>=1 && a[L-1].t==="s") emit(a[L-1].v); break;
      case "TJ":
        if(L>=1 && a[L-1].t==="a"){
          let s=""; a[L-1].v.forEach(el=>{
            if(el.t==="s") s+=el.v;
            else if(el.t==="n" && el.v<-180) s+=" ";     // a large negative kern is a space
          });
          emit(s);
        }
        break;
    }
    ops.length=0;
  }
  return items;
}

/* Group positioned text into lines, top of the page first. */
function pdfLines(items){
  const byPage=new Map();
  items.forEach(it=>{ const p=it.page||0; if(!byPage.has(p)) byPage.set(p,[]); byPage.get(p).push(it); });
  const lines=[];
  [...byPage.keys()].sort((a,b)=>a-b).forEach(p=>{
    const its=byPage.get(p).slice().sort((a,b)=>b.y-a.y || a.x-b.x);
    let cur=null;
    its.forEach(it=>{
      const tol=Math.max(2, (it.size||10)*0.35);
      if(cur && Math.abs(cur.y-it.y)<=tol){ cur.items.push(it); }
      else { cur={page:p, y:it.y, items:[it]}; lines.push(cur); }
    });
  });
  lines.forEach(l=>l.items.sort((a,b)=>a.x-b.x));
  return lines;
}

/* ============================================================
   FMC ACCESS CONTROL POLICY (PDF)
   FMC prints the policy one of two ways: a wide table with a row per
   rule, or a block per rule with labelled fields. Both are read.
   ============================================================ */

/* "TCP (6):443", "UDP (17):53", "TCP:8000-8010", "HTTPS", "ICMP (1)" */
const UDP_NAMED = new Set(["dns","domain","ntp","snmp","snmptrap","syslog","tftp","bootps","bootpc","netbios-ns"]);
function parseFmcPorts(text){
  const out=[], s=String(text||"");
  if(!s.trim() || /^\s*any\s*$/i.test(s)) return out;
  let m; const re=/\b(TCP|UDP|SCTP)\s*(?:\(\s*\d+\s*\))?\s*[:\/]\s*(\d{1,5})(?:\s*-\s*(\d{1,5}))?/gi;
  const used=[];
  while((m=re.exec(s))){ out.push({proto:m[1].toUpperCase(), port:m[3]?m[2]+"-"+m[3]:m[2]}); used.push([m.index, m.index+m[0].length]); }
  const re2=/\b(\d{1,5})\s*\/\s*(tcp|udp)\b/gi;
  while((m=re2.exec(s))){ out.push({proto:m[2].toUpperCase(), port:m[1]}); used.push([m.index, m.index+m[0].length]); }
  if(/\bICMP(v6)?\b/i.test(s)) out.push({proto:/ICMPv6/i.test(s)?"ICMPV6":"ICMP", port:""});
  // named services and port objects in whatever is left over
  let rest=s; used.sort((a,b)=>b[0]-a[0]).forEach(([a,b])=>{ rest=rest.slice(0,a)+" "+rest.slice(b); });
  rest.split(/[,;|\n]+/).map(x=>x.trim()).filter(Boolean).forEach(tok=>{
    if(/^(any|icmp.*|\(?\d+\)?)$/i.test(tok)) return;
    const key=tok.toLowerCase().replace(/\s+/g,"-");
    if(NAMED_PORTS[key]) out.push({proto:UDP_NAMED.has(key)?"UDP":"TCP", port:NAMED_PORTS[key], svc:key});
    else if(/^[A-Za-z][\w\-. ]{1,40}$/.test(tok)) out.push({proto:"", port:"", svc:tok});
  });
  return out;
}

/* a network object named in the policy may be a host the inventory knows */
function resolveNetObject(name){
  const n=String(name||"").trim().toLowerCase();
  if(!n) return "";
  for(const [ip,h] of HOSTMAP){
    const full=String(h.name||"").toLowerCase(), short=full.split(".")[0];
    if(n===full || n===short) return ip;
  }
  return "";
}

/* Split a networks cell into addresses and named objects. */
function splitNetworks(text){
  const out=[];
  String(text||"").split(/[,;|\n]+/).map(x=>x.trim()).filter(Boolean).forEach(piece=>{
    const addrs=piece.match(/\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?(?:\s*-\s*\d{1,3}(?:\.\d{1,3}){3})?/g);
    if(addrs){ addrs.forEach(a=>out.push({addr:a.replace(/\s+/g,""), obj:""})); return; }
    if(/^(any|any-ipv4|any-ipv6|all)$/i.test(piece)) return;
    piece.split(/\s{2,}/).forEach(p=>{ if(p.trim()) out.push({addr:"", obj:p.trim()}); });
  });
  return out;
}

/* One policy rule -> register rows. Shared by the PDF readers and the CSV one. */
function acpRuleRows(r){
  const rows=[], coll=collNow();
  const act=String(r.action||"").toLowerCase();
  if(r.enabled!==undefined && /^(false|no|disabled|off)$/i.test(String(r.enabled).trim())) return rows;
  const status = /allow|permit|trust/.test(act) ? "Permitted by rule"
               : /block|deny|reject/.test(act) ? "Denied by rule"
               : /monitor/.test(act) ? "Monitor only (rule)" : "Permitted by rule";
  let ports=r.ports || parseFmcPorts(r.portsText);
  if(!ports.length) ports=[{proto:"", port:""}];
  const nets=t=>{ const s=splitNetworks(t); return s.length?s:[{addr:"",obj:""}]; };
  const srcs=nets(r.srcNets), dsts=nets(r.dstNets);
  let made=0;
  for(const d of dsts){ for(const s of srcs){ for(const p of ports){
    if(made++>=80) break;
    const dAddr = d.addr || resolveNetObject(d.obj);
    const sAddr = s.addr || resolveNetObject(s.obj);
    const notes=[(act?act.toUpperCase():"ALLOW")+" rule"+(r.name?" '"+r.name+"'":"")+" in access control policy"];
    if(d.obj && !dAddr) notes.push("destination object '"+d.obj+"' not resolved to an address");
    if(s.obj && !sAddr) notes.push("source object '"+s.obj+"' not resolved to an address");
    if(r.apps && !/^\s*any\s*$/i.test(r.apps)) notes.push("application "+String(r.apps).replace(/\s*\|\s*/g,", "));
    rows.push(blank({
      src:sAddr, dest:dAddr, proto:p.proto, dstPort:p.port,
      dataService: p.svc || guessService(p.port, p.proto),
      srcZone: String(r.srcZones||"").replace(/\s*\|\s*/g,", ").replace(/^any$/i,""),
      dstZone: String(r.dstZones||"").replace(/\s*\|\s*/g,", ").replace(/^any$/i,""),
      status, origin:"firewall-rule", collector:coll, isaRef:r.name||"",
      notes:notes.join(" · "),
      srcObj: s.obj||"", dstObj: d.obj||""
    }));
  }}}
  return rows;
}

const ACP_FIELD = [
  [/^(#|no\.?|rule\s*#|rule\s*no\.?|sequence|seq)$/,              "num"],
  [/^(rule\s*)?name$|^rule$/,                                       "name"],
  [/^action$/,                                                      "action"],
  [/^(enabled|state|status)$/,                                      "enabled"],
  [/^(source|src)\s*zones?$/,                                       "srcZones"],
  [/^(destination|dest|dst)\s*zones?$/,                             "dstZones"],
  [/^(source|src)\s*(networks?|addresses?|objects?)$/,              "srcNets"],
  [/^(destination|dest|dst)\s*(networks?|addresses?|objects?)$/,    "dstNets"],
  [/^(source|src)\s*ports?$/,                                       "srcPorts"],
  [/^(destination|dest|dst)\s*ports?$|^services?$|^ports?$/,        "portsText"],
  [/^applications?$/,                                               "apps"]
];
function acpField(label){
  const l=String(label||"").trim().toLowerCase().replace(/\s+/g," ").replace(/:$/,"");
  for(const [re,f] of ACP_FIELD) if(re.test(l)) return f;
  return "";
}
const ACP_ACTION = /\b(allow|trust|block with reset|interactive block|block|monitor|deny|permit)\b/i;

/* ---- layout 1: one table row per rule, read by column position ---- */
function acpFromTable(items){
  const lines=pdfLines(items);
  // the header is the line carrying an Action column and at least three others
  /* The header often wraps: "Source" and "Dest" sit on the line above
     "Networks", "Ports" and "Action". Find the line with Action, then fold
     in any header words directly above or below it. */
  /* A header continuation is made of plain words. Anything with digits,
     punctuation from a port or address, or a value like "Any" or an action
     is data - even when it arrives on a line of its own, which happens
     whenever a wrapped cell pushes part of a row above the rest of it. */
  const HEADERWORD=/^[A-Za-z#][A-Za-z \/#&.\-]{0,30}$/;
  const isHeaderish = ln => ln.items.length>0 && ln.items.every(it=>{
    const s=it.s.trim();
    return HEADERWORD.test(s) && !/^(any|allow|trust|block|monitor|deny|permit|true|false|inside|outside|dmz)$/i.test(s);
  });
  const isDataish = ln => !isHeaderish(ln);
  const near = (a,b) => a && b && a.page===b.page &&
                        Math.abs(a.y-b.y) < ((b.items[0]||{}).size||10)*2.4;

  /* The header can be one, two or three lines depending on how the table
     aligns its cells: labels that wrap ("Source" over "Networks") and labels
     that do not ("#", "Name", "Action") can each end up on their own line.
     Take the line holding "Action" and every header-like line next to it,
     then group all of their words into columns by horizontal position. */
  let h=-1, blockTop=-1;
  for(let k=0;k<lines.length && h<0;k++){
    if(!lines[k].items.some(x=>x.s.trim().toLowerCase()==="action")) continue;
    let lo=k, hi=k;
    while(lo-1>=0 && near(lines[lo-1],lines[lo]) && isHeaderish(lines[lo-1])) lo--;
    while(hi+1<lines.length && near(lines[hi+1],lines[hi]) && isHeaderish(lines[hi+1])) hi++;
    const words=[]; for(let j=lo;j<=hi;j++) lines[j].items.forEach(it=>words.push(it));
    if(words.length<4) continue;
    if(!words.some(w=>/^(dest|destination|dst)\b/i.test(w.s.trim()) || /\b(dest|destination|dst)\b/i.test(w.s.trim()))) continue;
    h=hi; blockTop=lo;
  }
  if(h<0) return null;
  const hdrWords=[];
  for(let j=blockTop;j<=h;j++) lines[j].items.forEach(it=>hdrWords.push(it));
  hdrWords.sort((a,b)=>b.y-a.y || a.x-b.x);          // top line first
  const cols=[];
  hdrWords.forEach(it=>{
    const c=cols.find(c=>Math.abs(c.x-it.x)<18);
    if(c){ c.label=(c.label+" "+it.s.trim()).trim(); c.x=Math.min(c.x,it.x); }
    else cols.push({x:it.x, label:it.s.trim()});
  });
  const head=lines[h];
  cols.sort((a,b)=>a.x-b.x);
  cols.forEach(c=>c.field=acpField(c.label));
  if(!cols.some(c=>c.field==="action") || !cols.some(c=>c.field==="portsText"||c.field==="dstNets")) return null;
  const colOf=x=>{ let pick=cols[0]; for(const c of cols){ if(c.x<=x+4) pick=c; } return pick; };
  const headerText=cols.map(c=>c.label.toLowerCase()).join("|");
  const HDR_VOCAB=new Set(hdrWords.map(w=>w.s.trim().toLowerCase()));

  // data lines, skipping headers repeated at the top of later pages
  const data=[];
  for(let k=h+1;k<lines.length;k++){
    const ln=lines[k];
    const txt=ln.items.map(x=>x.s.trim().toLowerCase()).join("|");
    // any piece of the header, repeated at the top of a later page
    if(ln.items.every(x=>HDR_VOCAB.has(x.s.trim().toLowerCase()))) continue;
    // page furniture
    const whole=ln.items.map(x=>x.s.trim()).join(" ");
    if(/^(page\s+\d+(\s+of\s+\d+)?|\d+\s*\/\s*\d+|confidential.*|generated.*|printed.*)$/i.test(whole)) continue;
    const cells={};
    ln.items.forEach(it=>{ const c=colOf(it.x); if(!c.field) return;
      cells[c.field]=(cells[c.field]?cells[c.field]+" ":"")+it.s.trim(); });
    data.push({line:ln, cells});
  }
  /* Split the data into table rows by vertical spacing. Lines inside one row
     sit a single line-height apart; between rows there is cell padding as
     well, so the gap is visibly larger. That holds whether a table aligns its
     cells to the top, middle or bottom - unlike "nearest anchor", which goes
     wrong as soon as a tall row pushes its first line toward the row above. */
  const hasNum=cols.some(c=>c.field==="num");
  // a rule's anchor line carries its number and at least one other cell, so a
  // stray page number cannot pose as a rule
  const isAnchor=d => (hasNum ? /^\d+$/.test(String(d.cells.num||"").trim())
                              : ACP_ACTION.test(String(d.cells.action||""))) &&
                      Object.keys(d.cells).length>=2;
  if(!data.some(isAnchor)) return null;
  const gaps=[];
  for(let k=1;k<data.length;k++)
    if(data[k].line.page===data[k-1].line.page) gaps.push(data[k-1].line.y-data[k].line.y);
  const minGap = gaps.length ? Math.max(1, Math.min(...gaps.filter(g=>g>0.5))) : 10;
  const bands=[]; let band=[];
  data.forEach((d,k)=>{
    const prev=data[k-1];
    const split = !prev || prev.line.page!==d.line.page || (prev.line.y-d.line.y) > minGap*1.35;
    if(split && band.length){ bands.push(band); band=[]; }
    band.push(d);
  });
  if(band.length) bands.push(band);

  const rules=[];
  bands.forEach(b=>{
    const anchors=b.filter(isAnchor);
    if(anchors.length===1){ rules.push({anchor:anchors[0], parts:b}); return; }
    if(anchors.length===0){
      // no anchor of its own: the tail of the previous row
      if(rules.length) rules[rules.length-1].parts.push(...b);
      return;
    }
    // unpadded table: several rows ran together, so fall back to nearest anchor
    const rs=anchors.map(a=>({anchor:a, parts:[]}));
    b.forEach(d=>{ let best=rs[0], bd=1e9;
      rs.forEach(r=>{ const dist=Math.abs(r.anchor.line.y-d.line.y); if(dist<bd){ bd=dist; best=r; } });
      best.parts.push(d); });
    rules.push(...rs);
  });
  const out=[];
  rules.forEach(r=>{
    const f={};
    r.parts.sort((a,b)=>b.line.y-a.line.y).forEach(p=>{
      Object.entries(p.cells).forEach(([k,v])=>{ f[k]=f[k]?f[k]+" | "+v:v; });
    });
    if(f.name) f.name=f.name.replace(/\s*\|\s*/g,"");     // a wrapped name is one name
    f.action=(String(f.action||"").match(ACP_ACTION)||[])[1]||f.action||"";
    out.push(f);
  });
  return out;
}

/* ---- layout 2: a block per rule, "Label: value" ---- */
function acpFromBlocks(text){
  // a label on a line of its own takes the next line as its value
  const LABEL_ONLY=/^\s*(rule\s*name|rule|name|action|enabled|state|source\s*zones?|(?:destination|dest)\s*zones?|source\s*networks?|(?:destination|dest)\s*networks?|source\s*ports?|(?:destination|dest)\s*ports?|applications?)\s*:?\s*$/i;
  const src=text.split(/\r?\n/), joined=[];
  for(let k=0;k<src.length;k++){
    if(LABEL_ONLY.test(src[k]) && k+1<src.length && !LABEL_ONLY.test(src[k+1])){
      joined.push(src[k].replace(/:?\s*$/,"")+": "+src[k+1].trim()); k++;
    } else joined.push(src[k]);
  }
  text=joined.join("\n");
  const labelRe=/^\s*(rule\s*name|rule\s*\d+|rule|name|action|enabled|state|source\s*zones?|(?:destination|dest)\s*zones?|source\s*networks?|(?:destination|dest)\s*networks?|source\s*ports?|(?:destination|dest)\s*ports?|applications?)\s*(?::|\s{2,}|\s-\s)\s*(.*)$/i;
  const rules=[]; let cur=null, lastField=null;
  const start=()=>{ cur={}; rules.push(cur); };
  text.split(/\r?\n/).forEach(raw=>{
    const line=raw.replace(/\s+$/,"");
    if(!line.trim()) return;
    const m=line.match(labelRe);
    if(m){
      let label=m[1].toLowerCase().replace(/\s+/g," "), val=m[2].trim();
      if(/^rule \d+$/.test(label)){ start(); cur.name=val; lastField="name"; return; }
      const f = /^rule( name)?$/.test(label) ? "name" : acpField(label);
      if(!f) return;
      if(f==="name"){ if(!cur || cur.name) start(); cur.name=val; lastField="name"; return; }
      if(!cur) start();
      cur[f]=cur[f]?cur[f]+" | "+val:val; lastField=f;
    } else if(cur && lastField && lastField!=="name" && lastField!=="action" && lastField!=="enabled"){
      cur[lastField]=cur[lastField]+" | "+line.trim();       // a list continuing onto the next line
    }
  });
  return rules.filter(r=>r.name && (r.portsText || r.dstNets || r.action));
}

function parseAcpText(text, items){
  let rules=null, layout="";
  if(items && items.length){ rules=acpFromTable(items); if(rules&&rules.length) layout="table"; }
  if((!rules || !rules.length) && items && items.length){
    // positioned lines keep each label beside its value
    const lt=pdfLines(items).map(l=>l.items.map(i=>i.s.trim()).join("  ")).join("\n");
    rules=acpFromBlocks(lt); if(rules.length) layout="per-rule blocks";
  }
  if(!rules || !rules.length){ rules=acpFromBlocks(text); if(rules.length) layout="per-rule blocks"; }
  if(!rules || !rules.length) return {rows:[], note:""};
  let rows=[];
  rules.forEach(r=>{ rows=rows.concat(acpRuleRows(r)); });
  const unresolved=rows.filter(r=>/not resolved/.test(r.notes||"")).length;
  return {rows, note:"access control policy ("+layout+" layout): "+rules.length+" rules, "+rows.length+" entries"+
    (unresolved?" · "+unresolved+" with object names not yet resolved to addresses":"")};
}

/* positioned text from the most recent PDF, for the table readers */
let PDF_ITEMS = null;
