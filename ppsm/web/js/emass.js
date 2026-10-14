"use strict";
/* ============================================================
   eMASS PPSM BOUNDARY IMPORT TEMPLATE
   Exports the eMASS PPSM Boundary Information Import Template (allow.xlsx)
   one for one: 21 columns A-U, the header block, and the Glossary
   sheet so the lookup columns keep working as dropdowns.
   ============================================================ */
const EMASS_TYPE = ["External Services","Least Function"];
const EMASS_POINTS = [
 "AF Base Enclave (DoD Network)","AF Base Enclave DMZ (DoD Network)","DoD Enclave (DoD Network)",
 "DoD Enclave (External Network) (DoDIN Waiver)","DoD Enclave DMZ (DoD Network)",
 "DoD Level DMZ (DoD Network)","DREN Enclave (DoD Network)",
 "External Network (Approved Gateway) (DoDIN Waiver)","External Network (Commercial ISP) (DoDIN Waiver)",
 "External Network (Direct Connect) (ISP Waiver)","External Network (non-DoD Network)",
 "External Network (Public Internet)","Internal Use Only (Closed Environment – No Network)",
 "Internal Use Only (DoD Network)","Internal Use Only (External Network)",
 "Internal Use Only (Isolated Environment – No Network)","Internal Use Only (Zone D Environment – No Network)",
 "Off-Premise Cloud Service (DoD Network via DISA CAP)","Off-Premise Cloud Service (DoD Network via Waiver)",
 "Off-Premise Cloud Service (non-DoD Network)","Off-Premise Cloud Service DMZ (DoD Network via DISA CAP)",
 "Off-Premise Cloud Service DMZ (DoD Network via Waiver)","On-Premise Cloud Service (DoD Network)",
 "On-Premise Cloud Service DMZ (DoD Network)","SDREN Enclave (DoD Network)","Tenant (Nested) Enclave (DoD Network)"];
/* Column G of the template's Glossary, rows 2-24, exactly as it reads.
   "Type-1  Encrypted Tunnel" carries two spaces, and "Out of Band (OOB)"
   genuinely appears twice; both are reproduced rather than tidied, so the
   list matches the template it has to be validated against. */
const EMASS_VPNTYPE = ["AF VPN","Azure ExpressRoute","Cloud Layer 3 VPN","Cloud MPLS VPN","COI VPN",
 "DAF365 S4V Tunnel","DISA DECC VPN","DMZ COI","EURAM","EURAM/JRSS RA","Gateway VPN","GRE Tunnel",
 "GSU VPN","JRSS RA VPN","Management VLAN","Multiple VPNs","OSI COI VPN","Out of Band (OOB)",
 "Out of Band (OOB)","Pharicode VPN","RAS VPN","Type-1  Encrypted Tunnel","WLAN VPN"];
/* Columns A-U of the PPSM sheet, in the template's own order. Do not
   reorder, rename, add or remove: the importer reads them by position. */
const EMASS_HEADERS = [
  "#",                                                    // A  eMASS fills this in
  "Type",                                                 // B
  "Application/Software Record Name",                     // C
  "Protocol",                                             // D
  "Data Service",                                         // E
  "Port",                                                 // F
  "Boundary",                                             // G
  "Direction",                                            // H
  "VPN / Encrypted Tunnel Traffic",                       // I
  "VPN Tunnel Type",                                      // J
  "Source",                                               // K
  "Source Physical Location or Cloud Service Provider",   // L
  "Source IP Address",                                    // M
  "Source FQDN",                                          // N
  "Connection Logical Source Point",                      // O
  "Destination",                                          // P
  "Destination Physical Location or Cloud Service Provider", // Q
  "Destination IP Address",                               // R
  "Destination FQDN",                                     // S
  "Connection Logical Destination Point",                 // T
  "Purpose"                                               // U
];

/* Character limits, straight from the template's Instructions sheet. */
const EMASS_LIMIT = {D:20, F:20, C:40, K:500, P:500, N:750, S:750, M:750, R:750, L:1500, Q:1500, U:1000};
function emassCap(v, col){
  let s=String(v==null?"":v);
  if(col==="D") s=s.split("/").map(normProto).filter(Boolean).join("/"); // Protocol: no "?" or numbers; "TCP/UDP" kept
  /* The 20-char limits on Port and Protocol are per value; a consolidated
     cell holds several joined with "; ", so the limit does not apply to the
     joined string. Truncating it would cut a port in half. */
  if((col==="F"||col==="D"||col==="C") && s.indexOf(";")>=0) return s;
  const lim=EMASS_LIMIT[col];
  return lim && s.length>lim ? s.slice(0,lim) : s;
}
/* The glossary spells this one out in full. */
function emassDirection(d){
  const s=String(d||"").trim().toLowerCase();
  if(s.indexOf("bi")===0 || s==="both") return "Bi-Directional";
  if(s.indexOf("in")===0)  return "Inbound";
  if(s.indexOf("out")===0) return "Outbound";
  return "";
}
/* The template has no "Internal" boundary — internal traffic is one of the
   Internal Use Only boundaries. Which one is the assessor's call, so it is a
   setting rather than a guess. */
function emassBoundary(r){
  const one=b=>{
    if(isInternalBnd(b)){
      const code=CFG.internalExportBoundary || "B18";
      return (BND_BY_CODE[code]||{}).emass || "";
    }
    return bndLabel(b);
  };
  const b=String(r.boundary||"");
  if(b.indexOf(";")>=0){
    const out=[]; const seen=new Set();
    b.split(/\s*;\s*/).filter(Boolean).forEach(x=>{ const l=one(x); if(l && !seen.has(l)){ seen.add(l); out.push(l); } });
    return out.join("; ");
  }
  return one(b);
}

const isFqdn = h => !!h && h.indexOf(".")>0;
const shortName = h => !h ? "" : String(h).split(".")[0];

/* A short hostname plus the enclave's DNS domain is a fully qualified name,
   and the template asks for one. */
function emassFqdn(host){
  const s=String(host||"").trim();
  if(!s || isIP(s)) return "";
  if(s.indexOf(".")>0) return s;
  const d=String(CFG.dnsDomain||"").trim().replace(/^\.+/,"");
  return d ? s+"."+d : "";
}
/* Where a flow has no direction of its own: a row with no source is a
   listening service, so traffic comes to it; anything reaching outside the
   enclave goes out; everything else is client to server. */
function emassDirectionOf(r){
  const d=emassDirection(r.direction);
  if(d) return d;
  if(!r.src && r.dest) return "Inbound";
  if(scopeOf(r.dest)==="EXT") return "Outbound";
  if(scopeOf(r.src)==="EXT")  return "Inbound";
  return r.dstPort ? "Outbound" : "";
}
/* Physical location: the site for our own kit, the named provider for
   anything outside it. */
function emassLocation(addr, given, end){
  if(given) return given;
  if(!addr) return "";
  if(scopeOf(addr)==="EXT") return CFG.externalCsp||"";
  const own = end==="src" ? CFG.srcLocation : (end==="dst" ? CFG.dstLocation : "");
  return own || CFG.siteLocation || "";
}
/* VPN / Encrypted Tunnel Traffic for the export: the row's own value, the
   boundary's tunnel flag, or the whole-export setting from Settings. */
function emassVpn(r){
  const own=(r.vpn||"").trim();
  if(CFG.exportVpn && (CFG.exportVpnOverwrite || !own)) return CFG.exportVpn;
  if(own) return own;
  const b=bndCode(r.boundary); return b ? ((BND_BY_CODE[b]||{}).tunnel ? "Yes" : "No") : "";
}
function emassVpnType(r, vpn){
  const own=(r.vpnType||"").trim();
  if(CFG.exportVpnType && (CFG.exportVpnTypeOverwrite || !own) && vpn!=="No") return CFG.exportVpnType;
  if(own) return own;
  return vpn==="Yes" ? "" : (CFG.vpnTypeNone||"");
}
/* Purpose for the export: what was written, with any [DRAFT] marker
   removed; otherwise, when Settings say so, a generated statement so column
   U is never blank. */
function emassPurpose(r){
  const own=String(r.justification||"").replace(/\s*\[DRAFT[^\]]*\]\s*/g," ").trim();
  if(own) return own;
  if(CFG.exportPurpose===false) return "";
  return purposeStatement(r);
}

/* ---------------- shaping the register for the eMASS sheet ----------------
   The working register keeps one row per flow. The sheet that goes to eMASS
   is shaped from it on the way out:
     1. addresses only — a name in an address cell is swapped for its address
        where one is known (the name stays in the hostname cell for reference)
     2. one row per protocol/port (within boundary and direction, which are
        single-valued dropdowns): every service, application, source and
        destination seen on that port is joined into the one row, each named
        once
     3. ordered lowest port to highest
   The register itself is not changed. */
const joinUniq=(vals, norm)=>{
  const out=[], seen=new Set();
  vals.forEach(v=>String(v==null?"":v).split(/\s*;\s*/).forEach(x=>{
    x=x.trim(); if(!x) return;
    const k=norm?norm(x):x.toLowerCase();
    if(k && !seen.has(k)){ seen.add(k); out.push(x); } }));
  return out.join("; ");
};
/* application names: "Apache/2.4.57", "apache 2.4" and "Microsoft IIS/10.0"
   vs "microsoft iis 10" are one product each — version tokens are dropped
   before comparing */
const appKey=v=>{
  const base=String(v||"").toLowerCase().replace(/\bv?\d+(?:\.\d+)*[a-z]?\b/g," ");
  return normAppName(base)||normAppName(v)||String(v).toLowerCase();
};
function emassAddressOnly(r){
  const c=Object.assign({}, r);
  ["src","dest"].forEach(k=>{
    const v=String(c[k]||"").trim(); if(!v) return;
    const parts=v.split(/\s*;\s*/).filter(Boolean);
    const got=parts.map(x=> (isIP(x)||isCidr(x)) ? x : (lookupName(x)||x));
    c[k]=got.join("; ");
  });
  // a hostname with no address at all stays where it was so it can be seen and fixed
  return c;
}
function emassShape(rows){
  let out=(rows||ROWS).map(r=> CFG.emassIpOnly!==false ? emassAddressOnly(r) : Object.assign({}, r));
  if(CFG.emassOnePerPort!==false){
    /* a register row that Consolidate joined ("80; 443") is split back into
       its ports first, services lined up with them, so each port lands in
       exactly one exported row */
    const split=[];
    out.forEach(r=>{
      const ports=String(r.dstPort||"").split(/\s*;\s*/).filter(Boolean);
      if(ports.length<=1){ split.push(r); return; }
      const svcs=String(r.dataService||"").split(/\s*;\s*/);
      ports.forEach((pt,i)=>{ const c=Object.assign({}, r); c.dstPort=pt;
        c.dataService = svcs.length===ports.length ? (svcs[i]||"") : (r.dataService||"");
        split.push(c); });
    });
    out=split;
    /* a port is listed ONCE: TCP and UDP on the same port become one row
       reading "TCP/UDP"; a port seen both ways is "Bi-Directional"; a port
       seen across more than one boundary carries them semicolon-joined, as
       the template's Instructions sheet allows */
    const groups=new Map();
    out.forEach(r=>{
      const k=String(r.dstPort||"").trim().toLowerCase();
      if(!groups.has(k)) groups.set(k,[]); groups.get(k).push(r);
    });
    const PROTO_ORDER=["TCP","UDP","SCTP","ICMP"];
    out=[];
    groups.forEach(g=>{
      if(g.length===1){ out.push(g[0]); return; }
      const keep=Object.assign({}, g.slice().sort((a,b)=>cells(b)-cells(a))[0]);
      const protos=[...new Set(g.map(r=>normProto(r.proto)).filter(Boolean))]
        .sort((a,b)=>(PROTO_ORDER.indexOf(a)+1||99)-(PROTO_ORDER.indexOf(b)+1||99) || a.localeCompare(b));
      keep.proto = protos.join("/");
      const dirs=new Set(g.map(r=>emassDirectionOf(r)).filter(Boolean));
      keep.direction = dirs.size>1 ? "Bi-Directional" : ([...dirs][0]||keep.direction||"");
      const bnds=[]; const seenB=new Set();
      g.forEach(r=>{ const c=bndCode(r.boundary)||String(r.boundary||"").trim(); if(c && !seenB.has(c)){ seenB.add(c); bnds.push(c); } });
      keep.boundary = bnds.length>1 ? bnds.join("; ") : (bnds[0]||keep.boundary||"");
      keep.src        = joinUniq(g.map(r=>r.src));
      keep.srcHost    = joinUniq(g.map(r=>r.srcHost));
      keep.dest       = joinUniq(g.map(r=>r.dest));
      keep.dstHost    = joinUniq(g.map(r=>r.dstHost));
      keep.dataService= joinUniq(g.map(r=>r.dataService));
      keep.appName    = joinUniq(g.map(r=>r.appName||""), appKey);
      keep.banner     = joinUniq(g.map(r=>r.banner), appKey);
      keep.srcLoc     = joinUniq(g.map(r=>r.srcLoc));
      keep.dstLoc     = joinUniq(g.map(r=>r.dstLoc));
      keep.srcPoint   = joinUniq(g.map(r=>r.srcPoint));
      keep.dstPoint   = joinUniq(g.map(r=>r.dstPoint));
      keep.justification = g.map(r=>String(r.justification||"").replace(/\s*\[DRAFT[^\]]*\]\s*/g," ").trim()).find(Boolean) || "";
      keep.vpn        = g.map(r=>r.vpn).find(Boolean) || "";
      keep.vpnType    = g.map(r=>r.vpnType).find(Boolean) || "";
      keep.emassType  = g.map(r=>r.emassType).find(Boolean) || "";
      out.push(keep);
    });
  }
  // every application named once, even on rows that were not merged
  out.forEach(r=>{ r.appName=joinUniq([r.appName], appKey); r.dataService=joinUniq([r.dataService]); });
  if(CFG.emassSortByPort!==false){
    const firstPort=r=>{ const m=String(r.dstPort||"").match(/\d+/); return m?+m[0]:1e9; };
    out.sort((a,b)=>firstPort(a)-firstPort(b) || String(a.proto||"").localeCompare(String(b.proto||"")) ||
                    String(a.dest||"").localeCompare(String(b.dest||"")));
  }
  return out;
}

function emassRow(r){
  const vpn=emassVpn(r);
  return [
    "",                                                      // A  # — eMASS generates it
    r.emassType||"",                                         // B  Type
    emassCap(r.appName||r.dataService||r.banner||"","C"),    // C  Application/Software Record Name
    emassCap(r.proto||"","D"),                               // D  Protocol
    r.dataService||"",                                       // E  Data Service
    emassCap(r.dstPort||"","F"),                             // F  Port
    emassBoundary(r),                                        // G  Boundary
    emassDirectionOf(r),                                     // H  Direction
    vpn,                                                     // I  VPN / Encrypted Tunnel Traffic
    emassVpnType(r, vpn),                                    // J  VPN Tunnel Type
    emassCap(CFG.emassIpOnly!==false ? (r.src||r.srcHost||"") : (r.srcHost||r.src||""),"K"), // K  Source
    emassCap(emassLocation(r.src, r.srcLoc, "src"),"L"),     // L  Source Physical Location or CSP
    emassCap(r.src||"","M"),                                 // M  Source IP Address
    emassCap(CFG.emassIpOnly!==false ? (r.src||"") : emassFqdn(r.srcHost),"N"), // N  Source FQDN (address when IP-only)
    r.srcPoint||"",                                          // O  Connection Logical Source Point
    emassCap(CFG.emassIpOnly!==false ? (r.dest||r.dstHost||"") : (r.dstHost||r.dest||""),"P"), // P  Destination
    emassCap(emassLocation(r.dest, r.dstLoc, "dst"),"Q"),    // Q  Destination Physical Location or CSP
    emassCap(r.dest||"","R"),                                // R  Destination IP Address
    emassCap(CFG.emassIpOnly!==false ? (r.dest||"") : emassFqdn(r.dstHost),"S"), // S  Destination FQDN (address when IP-only)
    r.dstPoint||"",                                          // T  Connection Logical Destination Point
    emassCap(emassPurpose(r),"U")                            // U  Purpose
  ];
}

/* Every field is required by the importer (Purpose is generated when a row
   has none), so say which rows are not ready before they are sent. */
const EMASS_REQUIRED = [["B","Type"],["C","Application/Software Record Name"],["D","Protocol"],
  ["E","Data Service"],["F","Port"],["G","Boundary"],["H","Direction"],
  ["I","VPN / Encrypted Tunnel Traffic"],["J","VPN Tunnel Type"],["K","Source"],
  ["L","Source Physical Location or Cloud Service Provider"],["M","Source IP Address"],
  ["N","Source FQDN"],["O","Connection Logical Source Point"],["P","Destination"],
  ["Q","Destination Physical Location or Cloud Service Provider"],["R","Destination IP Address"],
  ["S","Destination FQDN"],["T","Connection Logical Destination Point"]];
function emassMissing(rows){
  const cols="ABCDEFGHIJKLMNOPQRSTU".split("");
  const tally=new Map();
  (rows||ROWS).forEach(r=>{
    const vals=emassRow(r);
    EMASS_REQUIRED.forEach(([col,name])=>{
      const i=cols.indexOf(col);
      if(!String(vals[i]||"").trim()) tally.set(name,(tally.get(name)||0)+1);
    });
  });
  return [...tally.entries()].sort((a,b)=>b[1]-a[1]);
}

function exportEmassCsv(){
  if(!ROWS.length) return flash("Nothing to export yet.","warn");
  const lines=[EMASS_HEADERS.map(csvCell).join(",")];
  emassShape(ROWS).forEach(r=>lines.push(emassRow(r).map(v=>csvCell(xmlClean(v))).join(",")));
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+".allow.csv",
    "\ufeff"+lines.join("\r\n"), "text/csv;charset=utf-8");
  flash("eMASS import CSV exported. Paste into the official template, or import directly where your instance accepts CSV.","ok");
}

let EMASS_DEFNAMES=[];
/* Pull one file back out of a freshly built xlsx (a store-or-deflate zip),
   so a self-test can confirm what was written. */
function inflateFromXlsx(bytes, name){
  try{
    const u8=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
    const dv=new DataView(u8.buffer,u8.byteOffset,u8.byteLength);
    let p=0;
    while(p+4<u8.length && dv.getUint32(p,true)===0x04034b50){
      const method=dv.getUint16(p+8,true), csize=dv.getUint32(p+18,true);
      const nlen=dv.getUint16(p+26,true), xlen=dv.getUint16(p+28,true);
      let fn=""; for(let k=0;k<nlen;k++) fn+=String.fromCharCode(u8[p+30+k]);
      const start=p+30+nlen+xlen;
      if(fn===name){
        const raw=u8.subarray(start,start+csize);
        const out=method===0?raw:inflateRaw(raw);
        return new TextDecoder("utf-8").decode(out);
      }
      p=start+csize;
    }
  }catch(e){}
  return "";
}
function buildEmassXlsx(m, rows){
  const enc=new TextEncoder();
  const cell=(ref,val,s)=>{ const v=xmlClean(val);
    if(v==="") return s?`<c r="${ref}" s="${s}"/>`:"";
    return `<c r="${ref}"${s?` s="${s}"`:""} t="inlineStr"><is><t xml:space="preserve">${esc(v)}</t></is></c>`; };
  const NC=EMASS_HEADERS.length, lastCol=colLetter(NC-1), last=rows.length+8;
  let body="";
  /* Rows 1-7 are the template's own header block: the classification label,
     the export details down column A, the system point of contact down column
     E, and the review details from column H. Row 8 is the column header row
     and the data starts at row 9. */
  body+=`<row r="1">`+cell("A1","***** CONTROLLED UNCLASSIFIED INFORMATION *****",5)+`</row>`;
  body+=`<row r="2">`+cell("A2","Date Exported:",4)+cell("B2",m.exportDate||new Date().toISOString().slice(0,10),0)+`</row>`;
  body+=`<row r="3">`+cell("A3","Exported By:",4)+cell("B3",m.exportedBy||"",0)
       +cell("E3","Office / Org:",4)+cell("F3",m.office||"",0)+`</row>`;
  body+=`<row r="4">`+cell("A4","Information System Owner:",4)+cell("B4",m.owner||"",0)
       +cell("E4","POC Name:",4)+cell("F4",m.pocName||m.poc||"",0)
       +cell("H4","Date Reviewed / Updated:",4)+cell("I4",m.reviewDate||"",0)+`</row>`;
  body+=`<row r="5">`+cell("A5","System Name:",4)+cell("B5",m.system||"",0)
       +cell("E5","POC Phone:",4)+cell("F5",m.pocPhone||"",0)
       +cell("H5","Reviewed / Updated By:",4)+cell("I5",m.reviewedBy||"",0)+`</row>`;
  body+=`<row r="6">`+cell("A6","System ID:",4)+cell("B6",m.systemId||"",0)
       +cell("E6","POC E-Mail:",4)+cell("F6",m.pocEmail||"",0)+`</row>`;
  body+=`<row r="7">`+cell("A7","DITPR ID:",4)+cell("B7",m.ditpr||"",0)
       +cell("E7","System Version/Release Number:",4)+cell("F7",m.version||"",0)+`</row>`;
  body+=`<row r="8">`+EMASS_HEADERS.map((h,i)=>cell(colLetter(i)+"8",h,1)).join("")+`</row>`;
  rows.forEach((r,idx)=>{ const rn=idx+9;
    body+=`<row r="${rn}">`+emassRow(r).map((v,i)=>cell(colLetter(i)+rn,v,2)).join("")+`</row>`; });

  const W=[6,18,34,12,20,10,44,14,26,24,28,34,20,30,34,28,34,20,30,34,44];
  const colsXml=`<cols>`+W.map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join("")+`</cols>`;
  const views=`<sheetViews><sheetView workbookViewId="0"><pane ySplit="8" topLeftCell="A9" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A9" sqref="A9"/></sheetView></sheetViews>`;

  /* dropdowns point at the Glossary sheet, exactly like the official template */
  /* Each register dropdown points at a defined name rather than a raw
     cross-sheet range. Some Excel builds will not render a list-validation
     that references another sheet directly, but every build honours a defined
     name, so the dropdowns appear reliably. The names are declared in
     workbook.xml below. */
  EMASS_DEFNAMES = [
    ["ppsm_boundary",  "A", BND_DEFS.length],
    ["ppsm_srcpoint",  "C", EMASS_POINTS.length],
    ["ppsm_dstpoint",  "E", EMASS_POINTS.length],
    ["ppsm_vpntype",   "G", EMASS_VPNTYPE.length],
    ["ppsm_type",      "I", EMASS_TYPE.length],
    ["ppsm_vpntraffic","K", 2],
    ["ppsm_direction", "M", 3]
  ];
  /* Direct Glossary ranges are what Excel itself writes for a list
     validation, so they render on desktop, web and mobile alike. (Defined
     names work on desktop but not reliably on Excel mobile, which is where
     these were not appearing.) The ranges are single-quoted in case a sheet
     name ever contains a space. */
  const gref=(col,n)=>`Glossary!$${col}$2:$${col}$${n+1}`;
  /* An inline literal list renders in every Excel; a range reference is only
     needed when the list is too long for the 255-char inline limit. Use
     inline wherever it fits (as the register export does), and fall back to a
     Glossary range for the three long lists. */
  const inlineList=arr=>{
    const joined=arr.map(s=>String(s).replace(/"/g,"")).join(",");
    return joined.length<=255 ? `"${esc(joined)}"` : null;
  };
  const pick=(arr,col,n)=>inlineList(arr) || gref(col,n);
  const dvs=[["B",pick(EMASS_TYPE,"I",EMASS_TYPE.length)],              // Type (inline)
             ["G",pick(BND_DEFS.map(x=>x.emass),"A",BND_DEFS.length)],  // Boundary (range)
             ["H",pick(["Bi-Directional","Inbound","Outbound"],"M",3)], // Direction (inline)
             ["I",pick(["Yes","No"],"K",2)],                            // VPN traffic (inline)
             ["J",pick(EMASS_VPNTYPE,"G",EMASS_VPNTYPE.length)],        // VPN tunnel type (range)
             ["O",pick(EMASS_POINTS,"C",EMASS_POINTS.length)],          // source point (range)
             ["T",pick(EMASS_POINTS,"E",EMASS_POINTS.length)]];         // dest point (range)
  /* showDropDown="0" is the OOXML quirk that MAKES the arrow appear (1 hides
     it). The input prompt shows the cell is a list before it is clicked, and
     showErrorMessage keeps a typed value inside the accepted set. */
  const dv=`<dataValidations count="${dvs.length}">`+dvs.map(([c,nm])=>
    `<dataValidation sqref="${c}9:${c}${Math.max(last,9)}" showDropDown="0" showInputMessage="1" showErrorMessage="1" allowBlank="1" type="list">`+
    `<formula1>${nm}</formula1></dataValidation>`).join("")+`</dataValidations>`;

  /* The filter arrows live on the header row (row 8) and cover the data
     below it, so a reviewer can click Protocol and show only TCP, filter Data
     Service, Port, Boundary, Direction, or any other column in row 8. In the
     OOXML schema autoFilter must come before dataValidations. */
  const headerRow=8;
  const filter=`<autoFilter ref="A${headerRow}:${lastCol}${Math.max(last,headerRow)}"/>`;
  const sheet1=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:${lastCol}${last}"/>${views}<sheetFormatPr defaultRowHeight="15"/>${colsXml}<sheetData>${body}</sheetData>${filter}${dv}</worksheet>`;

  /* The Glossary keeps one list per column with a blank column between,
     exactly as the template has it: A Boundaries, C source points,
     E destination points, G VPN tunnel types, I Type, K VPN traffic,
     M Direction. */
  const gcols=[["A","Boundaries",BND_DEFS.map(b=>b.emass)],
               ["C","Connection Logical Source Point",EMASS_POINTS],
               ["E","Connection Logical Destination Point",EMASS_POINTS],
               ["G","VPN Tunnel Type",EMASS_VPNTYPE],
               ["I","Type",EMASS_TYPE],
               ["K","VPN / Encrypted Tunnel Traffic",["Yes","No"]],
               ["M","Direction",["Bi-Directional","Inbound","Outbound"]]];
  const maxLen=Math.max(...gcols.map(g=>g[2].length))+1;
  let gbody="";
  for(let r=1;r<=maxLen;r++){
    let cells="";
    gcols.forEach(([col,title,vals])=>{
      const v = r===1 ? title : (vals[r-2]||"");
      if(v) cells+=cell(col+r, v, r===1?1:0);
    });
    if(cells) gbody+=`<row r="${r}">${cells}</row>`;
  }
  const gwidths=`<cols><col min="1" max="1" width="46" customWidth="1"/><col min="3" max="3" width="40" customWidth="1"/><col min="5" max="5" width="40" customWidth="1"/><col min="7" max="7" width="26" customWidth="1"/><col min="9" max="9" width="20" customWidth="1"/><col min="11" max="11" width="30" customWidth="1"/><col min="13" max="13" width="18" customWidth="1"/></cols>`;
  const sheet2=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:M${maxLen}"/><sheetFormatPr defaultRowHeight="15"/>${gwidths}<sheetData>${gbody}</sheetData></worksheet>`;

  /* The Instructions sheet, word for word from the template. */
  const INSTR=[
   "1. Enter valid information into the fields on the PPSM Boundary Template.",
   "2. Do not delete columns/sheets, delete the classification label, or add additional columns. Doing so may have a negative impact on the ability to ingest the template.",
   "3. For the \"Boundary\", \"Direction\", \"Connection Logical Source Point\", \"Connection Logical Destination Point\", \"VPN Tunnel Type, Type\", and \"VPN / Encrypted Tunnel Traffic\" fields, please refer to the \"Glossary\" worksheet for a listing of available/acceptable values. Where applicable, please separate multiple values by semicolons.",
   "4. If importing PPSM boundaries information, all fields except the \"Purpose\" field are required.",
   "5. The \"Asset ID #\" (Column A) is automatically generated after the PPSM asset is successfully imported. No user action is required to complete or update and therefore this column can be treated as read-only.",
   "6. The \"Port\" and \"Protocol\" fields have a character limit of 20. The \"Application/Software Record Name\" field has a character limit of 40. The \"Source\" and \"Destination\" fields have a character limit of 500. The \"Source FQDN\", \"Destination FQDN\", \"Source IP Address\", and \"Destination IP Address\" fields have a character limit of 750. The \"Source Physical Location or Cloud Service Provider\" and \"Destination Physical Location or Cloud Service Provider\" fields have a character limit of 1500. The \"Purpose\" field has a character limit of 1000.",
   "7. The following fields function as administrator-managed lookups: \"Boundary\", \"Direction\", \"Connection Logical Source Point\", \"Connection Logical Destination Point\", and \"VPN Tunnel Traffic\". If an appropriate value is not available and should be added, contact the System Administrators."
  ];
  let ibody=`<row r="1" ht="20" customHeight="1">`+cell("A1","PPSM Boundary Information Import Template Instructions",6)+`</row>`;
  INSTR.forEach((s,i)=>{ ibody+=`<row r="${i+2}">`+cell("A"+(i+2), s, 2)+`</row>`; });
  const sheet3=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:A${INSTR.length+1}"/><sheetFormatPr defaultRowHeight="15"/><cols><col min="1" max="1" width="150" customWidth="1"/></cols><sheetData>${ibody}</sheetData></worksheet>`;

  const styles=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="5"><font><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Arial"/></font><font><b/><sz val="11"/><name val="Arial"/></font><font><b/><color rgb="FF000000"/><sz val="10"/><name val="Arial"/></font><font><b/><u/><sz val="14"/><name val="Times New Roman"/></font></fonts><fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F4E79"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF92D9A9"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFC9D2DC"/></left><right style="thin"><color rgb="FFC9D2DC"/></right><top style="thin"><color rgb="FFC9D2DC"/></top><bottom style="thin"><color rgb="FFC9D2DC"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="7"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/><xf fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf fontId="3" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;

  const ct=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
  const rels=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const wb=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="PPSM" sheetId="1" r:id="rId1"/><sheet name="Glossary" sheetId="2" r:id="rId2"/><sheet name="Instructions" sheetId="3" r:id="rId3"/></sheets><definedNames>`+
    (EMASS_DEFNAMES||[]).map(([nm,col,n])=>
      `<definedName name="${nm}">Glossary!$${col}$2:$${col}$${n+1}</definedName>`).join("")+
    `</definedNames></workbook>`;
  const wbr=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  return zipStore([
    {name:"[Content_Types].xml", data:enc.encode(ct)},
    {name:"_rels/.rels", data:enc.encode(rels)},
    {name:"xl/workbook.xml", data:enc.encode(wb)},
    {name:"xl/_rels/workbook.xml.rels", data:enc.encode(wbr)},
    {name:"xl/worksheets/sheet1.xml", data:enc.encode(sheet1)},
    {name:"xl/worksheets/sheet2.xml", data:enc.encode(sheet2)},
    {name:"xl/worksheets/sheet3.xml", data:enc.encode(sheet3)},
    {name:"xl/styles.xml", data:enc.encode(styles)}
  ]);
}

function exportEmassXlsx(){
  if(!ROWS.length) return flash("Nothing to export yet.","warn");
  /* Make sure the register is finished before it is written: resolve names,
     derive what can be derived, merge duplicates and consolidate ports. This
     runs whether or not Finish Register was pressed, so the exported file is
     always the tidy one. */
  try{ applyHostmap(true); }catch(e){}
  try{ enrichRows(ROWS, null, false); }catch(e){}
  try{ excludeEphemeral(ROWS); }catch(e){}
  try{ dedupeRows(); }catch(e){}
  try{ if(CFG.consolidatePorts!==false) consolidateRows(ROWS); }catch(e){}
  render();
  const m=meta();
  const shaped=emassShape(ROWS);
  const buf=buildEmassXlsx(m, shaped);
  const stem=(m.system||"ppsm").replace(/[^\w.\-]+/g,"_");
  download(stem+".allow.xlsx",
    buf, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  const names=shaped.filter(r=>[r.src,r.dest].some(v=>String(v||"").split(/\s*;\s*/).some(x=>x && !isIP(x) && !isCidr(x)))).length;
  if(names && CFG.emassIpOnly!==false)
    flash(names+" row"+(names===1?"":"s")+" still carr"+(names===1?"ies":"y")+" a hostname with no known address — load a DNS export or type the address under Endpoints.","warn");
  /* say which required fields are still empty and in how many rows, most
     common first. */
  const miss=emassMissing(shaped);
  if(!miss.length){ flash("eMASS import workbook exported. Every required field is filled in.","ok"); }
  else{
    const top=miss.slice(0,4).map(([k,v])=>v+" \u00d7 "+k).join(" · ");
    flash("Exported. The importer needs every field except Purpose, and these are still empty: "+
          top+(miss.length>4?" · and "+(miss.length-4)+" more":"")+
          ". The Glossary sheet carries the dropdowns for the lookup fields.","warn");
  }
}
