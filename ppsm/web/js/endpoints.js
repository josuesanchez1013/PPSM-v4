"use strict";
/* ============================================================
   HOSTNAME RESOLUTION + ENDPOINT DISCOVERY
   A PPSM register is only useful if every endpoint is a named
   system. This module keeps an IP -> hostname inventory, applies
   it across the register, and reports which endpoints are still
   unidentified so they can be chased down.
   ============================================================ */

/* ip -> {name, source, os, owner, notes} */
let HOSTMAP = new Map();

/* shared quoted-CSV line splitter */
/* Split CSV text into records, honouring newlines inside quoted cells —
   Tenable's Plugin Output column is multi-line and would otherwise break a
   finding across several records. */
function splitCsvRecords(text){
  const out=[]; let cur="", q=false;
  const t=String(text||"");
  for(let i=0;i<t.length;i++){
    const c=t[i];
    if(c==='"'){ cur+=c; if(q && t[i+1]==='"'){ cur+='"'; i++; } else q=!q; }
    else if((c==="\n"||c==="\r") && !q){ if(c==="\r" && t[i+1]==="\n") i++; if(cur.trim()) out.push(cur); cur=""; }
    else cur+=c;
  }
  if(cur.trim()) out.push(cur);
  return out;
}
function splitCsvLine(l){
  const out=[]; let cur="", q=false;
  for(let i=0;i<l.length;i++){
    const c=l[i];
    if(c==='"'){ if(q&&l[i+1]==='"'){cur+='"';i++;} else q=!q; }
    else if(c===","&&!q){ out.push(cur); cur=""; }
    else cur+=c;
  }
  out.push(cur);
  return out.map(s=>s.trim());
}

/* Is this address inside the boundary? Internal systems must be identified by
   hostname; external destinations are documented by service and purpose instead,
   so they are scored separately. */
function isInternal(ip){
  if(!ip) return false;
  const extra=(CFG.internalRanges||"").split(/[,\s]+/).filter(Boolean);
  for(const c of extra){
    if(c.indexOf("/")>0){ if(inCidr(ip,c)) return true; }
    else if(ip===c || ip.indexOf(c)===0) return true;
  }
  if(/^10\./.test(ip)) return true;
  if(/^192\.168\./.test(ip)) return true;
  if(/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if(/^f[cd][0-9a-f]{2}:/i.test(ip)) return true;      // IPv6 unique-local
  return false;
}
function inCidr(ip,cidr){
  const m=cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if(!m || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const toInt=a=>a.split(".").reduce((x,o)=>((x<<8)>>>0)+(+o),0)>>>0;
  const bits=+m[2], mask=bits===0?0:((0xFFFFFFFF<<(32-bits))>>>0);
  return (toInt(ip)&mask)>>>0 === (toInt(m[1])&mask)>>>0;
}

/* loopback and link-local are noise in a PPSM register */
function isLoopback(ip){
  return /^127\./.test(ip) || ip==="::1" || /^169\.254\./.test(ip) || /^fe80:/i.test(ip);
}

function isIP(s){
  if(!s) return false;
  s=String(s).trim().replace(/^\[|\]$/g,"").replace(/%[A-Za-z0-9._-]+$/,"");
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every(o=>+o<=255);
  if(s.indexOf(":")<0) return false;
  // a MAC address is hex and colons too, and is not an address we can route to
  if(/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(s)) return false;
  if(!/^[0-9A-Fa-f:.]+$/.test(s)) return false;
  if((s.match(/::/g)||[]).length>1) return false;          // only one run of zeroes
  const parts=s.split(":");
  if(parts.length>8) return false;
  const last=parts[parts.length-1];
  if(last.indexOf(".")>=0 && !/^\d{1,3}(\.\d{1,3}){3}$/.test(last)) return false;
  return parts.filter(Boolean).every(p=>p.indexOf(".")>=0 || /^[0-9A-Fa-f]{1,4}$/.test(p));
}
/* A rule endpoint can be a whole network. That is an address, not a hostname,
   and it belongs in the IP column. */
function isCidr(s){
  return !!s && /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(String(s).trim());
}
function isAddrLike(s){ return isIP(s) || isCidr(s); }
function isHostname(s){
  if(!s) return false;
  s=String(s).trim();
  return !isIP(s) && /^[A-Za-z0-9]([A-Za-z0-9.\-_]*[A-Za-z0-9])?$/.test(s);
}
/* accepts "10.0.0.1", "host.lan", "10.0.0.1 (host.lan)", "host.lan [10.0.0.1]" */
function splitIpHost(v){
  if(!v) return {ip:"",host:""};
  const s=String(v).trim();
  if(isCidr(s)) return {ip:s, host:""};
  let m=s.match(/^(\S+)\s*[\(\[]\s*([^)\]]+?)\s*[\)\]]$/);
  if(m){
    const a=m[1], b=m[2];
    if(isIP(a)) return {ip:a, host:isIP(b)?"":b};
    if(isIP(b)) return {ip:b, host:isIP(a)?"":a};
    return {ip:"", host:a};
  }
  if(isIP(s)) return {ip:s, host:""};
  return {ip:"", host:s};
}

/* normalise a row so IP and hostname live in their own fields */
/* any boundary written as a label, a bare number or a legacy tag becomes a code */
/* Identity of a flow for merging: the same service on the same destination
   from the same source is one registration, no matter how many tools saw it. */
function flowKey(r){
  const basis = String(r.origin||"").indexOf("firewall-rule")>=0 ? "rule" : "seen";
  // same normalisation as dedupeRows: trimmed, case-folded, trailing dot
  // dropped, port/source lists order-independent — so "SRV01.lan." from one
  // tool and "srv01.lan" from another land on the same row at ingest
  const nz = v => String(v==null?"":v).trim().toLowerCase().replace(/\.+$/,"");
  const lst= v => String(v==null?"":v).split(/[;,]/).map(nz).filter(Boolean).sort().join(";");
  return [basis, nz(r.proto),
          nz(r.dest||r.dstHost||""),
          lst(r.dstPort),
          lst(r.src||r.srcHost||"")].join("|");
}

/* Merge a batch of parsed rows into the register, combining anything that
   describes a flow already present rather than adding a second row for it. */
function mergeIntoRegister(incoming){
  const index=new Map();
  ROWS.forEach(r=>{ const k=flowKey(r); if(!index.has(k)) index.set(k,r); });
  let added=0, merged=0;
  incoming.forEach(n=>{
    const k=flowKey(n);
    const cur=index.get(k);
    if(!cur){ index.set(k,n); ROWS.push(n); added++; return; }
    merged++;
    const hadZones = !!(cur.srcZone || cur.dstZone);
    const bringsZones = !!(n.srcZone || n.dstZone);
    const gainedZones = bringsZones && !hadZones;
    // keep whichever value is actually populated; never overwrite a real one
    ["srcHost","dstHost","dataService","banner","direction","boundary","enclave",
     "srcZone","dstZone","collector","data","classification","justification",
     "assurance","calRef","registryId","emassType","srcPoint","dstPoint","vpn",
     "vpnType","appName","srcLoc","dstLoc","isaRef","cal","srcPort"].forEach(f=>{
       if(!cur[f] && n[f]) cur[f]=n[f];
     });
    // counters: keep the larger observation
    ["pkts","bytes"].forEach(f=>{
      const a=+(cur[f]||0), b=+(n[f]||0);
      if(b>a) cur[f]=n[f];
    });
    // provenance: every tool that saw this flow
    const tools=new Set(String(cur.origin||"").split(/[,;]\s*/).filter(Boolean));
    String(n.origin||"").split(/[,;]\s*/).filter(Boolean).forEach(t=>tools.add(t));
    cur.origin=[...tools].join(", ");
    // an unconfirmed probe stays unconfirmed only if nothing ever answered
    if(cur.status==="Unconfirmed" && n.status && n.status!=="Unconfirmed") cur.status=n.status;
    // notes: keep both, without repeating
    if(n.notes && String(cur.notes||"").indexOf(n.notes)<0)
      cur.notes = cur.notes ? (cur.notes+" · "+n.notes) : n.notes;
    /* If this sighting brought firewall interface names that the first one
       lacked, that is better evidence than an address-only guess, so redo the
       boundary and everything derived from it. Otherwise whichever tool the
       browser happened to read first would decide the boundary. */
    if(gainedZones && !cur.boundary){
      const b=deriveBoundary(cur);
      if(b){
        cur.boundary=b;
        cur.subPath=submissionPath(b);
        cur.emassType=deriveType(cur);
        cur.srcPoint=derivePoint(cur.src, cur.srcZone);
        cur.dstPoint=derivePoint(cur.dest, cur.dstZone);
      }
    }
  });
  return {added, merged};
}

function normalizeBoundary(r){
  if(!r.boundary) return r;
  const c=bndCode(r.boundary);
  if(c) r.boundary=c;
  /* Anything an older version auto-assigned to a DISN boundary was a guess we
     can no longer stand behind, so fall back to what the addresses prove. */
  if(CROSS_DISN.has(r.boundary) && scopeOf(r.src)==="INT" && scopeOf(r.dest)==="INT")
    r.boundary=INTERNAL_BND;
  return r;
}
/* Socket listings decorate addresses: brackets round IPv6, a %zone suffix on
   link-local and loopback, and a wildcard meaning "every interface on this
   host". None of those are addresses a register can point at. */
function cleanAddr(v){
  let s=String(v||"").trim();
  if(!s) return "";
  s=s.replace(/^\[|\]$/g,"");         // [::1] -> ::1
  s=s.replace(/%[A-Za-z0-9._-]+$/,""); // 127.0.0.53%lo -> 127.0.0.53
  return s;
}
function isIPv4(v){
  const s=cleanAddr(v);
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split(".").every(o=>+o<=255);
}
/* An address that is a valid IP but not IPv4. Recognised so it can be set
   aside deliberately rather than misread as a hostname. */
function isIPv6Addr(v){
  const s=cleanAddr(v);
  return !!s && isIP(s) && !isIPv4(s);
}
function isWildcardAddr(v){
  const s=cleanAddr(v);
  return s==="0.0.0.0" || s==="::" || s==="*" || s==="";
}
function normalizeEndpoints(r){
  if(r.src)  r.src  = cleanAddr(r.src);
  if(r.dest) r.dest = cleanAddr(r.dest);
  // a wildcard bind is this host, not an address of its own
  if(isWildcardAddr(r.src)  && r.src!=="")  r.src="";
  if(isWildcardAddr(r.dest) && r.dest!=="") r.dest="";
  /* A bracketed IPv6 address can be mistaken for a hostname on the way in.
     Put it back in the address column, where the rest of the tool looks. */
  if(r.srcHost && isIP(cleanAddr(r.srcHost))){
    if(!r.src) r.src=cleanAddr(r.srcHost);
    r.srcHost="";
  }
  if(r.dstHost && isIP(cleanAddr(r.dstHost))){
    if(!r.dest) r.dest=cleanAddr(r.dstHost);
    r.dstHost="";
  }
  if(isWildcardAddr(r.src)  && r.src!=="")  r.src="";
  if(isWildcardAddr(r.dest) && r.dest!=="") r.dest="";
  if(r.src && !r.srcHost){
    const s=splitIpHost(r.src);
    if(s.host){ r.srcHost=s.host; r.src=s.ip; }        // s.ip may be "" — a name-only endpoint
  }
  if(r.dest && !r.dstHost){
    const d=splitIpHost(r.dest);
    if(d.host){ r.dstHost=d.host; r.dest=d.ip; }
  }
  return r;
}

/* learnHost: see NAME RESOLUTION */

/* harvest names already present in imported rows */
function learnFromRows(rows){
  (rows||ROWS).forEach(r=>{
    if(r.src && r.srcHost) learnHost(r.src, r.srcHost, r.origin);
    if(r.dest && r.dstHost) learnHost(r.dest, r.dstHost, r.origin);
  });
}

/* apply the inventory to every row that is missing a name */
/* applyHostmap: see NAME RESOLUTION */

/* ---------------- name-source parsers ---------------- */
/* seen = records recognised in the file; learned = names new to the inventory */
function nameNote(seen, learned, what){
  if(!seen) return "";
  if(learned===seen) return learned+" "+what+" learned";
  if(learned===0)    return seen+" "+what+" read — all already known";
  return seen+" "+what+" read · "+learned+" new";
}

/* hosts file (/etc/hosts, Windows hosts) */
function parseHostsFile(text){
  let n=0, seen=0;
  text.split(/\r?\n/).forEach(l=>{
    const s=l.replace(/#.*$/,"").trim(); if(!s) return;
    const p=s.split(/\s+/); if(p.length<2) return;
    if(!isIP(p[0])) return;
    // "ip neigh" output looks like a hosts line; its words are states, not names
    if(/\b(dev|lladdr)\b/.test(s)) return;
    const NOT_A_NAME=/^(dev|lladdr|reachable|stale|delay|probe|failed|incomplete|permanent|noarp|router|ether|dynamic|static|eth\d+|ens\d+\w*|enp\w+|em\d+|bond\d+|vlan\d+|lo)$/i;
    const names=p.slice(1).filter(x=>isHostname(x) && !NOT_A_NAME.test(x) &&
                                     !/^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$/i.test(x));
    if(!names.length) return;
    const best=names.reduce((a,b)=>b.length>a.length?b:a);
    seen++;
    if(learnHost(p[0], best, "hosts-file")) n++;
  });
  return {rows:[], names:n, seen, note:nameNote(seen,n,"host entries")};
}

/* DNS zone file — A / AAAA records */
/* parseDnsZone: see NAME RESOLUTION */

/* ISC dhcpd.leases and Windows DHCP CSV */
function parseDhcpLeases(text){
  let n=0, seen=0;
  if(/^\s*lease\s+\S+\s*\{/m.test(text)){
    const re=/lease\s+(\S+)\s*\{([\s\S]*?)\}/g; let m;
    while((m=re.exec(text))){
      const ip=m[1], body=m[2];
      const hm=body.match(/client-hostname\s+"([^"]+)"/i) || body.match(/hostname\s+"([^"]+)"/i);
      if(hm){ seen++; if(learnHost(ip,hm[1],"dhcp")) n++; }
    }
    return {rows:[], names:n, seen, note:nameNote(seen,n,"DHCP leases")};
  }
  // CSV form: IP Address,Name,Lease Expiration,...
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(!lines.length) return {rows:[],names:0,note:""};
  const hdr=lines[0].toLowerCase().split(",").map(s=>s.trim());
  const iIP=hdr.findIndex(h=>/ip address|ipaddress|^ip$/.test(h));
  const iNM=hdr.findIndex(h=>/name|host/.test(h));
  if(iIP<0||iNM<0) return {rows:[],names:0,seen:0,note:""};
  lines.slice(1).forEach(l=>{
    const c=splitCsvLine(l);
    if(c[iIP]&&isIP(c[iIP].trim())&&c[iNM]){ seen++;
      if(learnHost(c[iIP].trim(), c[iNM].trim(), "dhcp")) n++; }
  });
  return {rows:[], names:n, seen, note:nameNote(seen,n,"DHCP leases")};
}

/* ARP / neighbour table — IP+MAC, and a name when the OS resolved one */
function parseArpTable(text){
  let n=0, seen=0;
  text.split(/\r?\n/).forEach(l=>{
    const s=l.trim(); if(!s) return;
    // "host.lan (10.0.0.5) at 00:11:22:33:44:55" (arp -a on Linux/macOS)
    let m=s.match(/^(\S+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{11,})/);
    if(m){ if(isHostname(m[1])&&m[1]!=="?"){ seen++; if(learnHost(m[2],m[1],"arp")) n++; } return; }
    // "  10.0.0.5   00-11-22-33-44-55  dynamic"  (Windows arp -a) — MAC only, no name
  });
  return {rows:[], names:n, seen, note:nameNote(seen,n,"ARP names")};
}

/* AD computer export / CMDB inventory CSV */
function parseInventoryCsv(text){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return {rows:[],names:0,note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase().replace(/^"|"$/g,""));
  const f=(...names)=>{ for(const nm of names){ const i=hdr.findIndex(h=>h===nm); if(i>=0) return i; }
                        for(const nm of names){ const i=hdr.findIndex(h=>h.includes(nm)); if(i>=0) return i; } return -1; };
  const iIP=f("ipv4address","ip address","ipaddress","ip"),
        iNM=f("dnshostname","hostname","host name","name","cn","computername"),
        iOS=f("operatingsystem","os","platform"),
        iOW=f("owner","custodian","poc","managedby","system owner"),
        iEN=f("enclave","zone","site","location"),
        iRO=f("role","function","description","purpose");
  if(iIP<0||iNM<0) return {rows:[],names:0,seen:0,note:""};
  let n=0, seen=0;
  lines.slice(1).forEach(l=>{
    const c=splitCsvLine(l).map(s=>s.replace(/^"|"$/g,"").trim());
    const ip=c[iIP], nm=c[iNM];
    if(!ip||!isIP(ip)||!nm) return;
    seen++;
    if(learnHost(ip,nm,"inventory",{
      os:iOS>=0?c[iOS]:"", owner:iOW>=0?c[iOW]:"",
      enclave:iEN>=0?c[iEN]:"", role:iRO>=0?c[iRO]:""
    })) n++;
  });
  return {rows:[], names:n, seen, note:nameNote(seen,n,"inventory records")};
}

/* DNS query log — maps answers back to names */
function parseDnsLog(text){
  let n=0, seen=0;
  text.split(/\r?\n/).forEach(l=>{
    let m=l.match(/(\S+)\s+IN\s+A\s+(\d{1,3}(?:\.\d{1,3}){3})/i)
        || l.match(/query.*?\s(\S+?)\s.*?\b(\d{1,3}(?:\.\d{1,3}){3})\b/i);
    if(m && isHostname(m[1]) && isIP(m[2])){ seen++;
      if(learnHost(m[2], m[1], "dns-log")) n++; }
  });
  return {rows:[], names:n, seen, note:nameNote(seen,n,"DNS log names")};
}

/* ---------------- endpoint discovery ---------------- */
/*
   Every distinct system seen in the register, with the role it plays.
   This is the discovery deliverable: what is on the network, what it
   is called, and what it serves.
*/
function buildEndpoints(rows){
  rows = rows || ROWS;
  const map=new Map();
  const get=ip=>{
    let e=map.get(ip);
    if(!e){ e={ip, host:"", enclave:"", collectors:new Set(), services:new Map(),
                asServer:0, asClient:0, peers:new Set(), boundaries:new Set(),
                origins:new Set(), os:"", owner:""};
            map.set(ip,e); }
    return e;
  };
  /* A row whose endpoint is a hostname with no address yet is still a
     system: list it under its name, so a register that arrived with names
     only shows what the DNS zones have not covered. */
  const keyOf=(ip,host)=>{
    if(ip) return ip;
    if(host && !isCidr(host)) return "name:"+String(host).toLowerCase();
    return "";
  };
  rows.forEach(r=>{
    const dk=keyOf(r.dest, r.dstHost), sk=keyOf(r.src, r.srcHost);
    if(dk){
      const e=get(dk);
      if(!r.dest){ e.ip=""; e.noAddr=true; e.host=e.host||r.dstHost; }
      e.asServer++;
      if(r.dstHost && !e.host) e.host=r.dstHost;
      if(r.enclave && !e.enclave) e.enclave=r.enclave;
      if(r.collector) e.collectors.add(r.collector);
      if(r.origin) e.origins.add(r.origin);
      if(r.boundary) e.boundaries.add(r.boundary);
      if(sk) e.peers.add(sk);
      if(r.dstPort){
        const k=(r.proto||"")+"/"+r.dstPort+(r.dataService?" "+r.dataService:"");
        e.services.set(k,(e.services.get(k)||0)+1);
      }
    }
    if(sk){
      const e=get(sk);
      if(!r.src){ e.ip=""; e.noAddr=true; e.host=e.host||r.srcHost; }
      e.asClient++;
      if(r.srcHost && !e.host) e.host=r.srcHost;
      if(r.enclave && !e.enclave) e.enclave=r.enclave;
      if(r.collector) e.collectors.add(r.collector);
      if(r.origin) e.origins.add(r.origin);
      if(dk) e.peers.add(dk);
    }
  });
  map.forEach(e=>{
    if(e.noAddr){
      e.role = e.asServer&&e.asClient ? "Both" : (e.asServer ? "Server" : "Client");
      e.scope = nameLooksInternal(e.host) ? "Internal" : "External";
      return;
    }
    if(!e.host && HOSTMAP.has(e.ip)){ const h=HOSTMAP.get(e.ip); e.host=h.name; e.os=h.os||""; e.owner=h.owner||""; }
    else if(HOSTMAP.has(e.ip)){ const h=HOSTMAP.get(e.ip); e.os=e.os||h.os||""; e.owner=e.owner||h.owner||""; }
    e.role = e.asServer&&e.asClient ? "Both" : (e.asServer ? "Server" : "Client");
    e.scope = isInternal(e.ip) ? "Internal" : "External";
  });
  return [...map.values()].sort((a,b)=>
    (b.asServer+b.asClient)-(a.asServer+a.asClient) || (a.ip||a.host).localeCompare(b.ip||b.host));
}

/* Is a bare hostname one of ours? Unqualified names are, and so is anything
   under the enclave's DNS domain or under a domain the name sources taught
   us. A public name like update.microsoft.com is not. */
function nameLooksInternal(host){
  const h=String(host||"").trim().toLowerCase().replace(/\.$/,"");
  if(!h) return false;
  if(h.indexOf(".")<0) return true;
  const dom=String(CFG.dnsDomain||"").trim().toLowerCase().replace(/^\.+/,"");
  if(dom && (h===dom || h.endsWith("."+dom))) return true;
  const suffix=h.slice(h.indexOf(".")+1);
  for(const [ip,x] of HOSTMAP){
    const n=String(x.name||"").toLowerCase();
    if(n.indexOf(".")>0 && n.slice(n.indexOf(".")+1)===suffix && isInternal(ip)) return true;
  }
  return /\.(mil|local|lan|internal|corp|intranet|home)$/.test(h);
}

function endpointStats(eps){
  const internal=eps.filter(e=>e.scope==="Internal");
  const external=eps.filter(e=>e.scope==="External");
  const named=internal.filter(e=>e.host && !e.noAddr).length;
  const noAddr=eps.filter(e=>e.noAddr).length;
  return {
    total: eps.length,
    internal: internal.length,
    external: external.length,
    named,
    noAddr,
    unnamed: internal.length-named,
    servers: eps.filter(e=>e.role!=="Client").length,
    pct: internal.length ? Math.round(named/internal.length*100) : 100
  };
}

function renderEndpoints(){
  const host=$("epBody"); if(!host) return;
  const scope=($("epScope")&&$("epScope").value)==="filtered" ? getFiltered() : ROWS;
  const onlyUn=$("epUnnamed")&&$("epUnnamed").checked;
  let eps=buildEndpoints(scope);
  const st=endpointStats(eps);
  if(onlyUn) eps=eps.filter(e=>(!e.host || e.noAddr) && e.scope==="Internal");

  const bar=$("epStats");
  if(bar){
    bar.innerHTML = st.total
      ? `<span class="ep-pill"><b>${st.total}</b> endpoints</span>`+
        `<span class="ep-pill"><b>${st.internal}</b> internal</span>`+
        `<span class="ep-pill ok"><b>${st.named}</b> named</span>`+
        `<span class="ep-pill ${st.unnamed?"warn":"ok"}"><b>${st.unnamed}</b> unidentified</span>`+
        (st.noAddr ? `<span class="ep-pill warn" title="hostnames the register carries that no DNS zone, hosts file or inventory has an address for"><b>${st.noAddr}</b> name${st.noAddr===1?"":"s"} without an address</span>` : "")+
        `<span class="ep-pill"><b>${st.external}</b> external</span>`+
        `<span class="ep-pill"><b>${st.servers}</b> providing services</span>`+
        `<span class="ep-meter" title="${st.pct}% of internal systems identified"><i style="width:${st.pct}%"></i></span>`+
        `<span class="ep-pct">${st.pct}% of internal systems identified</span>`
      : "";
  }
  if(!eps.length){
    host.innerHTML='<div class="dg-empty">'+(st.total
      ? "Every internal system has been identified."
      : "No endpoints yet — import data first.")+'</div>';
    return;
  }
  const rowsHtml=eps.map(e=>{
    const svc=[...e.services.entries()].sort((a,b)=>b[1]-a[1]).slice(0,6).map(x=>x[0]);
    const ext = e.scope==="External";
    const nameCell = e.host
      ? `<span class="ep-name">${esc(e.host)}</span>`
      : (ext ? `<span class="ep-dim">external — document by service/purpose</span>`
             : `<input class="ep-in" data-ephost="${esc(e.ip)}" placeholder="unidentified — name it here">`);
    const ipCell = e.noAddr
      ? `<input class="ep-in" data-epip="${esc(e.host)}" placeholder="no address in any name source — enter it" title="Type the address for ${esc(e.host)} and press Enter; it is applied to every row that names this host">`
      : esc(e.ip);
    return `<tr${((!e.host||e.noAddr)&&!ext)?' class="ep-un"':''}>
      <td class="mono">${ipCell}</td>
      <td>${nameCell}</td>
      <td><span class="ep-role r-${e.role.toLowerCase()}">${e.role}</span></td>
      <td><span class="ep-scope s-${e.scope.toLowerCase()}">${e.scope}</span></td>
      <td class="mono ep-svc">${svc.length?esc(svc.join("  ")):"<span class='ep-dim'>—</span>"}</td>
      <td class="mono">${e.asServer}/${e.asClient}</td>
      <td class="mono">${(function(){ const inv=SOFTWARE_INV.get(e.ip); if(!inv||!inv.items.length) return "<span class='ep-dim'>—</span>";
          const top=inv.items.slice(0,12).map(i=>i.name+(i.version?" "+i.version:"")).join("\n");
          return `<span title="${esc(top)}${inv.items.length>12?"\n…":""}">${inv.items.length}</span>`; })()}</td>
      <td class="mono">${e.peers.size}</td>
      <td>${esc(e.enclave||"")}</td>
      <td class="mono ep-dim">${esc([...e.collectors].join(", "))}</td>
    </tr>`;
  }).join("");
  host.innerHTML=`<table class="ep-tbl"><thead><tr>
      <th>IP Address</th><th>Hostname / System</th><th>Role</th><th>Scope</th>
      <th>Services Offered</th><th>Srv/Cli</th><th title="Installed software from the ACAS inventory (hover for the list)">Software</th><th>Peers</th><th>Enclave</th><th>Seen By</th>
    </tr></thead><tbody>${rowsHtml}</tbody></table>`;

  host.querySelectorAll("input[data-epip]").forEach(inp=>{
    inp.addEventListener("change",()=>{
      const nm=inp.dataset.epip, ip=inp.value.trim();
      if(!ip) return;
      if(!isIP(ip)){ flash(ip+" is not an IP address.","warn"); return; }
      learnHost(ip,nm,"manual");
      let n=0;
      ROWS.forEach(r=>{
        if(!r.src  && r.srcHost && sameHost(r.srcHost,nm)){ r.src=ip;  rederive(r); n++; }
        if(!r.dest && r.dstHost && sameHost(r.dstHost,nm)){ r.dest=ip; rederive(r); n++; }
      });
      render(); renderEndpoints();
      flash("Set "+nm+" = "+ip+" on "+n+" row end"+(n===1?"":"s")+".","ok");
    });
  });
  host.querySelectorAll("input[data-ephost]").forEach(inp=>{
    inp.addEventListener("change",()=>{
      const ip=inp.dataset.ephost, nm=inp.value.trim();
      if(!nm) return;
      learnHost(ip,nm,"manual");
      ROWS.forEach(r=>{
        if(r.src===ip && !r.srcHost) r.srcHost=nm;
        if(r.dest===ip && !r.dstHost) r.dstHost=nm;
      });
      render(); renderEndpoints();
      flash("Named "+ip+" as "+nm+" and applied it across the register.","ok");
    });
  });
}

/* export the discovered endpoint inventory */
function exportEndpointsCsv(){
  const eps=buildEndpoints(($("epScope")&&$("epScope").value)==="filtered"?getFiltered():ROWS);
  if(!eps.length) return flash("No endpoints to export yet.","warn");
  const head=["IP Address","Hostname / System","Identified","Scope","Role","Services Offered",
              "Flows as Server","Flows as Client","Distinct Peers","Enclave","Boundaries",
              "Operating System","Owner / POC","Seen By (Collector)","Discovered Via"];
  const lines=[head.map(csvCell).join(",")];
  eps.forEach(e=>{
    lines.push([
      e.ip, e.host, e.noAddr?"Name only":(e.host?"Yes":(e.scope==="External"?"External":"No")), e.scope, e.role,
      [...e.services.keys()].join("; "),
      e.asServer, e.asClient, e.peers.size, e.enclave,
      [...e.boundaries].join("; "), e.os||"", e.owner||"",
      [...e.collectors].join("; "), [...e.origins].join("; ")
    ].map(csvCell).join(","));
  });
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-endpoints.csv",
    "\ufeff"+lines.join("\r\n"), "text/csv;charset=utf-8");
}

/* export just the unidentified ones, as a work list */
function exportUnnamedCsv(){
  /* Two kinds of gap go on the list: an address nobody has named, and a
     name nobody has an address for. Fill in whichever column is blank and
     load the file back with "Load Host Inventory". */
  const eps=buildEndpoints(ROWS).filter(e=>(!e.host || e.noAddr) && e.scope==="Internal");
  if(!eps.length) return flash("Every internal system has already been identified.","ok");
  const lines=[["IP Address","Role","Services Offered","Flows","Distinct Peers","Enclave",
                "Seen By (Collector)","Hostname (fill in)","Owner / POC (fill in)"].map(csvCell).join(",")];
  eps.forEach(e=>lines.push([
    e.noAddr ? "" : e.ip, e.role, [...e.services.keys()].join("; "), e.asServer+e.asClient,
    e.peers.size, e.enclave, [...e.collectors].join("; "), e.noAddr ? e.host : "", ""
  ].map(csvCell).join(",")));
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-unidentified-endpoints.csv",
    "\ufeff"+lines.join("\r\n"), "text/csv;charset=utf-8");
  flash("Exported "+eps.length+" unidentified endpoint"+(eps.length===1?"":"s")+" as a work list.","ok");
}

/* import a filled-in work list / host inventory back in */
function importHostInventory(text, fname){
  const before=HOSTMAP.size;
  let r=parseInventoryCsv(text);
  if(!r.names) r=parseHostsFile(text);
  if(!r.names) r=parseDnsExport(text);
  if(!r.names) r=parseDnsZone(text);
  if(!r.names) r=parseDhcpLeases(text);
  if(!r.names) r=parseArpTable(text);
  const learned=HOSTMAP.size-before;
  const applied=applyHostmap(true);
  render(); renderEndpoints();
  flash(learned
    ? ("Learned "+learned+" host name"+(learned===1?"":"s")+" · resolved "+applied+" register field"+(applied===1?"":"s")+".")
    : "No host names found in that file.", learned?"ok":"warn");
}

function exportHostmap(){
  if(!HOSTMAP.size) return flash("Host inventory is empty.","warn");
  const lines=[["IP Address","Hostname","Operating System","Owner / POC","Learned From"].map(csvCell).join(",")];
  [...HOSTMAP.entries()].sort((a,b)=>a[0].localeCompare(b[0])).forEach(([ip,h])=>
    lines.push([ip,h.name,h.os||"",h.owner||"",h.source||""].map(csvCell).join(",")));
  download("host-inventory.csv","\ufeff"+lines.join("\r\n"),"text/csv;charset=utf-8");
}
