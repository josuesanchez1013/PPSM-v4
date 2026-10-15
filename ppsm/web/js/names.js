"use strict";
/* ============================================================
   NAME RESOLUTION
   Every source that knows a name contributes to one inventory, and
   that inventory is applied to every row from every file, in both
   directions: an address gains its hostname, a hostname gains its
   address, and a bare NetBIOS name is upgraded to the full name.

   When sources disagree, the more authoritative one wins. A reverse
   DNS record is the system of record for "what is this address
   called"; an ARP table is a guess. Losing names are kept as aliases,
   so a lookup by any of them still lands on the right host.
   ============================================================ */

const NAME_RANK = {
  "manual":110,         // a person typed it
  "dns-ptr":100,        // reverse zone: the authoritative answer
  "dns-zone":95, "dns-csv":95,
  "inventory":90,       // AD / CMDB
  "collector":85,       // the host said so itself
  "nessus":80, "nmap":75, "hosts-file":70,
  "fmc-discovery":60, "dhcp":55, "dns-log":50,
  "netflow-report":40, "arp":30
};
const ALIASES = new Map();       // alias fqdn (lower) -> target fqdn (lower), from CNAMEs
let NAMEINDEX = new Map();       // any known name (lower, full or short) -> ip, or null if ambiguous
let LAST_RESOLVE = {names:0, ips:0, upgraded:0};

const nameKey = n => String(n||"").toLowerCase().split(".")[0];
const sameHost  = (a,b) => {
  const x=String(a||"").toLowerCase(), y=String(b||"").toLowerCase();
  return x===y || (nameKey(x)===nameKey(y) && (x.indexOf(".")<0 || y.indexOf(".")<0));
};

function learnHost(ip,name,source,extra){
  if(!ip || !isIP(ip) || !name) return false;
  if(CFG.ipv4Only!==false && isIPv6Addr(ip)) return false;   // AAAA records and the like
  if(isLoopback(ip)) return false;
  name=String(name).trim().replace(/\.$/,"");
  if(!name || isIP(name) || /^localhost$/i.test(name)) return false;
  if(/^(any|unknown|n\/a|-)$/i.test(name)) return false;
  const rank = NAME_RANK[source] !== undefined ? NAME_RANK[source] : 50;
  const cur = HOSTMAP.get(ip);
  const mergeExtra = e => { if(!e) return;
    ["os","owner","enclave","role"].forEach(k=>{ if(e[k] && !cur[k]) cur[k]=e[k]; }); };

  if(!cur){
    HOSTMAP.set(ip, Object.assign({name, source:source||"import", rank, alt:[]}, extra||{}));
    return true;
  }
  if(!Array.isArray(cur.alt)) cur.alt=[];
  const curRank = cur.rank!==undefined ? cur.rank : (NAME_RANK[cur.source]!==undefined ? NAME_RANK[cur.source] : 50);
  /* Remember how good the evidence behind each alternative name was, so a
     name that only ever came from a flow row can be told apart from one a
     scan or a hosts file vouched for. */
  if(!cur.altRank) cur.altRank={};
  const keepAlt=(n,rk)=>{ const l=n.toLowerCase();
    if(!cur.alt.some(a=>a.toLowerCase()===l)) cur.alt.push(n);
    cur.altRank[l]=Math.max(cur.altRank[l]||0, rk); };

  if(sameHost(cur.name, name)){
    // same machine: prefer the fully qualified form, whichever source gave it
    let changed=false;
    if(name.indexOf(".")>=0 && cur.name.indexOf(".")<0){
      keepAlt(cur.name, curRank);
      cur.name=name; changed=true;
    } else if(name.toLowerCase()!==cur.name.toLowerCase()) keepAlt(name, rank);
    if(rank>curRank){ cur.rank=rank; cur.source=source; }
    mergeExtra(extra);
    return changed;
  }
  // a genuinely different name for the same address
  if(rank>curRank){
    keepAlt(cur.name, curRank);
    cur.name=name; cur.source=source; cur.rank=rank;
    mergeExtra(extra);
    return true;
  }
  keepAlt(name, rank);
  mergeExtra(extra);
  return false;
}

/* Does the row's name for this address square with what the name sources
   say? Only worth asking when an authoritative source (DNS, AD) named the
   address; and a name is fine if it is the DNS name, a CNAME that leads to
   this address, or an alternative that a scan, hosts file or inventory —
   not merely another flow row — attached to it. */
function nameAgreesWithInventory(ip, host){
  const h=HOSTMAP.get(ip); if(!h) return true;
  const rank = h.rank!==undefined ? h.rank : (NAME_RANK[h.source]||50);
  if(rank<90) return true;
  if(sameHost(host, h.name)) return true;
  const l=String(host).toLowerCase().replace(/\.$/,"");
  if(ALIASES.has(l) && lookupName(l)===ip) return true;
  const ar=h.altRank||{};
  for(const a of (h.alt||[])){ if(sameHost(a,host) && (ar[a.toLowerCase()]||0)>=55) return true; }
  return false;
}

/* ---------------- DNS zone files ----------------
   BIND zone files, forward and reverse, and Windows "dnscmd /zoneprint"
   output. Handles $ORIGIN, @, relative names, lines that continue the
   previous owner, TTLs with units, the class field, Windows aging tags,
   multi-line SOA records, and PTR / CNAME as well as A / AAAA. */
const DNS_TYPES = /^(A|AAAA|PTR|CNAME|SOA|NS|MX|TXT|SRV|HINFO|RP|AFSDB|NAPTR|DNAME|CAA|SPF|WKS)$/;

function ptrToIp(owner){
  const o=String(owner||"").toLowerCase().replace(/\.$/,"");
  let m=o.match(/^((?:\d{1,3}\.){3}\d{1,3})\.in-addr\.arpa$/);
  if(m) return m[1].split(".").reverse().join(".");
  m=o.match(/^((?:[0-9a-f]\.){31}[0-9a-f])\.ip6\.arpa$/);
  if(m){
    const nib=m[1].split(".").reverse().join("");
    return nib.match(/.{4}/g).join(":").replace(/(^|:)0{1,3}/g,"$1");
  }
  return "";
}

function parseDnsZone(text, fname){
  let learned=0, seen=0, origin="", lastOwner="", inParen=false, aliases=0;
  /* dnscmd /enumrecords output and a zone file copied without its $ORIGIN
     carry relative names and no zone. The SOA's primary server sits one
     label under the zone, and so does a file named after the zone. */
  if(!/^\$ORIGIN\s+\S+/mi.test(text) && !/^\s*;+\s*Zone:/mi.test(text)){
    const soa=text.match(/\bSOA\s+([A-Za-z0-9.\-]+\.[A-Za-z0-9.\-]+)\.?\s/i);
    if(soa && !/arpa$/i.test(soa[1])){ const n=soa[1].replace(/\.$/,""); const i=n.indexOf("."); if(i>0 && n.indexOf(".",i+1)>0) origin=n.slice(i+1).toLowerCase(); }
    if(!origin && fname){
      const b=String(fname).split(/[\\\/]/).pop().toLowerCase().replace(/\.(txt|zone|db|dns|rev|csv|log)$/,"")
        .replace(/^(zone|dns|db|export|forward|reverse)[-_.]+/,"").replace(/[-_.]+(zone|export|forward|reverse)$/,"");
      if(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(b) && !isIP(b)) origin=b;
    }
  }
  const qualify = n => {
    if(!n) return "";
    if(n==="@") return origin;
    if(n.endsWith(".")) return n.slice(0,-1);
    return origin ? n+"."+origin : n;
  };
  text.split(/\r?\n/).forEach(raw=>{
    // dnscmd prints the zone name in a comment at the top
    const zc=raw.match(/^\s*;+\s*Zone:\s*(\S+)/i);
    if(zc && !origin) origin=zc[1].replace(/\.$/,"");
    const line=raw.replace(/;.*$/,"");
    if(inParen){ if(line.indexOf(")")>=0) inParen=false; return; }
    if(!line.trim()) return;
    let m=line.match(/^\$ORIGIN\s+(\S+)/i);
    if(m){ origin=m[1].replace(/\.$/,""); return; }
    if(/^\$(TTL|INCLUDE|GENERATE)\b/i.test(line)) return;
    if(line.indexOf("(")>=0 && line.indexOf(")")<0) inParen=true;

    const continues=/^\s/.test(line);
    const tok=line.trim().split(/\s+/);
    let owner;
    if(continues) owner=lastOwner;
    else { owner=qualify(tok.shift()); lastOwner=owner; }

    // skip TTL, class and Windows aging tags to reach the record type
    while(tok.length && !DNS_TYPES.test(tok[0].toUpperCase())){
      const t=tok[0];
      if(/^\d+$/.test(t) || /^(\d+[smhdw])+$/i.test(t) || /^(IN|CH|HS|CS)$/i.test(t) || /^\[.*\]$/.test(t)) tok.shift();
      else return;                     // not a record we can read
    }
    if(!tok.length) return;
    const type=tok.shift().toUpperCase(), rdata=tok;

    if((type==="A" || type==="AAAA") && rdata[0] && isIP(rdata[0]) && owner){
      seen++; if(learnHost(rdata[0], owner, "dns-zone")) learned++;
    } else if(type==="PTR" && rdata[0]){
      const ip=ptrToIp(owner);
      const target=rdata[0].endsWith(".") ? rdata[0].slice(0,-1) : rdata[0];
      if(ip){ seen++; if(learnHost(ip, target, "dns-ptr")) learned++; }
    } else if(type==="CNAME" && rdata[0] && owner){
      const target=qualify(rdata[0]).toLowerCase();
      ALIASES.set(owner.toLowerCase(), target); aliases++; seen++;
    }
  });
  const note = nameNote(seen, learned, "DNS records") + (aliases?" · "+aliases+" alias"+(aliases===1?"":"es"):"");
  return {rows:[], names:learned, seen, note};
}

/* ---------------- DNS export (any delimiter, any/no header) ----------------
   Works out, from the data itself, which column holds the record type and
   which holds the address, then reads name<->address pairs. Handles CSV, TSV,
   pipe- and space-delimited text; a BOM; quoted fields; trailing dots; "@" and
   blank owners; FQDNs already containing the zone; and PTR rows with the arpa
   name on either side. This is what reads a real-world DNS dump. */
const DNS_TYPE_RE = /^(A|AAAA|PTR|CNAME|NS|MX|TXT|SRV|SOA|HINFO|SPF|CAA|DNAME|NAPTR)$/i;
/* Windows DNS Manager and some exports write "A Record", "Host (A)",
   "Pointer (PTR)", "Alias (CNAME)", "IPv6 Host (AAAA)" instead of the bare
   type. Pull the real type out of any of those forms. */
function dnsRecordType(v){
  let s=String(v||"").trim().toUpperCase();
  if(!s) return "";
  if(DNS_TYPE_RE.test(s)) return s;
  // a bracketed abbreviation wins: "Host (A)" -> A, "Pointer (PTR)" -> PTR
  let m=s.match(/\(([A-Z0-9]{1,6})\)/);
  if(m && DNS_TYPE_RE.test(m[1])) return m[1];
  // a leading token: "A RECORD" / "CNAME RECORD" / "AAAA (...)"
  m=s.match(/^([A-Z0-9]{1,6})\b/);
  if(m && DNS_TYPE_RE.test(m[1])) return m[1];
  // spelled-out forms
  if(/^HOST\b/.test(s)) return /IPV6|AAAA/.test(s)?"AAAA":"A";
  if(/^(POINTER|REVERSE)\b/.test(s)) return "PTR";
  if(/^(ALIAS|CANONICAL)\b/.test(s)) return "CNAME";
  if(/^(MAIL|MX)\b/.test(s)) return "MX";
  if(/^(TEXT|TXT)\b/.test(s)) return "TXT";
  if(/^(NAME ?SERVER|NS)\b/.test(s)) return "NS";
  if(/^(SERVICE|SRV)\b/.test(s)) return "SRV";
  return "";
}
/* True if a cell is any recognizable record type, verbose or bare. */
function isDnsType(v){ return !!dnsRecordType(v); }

/* Split on whichever delimiter actually structures the line. Tab, pipe and
   semicolon are unambiguous; comma goes through the quote-aware splitter;
   whitespace runs are the last resort. Pick the one giving the most columns. */
function splitDnsLine(line){
  const unq=a=>a.map(s=>s.replace(/^"|"$/g,"").trim());
  const cand=[];
  if(line.indexOf("\t")>=0) cand.push(unq(line.split("\t")));
  if(line.indexOf("|")>=0)  cand.push(unq(line.split("|")));
  if(line.indexOf(";")>=0)  cand.push(unq(line.split(";")));
  if(line.indexOf(",")>=0)  cand.push(unq(splitCsvLine(line)));
  /* Whitespace is only a delimiter when nothing better structures the line:
     a CSV cell like "Start of Authority (SOA)" must not be split into words
     and shift every column after it. */
  if(!cand.some(c=>c.length>=3)) cand.push(unq(line.trim().split(/\s{2,}|\s+/)));
  // best = most fields; ties keep the earlier (more explicit) delimiter
  let best=cand[0];
  for(const c of cand) if(c.length>best.length) best=c;
  return best;
}
function dnsCleanName(s){
  s=String(s||"").trim().replace(/\.$/,"");
  return (!s || s==="@" || /^DnsServer/i.test(s)) ? "" : s;
}
/* The zone a DNS export belongs to, when the file does not say so in a
   column. DNS Manager's right-click export and "dnscmd /enumrecords" write
   owner names relative to the zone ("wsus11", not "wsus11.range2.mil"), so
   without the zone every name learned is a short name and the FQDN columns of
   the template stay empty. Looked for, in order: the SOA / NS row the export
   carries (the primary server and the responsible mailbox both sit under the
   zone), the file name when it is a domain ("range2.mil.csv",
   "zone-range2.mil.txt"), the suffix most fully-qualified rows share, and
   finally the DNS domain set under Settings. */
function inferDnsZone(rows, iName, iType, iData, fname){
  const strip=n=>String(n||"").trim().toLowerCase().replace(/\.$/,"");
  const parentOf=n=>{ const s=strip(n); const i=s.indexOf("."); return i>0 ? s.slice(i+1) : ""; };
  const isArpa=n=>/\.(in-addr|ip6)\.arpa$/i.test(strip(n));
  // 1. an SOA or NS row names servers that live under the zone
  for(const r of rows){
    const t=dnsRecordType(iType>=0?r[iType]:"");
    if(t!=="SOA" && t!=="NS") continue;
    const cells=(iData>=0 && r[iData]) ? String(r[iData]).split(/[\s,;\[\]]+/) : r.slice();
    for(const c of cells){
      const s=strip(c);
      if(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(s) && !isArpa(s) && !isIP(s)){ const p=parentOf(s); if(p && p.indexOf(".")>0) return p; }
    }
  }
  // 2. the file is named after the zone
  if(fname){
    let b=String(fname).split(/[\\\/]/).pop().toLowerCase()
      .replace(/\.(csv|txt|tsv|dns|zone|db|rev|log|xlsx|pdf)$/,"")
      .replace(/^(zone|dns|dns-?records?|export|forward|reverse|fwd|rev)[-_. ]+/,"")
      .replace(/[-_. ]+(zone|export|records?|dns|forward|reverse)$/,"");
    if(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(b) && !isArpa(b) && !isIP(b)) return b;
  }
  // 3. the suffix most fully-qualified owner names share
  if(iName>=0){
    const tally=new Map();
    rows.forEach(r=>{ const n=strip(r[iName]); if(!n || isIP(n) || isArpa(n) || n.indexOf(".")<0) return;
      const p=parentOf(n); if(p && p.indexOf(".")>0) tally.set(p,(tally.get(p)||0)+1); });
    let best="", bn=0, total=0;
    tally.forEach((v,k)=>{ total+=v; if(v>bn){ bn=v; best=k; } });
    if(best && bn>=2 && bn/total>=0.5) return best;
  }
  // 4. the enclave's DNS domain from Settings
  const d=String((typeof CFG!=="undefined" && CFG.dnsDomain)||"").trim().replace(/^\.+/,"").toLowerCase();
  return d || "";
}

function parseDnsExport(text, fname){
  // strip a BOM and split into non-empty lines
  let raw=String(text||"").replace(/^\uFEFF/,"");
  const lines=raw.split(/\r?\n/).filter(l=>l.trim() && !/^\s*[#;]/.test(l));
  if(lines.length<1) return {rows:[],names:0,seen:0,note:""};

  // never mistake a BIND zone file for a tabular export (it has $ORIGIN / SOA /
  // "IN A" syntax), nor flow data (ports, "LISTEN", "ESTAB", arrows)
  if(/^\s*\$(ORIGIN|TTL|GENERATE)\b/mi.test(raw) || /\bIN\s+(SOA|NS|A|AAAA|CNAME|PTR|MX)\b/i.test(raw))
    return {rows:[],names:0,seen:0,note:""};
  if(/\b(LISTEN|ESTAB|LISTENING|ESTABLISHED|TIME_WAIT|SYN_SENT)\b/i.test(raw))
    return {rows:[],names:0,seen:0,note:""};
  // dnscmd /zoneprint output and other zone dumps: a "; Zone:" header or an
  // [Aging:...] stamp means the zone parser should handle it (it qualifies
  // relative names against the zone), so stand aside.
  if(/^\s*;+\s*Zone:/mi.test(raw) || /\[Aging:/i.test(raw))
    return {rows:[],names:0,seen:0,note:""};

  // does the first line look like a header (no record type, no IP in it)?
  const first=splitDnsLine(lines[0]);
  const firstHasData = first.some(c=>isDnsType(c)) || first.some(c=>isIP(c));
  const header = firstHasData ? null : first.map(c=>c.toLowerCase());
  const dataLines = firstHasData ? lines : lines.slice(1);

  // A header is required UNLESS the body is unmistakably a DNS table. Decide by
  // sampling: there must be a column that is DNS record types in (nearly) every
  // row, and an address/arpa column. A flow CSV has a Port column and numeric
  // ports, which disqualifies it.
  const headerNamesDns = header && (
    (header.indexOf("type")>=0 || header.indexOf("recordtype")>=0 || header.indexOf("record type")>=0) &&
    (header.some(x=>/^(name|hostname|owner|host|record name|recordname)$/.test(x))) ) ||
    (header && header.some(x=>/recorddata|record data|ptrdomainname|hostnamealias/.test(x)));
  const headerLooksFlow = header && header.some(x=>/^(port|dst ?port|destination port|src ?port|source port|protocol)$/.test(x));
  if(header && headerLooksFlow) return {rows:[],names:0,seen:0,note:""};

  // sample rows to locate columns by content
  const sample=dataLines.slice(0,40).map(splitDnsLine).filter(c=>c.length>=2);
  if(!sample.length) return {rows:[],names:0,seen:0,note:""};
  const width=Math.max(...sample.map(c=>c.length));

  let iType=-1, iName=-1, iData=-1;
  // type column: the one where most cells are record types (verbose or bare)
  let bestType=0;
  for(let c=0;c<width;c++){
    let hit=0,n=0; sample.forEach(r=>{ if(r[c]!==undefined){n++; if(isDnsType(r[c])) hit++;} });
    if(n && hit/n>=0.5 && hit>bestType){ bestType=hit; iType=c; }
  }
  // address column: most cells are IPs or arpa names
  let bestAddr=0;
  for(let c=0;c<width;c++){
    if(c===iType) continue;
    let hit=0,n=0; sample.forEach(r=>{ if(r[c]!==undefined){n++;
      if(isIP(r[c]) || /\.(in-addr|ip6)\.arpa$/i.test(r[c])) hit++; } });
    if(n && hit/n>=0.4 && hit>bestAddr){ bestAddr=hit; iData=c; }
  }
  // name column: a hostname-ish column that is not the type or data column
  let bestName=0;
  for(let c=0;c<width;c++){
    if(c===iType||c===iData) continue;
    let hit=0,n=0; sample.forEach(r=>{ const v=r[c]; if(v!==undefined && v!==""){n++;
      if(!isIP(v) && (/[a-z]/i.test(v)) && !isDnsType(v)) hit++; } });
    if(n && hit/n>=0.5 && hit>bestName){ bestName=hit; iName=c; }
  }
  // if a header named the columns, prefer that where sensible
  let iPtr=-1, iAlias=-1, iZone=-1;
  if(header){
    const hi=(...names)=>{ for(const nm of names){ const i=header.indexOf(nm); if(i>=0) return i; } return -1; };
    const hN=hi("name","hostname","owner","host","record name","recordname");
    const hT=hi("type","recordtype","record type");
    const hD=hi("data","recorddata","record data","value","rdata","content","ipaddress","ip address","ipv4address","address","ip");
    iPtr=hi("ptrdomainname","ptr","target");
    iAlias=hi("hostnamealias","alias","canonicalname","cname");
    iZone=hi("zonename","zone");
    if(hT>=0) iType=hT;
    if(hD>=0) iData=hD;
    if(hN>=0) iName=hN;
  }
  if(iType<0 && iData<0) return {rows:[],names:0,seen:0,note:""};
  // confidence gate: with no DNS-naming header, demand a strong type column
  // (most rows are DNS record types) so we do not swallow flow or inventory CSVs
  if(!headerNamesDns){
    if(iType<0) return {rows:[],names:0,seen:0,note:""};
    let dnsTypes=0,n=0;
    sample.forEach(r=>{ if(r[iType]!==undefined){ n++; if(isDnsType(r[iType])) dnsTypes++; } });
    if(!n || dnsTypes/n<0.8) return {rows:[],names:0,seen:0,note:""};
  }

  /* With no zone column, work the zone out from the file itself so relative
     owner names ("wsus11") still become fully qualified names. */
  const allRows=dataLines.map(splitDnsLine).filter(c=>c.length>=2);
  const fileZone = iZone>=0 ? "" : inferDnsZone(allRows, iName, iType, iData, fname);

  let learned=0, seen=0, aliases=0, opaque=0, qualified=0;
  allRows.forEach(c=>{
    const type=dnsRecordType(iType>=0?c[iType]:"");
    const dataVal=(iData>=0?c[iData]:"")||"";
    let nameVal=dnsCleanName(iName>=0?c[iName]:"");
    // DNS Manager writes the zone apex as "(same as parent folder)"
    if(/^\(same as parent/i.test(nameVal)) nameVal="@";
    // when we could not find a name column, the non-type/non-data cell is the name
    let name=nameVal;
    if(!name){ for(let k=0;k<c.length;k++){ if(k===iType||k===iData) continue;
      const v=dnsCleanName(c[k]); if(v && !isIP(v) && !/arpa$/i.test(v)){ name=v; break; } } }

    const recType = type || (isIP(dataVal) ? "A" : (/arpa$/i.test(nameVal)||/arpa$/i.test(dataVal) ? "PTR" : ""));
    if(/^DnsServerResourceRecord/i.test(dataVal)) opaque++;

    // qualify a short owner with the zone column, or the zone worked out for the file
    const zone = iZone>=0 ? String(c[iZone]||"").replace(/\.$/,"") : fileZone;
    let fqName = name==="@" ? (zone && !/arpa$/i.test(zone) ? zone : "") : name;
    if(fqName && zone && !/arpa$/i.test(zone) && fqName.indexOf(".")<0){ fqName=fqName+"."+zone; qualified++; }

    if(recType==="A" || recType==="AAAA"){
      /* a round-robin name carries several addresses in one cell; every one
         of them is this host */
      const ips = String(dataVal).split(/[\s;,]+/).filter(isIP);
      if(!ips.length){ const f=c.find(isIP); if(f) ips.push(f); }
      if(ips.length && fqName){ ips.forEach(ip=>{ seen++; if(learnHost(ip, fqName, "dns-csv")) learned++; }); }
    } else if(recType==="PTR"){
      const ptrTarget = dnsCleanName((iPtr>=0?c[iPtr]:"") || dataVal);
      let arpa="", host="";
      if(/arpa$/i.test(nameVal)){ arpa=nameVal; host=ptrTarget; }
      else if(/arpa$/i.test(dataVal)){ arpa=dataVal; host=name; }
      else if(zone && /arpa$/i.test(zone)){ arpa=(nameVal.indexOf("arpa")>=0?nameVal:nameVal+"."+zone); host=ptrTarget; }
      const ip=ptrToIp(arpa);
      if(ip && host && !isIP(host) && !/arpa$/i.test(host)){ seen++; if(learnHost(ip, host, "dns-ptr")) learned++; }
    } else if(recType==="CNAME"){
      const target=dnsCleanName((iAlias>=0?c[iAlias]:"") || dataVal);
      if(fqName && target && !isIP(target)){ ALIASES.set(fqName.toLowerCase(), target.toLowerCase()); aliases++; seen++; }
    }
  });
  let note=nameNote(seen, learned, "DNS records")+(aliases?" \u00b7 "+aliases+" alias"+(aliases===1?"":"es"):"");
  if(fileZone && qualified) note+=" \u00b7 short names qualified under "+fileZone;
  if(opaque && !seen)
    note="the DNS export has no addresses in it \u2014 RecordData did not survive the export; re-export with the address expanded (see the SOP)";
  return {rows:[], names:learned, seen, note};
}

/* ---------------- Windows DNS as CSV ----------------
   Get-DnsServerResourceRecord piped through Select-Object, one row per
   record. RecordData itself does not survive Export-Csv, so the SOP gives
   the command that expands it; both forms are accepted here. */
function parseDnsCsv(text){
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return {rows:[],names:0,seen:0,note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase().replace(/^"|"$/g,""));
  const col=(...ns)=>{ for(const n of ns){ const i=hdr.indexOf(n); if(i>=0) return i; } return -1; };
  const iType=col("recordtype","type"), iHost=col("hostname","name","owner"),
        iZone=col("zonename","zone"),
        iIp=col("ipv4address","ipaddress","ip","address"),
        iIp6=col("ipv6address"),
        iPtr=col("ptrdomainname","ptr","target"),
        iAl=col("hostnamealias","alias","canonicalname"),
        iData=col("data","recorddata","value","rdata","content");
  if(iType<0 || iHost<0) return {rows:[],names:0,seen:0,note:""};
  let learned=0, seen=0, aliases=0, opaque=0;
  lines.slice(1).forEach(l=>{
    const c=splitCsvLine(l).map(s=>s.replace(/^"|"$/g,"").trim());
    const type=(c[iType]||"").toUpperCase();
    const zone=(iZone>=0?c[iZone]:"").replace(/\.$/,"");
    let host=c[iHost]||"";
    const fq = host==="@" ? zone : (host.endsWith(".") ? host.slice(0,-1)
             : (zone && !/\.in-addr\.arpa$|\.ip6\.arpa$/i.test(zone) && host.toLowerCase().indexOf(zone.toLowerCase())<0
                ? host+"."+zone : host));
    const data = iData>=0 ? c[iData] : "";
    if(/^DnsServerResourceRecord/i.test(data)) opaque++;
    if(type==="A" || type==="AAAA"){
      const pickCol = (type==="AAAA" && iIp6>=0) ? iIp6 : iIp;
      const ip = pickCol>=0 && isIP(c[pickCol]) ? c[pickCol] : (isIP(data)?data:"");
      if(ip && fq){ seen++; if(learnHost(ip, fq, "dns-csv")) learned++; }
    } else if(type==="PTR"){
      /* A PTR pairs an arpa name with a hostname. Either can be in the
         name/owner column or the data column, so detect which side is the
         arpa address and take the other as the hostname. */
      const ptrData=((iPtr>=0?c[iPtr]:"")||data).replace(/\.$/,"");
      let arpa="", name="";
      if(/arpa$/i.test(host)){ arpa=host; name=ptrData; }
      else if(/arpa$/i.test(ptrData)){ arpa=ptrData; name=host; }
      else if(zone && /arpa$/i.test(zone)){ arpa=host+"."+zone; name=ptrData; }
      const ip = ptrToIp(arpa);
      if(ip && name && !isIP(name) && !/arpa$/i.test(name) && !/^DnsServer/i.test(name)){
        seen++; if(learnHost(ip, name, "dns-ptr")) learned++; }
    } else if(type==="CNAME"){
      const target=((iAl>=0?c[iAl]:"")||data).replace(/\.$/,"");
      if(target && fq && !/^DnsServer/i.test(target)){ ALIASES.set(fq.toLowerCase(), target.toLowerCase()); aliases++; seen++; }
    }
  });
  let note=nameNote(seen, learned, "DNS records")+(aliases?" · "+aliases+" aliases":"");
  if(opaque && !seen)
    note="the DNS export has no addresses in it — RecordData does not survive Export-Csv on its own; "+
         "use the command in the SOP, which expands it";
  return {rows:[], names:learned, seen, note};
}

/* ---------------- applying names everywhere ---------------- */
function rebuildNameIndex(){
  NAMEINDEX=new Map();
  const v4 = a => /^\d{1,3}(\.\d{1,3}){3}$/.test(a||"");
  const add=(key,ip)=>{
    if(!key) return;
    if(!NAMEINDEX.has(key)){ NAMEINDEX.set(key,ip); return; }
    const cur=NAMEINDEX.get(key);
    if(cur===ip || cur===null) return;
    // one host with an IPv4 and an IPv6 address is not ambiguous: keep the IPv4
    if(v4(cur) && !v4(ip)) return;
    if(!v4(cur) && v4(ip)){ NAMEINDEX.set(key,ip); return; }
    NAMEINDEX.set(key,null);            // two different hosts share this name: never guess
  };
  HOSTMAP.forEach((h,ip)=>{
    if(!isIP(ip) || !h || !h.name) return;
    [h.name].concat(h.alt||[]).forEach(n=>{ const l=String(n).toLowerCase(); add(l,ip); add(nameKey(l),ip); });
  });
  /* CNAME chains: patch -> wsus -> wsus11.range2.mil. Follow each alias to
     the end of its chain (bounded, so a loop cannot hang the page) and give
     every alias along the way the address at the end. */
  const resolveAlias=alias=>{
    let cur=alias, hops=0;
    const seen=new Set();
    while(ALIASES.has(cur) && hops++<8 && !seen.has(cur)){ seen.add(cur); cur=ALIASES.get(cur); }
    return NAMEINDEX.get(cur) || NAMEINDEX.get(nameKey(cur)) || null;
  };
  ALIASES.forEach((target,alias)=>{
    const ip=resolveAlias(alias);
    if(ip){ add(alias,ip); add(nameKey(alias),ip); }
  });
  return NAMEINDEX;
}
function lookupName(n){
  if(!n) return "";
  const l=String(n).trim().toLowerCase().replace(/\.$/,"");
  const ip = NAMEINDEX.has(l) ? NAMEINDEX.get(l) : NAMEINDEX.get(nameKey(l));
  return ip || "";
}

/* Everything that depends on an endpoint, worked out again from scratch. */
function rederive(r){
  const enc=deriveEnclave(r); if(enc) r.enclave=enc;
  const b=deriveBoundary(r);  if(b) r.boundary=b;
  r.subPath   = submissionPath(r.boundary) || r.subPath;
  r.emassType = deriveType(r) || r.emassType;
  const sp=derivePoint(r.src, r.srcZone);  if(sp) r.srcPoint=sp;
  const dp=derivePoint(r.dest, r.dstZone); if(dp) r.dstPoint=dp;
}

/* Hostnames that no name source could turn into an address, with the rows
   that carry them. Filled by applyHostmap; shown on the Endpoints panel. */
let UNRESOLVED = new Map();     // name (as written) -> {rows:Set, lower}
/* Rows where the address and the hostname disagree with the DNS zones. */
let NAME_CONFLICTS = [];

function applyHostmap(silent){
  rebuildNameIndex();
  let names=0, ips=0, upgraded=0, conflicts=0;
  const changed=new Set();
  UNRESOLVED=new Map(); NAME_CONFLICTS=[];
  const noteUnresolved=(r,h)=>{
    const k=String(h).trim(); if(!k) return;
    if(!UNRESOLVED.has(k)) UNRESOLVED.set(k,{rows:new Set()});
    UNRESOLVED.get(k).rows.add(r);
  };
  const side=(r, ipKey, hostKey)=>{
    let ip=r[ipKey], host=r[hostKey];
    /* a name in the address cell ("wsus11", "dc01.range2.mil; wsus11") is a
       name: move it to the hostname cell and resolve it like any other */
    if(ip && !isIP(ip) && !isCidr(ip) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)){
      const parts=String(ip).split(/\s*;\s*/).filter(Boolean);
      if(parts.some(x=>!isIP(x) && !isCidr(x))){
        const names=parts.filter(x=>!isIP(x)&&!isCidr(x)), addrs=parts.filter(x=>isIP(x)||isCidr(x));
        if(!host) r[hostKey]=names.join("; ");
        const got=names.map(n=>lookupName(n));
        if(got.every(Boolean)){ r[ipKey]=addrs.concat(got).join("; "); ips++; changed.add(r); }
        else { names.forEach((n,i)=>{ if(!got[i]) noteUnresolved(r,n); }); return; }
        ip=r[ipKey]; host=r[hostKey];
        if(ip.indexOf(";")>=0) return;
      }
    }
    if(ip && isIP(ip) && HOSTMAP.has(ip)){
      const known=HOSTMAP.get(ip).name;
      if(!host){ r[hostKey]=known; names++; }
      else if(host!==known && sameHost(host, known) && known.indexOf(".")>=0 && host.indexOf(".")<0){
        r[hostKey]=known; upgraded++;                 // WSUS11 -> wsus11.range2.mil
      }
      else if(!nameAgreesWithInventory(ip, host)){
        /* The row says one name, the zones say another for the same address.
           Leave the row as it was — the data it came from is the evidence —
           but say so, because one of the two is wrong and a reviewer should
           know which address the register is really pointing at. */
        const other=lookupName(host);
        const msg="name/address check: DNS has "+ip+" = "+known+(other && other!==ip ? "; "+host+" = "+other : "");
        if(String(r.notes||"").indexOf("name/address check")<0) r.notes=(r.notes?r.notes+" · ":"")+msg;
        NAME_CONFLICTS.push({row:r, side:ipKey, ip, host, known, other}); conflicts++;
      }
    } else if(!ip && host && !isCidr(host)){
      /* Several names in one cell ("analyst61; analyst63") resolve one by one
         and the addresses are joined the same way, so a consolidated row keeps
         its shape. */
      const parts=String(host).split(/\s*;\s*/).filter(Boolean);
      if(parts.length>1){
        const got=parts.map(p=>lookupName(p));
        if(got.every(Boolean)){ r[ipKey]=got.join("; "); ips++; changed.add(r); }
        else parts.forEach((p,i)=>{ if(!got[i]) noteUnresolved(r,p); });
        return;
      }
      const found=lookupName(host);
      if(found){ r[ipKey]=found; ips++; changed.add(r);
        const known=HOSTMAP.get(found);
        if(known && sameHost(host, known.name) && known.name.indexOf(".")>=0 && host.indexOf(".")<0){
          r[hostKey]=known.name; upgraded++; }
      } else noteUnresolved(r,host);
    }
  };
  ROWS.forEach(r=>{ side(r,"src","srcHost"); side(r,"dest","dstHost"); });
  changed.forEach(rederive);
  LAST_RESOLVE={names, ips, upgraded, conflicts, unresolved:UNRESOLVED.size};
  const n=names+ips+upgraded;
  if(!silent){
    render(); renderEndpoints();
    const bits=[];
    if(names)    bits.push(names+" hostname"+(names===1?"":"s")+" filled in");
    if(ips)      bits.push(ips+" address"+(ips===1?"":"es")+" found from a name");
    if(upgraded) bits.push(upgraded+" short name"+(upgraded===1?"":"s")+" completed");
    if(conflicts) bits.push(conflicts+" name/address mismatch"+(conflicts===1?"":"es")+" noted on the rows");
    if(UNRESOLVED.size) bits.push(UNRESOLVED.size+" hostname"+(UNRESOLVED.size===1?"":"s")+" still without an address — listed under Endpoints");
    flash(n||conflicts||UNRESOLVED.size ? bits.join(" · ")+"." : "Nothing new to resolve — every endpoint with a known name already has one.", n?"ok":"warn");
  }
  return n;
}


/* ---------------- collector connections CSV ----------------
   Written by ppsm-collect.ps1 / ppsm.yml: one row per socket with State,
   Process, PID, Host and (newer) Collector columns alongside the template's
   own column names. Direction is decided HERE, from the listener set in the
   same file, rather than trusted from the collector: an established
   connection whose local port is one the host listens on is an inbound
   client of that service, however the collector labelled it. The process
   name is an application, not a service — it goes to Application and the
   service name comes from the product directory or the port. */
function looksLikeCollectorCsv(l1){
  const h=String(l1||"").toLowerCase();
  return /destination port/.test(h) && /source ip/.test(h) && /direction/.test(h) &&
         (/\bpid\b/.test(h) || /\bstate\b/.test(h) || /\bcollector\b/.test(h) || /\bprocess\b/.test(h));
}
function parseCollectorCsv(text, fname){
  let lines=text.split(/\r?\n/).filter(l=>l.trim());
  const hi=lines.slice(0,5).findIndex(l=>looksLikeCollectorCsv(l));
  if(hi<0) return {rows:[],note:""};
  lines=lines.slice(hi);
  if(lines.length<2) return {rows:[],note:""};
  const hdr=splitCsvLine(lines[0]).map(x=>x.trim().toLowerCase().replace(/^"|"$/g,""));
  const c=(...n)=>{ for(const x of n){ const i=hdr.indexOf(x); if(i>=0) return i; } return -1; };
  const iSIP=c("source ip"), iSPT=c("source port"), iDIP=c("destination ip"), iDPT=c("destination port"),
        iPR=c("protocol"), iSvc=c("data service / application","data service"), iDir=c("direction"),
        iHost=c("host"), iSt=c("state"), iProc=c("process"), iPid=c("pid"), iColl=c("collector");
  if(iDIP<0 || iDPT<0) return {rows:[],note:""};
  const fm=String(fname||"").match(/^(.+?)[-_](tcp|udp|connections|netstat|sockets|ports)\b/i);
  const wild=v=>/^(0\.0\.0\.0|::|\*|)$/.test(String(v||"").trim());
  const recs=lines.slice(1).map(l=>splitCsvLine(l).map(x=>x.replace(/^"|"$/g,"").trim())).filter(f=>f.length>=4);
  // the host's own listeners, by protocol and port
  const listens=new Set();
  recs.forEach(f=>{ const st=(iSt>=0?f[iSt]:"").toLowerCase(); const pr=normProto(iPR>=0?f[iPR]:"")||"TCP";
    if(/listen/.test(st) || (iDir>=0 && /inbound/i.test(f[iDir]) && !(iSIP>=0&&f[iSIP]))) listens.add(pr+"/"+f[iDPT]); });
  const rows=[], seen=new Set(), coll=collNow();
  let shells=new Set();
  recs.forEach(f=>{
    const proto=normProto(iPR>=0?f[iPR]:"")||"TCP";
    const host=(iHost>=0?f[iHost]:"") || (fm?fm[1]:"");
    const proc=(iProc>=0?f[iProc]:"") || (iSvc>=0?f[iSvc]:"");
    const st=(iSt>=0?f[iSt]:"").toLowerCase();
    if(iColl>=0 && f[iColl]) shells.add(f[iColl]);
    let sip=iSIP>=0?f[iSIP]:"", spt=iSPT>=0?f[iSPT]:"", dip=f[iDIP], dpt=f[iDPT];
    let src="", sport="", dest="", dport="", dir="", srcHost="", dstHost="";
    const isListen = /listen/.test(st) || !sip;
    if(isListen){
      if(!validPort(dpt)) return;
      dest = wild(dip) ? "" : dip; dport=dpt; dir="Inbound"; dstHost=host;
      sport = CFG.ephemeralRange || "1024-65535";
    } else {
      // collector wrote local as source, remote as destination
      const localIsService = listens.has(proto+"/"+spt);
      if(localIsService){ src=dip; sport=dpt; dest=sip; dport=spt; dir="Inbound"; dstHost=host; }
      else {
        const o=orientPair(sip,spt,dip,dpt);
        src=o.src; sport=o.srcPort; dest=o.dest; dport=o.dstPort;
        dir = (o.dest===dip) ? "Outbound" : "Inbound";
        if(dir==="Outbound") srcHost=host; else dstHost=host;
      }
      if(!validPort(dport)) return;
    }
    if(isLoopback(src||"") || isLoopback(dest||"")) return;
    const key=[proto,src,dest,dport].join("|");
    if(seen.has(key)) return; seen.add(key);
    const fromApp = proc ? serviceFromApp(proc) : null;
    rows.push(blank({src, dest, proto, srcPort:sport, dstPort:dport, srcHost, dstHost,
      appName: proc,
      dataService: (fromApp && fromApp.service) || guessService(dport, proto),
      direction:dir, status:"New", origin:"collector", collector:coll||host,
      notes: (iPid>=0 && f[iPid] && !proc) ? ("PID "+f[iPid]+" — no process name") : ""}));
  });
  const shellNote = shells.size ? (" · read with "+[...shells].join(", ")) : "";
  return {rows, note: rows.length?("collector connections: "+rows.length+" entries"+shellNote):""};
}

/* ---------------- Get-NetTCPConnection / Get-NetUDPEndpoint as CSV ----------------
   The obvious Windows command is "Get-NetTCPConnection | Export-Csv", and its
   columns are the raw cmdlet properties. Read by State rather than by column
   position: a listener's service is its local port, an established connection's
   is whichever end is the better-known port. Without this the generic CSV
   reader takes the client's ephemeral port as the service. */
function parseWinTcpCsv(text, fname){
  /* A CSV carries no host identity, so a listener on 0.0.0.0 would have no
     owner. Take it from the file name, which is how the collector names
     these: WSUS11-tcp.csv, WSUS11-connections.csv. */
  const fm=String(fname||"").match(/^(.+?)[-_](tcp|udp|connections|netstat|sockets|ports)\b/i);
  const selfHost = fm ? fm[1] : "";
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return {rows:[],note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase().replace(/^"|"$/g,""));
  const c=(...n)=>{ for(const x of n){ const i=hdr.indexOf(x); if(i>=0) return i; } return -1; };
  const iLA=c("localaddress"), iLP=c("localport"), iRA=c("remoteaddress"),
        iRP=c("remoteport"), iST=c("state"), iPR=c("process","processname","owningprocessname"),
        iPID=c("owningprocess"), iProto=c("protocol");
  if(iLA<0 || iLP<0) return {rows:[],note:""};
  const rows=[], seen=new Set(), coll=collNow();
  const wild=v=>/^(0\.0\.0\.0|::|\*)$/.test(String(v||"").trim());
  lines.slice(1).forEach(l=>{
    const f=splitCsvLine(l).map(x=>x.replace(/^"|"$/g,"").trim());
    const lp=f[iLP], la=f[iLA];
    if(!validPort(lp)) return;
    // no remote columns at all means this is the UDP endpoint list
    const isUdp = iProto>=0 ? /udp/i.test(f[iProto]||"") : (iRA<0 && iRP<0);
    const proto = isUdp ? "UDP" : "TCP";
    const state = iST>=0 ? String(f[iST]||"").toLowerCase() : "";
    const svc = iPR>=0 ? (f[iPR]||"") : "";
    const ra = iRA>=0 ? f[iRA] : "", rp = iRP>=0 ? f[iRP] : "";
    let src="", sport="", dest="", dport="", dir="";
    if(isUdp || /listen|bound/.test(state) || !validPort(rp) || wild(ra)){
      dest = wild(la) ? "" : la; dport = lp; dir = "Inbound";
      if(!dest && !selfHost) { /* owner unknown; kept, and named once a host is known */ }
      sport = CFG.ephemeralRange || "1024-65535";
    } else {
      const o = orientPair(la, lp, ra, rp);          // the better-known port is the service
      src=o.src; sport=o.srcPort; dest=o.dest; dport=o.dstPort;
      dir = (o.dest===ra) ? "Outbound" : "Inbound";
    }
    const key=[proto,src,dest,dport].join("|");
    if(seen.has(key)) return; seen.add(key);
    const fromApp = svc ? serviceFromApp(svc) : null;
    rows.push(blank({src, dest, proto, srcPort:sport, dstPort:dport,
      dstHost: (!dest && selfHost) ? selfHost : "",
      appName: svc,
      dataService: (fromApp && fromApp.service) || guessService(dport, proto),
      direction:dir, status:"New", origin:"win-connections", collector:coll||selfHost,
      notes: (!svc && iPID>=0 && f[iPID]) ? ("PID "+f[iPID]+" — no process name in this export") : ""}));
  });
  return {rows, note: rows.length?("Windows connections: "+rows.length+" entries"):""};
}
