"use strict";
/* ============================================================
   DERIVATION ENGINE
   Fills in what can be worked out from the collected data instead
   of leaving the register mostly blank. Everything here is derived
   from evidence already in the row; nothing is invented. Anything a
   reviewer must decide is left alone.
   ============================================================ */

/* zone names firewalls actually use, mapped to PPSM connection points */
const ZONE_KIND = {
  inside:"ENC", in:"ENC", internal:"ENC", trust:"ENC", trusted:"ENC", lan:"ENC",
  outside:"EXT", out:"EXT", untrust:"EXT", untrusted:"EXT", internet:"EXT", wan:"EXT",
  dmz:"ENCDMZ", dmz1:"ENCDMZ", "dmz-in":"ENCDMZ", "dmz-out":"ENCDMZ",
  mgmt:"ENC", management:"ENC", oob:"ENC", admin:"ENC",
  vpn:"ENCGW", tunnel:"ENCGW", remote:"ENCGW"
};
function zoneKind(z){
  if(!z) return "";
  return ZONE_KIND[String(z).trim().toLowerCase()] || "";
}

/* where does this address sit, as far as we can tell */
function scopeOf(ip){
  if(!ip) return "";
  const probe = isCidr(ip) ? String(ip).split("/")[0] : ip;
  return isInternal(probe) ? "INT" : "EXT";
}

/* --- boundary ---------------------------------------------------------
   Uses firewall zone names when the data carried them, otherwise the
   address scope. Returns "" when there is not enough evidence, because a
   wrong boundary is worse than a blank one. */
/* What we can and cannot prove from collected data:
     - both ends inside our ranges  -> Internal. No B number. Host and
       firewall data cannot tell an Enclave-DMZ crossing from one segment
       talking to another, and guessing wrong is worse than leaving it.
     - one end a public address     -> it leaves the enclave, so B13/B14.
     - anything else                -> blank, for a person to decide.
   Nothing is ever auto-assigned to a DISN boundary (B1-B8, B15). Those
   require architecture knowledge this tool does not have. */
function deriveBoundary(r){
  const ss=scopeOf(r.src), ds=scopeOf(r.dest);
  if(ss==="INT" && ds==="INT") return INTERNAL_BND;
  if(ss==="INT" && ds==="EXT") return "B14";
  if(ss==="EXT" && ds==="INT") return "B13";
  if(!r.src && ds==="INT")     return INTERNAL_BND;
  if(!r.src && ds==="EXT")     return "B14";
  if(!r.dest && ss==="INT")    return INTERNAL_BND;
  return "";
}
function deriveBoundaryLegacy(r){
  const sz=zoneKind(r.srcZone), dz=zoneKind(r.dstZone);
  const ss=scopeOf(r.src), ds=scopeOf(r.dest);

  /* A zone called "outside" on an enclave firewall usually means "toward the
     enclave gateway", not "the public internet". So the zone tells us the
     direction of travel and the address tells us how far it actually goes:
     a private address that leaves the enclave crosses the enclave gateway
     (B11/B12); a public one leaves for an ISP or external network (B13/B14). */
  const outbound = ext => (ext==="EXT") ? "B14" : "B12";
  const inbound  = ext => (ext==="EXT") ? "B13" : "B11";

  if(sz && dz){
    if(sz==="ENC" && dz==="ENCDMZ") return "B9";
    if(sz==="ENCDMZ" && dz==="ENC") return "B10";
    if(sz==="ENC"    && dz==="EXT") return outbound(ds);
    if(sz==="EXT"    && dz==="ENC") return inbound(ss);
    if(sz==="ENCDMZ" && dz==="EXT") return outbound(ds);
    if(sz==="EXT" && dz==="ENCDMZ") return inbound(ss);
    if(sz==="ENC" && dz==="ENC")    return crossEnclave(r) || "B18";
  }

  // no usable zone names — fall back to address scope
  if(ss==="INT" && ds==="EXT") return "B14";
  if(ss==="EXT" && ds==="INT") return "B13";
  if(ss==="INT" && ds==="INT") return crossEnclave(r) || "B18";
  if(!r.src && ds==="EXT")     return "B14";
  if(!r.src && ds==="INT")     return "B18";
  return "";
}

/* Two internal addresses that the subnet map puts in different enclaves are
   not "internal use only" — the traffic leaves one enclave to reach another,
   which crosses the enclave gateway. */
function crossEnclave(r){
  if(!r.src || !r.dest) return "";
  const a=enclaveOf(r.src), b=enclaveOf(r.dest);
  if(a && b && a!==b) return /dmz/i.test(b) ? "B9" : "B12";
  return "";
}
function enclaveOf(ip){
  if(!ip) return "";
  // a network works as well as an address: use the network address itself
  const probe = isCidr(ip) ? String(ip).split("/")[0] : ip;
  const map=(CFG.subnetEnclaves||"").split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  for(const line of map){
    const m=line.match(/^(\S+)\s*[=:,]\s*(.+)$/);
    if(!m) continue;
    if(m[1].indexOf("/")>0 ? inCidr(probe,m[1]) : probe.indexOf(m[1])===0) return m[2].trim();
  }
  return "";
}

/* --- enclave ----------------------------------------------------------
   From the user's subnet map when they have one, else the import default. */
/* With a subnet map, use it. Without one, fall back to the /24 the address
   sits in, so the column is populated and groupable without anyone having to
   configure anything first. Rename later with bulk-apply if you want. */
function subnetLabel(ip){
  if(!ip) return "";
  if(isCidr(ip)) return ip;
  if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return "";
  return ip.split(".").slice(0,3).join(".")+".0/24";
}
function deriveEnclave(r){
  const mapped = enclaveOf(r.src) || enclaveOf(r.dest);
  if(mapped) return mapped;
  if(CFG.defaultEnclave) return CFG.defaultEnclave;
  if(CFG.autoEnclaveFromSubnet===false) return "";
  // the internal end of the flow is the one worth labelling
  const probe=v=>isCidr(v)?String(v).split("/")[0]:v;
  const ip = isInternal(probe(r.src)) ? r.src
           : (isInternal(probe(r.dest)) ? r.dest : "");
  return subnetLabel(ip);
}

/* --- eMASS logical connection points ---------------------------------- */
/* Same rule as the boundary: the zone says which direction, the address says
   how far. A private address behind an interface named "outside" is still on
   the DoD network, not the public internet. */
function derivePoint(ip, zone){
  const zk=zoneKind(zone), s=scopeOf(ip);
  if(zk==="ENCDMZ") return "DoD Enclave DMZ (DoD Network)";
  if(zk==="EXT")    return s==="EXT" ? "External Network (Public Internet)"
                                     : "DoD Enclave (DoD Network)";
  if(zk==="ENC")    return "DoD Enclave (DoD Network)";
  if(s==="INT") return "DoD Enclave (DoD Network)";
  if(s==="EXT") return "External Network (Public Internet)";
  return "";
}

/* --- plain-language description of what the flow is ------------------- */
const SERVICE_DESC = {
  https:"Encrypted web / application traffic", http:"Web traffic",
  ssh:"Encrypted remote administration", telnet:"Unencrypted remote administration",
  dns:"Name resolution", ldap:"Directory lookup and authentication",
  ldaps:"Directory lookup and authentication over TLS",
  "ms-sql-s":"Database query traffic", "microsoft-ds":"Windows file and print sharing",
  "netbios-ns":"Legacy NetBIOS name resolution", "ms-wbt-server":"Remote Desktop session",
  smtp:"Mail transfer", ntp:"Time synchronisation", snmp:"Network device monitoring",
  "snmp-trap":"Network device alerting", syslog:"Log forwarding",
  kerberos:"Kerberos authentication", ftp:"File transfer", tftp:"Trivial file transfer",
  jetdirect:"Network print job submission", rdp:"Remote Desktop session",
  "splunk-forwarder":"Endpoint log forwarding to the indexer",
  "https-alt":"Encrypted web / application traffic on an alternate port",
  imap:"Mail retrieval", pop3:"Mail retrieval", vnc:"Remote desktop session",
  smb:"Windows file and print sharing", rsync:"File synchronisation",
  wsus:"Windows update distribution", oracle:"Database query traffic",
  "ms-sql-m":"Database instance discovery", mysql:"Database query traffic",
  postgresql:"Database query traffic", "iscsi-target":"Block storage",
  ipp:"Network printing", "ms-lsa":"Windows authentication",
  netbios_ssn:"Legacy Windows file sharing", nfs:"Network file share",
  radius:"Network access authentication", tacacs:"Device administration authentication",
  "ldap-admin":"Directory administration", ssl:"Encrypted web / application traffic",
  ike:"IPSec key exchange", esp:"IPSec encrypted payload", ospf:"Routing protocol",
  bgp:"Routing protocol", vrrp:"Gateway redundancy", gre:"Tunnelled traffic"
};
const PORT_DESC = {"8530":"Windows update distribution (WSUS)","8531":"Windows update distribution (WSUS over TLS)",
  "1521":"Database query traffic (Oracle)","3306":"Database query traffic (MySQL)",
  "5432":"Database query traffic (PostgreSQL)","514":"Log forwarding (syslog)",
  "9997":"Endpoint log forwarding to the indexer","8089":"Management API",
  "9100":"Network print job submission","5985":"Windows remote management",
  "5986":"Windows remote management over TLS","88":"Kerberos authentication",
  "445":"Windows file and print sharing","3268":"Directory global catalog lookup"};
function deriveDataDesc(r){
  const svc=(r.dataService||"").toLowerCase();
  if(SERVICE_DESC[svc]) return SERVICE_DESC[svc];
  if(PORT_DESC[String(r.dstPort)]) return PORT_DESC[String(r.dstPort)];
  /* Only describe a service we actually recognise. Echoing an unknown token
     back as "<token> traffic" reads like a real description but says nothing. */
  return "";
}

/* --- eMASS Type -------------------------------------------------------
   External Services when the flow leaves the enclave, Least Function when
   it stays inside it. */
/* External Services when the flow leaves the component enclave (the VA /
   Further Action boundaries), Least Function when it stays inside it. */
function deriveType(r){
  const b=bndCode(r.boundary||deriveBoundary(r));
  if(!b) return "";
  if(b===INTERNAL_BND) return "Least Function";
  /* B13/B14 reach a commercial ISP or external network, so they are external
     services even though they take the CLSA submission route. */
  const EXTERNAL_TYPE = new Set(["B1","B2","B3","B4","B5","B6","B7","B8","B13","B14","B15"]);
  return EXTERNAL_TYPE.has(b) ? "External Services" : "Least Function";
}

/* --- assurance category ----------------------------------------------
   Only from an explicit user-supplied service map; PPSM assurance is a
   CAL determination, not something to guess from a port number. */
function deriveAssurance(r){
  const map=CFG.serviceAssurance||{};
  const k=(r.dataService||"").toLowerCase(), p=String(r.dstPort||"");
  return map[k] || map[p] || "";
}

/* ---------------- the pass itself ---------------- */
const ENRICH_FIELDS = [
  ["boundary",     "Boundary",                       r=>deriveBoundary(r)],
  ["enclave",      "Enclave",                        r=>deriveEnclave(r)],
  ["dataService",  "Data Service",                   r=>guessService(r.dstPort, r.proto)],
  ["data",         "Data Description",               r=>deriveDataDesc(r)],
  ["appName",      "Application/Software Record Name", r=>r.dataService||r.banner||""],
  ["emassType",    "Type (eMASS)",                   r=>deriveType(r)],
  ["srcPoint",     "Connection Logical Source Point",      r=>derivePoint(r.src, r.srcZone)],
  ["dstPoint",     "Connection Logical Destination Point", r=>derivePoint(r.dest, r.dstZone)],
  ["vpn",          "VPN / Encrypted Tunnel Traffic", r=>{
      const b=bndCode(r.boundary); return b ? ((BND_BY_CODE[b]||{}).tunnel ? "Yes" : "No") : ""; }],
  ["subPath",      "Submission Path",                r=>submissionPath(r.boundary)],
  ["classification","Classification",                r=>meta().classification||""],
  ["assurance",    "Assurance Category",             r=>deriveAssurance(r)],
  ["collector",    "Collector / Source Host",        r=>CFG.defaultCollector||""],
  ["srcHost",      "Source Hostname",                r=>{
      const h=HOSTMAP.get(r.src); return h?h.name:""; }],
  ["dstHost",      "Destination Hostname",           r=>{
      const h=HOSTMAP.get(r.dest); return h?h.name:""; }],
  // a DRAFT, never filled automatically: only when ticked under Fill In
  ["justification","Mission Justification (draft from service)", r=>draftJustification(r), "manual"]
];

/* ---------------- purpose drafts ----------------
   eMASS wants a Purpose on every row and most registers ship with 300
   blanks. A draft from the service, the ends and the data description is
   a starting point an engineer edits, not a determination — so it is only
   written when asked for under Fill In, and it reads as a draft. */
const SERVICE_PURPOSE = {
  "https":"secure web/application access", "http":"web/application access", "ssh":"encrypted remote administration",
  "ms-wbt-server":"remote desktop administration", "rdp":"remote desktop administration",
  "ldap":"directory lookup and authentication", "ldaps":"directory lookup and authentication over TLS",
  "kerberos":"Kerberos authentication", "kpasswd":"Kerberos password changes", "dns":"name resolution", "domain":"name resolution",
  "ntp":"time synchronisation", "smtp":"mail transfer", "smtps":"mail transfer over TLS", "submission":"mail submission",
  "microsoft-ds":"file and print sharing", "cifs":"file and print sharing", "smb":"file and print sharing",
  "msrpc":"Windows RPC used by directory, management and file services", "epmap":"Windows RPC endpoint mapping",
  "netbios-ssn":"legacy NetBIOS session traffic", "netbios-ns":"legacy NetBIOS name resolution",
  "wsman-http":"Windows Remote Management", "wsman-https":"Windows Remote Management over TLS", "winrm":"Windows Remote Management",
  "ms-sql-s":"database access", "mysql":"database access", "postgresql":"database access", "oracle":"database access", "db2":"database access", "mongodb":"database access",
  "syslog":"log forwarding to the audit/SIEM collector", "syslog-tls":"log forwarding to the audit/SIEM collector over TLS",
  "snmp":"network device monitoring", "snmptrap":"network device alerting", "nessus":"vulnerability scanning (ACAS)",
  "wsus":"Windows patch distribution", "wsus-ssl":"Windows patch distribution over TLS", "splunkd":"log collection and search",
  "splunk-forwarder":"log forwarding", "ftp":"file transfer", "ftps":"file transfer over TLS", "sftp":"secure file transfer", "tftp":"device configuration/image transfer",
  "nfs":"network file system access", "iscsi":"block storage access", "vnc":"remote desktop administration",
  "radius":"network access authentication", "radius-acct":"network access accounting", "tacacs":"device administration authentication",
  "dhcps":"address assignment", "dhcp":"address assignment", "dhcpc":"address assignment", "icmp":"reachability checks",
  "sip":"voice signalling", "sip-tls":"voice signalling over TLS", "globalcat-ldap":"Active Directory global catalog lookups",
  "globalcat-ldaps":"Active Directory global catalog lookups over TLS", "adws":"Active Directory Web Services for management tooling",
  "elasticsearch":"search/log indexing", "kibana":"log dashboards", "prometheus":"metrics collection", "zabbix-agent":"host monitoring", "zabbix-server":"host monitoring",
  "nrpe":"host monitoring", "openvpn":"VPN tunnel", "isakmp":"IPsec key exchange", "ipsec-nat-t":"IPsec tunnel", "l2tp":"VPN tunnel", "pptp":"VPN tunnel",
  "ipp":"network printing", "printer":"network printing", "jetdirect":"network printing", "rsync":"file replication", "git":"source control"
};
function draftPurpose(r){
  const code=(()=>{ // find the short code behind the display name, if any
    const dn=String(r.dataService||"").split(";")[0].trim().toLowerCase();
    if(!dn) return guessServiceCode(r.dstPort, r.proto);
    if(SERVICE_PURPOSE[dn]) return dn;
    for(const k in SERVICE_NAMES) if(SERVICE_NAMES[k] && SERVICE_NAMES[k].toLowerCase()===dn) return k;
    return guessServiceCode(r.dstPort, r.proto);
  })();
  const svc = String(r.dataService||"").split(";")[0].trim() || serviceDisplayName(code);
  if(!svc && !r.dstPort) return "";
  const why = SERVICE_PURPOSE[code] || (deriveDataDesc(r) ? deriveDataDesc(r).toLowerCase() : "");
  const end = (ip,host,fallback)=> host ? host : (ip ? ip : fallback);
  const from = end(r.src, r.srcHost, "the source enclave");
  const to   = end(r.dest, r.dstHost, "the destination system");
  const port = r.dstPort ? ((r.proto||"TCP").toUpperCase()+" "+r.dstPort) : "";
  const what = why ? ("Required for "+why) : ("Required for "+(svc||"this service"));
  return what+(svc && why ? " ("+svc+")" : "")+" from "+from+" to "+to+(port?" on "+port:"")+".";
}
/* The same sentence for the export, where it must read as a purpose. */
function purposeStatement(r){ return draftPurpose(r); }
function draftJustification(r){
  const p=draftPurpose(r);
  return p ? p+" [DRAFT — confirm the mission need and edit before submission]" : "";
}

/* Runs over rows, filling only empty fields. Returns a per-field count so
   the user can see what was actually worked out. */
/* A product name in Application/Software Record Name implies a common
   service; fill Data Service from it when the row has none, and supply the
   product's usual port when the row has none. */
function deriveServiceFromApp(r){
  if(r.appName && !r.dataService){
    const m=serviceFromApp(r.appName);
    if(m){ r.dataService=m.service; if(!r.dstPort && m.port) r.dstPort=m.port; }
  }
  // also let a banner stand in for the product name
  if(!r.dataService && r.banner){
    const m=serviceFromApp(r.banner);
    if(m){ r.dataService=m.service; if(!r.dstPort && m.port) r.dstPort=m.port; }
  }
}
function enrichRows(rows, keys, overwrite){
  const sw=applySoftwareInventory(rows||ROWS);
  (rows||ROWS).forEach(deriveServiceFromApp);
  normaliseServiceNames(rows||ROWS);
  const counts={};
  // the automatic pass (no keys) skips fields marked manual — drafts only come when asked for
  const wanted = keys ? new Set(keys) : new Set(ENRICH_FIELDS.filter(f=>f[3]!=="manual").map(f=>f[0]));
  rows.forEach(r=>{
    ENRICH_FIELDS.forEach(([key,label,fn])=>{
      if(!wanted.has(key)) return;
      if(!overwrite && r[key]) return;
      let v="";
      try{ v=fn(r)||""; }catch(e){ v=""; }
      if(v && v!==r[key]){ r[key]=v; counts[label]=(counts[label]||0)+1; }
    });
  });
  return counts;
}

/* Legacy blanket "Internal only" tags are replaced by a derived boundary
   wherever the evidence supports one. */
function repairLegacyBoundaries(rows){
  let n=0;
  rows.forEach(r=>{
    if(r.boundary==="Internal only" || r.boundary==="Inter-enclave" || r.boundary==="Interconnection"){
      const d=deriveBoundary(r);
      if(d && d!==bndCode(r.boundary)){ r.boundary=d; n++; }
      else if(d){ r.boundary=d; }
    }
  });
  return n;
}

function runAutoFill(){
  if(!ROWS.length) return flash("Nothing to fill in yet — import data first.","warn");
  const keys=[...document.querySelectorAll("input[data-enrich]:checked")].map(e=>e.dataset.enrich);
  if(!keys.length) return flash("Select at least one field to fill in.","warn");
  const overwrite=$("enrichOverwrite") && $("enrichOverwrite").checked;
  const scope=($("enrichScope")&&$("enrichScope").value)==="filtered" ? getFiltered() : ROWS;
  const fixed=repairLegacyBoundaries(scope);
  const counts=enrichRows(scope, keys, overwrite);
  render(); renderEndpoints();
  if(typeof renderDiagram==="function" && ROWS.length) renderDiagram();
  const parts=Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([k,v])=>v+" "+k);
  flash(parts.length
    ? ("Filled in "+parts.slice(0,4).join(", ")+(parts.length>4?" and more":"")+
       (fixed?" · "+fixed+" legacy boundary tag"+(fixed===1?"":"s")+" replaced":""))
    : "Nothing further could be derived — the remaining fields need a person.",
    parts.length?"ok":"warn");
}

/* ============================================================
   PPSM POLICY LAYER
   Implements the parts of DoDI 8551.01 / the DISA PPSM process the
   tool can actually check: assurance categories as they appear on the
   CAL, VA vs CLSA submission routing, the listener-only registration
   rule, and the checks that map to what reviewers reject packages for.
   ============================================================ */

/* --- CAL assurance categories -------------------------------------------
   Colour designations as used on the Category Assurance List. Green /
   Yellow / Red are the current formal designations; Orange appears in
   legacy STIG material and is kept so older registers still read. */
const ASSURANCE_DEFS = [
  {code:"", label:"— not assessed —"},
  {code:"Green",  label:"Green — Best Practice (acceptable, minimal mitigation)"},
  {code:"Yellow", label:"Yellow — Conditional (acceptable with documented mitigations)"},
  {code:"Red",    label:"Red — Banned (will not cross the DISN without an approved exception)"},
  {code:"Orange", label:"Orange — Exception (legacy; not for new systems)"},
  {code:"AO",     label:"AO — Local Service (internal to the enclave, AO accepts the risk)"},
  {code:"Temporary", label:"Temporary — on the CAL pending completion of a VA"},
  {code:"Nonstandard", label:"Nonstandard usage — not compliant with the approved CAL standard"}
];
const ASSURANCE_LIST = ASSURANCE_DEFS.map(a=>({value:a.code,label:a.label}));

/* --- submission routing --------------------------------------------------
   Services crossing boundaries external to the component enclave (1-8, 15)
   need a Vulnerability Assessment / Further Action through the PPSM CCB/TAG.
   Services crossing internal boundaries (9-14, 16) take the Component Local
   Service Assessment path. Internal Use Only (17-19) still registers. */
const VA_BOUNDARIES   = new Set(["B1","B2","B3","B4","B5","B6","B7","B8","B15"]);
const CLSA_BOUNDARIES = new Set(["B9","B10","B11","B12","B13","B14","B16"]);

function submissionPath(boundary){
  const c = bndCode(boundary);
  if(!c) return "";
  if(c===INTERNAL_BND)       return "Internal — no boundary submission";
  if(VA_BOUNDARIES.has(c))   return "VA / Further Action (PPSM CCB/TAG)";
  if(CLSA_BOUNDARIES.has(c)) return "CLSA (component local)";
  return "Registry entry only (internal use)";
}
function needsDodinWaiver(boundary){
  const c=bndCode(boundary);
  return c==="B13" || c==="B14";
}

/* --- the listener-only rule ---------------------------------------------
   PPSM registers the listening server/service. A client's ephemeral source
   port is never the thing being registered, so a destination port sitting in
   an ephemeral range almost always means the flow was captured backwards. */
const EPHEMERAL = {
  windows:[49152,65535],   // IANA dynamic range, Vista/2008 and later
  linux:[32768,60999],     // /proc/sys/net/ipv4/ip_local_port_range default
  iana:[49152,65535]
};
/* The user can set their own ephemeral range as "lo-hi"; fall back to the
   OS defaults. Used by the exclusion option below. */
function ephemeralBounds(){
  const m=String((typeof CFG!=="undefined"&&CFG.ephemeralRange)||"").match(/(\d+)\s*-\s*(\d+)/);
  return m ? [+m[1],+m[2]] : [1024,65535];
}
function portIsEphemeral(port){
  const p=+port; if(!p) return false;
  const [lo,hi]=ephemeralBounds();
  return p>=lo && p<=hi;
}
/* Apply the exclude-ephemeral options to the register: optionally drop rows
   whose destination port is ephemeral (almost always a reversed capture),
   and blank an ephemeral source port so it does not clutter the Source
   column. Returns how many of each it did. */
function excludeEphemeral(rows){
  rows = rows || ROWS;
  let dropped=0, blanked=0;
  if(CFG.excludeEphemeralSrc!==false){
    rows.forEach(r=>{
      if(r.srcPort && /^\d+$/.test(r.srcPort) && portIsEphemeral(r.srcPort)){
        r.srcPort=""; blanked++;
      }
    });
  }
  if(CFG.excludeEphemeralDst===true){
    const keep=[]; const drop=new Set();
    rows.forEach(r=>{
      // a single numeric destination port in the ephemeral range, and not a
      // registered listener we trust, is dropped
      if(r.dstPort && /^\d+$/.test(r.dstPort) && portIsEphemeral(r.dstPort) &&
         String(r.origin||"").indexOf("firewall-rule")<0 && r.status!=="Registered"){
        drop.add(r); dropped++;
      }
    });
    if(drop.size){
      for(let i=ROWS.length-1;i>=0;i--) if(drop.has(ROWS[i])) ROWS.splice(i,1);
      const live=new Set(ROWS.map(x=>x.id));
      [...SELECTED].forEach(id=>{ if(!live.has(id)) SELECTED.delete(id); });
    }
  }
  return {dropped, blanked};
}
function inEphemeralRange(port){
  const p=+port;
  if(!p) return false;
  return (p>=EPHEMERAL.linux[0] && p<=EPHEMERAL.linux[1]) ||
         (p>=EPHEMERAL.iana[0]  && p<=EPHEMERAL.iana[1]);
}

/* Services whose registration is expected on a fixed port; seeing them
   elsewhere is "nonstandard usage" and needs an exception. */
const STANDARD_PORTS = {http:[80,8080], https:[443], ssh:[22], telnet:[23],
  dns:[53], smtp:[25,587], ldap:[389], ldaps:[636], ntp:[123], snmp:[161,162],
  "microsoft-ds":[445], "ms-wbt-server":[3389], "ms-sql-s":[1433]};

/* ---------------- review checks ----------------
   Each returns the rows it is unhappy about, with a short reason. These
   mirror what PPSM submissions actually get sent back for. */
const PPSM_CHECKS = [
  {id:"disn", severity:"high", title:"Internal traffic tagged with a DISN boundary",
   why:"Both ends of this flow are inside your own ranges, but it carries a boundary that describes traffic crossing the DISN. Internal traffic does not cross a CAL-defined boundary and should be marked Internal instead.",
   test:r=>{ const c=bndCode(r.boundary);
     return !!c && c!==INTERNAL_BND && VA_BOUNDARIES.has(c) &&
            scopeOf(r.src)==="INT" && scopeOf(r.dest)==="INT"; }},

  {id:"boundary", severity:"high", title:"Boundary not set",
   why:"Every registration needs the boundary it crosses. It drives whether the service goes the VA/Further Action route or the CLSA route.",
   test:r=>!bndCode(r.boundary)},

  {id:"ephemeral", severity:"high", title:"Destination port is in an ephemeral range",
   why:"PPSM registers the listening service. A destination port in 32768-60999 or 49152-65535 usually means the capture was read backwards and the client side was recorded as the server. Confirm which end listens before registering.",
   test:r=>inEphemeralRange(r.dstPort)},

  {id:"service", severity:"med", title:"No data service identified",
   why:"The CAL is organised by data service. A bare port number cannot be matched against a CAL entry or a VA report.",
   test:r=>!r.dataService && !!r.dstPort},

  {id:"calref", severity:"high", title:"No CAL / VA reference",
   why:"Reviewers reject entries that do not cite the VA report or CAL standard they register against. Check the CAL first: if the service is already listed, register against it rather than raising a duplicate.",
   test:r=>!r.calRef && !!bndCode(r.boundary) && !isInternalBnd(r.boundary)},

  {id:"assurance", severity:"med", title:"No assurance category",
   why:"Each registered service carries a CAL assurance category. Internal-only services assessed locally are AO / Local Service.",
   test:r=>!r.assurance && !!bndCode(r.boundary) && !isInternalBnd(r.boundary)},

  {id:"nspu", severity:"med", title:"Web service on a non-standard port",
   why:"HTTP or HTTPS on a port other than the approved standard is non-standard port usage and needs an NSPU exception.",
   test:r=>{ const s=(r.dataService||"").toLowerCase();
     if(s!=="http" && s!=="https" && s!=="https-alt" && s!=="http-alt") return false;
     const std=STANDARD_PORTS[s==="https-alt"?"https":(s==="http-alt"?"http":s)]||[];
     return !!r.dstPort && std.indexOf(+r.dstPort)<0; }},

  {id:"banned", severity:"high", title:"Assurance category is Red / Banned",
   why:"A banned service will not be allowed across the DISN without an approved exception. Either remove it or raise the exception before submitting.",
   test:r=>/^(Red|Banned)/i.test(r.assurance||"")},

  {id:"waiver", severity:"med", title:"Boundary 13/14 needs a DoDIN waiver",
   why:"Traffic to or from a commercial ISP or approved gateway requires a DoDIN waiver, which is a separate process from the DSAWG.",
   test:r=>needsDodinWaiver(r.boundary) && !/waiver/i.test((r.isaRef||"")+(r.notes||""))},

  {id:"swgap", severity:"low", title:"No installed software matches this port",
   why:"The ACAS inventory for this host lists its installed software, and none of it is known to serve this port. Either the product is not in the directory, or the listener is something the scan did not catalogue — worth naming by hand.",
   test:r=>/no matching software in the ACAS inventory/.test(r.notes||"")},
  {id:"justdraft", severity:"med", title:"Mission justification is still a draft",
   why:"The purpose was drafted from the service name and never edited; a reviewer will read it as boilerplate.",
   test:r=>/\[DRAFT/.test(r.justification||"")},
  {id:"justification", severity:"med", title:"No mission justification",
   why:"The purpose of the flow is what the reviewer reads to decide whether it is warranted. This one cannot be derived; it has to be written.",
   test:r=>!r.justification && !!bndCode(r.boundary) && !isInternalBnd(r.boundary)},

  {id:"endpoint", severity:"low", title:"Destination system not named",
   why:"An address alone does not identify a system. Name the endpoint before the register goes forward.",
   test:r=>!!r.dest && !r.dstHost && isInternal(r.dest) &&
           String(r.origin||"").indexOf("firewall-rule")<0},

  {id:"noaddr", severity:"high", title:"Hostname with no IP address",
   why:"The template requires the IP address on both ends, and this row only has a name for one of them. No DNS zone, hosts file, AD export or inventory loaded so far knows the address. Load the zone that holds it (forward zone, or a DNS Manager / Get-DnsServerResourceRecord export), or type the address against the name under Endpoints Discovered.",
   test:r=>(!r.src && !!r.srcHost && !isCidr(r.srcHost)) || (!r.dest && !!r.dstHost && !isCidr(r.dstHost))},

  {id:"namecheck", severity:"med", title:"Hostname disagrees with DNS for that address",
   why:"The row names the system one way and the DNS zones name the same address another way, and it is not a CNAME or a name a scan or inventory also gave it. Either the register is pointing at the wrong address, or the record is stale and the name has moved. The row's note says what DNS has. Settle which is right before it goes forward — a register that names one box and lists another's address fails review.",
   test:r=>/name\/address check/.test(String(r.notes||""))},

  {id:"nosource", severity:"high", title:"No source — a scan found the service but not who reaches it",
   why:"A vulnerability scan (ACAS / Nessus / nmap) sees the listening service, which is the destination, but not the clients that connect to it. To fill the source, add something that shows conversations for the same host and port: a firewall connection table (show conn), the firewall ruleset (access-list), a NetFlow cache, or Zeek conn.log. The tool then matches them up automatically. Until then these rows have a destination but no source.",
   test:r=>!r.src && !r.srcHost && !!r.dest &&
           /nessus|nmap|fmc-servers|fmc-applications/.test(String(r.origin||"")) &&
           String(r.origin||"").indexOf("firewall-rule")<0},

  {id:"unusedrule", severity:"med", title:"Rule permits traffic that was never seen",
   why:"This port is permitted by a firewall rule, but no collected traffic used it. Either the collection missed it, or the rule is stale and should be put forward for removal. Least functionality means the ruleset should not be wider than the traffic needs.",
   test:null},

  {id:"norule", severity:"high", title:"Observed traffic with no rule behind it",
   why:"This flow was seen on the wire, but nothing in the rulesets you imported permits it. Either a ruleset is missing from the collection, or the traffic is taking a path nobody authorised. Worth resolving before the register goes forward.",
   test:null},

  {id:"uncred", severity:"med", title:"Found by an uncredentialed scan",
   why:"The scan that found this ran without credentials, so it saw only what answered from the network. Listening services bound to an interface it could not reach, and anything firewalled off from the scanner, will be missing. Re-run that host credentialed, or confirm its ports from the host itself.",
   test:r=>/uncredentialed scan/i.test(r.notes||"")},

  {id:"duplicate", severity:"low", title:"Duplicate registration",
   why:"The same protocol, port, service and boundary appears more than once. Registering something already covered is the most common PPSM rejection.",
   test:null}   // handled separately, needs the whole set
];

function findDuplicates(rows){
  const seen=new Map(), dupes=[];
  rows.forEach(r=>{
    const basis=String(r.origin||"").indexOf("firewall-rule")>=0?"rule":"seen";
    const k=[basis,(r.proto||"").toUpperCase(), r.dstPort||"", (r.dataService||"").toLowerCase(),
             bndCode(r.boundary), r.dest||"", r.isaRef||""].join("|");
    if(!r.dstPort) return;
    if(seen.has(k)) dupes.push(r); else seen.set(k,r);
  });
  return dupes;
}

function runPpsmChecks(rows){
  rows = rows || ROWS;
  const out=[];
  PPSM_CHECKS.forEach(c=>{
    if(!c.test) return;
    const hits=rows.filter(r=>{ try{ return c.test(r); }catch(e){ return false; } });
    if(hits.length) out.push({...c, rows:hits, count:hits.length});
  });
  const d=findDuplicates(rows);
  if(d.length){
    const def=PPSM_CHECKS.find(c=>c.id==="duplicate");
    out.push({...def, rows:d, count:d.length});
  }
  /* Rule-versus-traffic reconciliation only means anything when both are
     present, so it stays quiet until a ruleset has been imported. */
  const rt=ruleTrafficReview(rows);
  if(rt.ruled && rt.observed){
    if(rt.unusedRules.length){
      const def=PPSM_CHECKS.find(c=>c.id==="unusedrule");
      out.push({...def, rows:rt.unusedRules, count:rt.unusedRules.length});
    }
    if(rt.unauthorised.length){
      const def=PPSM_CHECKS.find(c=>c.id==="norule");
      out.push({...def, rows:rt.unauthorised, count:rt.unauthorised.length});
    }
  }
  const order={high:0,med:1,low:2};
  return out.sort((a,b)=>order[a.severity]-order[b.severity] || b.count-a.count);
}

function renderPpsmChecks(){
  const host=$("chkBody"); if(!host) return;
  const scope=($("chkScope")&&$("chkScope").value)==="filtered" ? getFiltered() : ROWS;
  if(!scope.length){
    host.innerHTML='<div class="dg-empty">No register entries yet — import data first.</div>';
    if($("chkSummary")) $("chkSummary").innerHTML="";
    return;
  }
  const issues=runPpsmChecks(scope);
  const high=issues.filter(i=>i.severity==="high").reduce((a,b)=>a+b.count,0);
  const med =issues.filter(i=>i.severity==="med").reduce((a,b)=>a+b.count,0);
  const low =issues.filter(i=>i.severity==="low").reduce((a,b)=>a+b.count,0);
  if($("chkSummary")){
    $("chkSummary").innerHTML = issues.length
      ? `<span class="ep-pill"><b>${scope.length}</b> rows checked</span>`+
        `<span class="ep-pill ${high?"warn":"ok"}"><b>${high}</b> must fix</span>`+
        `<span class="ep-pill"><b>${med}</b> should fix</span>`+
        `<span class="ep-pill"><b>${low}</b> worth a look</span>`
      : `<span class="ep-pill ok"><b>${scope.length}</b> rows checked · nothing outstanding</span>`;
  }
  if(!issues.length){
    host.innerHTML='<div class="dg-empty">Every check passed. Worth re-running after any edit.</div>';
    return;
  }
  host.innerHTML=issues.map(i=>{
    const ex=i.rows.slice(0,4).map(r=>
      (r.dstHost||r.dest||"?")+" "+(r.proto||"")+"/"+(r.dstPort||"")+
      (r.dataService?" "+r.dataService:"")).join(" · ");
    return `<div class="chk chk-${i.severity}">
      <div class="chk-h"><span class="chk-sev">${i.severity==="high"?"MUST FIX":i.severity==="med"?"SHOULD FIX":"WORTH A LOOK"}</span>
        <b>${esc(i.title)}</b><span class="chk-n">${i.count} row${i.count===1?"":"s"}</span></div>
      <div class="chk-why">${esc(i.why)}</div>
      <div class="chk-ex">${esc(ex)}${i.count>4?" · and "+(i.count-4)+" more":""}</div>
    </div>`;
  }).join("");
}

function exportChecksCsv(){
  const issues=runPpsmChecks(ROWS);
  if(!issues.length) return flash("Nothing outstanding to export.","ok");
  const lines=[["Severity","Finding","Why it matters","Enclave","Source","Destination","Protocol","Port","Data Service","Boundary"].map(csvCell).join(",")];
  issues.forEach(i=>{
    i.rows.forEach(r=>{
      lines.push([
        i.severity==="high"?"Must fix":(i.severity==="med"?"Should fix":"Worth a look"),
        i.title, i.why, r.enclave, r.srcHost||r.src, r.dstHost||r.dest,
        r.proto, r.dstPort, r.dataService, r.boundary
      ].map(v=>csvCell(asciiSafe(v))).join(","));
    });
  });
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-ppsm-review-findings.csv",
    "\ufeff"+lines.join("\r\n"), "text/csv;charset=utf-8");
}
