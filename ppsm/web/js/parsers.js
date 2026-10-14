"use strict";
/* ---------------- parsers ---------------- */
// returns {rows:[...], note:""}
/* The collector scripts stamp the host they ran on at the top of the file.
   Without it a listener bound to 0.0.0.0 has no owner. */
function readHostHeader(text){
  const h=(text||"").slice(0,400);
  const n=h.match(/^#\s*ppsm-host:\s*(\S+)/mi);
  const i=h.match(/^#\s*ppsm-ip:\s*(\S+)/mi);
  return {name:n?n[1]:"", ip:(i&&i[1]&&i[1]!=="-")?i[1]:""};
}

function parseFile(name, text){
  const lower=name.toLowerCase();
  const rawHead=(text||"").slice(0,2000);          // keep the raw bytes for format sniffing
  text = xmlClean(text);                            // ANSI + control characters out
  const head=text.slice(0,4000);
  // nmap
  if(/<nmaprun/i.test(head)) return {kind:"nmap XML", ...parseNmap(text)};
  // nessus / ACAS
  if(/<NessusClientData/i.test(head)) return {kind:"Nessus/ACAS", ...parseNessus(text)};
  // ---- v2 formats: structured XML above wins first, then these, then generic heuristics ----
  if(/^#separator|^#fields\b|\bid\.orig_h\b/m.test(head) || /conn\.log/.test(lower)){
    const r=parseZeek(text); if(r.rows.length) return {kind:"zeek", ...r}; }
  if(/#Version:.*Microsoft|#Software:.*Firewall|pfirewall/i.test(head) || /pfirewall/.test(lower)){
    const r=parseWinFirewall(text); if(r.rows.length) return {kind:"win-firewall", ...r}; }
  if(/IPV4 SRC ADDR|IPV4 SOURCE ADDRESS|flow monitor/i.test(head) || /netflow|flowmon/.test(lower)){
    const r=parseNetflowCache(text); if(r.rows.length) return {kind:"netflow", ...r}; }
  if(/%ASA-\d|%FTD-\d|Built (inbound|outbound) (TCP|UDP)/i.test(head)){
    const r=parseAsaSyslog(text); if(r.rows.length) return {kind:"asa-syslog", ...r}; }
  if(/^\s*(TCP|UDP|ICMP)\s+\S+\s+[\w.\-]+[:\/]\d+\s+\S+\s+[\w.\-]+[:\/]\d+/mi.test(head)
     || /\bidle\s+\d+:\d+:\d+.*bytes\s+\d+/i.test(head) || /show[-_ ]?conn/.test(lower)){
    const r=parseShowConn(text); if(r.rows.length) return {kind:"show-conn", ...r}; }
  if(/SRC=\S+.*DST=\S+/.test(head)){
    const r=parseIptables(text); if(r.rows.length) return {kind:"iptables", ...r}; }
  if(/\bIP6?\s+\S+\s+>\s+\S+:/.test(head) || /tcpdump|tshark/.test(lower)){
    const r=parseTcpdumpText(text); if(r.rows.length) return {kind:"tcpdump", ...r}; }
  if(/pktmon/.test(lower)){
    const r=parsePktmon(text); if(r.rows.length) return {kind:"pktmon", ...r}; }
  // an access control policy printed or saved as a report (usually via PDF)
  if(/access\s*control/i.test(text.slice(0,20000)) &&
     /(destination|dest)\s*(networks?|ports?)/i.test(text) && /\baction\b/i.test(text)){
    const r=parseAcpText(text, PDF_ITEMS);
    if(r.rows.length) return {kind:"FMC access control policy", ...r};
  }

  /* The collector scripts' own connections CSV (ppsm-collect.ps1 and the
     Windows play in ppsm.yml). Its header shares "Source IP / Destination
     Port / Data Service / Direction" with the eMASS template, so it has to
     be claimed first: read as an eMASS export it lost every listener, took
     the SOURCE port as the service port and marked the rows Registered. */
  if(/[,\t]/.test(head)){
    // header may sit under a stray console line (a warning echoed by powershell.exe)
    const l1=head.split(/\r?\n/).slice(0,5).find(l=>looksLikeCollectorCsv(l))||"";
    if(l1){
      const r=parseCollectorCsv(text, name);
      if(r.rows.length) return {kind:"Windows connections (collector)", ...r};
    }
  }

  /* A PPSM register in the eMASS template's column layout — an eMASS export,
     or a register someone kept in that shape with hostnames where the
     addresses should be — is claimed here, before the FMC and NetFlow
     report readers get a look. Its "VPN / Encrypted Tunnel Traffic" column
     used to read as a traffic-volume column and the file was taken for a
     top-conversations report, keeping one row in four. */
  if(/[,\t]/.test(head)){
    const first30=text.split(/\r?\n/).slice(0,30);
    if(first30.some(l=>{ const c=splitCsvLine(l).map(s=>s.replace(/^"|"$/g,"").trim());
                         return c.length>=4 && looksLikeEmassExport(c); })){
      const r=parseEmassExport(text);
      if(r.rows.length) return {kind:"eMASS PPSM export", ...r};
    }
  }

  // FMC exports a family of reports; work out which one this is
  if(/[,\t]/.test(head)){
    const fmc=parseFmcReport(text, name);
    if(fmc && (fmc.rows.length || fmc.seen)) return fmc;
  }

  // NetFlow analyser "top conversations" tables, from any vendor
  if(/[,\t]/.test(head)){
    const cv=parseConversations(text);
    if(cv.rows.length) return {kind:"NetFlow top conversations", ...cv};
  }

  // a firewall policy export is a rules file, not a generic flow CSV
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    if(/displayname/.test(l1) && /(localport|protocol)/.test(l1)){
      const r=parseWinFirewallRules(text); if(r.rows.length) return {kind:"Windows Firewall rules", ...r}; }
    if(/(rule name|^name|policy)/.test(l1) &&
       /(destination port|destination network|source network|destination zone)/.test(l1)){
      const r=parseAcpExport(text); if(r.rows.length) return {kind:"access control policy", ...r}; }
  }

  // Get-NetTCPConnection / Get-NetUDPEndpoint exported straight to CSV
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    if(/localaddress/.test(l1) && /localport/.test(l1)){
      const r=parseWinTcpCsv(text, name); if(r.rows.length) return {kind:"Windows connections", ...r}; }
  }

  // an eMASS PPSM export being read back in
  {
    const first=(text.split(/\r?\n/).slice(0,30).join("\n"));
    if(/[,\t]/.test(first)){
      const r=parseEmassExport(text);
      if(r.rows.length) return {kind:"eMASS PPSM export", ...r};
    }
  }

  // a Tenable / ACAS findings export as CSV
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    if(/plugin\s*id|plugin_?id/.test(l1) && /\bport\b/.test(l1)){
      const r=parseTenableCsv(text); if(r.rows.length) return {kind:"Tenable / ACAS export", ...r}; }
  }

  // a DNS export — Windows Get-DnsServerResourceRecord, a name/type/data/
  // timestamp dump, or any table with a record-type column and an address
  // column. Detected by CONTENT, so header wording, column order, extra
  // columns, and the delimiter (comma, tab, pipe, or runs of spaces) do not
  // matter — and a file with no header row still works.
  {
    const r=parseDnsExport(text, name);
    if(r.seen || /no addresses/.test(r.note||"")) return {kind:"DNS export", ...r};
  }

  // an inventory / work-list CSV carries names, not flows — catch it before generic CSV
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    const looksInv = /dnshostname|operatingsystem|computername|ipv4address/.test(l1) ||
      (/\b(ip address|ipaddress|ipv4)\b/.test(l1) && /host ?name|dns name|\bname\b/.test(l1));
    const hasPort = /\bport\b/.test(l1);
    if(looksInv && !hasPort){
      const r=parseInventoryCsv(text); if(r.seen) return {kind:"host inventory", ...r}; }
  }

  // explicit .csv extension wins
  if(lower.endsWith(".csv")){ const r=parseCsv(text);
    if(r.rows.length) return {kind:"CSV", ...r};
    if(r.seen) return {kind:"name/IP list", ...r}; }
  // netstat / ss — checked BEFORE the generic comma heuristic, since ss lines contain commas
  const looksNetstat = /netid\s+state|proto\s+local address|active connections|^\s*(tcp|udp)6?\s/im.test(head)
    || /^\s*(TCP|UDP)\s+\S+:\d+\s+\S+:/im.test(head)
    || /netstat|\bss\b/i.test(lower);
  if(looksNetstat){ const r=parseNetstat(text); if(r.rows.length) return {kind:"netstat/ss", ...r}; }
  // generic CSV (commas, multiple lines, not XML)
  if(/,/.test(head) && /\n/.test(head) && !/<\w+/.test(head)){
    const r=parseCsv(text); if(r.rows.length) return {kind:"CSV", ...r}; }
  // ---- firewall rules: what is permitted, as opposed to what happened ----
  if(/^\s*access-list\s+\S+/mi.test(head) || /^\s*ip\s+access-list\s+/mi.test(head) ||
     /^object-group\s+(network|service)/mi.test(head)){
    const r=parseCiscoAcl(text); if(r.rows.length) return {kind:"firewall ACL", ...r}; }
  if(/^set\s+.*rulebase\s+security\s+rules/mi.test(head)){
    const r=parsePaloAltoRules(text); if(r.rows.length) return {kind:"PAN security rules", ...r}; }
  if(/^\*filter/m.test(head) && /^-A\s/m.test(head)){
    const r=parseIptablesSave(text); if(r.rows.length) return {kind:"iptables ruleset", ...r}; }
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    if(/displayname/.test(l1) && /(localport|protocol)/.test(l1)){
      const r=parseWinFirewallRules(text); if(r.rows.length) return {kind:"Windows Firewall rules", ...r}; }
    if(/(rule name|^name)/.test(l1) && /(destination port|destination networks|source networks)/.test(l1)){
      const r=parseAcpExport(text); if(r.rows.length) return {kind:"access control policy", ...r}; }
  }

  // ---- name sources: no flows, only hostnames. Checked after every flow parser
  //      so a capture or cache file can never be mistaken for a name list. ----
  {
    const l1=(head.split(/\r?\n/)[0]||"").toLowerCase();
    // hosts file: "<ip> <name>" where the second token starts with a letter
    const hostLines=(head.match(/^[ \t]*\d{1,3}(?:\.\d{1,3}){3}[ \t]+[A-Za-z][\w.\-]*/mg)||[]).length;
    const bodyLines=(head.match(/^[^\s#].*$/mg)||[]).length;
    /* A hosts file is almost entirely "<ip> <name>" lines. Prose that happens
       to contain one such line is not one, so require both a real count and a
       decent share of the file. */
    if(/^\s*\d{1,3}(\.\d{1,3}){3}\s+dev\s+\S+\s+(lladdr|FAILED|INCOMPLETE)/mi.test(head)){
      const cnt=(head.match(/\s+dev\s+\S+\s+lladdr\s+/g)||[]).length;
      return {kind:"neighbour table", rows:[], names:0, seen:cnt,
        note:cnt+" neighbour entr"+(cnt===1?"y":"ies")+" read · ip neigh carries no hostnames, so it adds none"};
    }
    const hostsLike = hostLines>=1 && bodyLines>0 && (hostLines/bodyLines)>0.5;
    if(hostsLike || /(^|[\\\/])hosts(\.\w+)?$/.test(lower)){
      const r=parseHostsFile(text); if(r.seen) return {kind:"hosts file", ...r}; }
    if(/^\$ORIGIN|\bIN\s+SOA\b/mi.test(head) || /^\S+\s+(?:\d+\s+)?IN\s+(AAAA?|PTR|CNAME)\s/mi.test(head) ||
       /in-addr\.arpa|ip6\.arpa/i.test(head) || /^\s*;+\s*Zone:/mi.test(head) ||
       /^\S+\s+(?:\[Aging:\d+\]\s+)?\d+\s+(A|PTR|CNAME)\s+\S+/mi.test(head) ||
       /\.(zone|db|rev)$|(^|[\\\/])db\.[\w.\-]+$/.test(lower)){
      const r=parseDnsZone(text, name); if(r.seen) return {kind:"DNS zone", ...r}; }
    if(/^\s*lease\s+\S+\s*\{/m.test(head) || /\.leases$/.test(lower) ||
       (/ip address/.test(l1) && /lease/.test(l1))){
      const r=parseDhcpLeases(text); if(r.seen) return {kind:"DHCP leases", ...r}; }
    if(/\bat\s+[0-9a-f]{2}(:[0-9a-f]{2}){5}\b/i.test(head) || /(^|[\\\/])arp\b/.test(lower)){
      const r=parseArpTable(text); if(r.seen) return {kind:"ARP table", ...r}; }
    // inventory / work list: a name column plus an IP column, and no port column
    if(/dnshostname|operatingsystem|computername|ipv4address/.test(l1) ||
       (/\b(ip address|ipaddress|ipv4)\b/.test(l1) && /host ?name|dns name|\bname\b/.test(l1))){
      const r=parseInventoryCsv(text); if(r.seen) return {kind:"host inventory", ...r}; }
  }

  // last resort — try everything
  const ns=parseNetstat(text); if(ns.rows.length) return {kind:"netstat/ss", ...ns};
  const sc=parseShowConn(text); if(sc.rows.length) return {kind:"show-conn", ...sc};
  const nf=parseNetflowCache(text); if(nf.rows.length) return {kind:"netflow", ...nf};
  const td=parseTcpdumpText(text); if(td.rows.length) return {kind:"tcpdump", ...td};
  const zk=parseZeek(text); if(zk.rows.length) return {kind:"zeek", ...zk};
  const cs=parseCsv(text); if(cs.rows.length) return {kind:"CSV", ...cs};
  if(cs.seen) return {kind:"name/IP list", ...cs};
  const inv=parseInventoryCsv(text); if(inv.seen>=2) return {kind:"host inventory", ...inv};
  /* Only claim a file as a hosts list here if most of it looks like one;
     a document that happens to contain an address is not a name source. */
  const hf=parseHostsFile(text);
  if(hf.seen>=1){
    const body=(text.match(/^[^\s#].*$/mg)||[]).length;
    if(body>0 && hf.seen/body>0.5) return {kind:"hosts file", ...hf};
  }
  return {kind:"unknown", rows:[], note:"no recognizable port/service data"};
}

function parseNmap(xml){
  const rows=[]; let note="";
  try{
    const doc=new DOMParser().parseFromString(xml,"application/xml");
    if(doc.querySelector("parsererror")) return {rows,note:"XML parse error"};
    doc.querySelectorAll("host").forEach(host=>{
      let ip="";
      const addr=host.querySelector("address[addrtype='ipv4'],address[addrtype='ipv6'],address");
      if(addr) ip=addr.getAttribute("addr")||"";
      const hn=host.querySelector("hostname");
      const hostname=hn?hn.getAttribute("name"):"";
      if(hostname) learnHost(ip,hostname,"nmap");
      host.querySelectorAll("ports > port").forEach(p=>{
        const st=p.querySelector("state");
        const state=st?st.getAttribute("state"):"";
        if(state && state!=="open" && state!=="open|filtered") return;
        const proto=normProto(p.getAttribute("protocol"));
        const port=p.getAttribute("portid")||"";
        const sv=p.querySelector("service");
        let service=sv?(sv.getAttribute("name")||""):"";
        if(!service) service=guessService(port,proto);
        let ver="";
        if(sv){ver=[sv.getAttribute("product"),sv.getAttribute("version"),sv.getAttribute("extrainfo")]
          .filter(Boolean).join(" ");}
        rows.push(blank({dest:ip,dstHost:hostname,proto,dstPort:port,dataService:service,banner:ver,
          direction:"Inbound",status:"New",origin:"nmap"}));
      });
    });
  }catch(e){note="exception: "+e.message;}
  return {rows,note};
}

// pull a product/version banner out of a detection plugin's output
function bannerFromPlugin(name, out){
  if(!out) return "";
  const pats=[
    /SSH-\d[\d.]*-([\w.\-]+)/i,                       // SSH-2.0-OpenSSH_8.0 / Cisco-1.25
    /(OpenSSH[_\/][\w.\-]+)/i,
    /(Apache\/[\w.\-]+)/i,
    /(nginx\/[\w.\-]+)/i,
    /(Microsoft-IIS\/[\w.\-]+)/i,
    /(lighttpd\/[\w.\-]+)/i,
    /(PostgreSQL \d[\w.\-]*)/i,
    /(MySQL \d[\w.\-]*)/i,
    /(Microsoft SQL Server \d{4}[^\n\r]*?\d[\d.]+)/i,
    /(Windows Server \d{4}[^\n\r]*)/i,
    /(Cisco-[\w.\-]+)/i,
    /server type is\s*:?\s*([^\n\r]+)/i,
    /version\s*(?:is)?\s*:\s*([^\n\r]+)/i
  ];
  for(const p of pats){ const m=out.match(p); if(m){ return (m[1]||m[0]).trim().slice(0,80); } }
  return "";
}

/* ---------------- Nessus / ACAS ----------------
   A .nessus file holds far more than a port list. Every host carries its
   FQDN, NetBIOS name, reverse-DNS name, MAC, operating system and type;
   the scan records whether it ran credentialed; and individual plugins
   name the product behind a port, the interfaces a host owns, and whether
   a service is encrypted. All of that is worth having in a register. */

/* Everything HostProperties knows about a host. */
function nessusHostProps(hostEl){
  const p={};
  hostEl.querySelectorAll("HostProperties > tag").forEach(t=>{
    const n=t.getAttribute("name"); if(n) p[n]=(t.textContent||"").trim();
  });
  return p;
}

/* Pick the best name for the host, and keep the others as aliases. */
function nessusNames(props, nameAttr){
  const out=[];
  const push=(v,rank)=>{ v=(v||"").trim(); if(v && !isIP(v)) out.push({name:v,rank}); };
  push(props["host-fqdn"], 3);
  push(props["host-rdns"], 2);
  push(props["netbios-name"], 1);
  push(props["hostname"], 1);
  if(!isIP(nameAttr||"")) push(nameAttr, 0);
  out.sort((a,b)=>b.rank-a.rank);
  return out.map(x=>x.name);
}

/* "Credentialed checks : yes" in the Nessus Scan Information output. */
function nessusCredentialed(text){
  const m=String(text||"").match(/Credentialed checks\s*:\s*(\S+)/i);
  if(!m) return null;
  return /^(yes|true)/i.test(m[1]);
}

/* Interfaces enumeration lists every address a host owns, which lets the
   same name resolve from any of them. */
function nessusInterfaceIps(text){
  const out=new Set();
  String(text||"").split(/\r?\n/).forEach(l=>{
    const m=l.match(/(?:IPAddress|IP address|inet addr:?|address)\s*[:=]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i)
         || l.match(/^\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/);
    if(m && !isLoopback(m[1])) out.add(m[1]);
  });
  return [...out];
}

/* A product name out of a service-detection plugin, for the eMASS
   Application / Software Record Name column. */
/* Plugin output mixes prose with the product line. Read it line by line and
   keep the line that names a product, not the sentence describing it. */
const PRODUCT_RE=/^(Microsoft SQL Server[\w .()]*|Oracle Database[\w .()]*|Apache(?:[\/ ]Tomcat)?[\w\/.\- ]*|nginx[\w\/.\- ]*|Microsoft[- ]IIS[\w\/.\- ]*|OpenSSH[\w_.\- ]*|MySQL[\w .\-]*|PostgreSQL[\w .\-]*|PostgreSQL|Splunk[\w .\-]*|VMware[\w .\-]*|Postfix[\w .\-]*|Exim[\w .\-]*|BIND[\w .\-]*)$/i;
function nessusProduct(pluginName, out){
  const lines=String(out||"").split(/\r?\n/).map(l=>l.trim()).filter(Boolean);
  for(const l of lines){
    if(/ is running on this port| service is | remote host | following /i.test(l)) continue;
    if(l.length>70) continue;
    const m=l.match(PRODUCT_RE);
    if(m) return m[1].trim().replace(/[.,;]$/,"");
  }
  return "";
}

/* ---------------- ACAS software inventory ----------------
   A credentialed scan lists what is INSTALLED on each host — Windows
   "Installed Software Enumeration" (20811), "Software Enumeration (SSH)"
   (22869) for RPM/DEB, the CPE list (45590), and the Windows service list
   (44401). That is better evidence for Application/Software Record Name
   than a process name or a port guess: the product behind port 1433 on a
   host that has "Microsoft SQL Server 2019 (64-bit)" installed is that.
   The inventory is kept per address and joined to the register in the
   enrichment pass (see applySoftwareInventory). */
let SOFTWARE_INV = new Map();          // ip -> {host, items:[{name, version, source}]}
const SW_PLUGIN_RE=/Installed Software Enumeration|Software Enumeration|Common Platform Enumeration|Service Config Enumeration|Windows Service Enumeration|Installed Packages/i;
const SW_PLUGIN_IDS=new Set(["20811","22869","83991","45590","44401","110483","178102"]);
function isSoftwarePlugin(pid, pname){ return SW_PLUGIN_IDS.has(String(pid||"")) || SW_PLUGIN_RE.test(pname||""); }

/* Package names from the plugin text. Returns [{name, version}]. */
function softwareFromPlugin(pname, out){
  const items=[]; const seen=new Set();
  const push=(name,version)=>{
    name=String(name||"").replace(/\s+/g," ").trim().replace(/[.,;:]$/,"");
    if(!name || name.length<2 || name.length>120) return;
    if(/^(the following|here is|this plugin|note that|see also|list of|the remote)/i.test(name)) return;
    const k=name.toLowerCase()+"|"+(version||"");
    if(seen.has(k)) return; seen.add(k);
    items.push({name, version:String(version||"").trim()});
  };
  const lines=String(out||"").split(/\r?\n/).map(l=>l.replace(/\s+$/,"")).filter(l=>l.trim());
  const isCpe=/Common Platform Enumeration/i.test(pname) || /cpe:\//.test(out||"");
  lines.forEach(l=>{
    const t=l.trim();
    if(/:\s*$/.test(t) && !/cpe:/.test(t)) return;          // "...installed on the remote host :"
    // CPE: cpe:/a:apache:http_server:2.4.37  -> Apache Http Server 2.4.37
    let m=t.match(/cpe:\/[aoh]:([^:\s]+):([^:\s]+)(?::([^:\s]+))?/i);
    if(m){
      const vendor=m[1].replace(/_/g," "), prod=m[2].replace(/_/g," ");
      const title=s=>s.replace(/\b[a-z]/g,c=>c.toUpperCase());
      const name=prod.toLowerCase().startsWith(vendor.toLowerCase()) ? title(prod) : title(vendor)+" "+title(prod);
      push(name, m[3]||""); return;
    }
    if(isCpe) return;
    // Windows: Name  [version X]  [installed on D]
    m=t.match(/^(.+?)\s{2,}\[version\s+([^\]]+)\]/i) || t.match(/^(.+?)\s+\[version\s+([^\]]+)\]/i);
    if(m){ push(m[1], m[2]); return; }
    // Windows service list: "Service Name : ..." / "Display Name : X" — keep the display name
    m=t.match(/^Display Name\s*:\s*(.+)$/i);
    if(m){ push(m[1],""); return; }
    if(/^(Service Name|Start Type|Service Type|Binary Path|Account)\s*:/i.test(t)) return;
    // RPM: name-1.2.3-4.el8.x86_64 (optionally "|..." fields after it)
    m=t.match(/^([A-Za-z][A-Za-z0-9_+.]*?(?:-[A-Za-z][A-Za-z0-9_+.]*)*)-(\d[\w.+~]*?)(?:-[\w.+~]+)?(?:\.(?:noarch|x86_64|i[3-6]86|aarch64|ppc64le|s390x|src))(?:\||\s|$)/);
    if(m){ push(m[1], m[2]); return; }
    // DEB: "ii  name  version  arch  description" or "name version"
    m=t.match(/^(?:ii\s+)?([a-z0-9][a-z0-9+.-]+)\s+(\d[\w.:+~-]*)\b/);
    if(m && /^[a-z0-9]/.test(t)){ push(m[1], m[2]); return; }
    // plain "Name version" line from other enumerators
    m=t.match(/^([A-Za-z][\w .()+\/-]{1,80}?)\s+(?:v(?:ersion)?\s*)?(\d+(?:\.\d+)+[\w.-]*)\s*$/);
    if(m){ push(m[1], m[2]); return; }
  });
  return items;
}
function learnSoftware(ip, host, items, source){
  if(!ip || !isIP(ip) || !items || !items.length) return 0;
  let cur=SOFTWARE_INV.get(ip);
  if(!cur){ cur={host:host||"", items:[]}; SOFTWARE_INV.set(ip,cur); }
  if(host && !cur.host) cur.host=host;
  const seen=new Set(cur.items.map(i=>i.name.toLowerCase()+"|"+i.version));
  let n=0;
  items.forEach(i=>{ const k=i.name.toLowerCase()+"|"+i.version; if(seen.has(k)) return; seen.add(k);
    cur.items.push({name:i.name, version:i.version, source:source||"nessus"}); n++; });
  return n;
}
/* Is the Application cell something the inventory should improve on? Blank,
   a bare process name (svchost, w3wp, sqlservr), or a copy of the service. */
function isWeakAppName(a, r){
  const v=String(a||"").trim();
  if(!v) return true;
  if(r && v===String(r.dataService||"").trim()) return true;
  if(/^[a-z0-9_.-]+(\.exe)?$/i.test(v) && v.indexOf(" ")<0 && !serviceFromApp(v)) return true;
  return false;
}
/* The product on a host that answers for a row's port: by the product
   directory's usual port, by the service it implies, or by a process name
   the product is known under. */
const PROCESS_PRODUCT={ sqlservr:"sql server", w3wp:"iis", inetinfo:"iis", httpd:"apache", nginx:"nginx", mysqld:"mysql",
  postgres:"postgresql", oracle:"oracle", tnslsnr:"oracle", java:"", tomcat:"tomcat", splunkd:"splunk", named:"bind",
  sshd:"openssh", lsass:"active directory", dns:"dns server", svchost:"", spoolsv:"print", smbd:"samba", vmware:"vmware" };
function softwareForRow(r){
  const inv=SOFTWARE_INV.get(r.dest); if(!inv || !inv.items.length) return null;
  const port=String(r.dstPort||"").split(/[;,]/)[0].trim(), proto=r.proto||"";
  const svcCode=(()=>{ const dn=String(r.dataService||"").split(";")[0].trim().toLowerCase();
    for(const k in SERVICE_NAMES) if(SERVICE_NAMES[k] && SERVICE_NAMES[k].toLowerCase()===dn) return k;
    return dn||guessServiceCode(port,proto); })();
  const procHint=(PROCESS_PRODUCT[String(r.appName||"").toLowerCase().replace(/\.exe$/,"")]||"");
  let best=null, bestScore=0;
  inv.items.forEach(it=>{
    const m=serviceFromApp(it.name); let score=0;
    if(m && port && m.port===port) score+=3;
    if(m && svcCode && m.code===svcCode) score+=2;
    if(procHint && it.name.toLowerCase().indexOf(procHint)>=0) score+=2;
    if(score>bestScore){ best=it; bestScore=score; }
  });
  return best ? {item:best, score:bestScore} : null;
}
function applySoftwareInventory(rows){
  let filled=0, gaps=0;
  (rows||ROWS).forEach(r=>{
    if(!r.dest || !SOFTWARE_INV.has(r.dest) || !r.dstPort) return;
    if(!isWeakAppName(r.appName, r)) return;
    const hit=softwareForRow(r);
    if(hit){
      r.appName = hit.item.name + (hit.item.version && hit.item.name.indexOf(hit.item.version)<0 ? " "+hit.item.version : "");
      if(String(r.notes||"").indexOf("software from ACAS inventory")<0)
        r.notes=(r.notes?r.notes+" · ":"")+"software from ACAS inventory";
      filled++;
    } else {
      if(String(r.notes||"").indexOf("no matching software in the ACAS inventory")<0)
        r.notes=(r.notes?r.notes+" · ":"")+"no matching software in the ACAS inventory for this port";
      gaps++;
    }
  });
  return {filled, gaps, hosts:SOFTWARE_INV.size};
}

function parseNessus(xml){
  const rows=[]; let note="";
  let hosts=0, creds=0, uncred=0, ifaceIps=0, namesLearned=0, encrypted=0, products=0, software=0;
  const swHosts=new Set();
  try{
    const doc=new DOMParser().parseFromString(xml,"application/xml");
    if(doc.querySelector("parsererror")) return {rows,note:"XML parse error"};

    doc.querySelectorAll("ReportHost").forEach(hst=>{
      hosts++;
      const nameAttr=hst.getAttribute("name")||"";
      const props=nessusHostProps(hst);
      const ip = props["host-ip"] || (isIP(nameAttr)?nameAttr:"");
      const names = nessusNames(props, nameAttr);
      const hostLabel = names[0] || "";
      const os = props["operating-system"] || props["os"] || "";
      const role = props["system-type"] || "";

      if(ip && hostLabel){
        if(learnHost(ip, hostLabel, "nessus", {os, role})) namesLearned++;
        // the other names become aliases, so a lookup by any of them works
        names.slice(1).forEach(n=>{
          if(n.toLowerCase()!==hostLabel.toLowerCase()) ALIASES.set(n.toLowerCase(), hostLabel.toLowerCase());
        });
      }

      const label = ip || nameAttr;
      const byPort=new Map(), connSeen=new Set();
      let credentialed=null;

      hst.querySelectorAll("ReportItem").forEach(it=>{
        const port=it.getAttribute("port")||"";
        const proto=normProto(it.getAttribute("protocol"));
        const svc=it.getAttribute("svc_name")||"";
        const pname=it.getAttribute("pluginName")||"";
        const pid=it.getAttribute("pluginID")||"";
        const po=it.querySelector("plugin_output");
        const poText=po?po.textContent:"";

        // ---- host-level plugins, which carry no port of their own
        if(pid==="19506" || /Nessus Scan Information/i.test(pname)){
          const c=nessusCredentialed(poText);
          if(c!==null) credentialed=c;
          return;
        }
        if(pid==="24272" || /Network Interfaces Enumeration/i.test(pname)){
          nessusInterfaceIps(poText).forEach(extra=>{
            if(extra!==ip && hostLabel && learnHost(extra, hostLabel, "nessus", {os})) ifaceIps++;
          });
          return;
        }
        if(isSoftwarePlugin(pid, pname) && poText){
          const n=learnSoftware(ip||label, hostLabel, softwareFromPlugin(pname, poText), "nessus");
          if(n){ software+=n; if(!swHosts.has(ip||label)) swHosts.add(ip||label); }
          return;
        }

        // ---- the host's own connection table, where a credentialed scan got one
        if(/netstat|connection information|active connections|established sessions/i.test(pname) && poText){
          const sub=parseNetstat(poText);
          sub.rows.forEach(sr=>{
            sr.origin="nessus-netstat";
            if(sr.direction==="Inbound" && !sr.src){
              const k=sr.proto+"|"+sr.dstPort;
              if(byPort.has(k)) return;
              if(!sr.dest||isWildcardAddr(sr.dest)) sr.dest=label;
              if(hostLabel && !sr.dstHost) sr.dstHost=hostLabel;
              if(!sr.dataService) sr.dataService=guessService(sr.dstPort,sr.proto);
              byPort.set(k,sr); rows.push(sr);
            } else {
              const k=sr.proto+"|"+sr.src+"|"+sr.dest+"|"+sr.dstPort;
              if(connSeen.has(k)) return; connSeen.add(k);
              if(hostLabel && sr.src===label && !sr.srcHost) sr.srcHost=hostLabel;
              if(!sr.dataService) sr.dataService=guessService(sr.dstPort,sr.proto);
              rows.push(sr);
            }
          });
          return;
        }

        if(port==="0") return;                  // a finding about the host, not a service

        const key=proto+"|"+port;
        let row=byPort.get(key);
        if(!row){
          row=blank({dest:label,dstHost:hostLabel,proto,dstPort:port,
            srcPort: CFG.ephemeralRange || "1024-65535",
            dataService:(svc&&svc!=="unknown"?svc:guessService(port,proto)),
            direction:"Inbound",status:"New",origin:"nessus"});
          byPort.set(key,row); rows.push(row);
        }
        if(svc&&svc!=="unknown"&&!row.dataService) row.dataService=svc;

        const banner=bannerFromPlugin(pname, poText);
        if(banner && !row.banner) row.banner=banner;

        // the product behind the port, for the eMASS software record column
        if(!row.appName){
          const prod=nessusProduct(pname, poText);
          if(prod){ row.appName=prod; products++; if(!row.banner) row.banner=prod; }
        }
        // TLS on this port is worth recording: it is what the data description says
        if(/^(SSL|TLS)\b|SSL Certificate|Cipher Suites|Supported SSL|TLS Version/i.test(pname)){
          if(!/encrypted/i.test(row.notes||"")){
            row.notes=(row.notes?row.notes+" · ":"")+"TLS confirmed by the scan";
            encrypted++;
          }
        }
      });

      // an uncredentialed scan sees only what it could reach from outside
      if(credentialed===true) creds++;
      else if(credentialed===false){
        uncred++;
        rows.filter(r=>r.dest===label).forEach(r=>{
          if(!/uncredentialed/i.test(r.notes||""))
            r.notes=(r.notes?r.notes+" · ":"")+"uncredentialed scan — the port list may be incomplete";
        });
      }
    });

    const bits=[hosts+" host"+(hosts===1?"":"s")];
    if(namesLearned) bits.push(namesLearned+" named");
    if(ifaceIps)     bits.push(ifaceIps+" extra interface"+(ifaceIps===1?"":"s"));
    if(products)     bits.push(products+" product"+(products===1?"":"s")+" identified");
    if(software)     bits.push(software+" installed package"+(software===1?"":"s")+" inventoried on "+swHosts.size+" host"+(swHosts.size===1?"":"s"));
    if(encrypted)    bits.push(encrypted+" TLS service"+(encrypted===1?"":"s"));
    if(uncred)       bits.push(uncred+" host"+(uncred===1?"":"s")+" scanned without credentials");
    note=bits.join(" · ");
  }catch(e){note="exception: "+e.message;}
  return {rows,note};
}

/* ---------------- Tenable / ACAS CSV export ----------------
   Tenable.sc and Nessus both export findings as CSV, and that is often what
   comes out of ACAS rather than the .nessus file itself. */
function parseTenableCsv(text){
  const lines=splitCsvRecords(text);
  if(lines.length<2) return {rows:[],note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase().replace(/^"|"$/g,""));
  const col=(...n)=>{ for(const x of n){ const i=hdr.indexOf(x); if(i>=0) return i; }
                      for(const x of n){ const i=hdr.findIndex(c=>c.indexOf(x)>=0); if(i>=0) return i; } return -1; };
  const iHost=col("ip address","ip","host","asset"), iPort=col("port"),
        iProto=col("protocol","proto"), iSvc=col("service","svc"),
        iName=col("name","plugin name"), iOut=col("plugin output","output"),
        iDns=col("dns name","fqdn","hostname"), iNb=col("netbios name","netbios"),
        iOs=col("os","operating system");
  if(iHost<0 || iPort<0) return {rows:[],note:""};
  const rows=[], byKey=new Map(), coll=collNow();
  const iPid=col("plugin id","plugin_id","pluginid");
  let named=0, software=0;
  lines.slice(1).forEach(l=>{
    const c=splitCsvLine(l).map(x=>x.replace(/^"|"$/g,"").trim());
    const ip=c[iHost]; const port=c[iPort];
    if(!isIP(ip)) return;
    const name=(iDns>=0?c[iDns]:"") || (iNb>=0?c[iNb]:"");
    if(name && !isIP(name) && learnHost(ip,name,"nessus",{os:iOs>=0?c[iOs]:""})) named++;
    if(isSoftwarePlugin(iPid>=0?c[iPid]:"", iName>=0?c[iName]:"") && iOut>=0 && c[iOut]){
      software+=learnSoftware(ip, name, softwareFromPlugin(iName>=0?c[iName]:"", c[iOut]), "tenable-csv");
    }
    if(!validPort(port) || port==="0") return;
    const proto=normProto(iProto>=0?c[iProto]:"") || "TCP";
    const key=proto+"|"+ip+"|"+port;
    let row=byKey.get(key);
    if(!row){
      row=blank({dest:ip, dstHost:(name&&!isIP(name))?name:"", proto, dstPort:port,
        srcPort: CFG.ephemeralRange || "1024-65535",
        dataService:(iSvc>=0&&c[iSvc]&&c[iSvc]!=="unknown")?c[iSvc]:guessService(port,proto),
        direction:"Inbound", status:"New", origin:"nessus", collector:coll});
      byKey.set(key,row); rows.push(row);
    }
    const pn=iName>=0?c[iName]:"", out=iOut>=0?c[iOut]:"";
    if(!row.banner){ const b=bannerFromPlugin(pn,out); if(b) row.banner=b; }
    if(!row.appName){ const p=nessusProduct(pn,out); if(p) row.appName=p; }
    if(/^(SSL|TLS)\b|SSL Certificate|Cipher Suites/i.test(pn) && !/TLS confirmed/i.test(row.notes||""))
      row.notes=(row.notes?row.notes+" · ":"")+"TLS confirmed by the scan";
  });
  return {rows, seen: software?1:0, note: (rows.length||software)?("Tenable export: "+rows.length+" services"+(named?" · "+named+" named":"")+
    (software?" · "+software+" installed package"+(software===1?"":"s")+" inventoried":"")):""};
}

function parseNetstat(text){
  const rows=[]; const seen=new Set();
  const INCLUDE_CONNS = document.getElementById("conns") ? document.getElementById("conns").checked : true;
  const lines=text.split(/\r?\n/);
  for(const raw of lines){
    const line=raw.trim();
    if(!line) continue;
    // windows netstat: TCP local:lport foreign:fport STATE pid
    let m=line.match(/^(TCP|UDP)\s+(\[?[0-9a-fA-F:.%]+\]?):(\d+)\s+(\[?[0-9a-fA-F:.*]+\]?):(\d+|\*)\s*(\w+)?/);
    if(m){
      const proto=m[1].toUpperCase(), local=m[2], lport=m[3], foreign=m[4], fport=m[5], state=m[6]||"";
      if(proto==="UDP") pushListener(proto,local,lport);
      else if(/LISTEN/i.test(state)) pushListener(proto,local,lport);
      else if(INCLUDE_CONNS && /ESTAB/i.test(state)) pushConn(proto,local,lport,foreign,fport);
      continue;
    }
    // linux ss: proto state recvq sendq local:lport peer:pport process
    m=line.match(/^(tcp|udp|tcp6|udp6)\s+(\S+)\s+\d+\s+\d+\s+(\S+):(\d+|\*)\s+(\S+):(\d+|\*)(?:\s+(.*))?/i);
    if(m){
      const proto=m[1].toUpperCase().replace("6",""), state=m[2], local=m[3], lport=m[4],
            peer=m[5], pport=m[6], tail=m[7]||"";
      let svc=""; const um=tail.match(/"([^"]+)"/); if(um) svc=um[1];
      if(/LISTEN/i.test(state) || (/UNCONN/i.test(state) && proto==="UDP")) pushListener(proto,local,lport,svc);
      else if(INCLUDE_CONNS && /ESTAB/i.test(state)) pushConn(proto,local,lport,peer,pport,svc);
      continue;
    }
    // linux netstat -tulpn / -an: proto recvq sendq local:lport foreign:fport STATE pid/prog
    m=line.match(/^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+):(\d+|\*)\s+(\S+):(\d+|\*)\s+(\w+)?\s*(?:\d+\/(\S+))?/i);
    if(m){
      const proto=m[1].toUpperCase().replace("6",""), local=m[2], lport=m[3], foreign=m[4],
            fport=m[5], state=m[6]||"", svc=m[7]||"";
      if(/LISTEN/i.test(state) || (proto==="UDP" && (!state||/^\s*$/.test(state)))) pushListener(proto,local,lport,svc);
      else if(INCLUDE_CONNS && /ESTAB/i.test(state)) pushConn(proto,local,lport,foreign,fport,svc);
      continue;
    }
  }
  function pushListener(proto,local,port,svc){
    if(port==="*"||!port) return;
    const key="L|"+proto+"|"+local+"|"+port; if(seen.has(key)) return; seen.add(key);
    rows.push(blank({dest:local,proto,dstPort:port,dataService:svc||guessService(port,proto),
      direction:"Inbound",status:"New",origin:"netstat",collector:collNow()}));
  }
  // capture an active connection as an internal flow; collapse ephemeral side, dedupe by service tuple
  function pushConn(proto,local,lport,foreign,fport,svc){
    if(!foreign||foreign==="*"||foreign==="0.0.0.0"||foreign==="::"||fport==="*"||fport==="0") return;
    const lp=+lport, fp=+fport;
    const known=p=>(guessService(p)!=="")||(p>0&&p<1024);
    let svcPort,srcIP,dstIP,srcPort,dstPort,dir;
    if(known(fp)&&!known(lp)){svcPort=fp;srcIP=local;dstIP=foreign;srcPort=lport;dstPort=fport;dir="Outbound";}
    else if(known(lp)&&!known(fp)){svcPort=lp;srcIP=foreign;dstIP=local;srcPort=fport;dstPort=lport;dir="Inbound";}
    else if(fp<=lp){svcPort=fp;srcIP=local;dstIP=foreign;srcPort=lport;dstPort=fport;dir="Outbound";}
    else{svcPort=lp;srcIP=foreign;dstIP=local;srcPort=fport;dstPort=lport;dir="Inbound";}
    const key="C|"+proto+"|"+srcIP+"|"+dstIP+"|"+svcPort; if(seen.has(key)) return; seen.add(key);
    rows.push(blank({src:srcIP,dest:dstIP,proto,srcPort:String(srcPort),dstPort:String(dstPort),
      dataService:svc||guessService(svcPort,proto),direction:dir,status:"New",origin:"netstat-conn",
      collector:collNow()}));
  }
  return {rows,note:""};
}

function parseCsv(text){
  const rows=[];
  const lines=text.split(/\r?\n/).filter(l=>l.trim().length);
  if(lines.length<2) return {rows,note:""};
  const split=l=>{const out=[];let cur="",q=false;
    for(let i=0;i<l.length;i++){const c=l[i];
      if(c==='"'){ if(q&&l[i+1]==='"'){cur+='"';i++;} else q=!q; }
      else if(c===","&&!q){out.push(cur);cur="";}
      else cur+=c;}
    out.push(cur);return out.map(s=>s.trim());};
  const hdr=split(lines[0]).map(h=>h.toLowerCase());
  const find=(...names)=>{for(const n of names){const i=hdr.findIndex(h=>h.includes(n));if(i>=0)return i;}return -1;};
  const iIp=find("source ip","src ip","ip","host","address","source"),
        iDest=find("dest ip","destination ip","dest","destination","remote","peer"),
        iSrcPort=find("source port","src port","sport","local port"),
        iDstPort=find("dest port","destination port","dport","service port","remote port"),
        iPort=find("port"),
        iProto=find("protocol","proto"),
        iSvc=find("data service","service name","svc_name","application","service","svc"),
        iBanner=find("banner","version","product"),
        iDir=find("direction"),
        iBnd=find("boundary"),
        iCls=find("classification","class"),
        iCal=find("cal"),
        iColl=find("collector","source host","gathered from","sensor","observed by"),
        iSZone=find("source zone","src zone","src interface","ingress"),
        iDZone=find("destination zone","dst zone","dst interface","egress"),
        iPkts=find("packets","pkts"),
        iBytes=find("bytes"),
        iEnc=find("enclave"),
        iNotes=find("notes","comment"),
        iSHost=find("source hostname","src hostname","source host","src host","source name"),
        iDHost=find("destination hostname","dest hostname","destination host","dst host","destination name","hostname","host name","fqdn","dns name");
  // a lone service column with no port is not a flow table; treat as no-flow
  const hasFlowCol = iPort>=0 || iSrcPort>=0 || iDstPort>=0 ||
    (iSvc>=0 && (iIp>=0 || iDest>=0));
  if(!hasFlowCol){
    /* No flow columns. Before giving up, see if this is a name/IP table (a DNS
       export, an inventory, a host list) and learn the mappings. We look for
       ANY column of IPs and ANY column of hostnames, by content, so column
       names and record-type wording do not matter. */
    const allRows=lines.slice(1).map(split).filter(c=>c.some(x=>x));
    if(allRows.length){
      const w=Math.max(...allRows.map(c=>c.length));
      const ipCols=[], nameCols=[];
      for(let col=0;col<w;col++){
        let ips=0, names=0, nonEmpty=0;
        allRows.slice(0,60).forEach(c=>{ const v=(c[col]||"").trim(); if(!v) return; nonEmpty++;
          if(isIP(v)) ips++;
          else if(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*$/i.test(v) &&
                  /[a-z]/i.test(v) && !/^(a|aaaa|ptr|cname|ns|mx|txt|srv|soa)$/i.test(v) &&
                  v.indexOf(" ")<0) names++; });
        if(nonEmpty){ if(ips/nonEmpty>=0.5) ipCols.push(col); else if(names/nonEmpty>=0.5) nameCols.push(col); }
      }
      if(ipCols.length && nameCols.length){
        let learned=0, seen=0;
        allRows.forEach(c=>{
          // pair each IP column with the nearest name column in the row
          ipCols.forEach(ic=>{ const ip=(c[ic]||"").trim(); if(!isIP(ip)) return;
            let best="", bestDist=1e9;
            nameCols.forEach(nc=>{ const nm=(c[nc]||"").trim();
              if(nm && !isIP(nm) && Math.abs(nc-ic)<bestDist){ best=nm; bestDist=Math.abs(nc-ic); } });
            if(best){ seen++; if(learnHost(ip, best.replace(/\.$/,""), "dns-csv")) learned++; }
          });
        });
        if(seen) return {rows:[], names:learned, seen, note:nameNote(seen,learned,"name/IP pairs")};
      }
    }
    return {rows,note:"no port/service column found"};
  }
  for(let i=1;i<lines.length;i++){
    const c=split(lines[i]); if(c.every(x=>!x)) continue;
    const dstPort = iDstPort>=0?c[iDstPort] : (iPort>=0?c[iPort]:"");
    rows.push(blank({
      src:iIp>=0?c[iIp]:"", dest:iDest>=0?c[iDest]:"",
      proto:iProto>=0?(c[iProto]||"").toUpperCase():"",
      srcPort:iSrcPort>=0?c[iSrcPort]:"", dstPort,
      dataService:iSvc>=0?c[iSvc]:"", banner:iBanner>=0?c[iBanner]:"",
      direction:iDir>=0?c[iDir]:"", boundary:iBnd>=0?c[iBnd]:"",
      classification:iCls>=0?c[iCls]:"", cal:iCal>=0?c[iCal]:"",
      enclave:iEnc>=0?c[iEnc]:"",
      collector:iColl>=0?c[iColl]:collNow(),
      srcZone:iSZone>=0?c[iSZone]:"", dstZone:iDZone>=0?c[iDZone]:"",
      pkts:iPkts>=0?c[iPkts]:"", bytes:iBytes>=0?c[iBytes]:"",
      notes:iNotes>=0?c[iNotes]:"",
      srcHost:iSHost>=0?c[iSHost]:"", dstHost:iDHost>=0?c[iDHost]:"",
      status:"New",origin:"csv"}));
  }
  return {rows,note:""};
}
