"use strict";
/* ============================================================
   FIREWALL RULES: ACCESS CONTROL POLICIES AND ACLs
   A connection table shows what happened. A ruleset shows what is
   permitted, which is what PPSM actually registers. Reading both
   lets the register show whether a permitted flow was ever used and
   whether an observed flow was ever authorised.

   Handles: Cisco ASA / FTD access-lists (with object-group
   resolution), IOS extended ACLs, FMC access control policy exports,
   Palo Alto set-format security rules, iptables-save, and Windows
   Get-NetFirewallRule CSV exports.
   ============================================================ */

/* An endpoint in a rule can be an address, a network, "any", or a group. */
function aclAddr(tokens, i){
  const t = (tokens[i]||"").toLowerCase();
  if(t==="any" || t==="any4" || t==="any6") return {val:"any", next:i+1};
  if(t==="host")            return {val:tokens[i+1]||"", next:i+2};
  if(t==="object-group" || t==="object" || t==="group")
                            return {val:"@"+(tokens[i+1]||""), next:i+2};
  if(t==="interface")       return {val:"if:"+(tokens[i+1]||""), next:i+2};
  // "10.1.1.0 255.255.255.0" or "10.1.1.0 0.0.0.255" (IOS wildcard)
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(tokens[i]||"")){
    const m = tokens[i+1]||"";
    if(/^\d{1,3}(\.\d{1,3}){3}$/.test(m)) return {val:tokens[i]+"/"+maskToBits(m), next:i+2};
    return {val:tokens[i], next:i+1};
  }
  if(/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(tokens[i]||"")) return {val:tokens[i], next:i+1};
  return {val:tokens[i]||"", next:i+1};
}

function maskToBits(m){
  const o = m.split(".").map(Number);
  if(o.some(isNaN)) return m;
  // a wildcard mask (0.0.0.255) is the inverse of a netmask
  const wildcard = o[0]===0 && (o[3]>0 || o[1]>0 || o[2]>0);
  const bytes = wildcard ? o.map(x=>255-x) : o;
  let bits=0;
  for(const b of bytes){
    for(let k=7;k>=0;k--) if((b>>k)&1) bits++; else return bits;
  }
  return bits;
}

/* port clause: eq 443 | range 8000 8010 | gt 1023 | lt 100 | neq 22 */
function aclPort(tokens, i, isSvcGroup){
  const t=(tokens[i]||"").toLowerCase();
  if(t==="eq")    return {val:tokens[i+1]||"", next:i+2};
  if(t==="range") return {val:(tokens[i+1]||"")+"-"+(tokens[i+2]||""), next:i+3};
  if(t==="gt")    return {val:">"+(tokens[i+1]||""), next:i+2};
  if(t==="lt")    return {val:"<"+(tokens[i+1]||""), next:i+2};
  if(t==="neq")   return {val:"!"+(tokens[i+1]||""), next:i+2};
  if(t==="object-group" || t==="object"){
    const name=tokens[i+1]||"";
    // only a service group is a port clause; a network group here is the
    // destination address, which the caller still needs to read
    if(!isSvcGroup || isSvcGroup(name)) return {val:"@"+name, next:i+2};
  }
  return {val:"", next:i};
}

/* a named port becomes its number where we know it */
const NAMED_PORTS = {www:"80",http:"80",https:"443",ssh:"22",telnet:"23",ftp:"21",
  "ftp-data":"20",smtp:"25",domain:"53",tftp:"69",bootps:"67",bootpc:"68",ntp:"123",
  snmp:"161","snmptrap":"162",ldap:"389",ldaps:"636",syslog:"514",sqlnet:"1521",
  "ms-sql":"1433",rdp:"3389",pop3:"110",imap4:"143",nfs:"2049",kerberos:"88",
  "netbios-ssn":"139","netbios-ns":"137",citrix:"1494",h323:"1720",sip:"5060",
  isakmp:"500","non500-isakmp":"4500",pptp:"1723",echo:"7",discard:"9",daytime:"13"};
function portNum(p){
  if(!p) return "";
  const s=String(p).toLowerCase();
  return NAMED_PORTS[s] || p;
}

/* ---------------- Cisco ASA / FTD / IOS access-lists ---------------- */
function parseCiscoAcl(text){
  const lines=text.split(/\r?\n/);
  const rows=[], seen=new Set(), coll=collNow();

  /* pass 1: object-groups, so a rule referring to one can be expanded */
  const netGroups=new Map(), svcGroups=new Map();
  let cur=null, curKind=null, curProto=null;
  for(const raw of lines){
    const l=raw.trim();
    let m=l.match(/^object-group\s+(network|service|protocol)\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?/i);
    if(m){ curKind=m[1].toLowerCase(); cur=m[2]; curProto=(m[3]||"").toLowerCase();
           if(curKind==="network") netGroups.set(cur,[]);
           else if(curKind==="service") svcGroups.set(cur,{proto:curProto,ports:[]});
           continue; }
    m=l.match(/^object\s+network\s+(\S+)/i);
    if(m){ curKind="network"; cur=m[1]; netGroups.set(cur,[]); continue; }
    if(!cur){ continue; }
    if(curKind==="network"){
      let g=l.match(/^network-object\s+host\s+(\S+)/i);
      if(g){ netGroups.get(cur).push(g[1]); continue; }
      g=l.match(/^network-object\s+(?:object\s+)?(\S+)(?:\s+(\S+))?/i);
      if(g){ netGroups.get(cur).push(g[2]&&/^\d/.test(g[2]) ? g[1]+"/"+maskToBits(g[2]) : g[1]); continue; }
      g=l.match(/^(?:host|subnet)\s+(\S+)(?:\s+(\S+))?/i);
      if(g){ netGroups.get(cur).push(g[2]?g[1]+"/"+maskToBits(g[2]):g[1]); continue; }
      g=l.match(/^group-object\s+(\S+)/i);
      if(g){ netGroups.get(cur).push("@"+g[1]); continue; }
    } else if(curKind==="service"){
      let g=l.match(/^port-object\s+eq\s+(\S+)/i);
      if(g){ svcGroups.get(cur).ports.push(portNum(g[1])); continue; }
      g=l.match(/^port-object\s+range\s+(\S+)\s+(\S+)/i);
      if(g){ svcGroups.get(cur).ports.push(portNum(g[1])+"-"+portNum(g[2])); continue; }
      g=l.match(/^service-object\s+(tcp|udp)(?:\s+destination)?\s+eq\s+(\S+)/i);
      if(g){ const s=svcGroups.get(cur); s.proto=s.proto||g[1].toLowerCase();
             s.ports.push(portNum(g[2])); continue; }
      g=l.match(/^group-object\s+(\S+)/i);
      if(g){ svcGroups.get(cur).ports.push("@"+g[1]); continue; }
    }
    if(/^\S/.test(raw) && !/^(object|network-object|port-object|service-object|group-object|host|subnet)/i.test(l))
      cur=null;
  }

  const expandNet=(v,depth)=>{
    if(!v || v[0]!=="@") return [v];
    if((depth||0)>3) return [v.slice(1)];
    const g=netGroups.get(v.slice(1));
    if(!g || !g.length) return [v.slice(1)];
    let out=[];
    g.forEach(x=>{ out=out.concat(expandNet(x,(depth||0)+1)); });
    return out.slice(0,40);
  };
  const expandSvc=(v,depth)=>{
    if(!v || v[0]!=="@") return {ports:[v], proto:""};
    if((depth||0)>3) return {ports:[v.slice(1)], proto:""};
    const g=svcGroups.get(v.slice(1));
    if(!g) return {ports:[v.slice(1)], proto:""};
    let ports=[];
    g.ports.forEach(p=>{ ports = ports.concat(p && p[0]==="@" ? expandSvc(p,(depth||0)+1).ports : [p]); });
    return {ports:ports.slice(0,40), proto:g.proto||""};
  };

  /* pass 2: the rules themselves */
  let iosAcl=null;
  for(const raw of lines){
    const l=raw.trim();
    if(!l || l.startsWith("!")) continue;

    let m=l.match(/^ip\s+access-list\s+(?:extended|standard)\s+(\S+)/i);
    if(m){ iosAcl=m[1]; continue; }

    let name="", body="";
    m=l.match(/^access-list\s+(\S+)\s+(?:extended\s+|line\s+\d+\s+(?:extended\s+)?)?(.*)$/i);
    if(m){ name=m[1]; body=m[2]; }
    else if(iosAcl && /^(permit|deny)\s/i.test(l)){ name=iosAcl; body=l; }
    else { if(/^\S/.test(raw) && !/^(permit|deny)/i.test(l)) iosAcl=null; continue; }

    if(/^remark|^standard/i.test(body)) continue;
    const tok=body.split(/\s+/).filter(Boolean);
    if(!tok.length) continue;
    const action=(tok[0]||"").toLowerCase();
    if(action!=="permit" && action!=="deny") continue;
    // only permitted traffic is registrable; a deny is recorded as context
    let i=1;
    let proto=(tok[i]||"").toLowerCase(); i++;
    if(proto==="object-group" || proto==="object"){ proto=(tok[i]||"").toLowerCase(); i++; }

    const isSvc=n=>svcGroups.has(n);
    const s=aclAddr(tok,i); i=s.next;
    const sp=aclPort(tok,i,isSvc); i=sp.next;
    const d=aclAddr(tok,i); i=d.next;
    const dp=aclPort(tok,i,isSvc); i=dp.next;

    const logOnly=/\blog\b/i.test(body) && !dp.val && !d.val;
    if(logOnly) continue;

    const srcs=expandNet(s.val);
    const dsts=expandNet(d.val);
    let ports=[dp.val], pproto=proto;
    if(dp.val && dp.val[0]==="@"){ const e=expandSvc(dp.val); ports=e.ports; if(e.proto) pproto=e.proto; }
    if(!dp.val && proto && svcGroups.has(proto)){ const e=expandSvc("@"+proto); ports=e.ports; pproto=e.proto||proto; }

    let made=0;
    for(const sv of srcs){
      for(const dv of dsts){
        for(const pv of ports){
          if(made>=60) break;
          const port=portNum(pv);
          const key=[name,pproto,sv,dv,port].join("|");
          if(seen.has(key)) continue; seen.add(key);
          made++;
          rows.push(blank({
            src: sv==="any" ? "" : sv,
            dest: dv==="any" ? "" : dv,
            proto: (pproto||"").toUpperCase().replace(/^IP$/,"IP"),
            srcPort: sp.val?portNum(sp.val):"",
            dstPort: port || "",
            dataService: guessService(port, pproto),
            direction: "", status: action==="permit" ? "Permitted by rule" : "Denied by rule",
            origin: "firewall-rule", collector: coll,
            isaRef: name,
            notes: (action==="deny"?"DENY rule":"PERMIT rule")+" in ACL "+name+
                   (sv==="any"?" · source any":"")+(dv==="any"?" · destination any":"")
          }));
        }
      }
    }
  }
  return {rows, note: rows.length ? ("access-list rules: "+rows.length+
    (netGroups.size?(" · "+netGroups.size+" object-groups resolved"):"")) : ""};
}

/* ---------------- FMC access control policy export ---------------- */
function parseAcpExport(text){
  const rows=[], seen=new Set(), coll=collNow();
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(!lines.length) return {rows,note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase());
  const f=(...names)=>{ for(const n of names){ const i=hdr.findIndex(h=>h===n); if(i>=0) return i; }
                        for(const n of names){ const i=hdr.findIndex(h=>h.includes(n)); if(i>=0) return i; }
                        return -1; };
  const iName=f("rule name","name","rule"),
        iAct =f("action"),
        iSrcN=f("source networks","source network","source zone","source"),
        iDstN=f("destination networks","destination network","destination"),
        iPort=f("destination ports","destination port","ports","port","service"),
        iSrcP=f("source ports","source port"),
        iEnab=f("enabled","state");
  if(iPort<0 && iDstN<0) return {rows,note:""};

  lines.slice(1).forEach(line=>{
    const c=splitCsvLine(line).map(x=>x.replace(/^"|"$/g,"").trim());
    const name=iName>=0?c[iName]:"";
    const act=(iAct>=0?c[iAct]:"allow").toLowerCase();
    if(iEnab>=0 && /^(false|no|disabled)$/i.test(c[iEnab]||"")) return;
    const portField=iPort>=0?c[iPort]:"";
    const srcField=iSrcN>=0?c[iSrcN]:"";
    const dstField=iDstN>=0?c[iDstN]:"";
    // "TCP/443, TCP/8443" or "HTTPS (TCP/443)" or "443"
    let specs=parseFmcPorts(portField).map(x=>({proto:x.proto, port:x.port, svc:x.svc}));
    if(specs.length) { /* FMC notation, "TCP (6):443", understood directly */ }
    else String(portField).split(/[,;]/).forEach(p=>{
      p=p.trim(); if(!p) return;
      let m=p.match(/(TCP|UDP|ICMP|SCTP)\s*[\/:]\s*(\d+(?:-\d+)?)/i);
      if(m){ specs.push({proto:m[1].toUpperCase(), port:m[2]}); return; }
      m=p.match(/^(\d+(?:-\d+)?)$/);
      if(m){ specs.push({proto:"", port:m[1]}); return; }
      m=p.match(/\(([^)]*)\)/);
      if(m){ const mm=m[1].match(/(TCP|UDP)\s*[\/:]\s*(\d+)/i);
             if(mm){ specs.push({proto:mm[1].toUpperCase(), port:mm[2]}); return; } }
      specs.push({proto:"", port:"", svc:p});
    });
    if(!specs.length) specs.push({proto:"",port:""});
    const dsts = String(dstField).split(/[,;]/).map(x=>x.trim()).filter(Boolean);
    const srcs = String(srcField).split(/[,;]/).map(x=>x.trim()).filter(Boolean);
    (dsts.length?dsts:[""]).forEach(dv=>{
      (srcs.length?srcs:[""]).forEach(sv=>{
        specs.forEach(sp=>{
          const key=[name,sp.proto,sp.port,sv,dv].join("|");
          if(seen.has(key)) return; seen.add(key);
          const anyish=v=>/^(any|any-ipv4|any-ipv6|all)$/i.test(v||"")?"":v;
          rows.push(blank({
            src:anyish(sv), dest:anyish(dv), proto:sp.proto,
            dstPort:sp.port, dataService: sp.svc || guessService(sp.port, sp.proto),
            status: /allow|permit|trust/.test(act) ? "Permitted by rule" : "Denied by rule",
            origin:"firewall-rule", collector:coll, isaRef:name,
            notes:(act?act.toUpperCase()+" rule":"rule")+(name?" '"+name+"'":"")+" in access control policy"
          }));
        });
      });
    });
  });
  return {rows, note: rows.length?("access control policy: "+rows.length+" rule entries"):""};
}

/* ---------------- Palo Alto set-format security rules ---------------- */
function parsePaloAltoRules(text){
  const rows=[], coll=collNow(), byRule=new Map();
  text.split(/\r?\n/).forEach(l=>{
    const m=l.match(/^set\s+.*?rulebase\s+security\s+rules\s+(\S+)\s+(\S+)\s+(.*)$/i);
    if(!m) return;
    const [, name, key, val] = m;
    if(!byRule.has(name)) byRule.set(name,{});
    const r=byRule.get(name);
    const clean=v=>v.replace(/^\[\s*/,"").replace(/\s*\]$/,"").split(/\s+/).filter(Boolean);
    if(key==="service")      r.service=clean(val);
    else if(key==="destination") r.dest=clean(val);
    else if(key==="source")  r.src=clean(val);
    else if(key==="action")  r.action=val.trim();
    else if(key==="application") r.app=clean(val);
    else if(key==="disabled") r.disabled=/yes/i.test(val);
  });
  byRule.forEach((r,name)=>{
    if(r.disabled) return;
    const svcs=(r.service&&r.service.length)?r.service:["any"];
    const dsts=(r.dest&&r.dest.length)?r.dest:["any"];
    const srcs=(r.src&&r.src.length)?r.src:["any"];
    dsts.slice(0,20).forEach(d=>srcs.slice(0,20).forEach(s=>svcs.slice(0,20).forEach(sv=>{
      const anyish=v=>/^any$/i.test(v)?"":v;
      rows.push(blank({
        src:anyish(s), dest:anyish(d),
        dataService: (r.app&&r.app.length&&!/^any$/i.test(r.app[0]))?r.app[0]:(/^any$/i.test(sv)?"":sv),
        status: /allow/i.test(r.action||"allow")?"Permitted by rule":"Denied by rule",
        origin:"firewall-rule", collector:coll, isaRef:name,
        notes:"security rule '"+name+"'"+(r.app&&r.app.length?" · app "+r.app.join(","):"")
      }));
    })));
  });
  return {rows, note: rows.length?("Palo Alto security rules: "+rows.length+" entries"):""};
}

/* ---------------- iptables-save ---------------- */
function parseIptablesSave(text){
  const rows=[], seen=new Set(), coll=collNow();
  text.split(/\r?\n/).forEach(l=>{
    if(!/^-A\s/.test(l)) return;
    if(!/-j\s+(ACCEPT|DROP|REJECT)/i.test(l)) return;
    const g=k=>{ const m=l.match(new RegExp("(?:^|\\s)"+k+"\\s+(\\S+)")); return m?m[1]:""; };
    const proto=(g("-p")||"").toUpperCase();
    const dport=g("--dport")||g("--dports");
    const sport=g("--sport");
    const src=g("-s"), dst=g("-d");
    const act=(l.match(/-j\s+(\w+)/i)||[])[1]||"";
    const chain=(l.match(/^-A\s+(\S+)/)||[])[1]||"";
    if(!dport && !dst && !src) return;
    const key=[chain,proto,src,dst,dport].join("|");
    if(seen.has(key)) return; seen.add(key);
    rows.push(blank({
      src:/0\.0\.0\.0\/0/.test(src)?"":src, dest:/0\.0\.0\.0\/0/.test(dst)?"":dst,
      proto, srcPort:sport, dstPort:dport,
      dataService:guessService(dport,proto),
      status:/ACCEPT/i.test(act)?"Permitted by rule":"Denied by rule",
      origin:"firewall-rule", collector:coll, isaRef:chain,
      notes:act.toUpperCase()+" rule in chain "+chain
    }));
  });
  return {rows, note: rows.length?("iptables rules: "+rows.length+" entries"):""};
}

/* ---------------- Windows Get-NetFirewallRule CSV ---------------- */
function parseWinFirewallRules(text){
  const rows=[], coll=collNow();
  const lines=text.split(/\r?\n/).filter(l=>l.trim());
  if(lines.length<2) return {rows,note:""};
  const hdr=splitCsvLine(lines[0]).map(s=>s.trim().toLowerCase());
  const f=(...n)=>{ for(const x of n){ const i=hdr.findIndex(h=>h===x); if(i>=0) return i; }
                    for(const x of n){ const i=hdr.findIndex(h=>h.includes(x)); if(i>=0) return i; } return -1; };
  const iName=f("displayname","name"), iDir=f("direction"), iAct=f("action"),
        iEn=f("enabled"), iProto=f("protocol"), iLp=f("localport"), iRp=f("remoteport"),
        iRa=f("remoteaddress"), iLa=f("localaddress");
  if(iProto<0 && iLp<0) return {rows,note:""};
  lines.slice(1).forEach(line=>{
    const c=splitCsvLine(line).map(x=>x.replace(/^"|"$/g,"").trim());
    if(iEn>=0 && /^(false|no)$/i.test(c[iEn]||"")) return;
    const dir=(iDir>=0?c[iDir]:"").toLowerCase();
    const inbound=/in/.test(dir) && !/out/.test(dir);
    const proto=(iProto>=0?c[iProto]:"").toUpperCase();
    const port=(inbound ? (iLp>=0?c[iLp]:"") : (iRp>=0?c[iRp]:"")) || "";
    if(/^any$/i.test(port) || !port) return;
    const anyish=v=>/^(any|\*)$/i.test(v||"")?"":v;
    rows.push(blank({
      src: inbound ? anyish(iRa>=0?c[iRa]:"") : anyish(iLa>=0?c[iLa]:""),
      dest: inbound ? anyish(iLa>=0?c[iLa]:"") : anyish(iRa>=0?c[iRa]:""),
      proto, dstPort:port, dataService:guessService(port,proto),
      direction: inbound?"Inbound":"Outbound",
      status: /allow/i.test(iAct>=0?c[iAct]:"allow")?"Permitted by rule":"Denied by rule",
      origin:"firewall-rule", collector:coll, isaRef:iName>=0?c[iName]:"",
      notes:"Windows Firewall rule"+(iName>=0&&c[iName]?" '"+c[iName]+"'":"")
    }));
  });
  return {rows, note: rows.length?("Windows Firewall rules: "+rows.length+" entries"):""};
}

/* Does this address fall inside a rule's scope? A blank or "any" scope
   matches anything, which is what a rule with no source means. */
function ipInScope(ip, scope){
  if(!scope || /^any$/i.test(scope)) return true;
  if(!ip) return false;
  if(isCidr(scope)) return inCidr(ip, scope);
  return ip===scope;
}

/* ---------------- cross-referencing the sources ----------------
   A ruleset knows what is permitted but not who used it. Traffic knows who
   but not what authorises it. Reading them against each other fills both
   gaps, which is the difference between a pile of rows and a register. */
function crossReference(rows){
  rows = rows || ROWS;
  const isRule = r => String(r.origin||"").indexOf("firewall-rule")>=0;
  const rules = rows.filter(isRule);
  const seen  = rows.filter(r=>!isRule(r));
  let filledSrc=0, filledPort=0, filledRef=0, confirmed=0, filledHost=0;
  const touched=new Set();

  /* observed traffic, indexed by the service it reached */
  const byService = new Map();
  seen.forEach(r=>{
    if(!r.dstPort) return;
    const k=(r.proto||"").toUpperCase()+"|"+r.dstPort;
    if(!byService.has(k)) byService.set(k,[]);
    byService.get(k).push(r);
  });

  /* 0. a policy that names objects instead of addresses: resolve them now
     that every name source has been read */
  rules.forEach(r=>{
    if(!r.dest && r.dstObj){ const ip=resolveNetObject(r.dstObj);
      if(ip){ r.dest=ip; r.notes=String(r.notes||"").replace(/ · destination object '[^']*' not resolved to an address/,"");
              touched.add(r); filledSrc++; } }
    if(!r.src && r.srcObj){ const ip=resolveNetObject(r.srcObj);
      if(ip){ r.src=ip; r.notes=String(r.notes||"").replace(/ · source object '[^']*' not resolved to an address/,"");
              touched.add(r); filledSrc++; } }
  });

  /* 1. rules gain the hosts and ports that actually used them */
  rules.forEach(rule=>{
    if(!rule.dstPort) return;
    const cand=(byService.get((rule.proto||"").toUpperCase()+"|"+rule.dstPort)||[])
      .filter(o => ipInScope(o.dest, rule.dest) && ipInScope(o.src, rule.src));
    if(!cand.length) return;

    confirmed++;
    if(!/seen in traffic/.test(rule.notes||"")){
      const hosts=[...new Set(cand.map(o=>o.srcHost||o.src).filter(Boolean))];
      rule.notes=(rule.notes?rule.notes+" · ":"")+"seen in traffic from "+
        (hosts.length?hosts.slice(0,3).join(", ")+(hosts.length>3?" +"+(hosts.length-3):""):cand.length+" source(s)");
    }
    // a rule written against a network gets the one host that used it, where
    // there is only one; several sources stay as the network, which is honest
    const srcs=[...new Set(cand.map(o=>o.src).filter(Boolean))];
    const srcHosts=[...new Set(cand.map(o=>o.srcHost).filter(Boolean))];
    if(srcs.length===1 && (!rule.src || isCidr(rule.src))){
      if(!isCidr(rule.src) || inCidr(srcs[0], rule.src)){
        rule.src=srcs[0]; filledSrc++; touched.add(rule);
      }
    }
    if(srcHosts.length===1 && !rule.srcHost){ rule.srcHost=srcHosts[0]; filledHost++; }
    if(!rule.dstHost){
      const dh=[...new Set(cand.map(o=>o.dstHost).filter(Boolean))];
      if(dh.length===1){ rule.dstHost=dh[0]; filledHost++; }
    }
    if(!rule.dest){
      const dd=[...new Set(cand.map(o=>o.dest).filter(Boolean))];
      if(dd.length===1){ rule.dest=dd[0]; filledSrc++; touched.add(rule); }
    }
    if(!rule.srcPort){
      const sp=[...new Set(cand.map(o=>o.srcPort).filter(Boolean))];
      rule.srcPort = sp.length===1 ? sp[0] : (CFG.ephemeralRange||"1024-65535");
      filledPort++;
    }
    if(!rule.pkts){
      const tot=cand.reduce((a,o)=>a+(+o.pkts||0),0);
      if(tot) rule.pkts=String(tot);
    }
  });

  /* 1b. A discovered listening service and an observed flow to that same
     service are one registration, not two. The listener knows the banner and
     the version; the flow knows who used it. Fold the listener into the flow
     and drop the leftover. */
  const absorbed=[];
  seen.forEach(l=>{
    if(l.src || l.srcHost) return;                 // not a bare listener
    if(!l.dest || !l.dstPort) return;
    const match=seen.filter(o=>o!==l && o.src &&
      (o.proto||"").toUpperCase()===(l.proto||"").toUpperCase() &&
      o.dstPort===l.dstPort && o.dest===l.dest);
    if(!match.length) return;
    match.forEach(o=>{
      if(!o.banner && l.banner) o.banner=l.banner;
      if(!o.dataService && l.dataService) o.dataService=l.dataService;
      if(!o.dstHost && l.dstHost) o.dstHost=l.dstHost;
      /* A product named by the scan beats one derived from the service name,
         which is only ever a restatement of it. */
      if(l.appName && (!o.appName || o.appName===o.dataService)) o.appName=l.appName;
      if(l.banner && (!o.banner || o.banner===o.dataService)) o.banner=l.banner;
      // what the scan established about the service travels with it
      String(l.notes||"").split(" · ").filter(Boolean).forEach(n=>{
        if(String(o.notes||"").indexOf(n)<0) o.notes=o.notes?o.notes+" · "+n:n;
      });
      const tools=new Set(String(o.origin||"").split(/,\s*/).filter(Boolean));
      String(l.origin||"").split(/,\s*/).filter(Boolean).forEach(t=>tools.add(t));
      o.origin=[...tools].join(", ");
      touched.add(o);
    });
    absorbed.push(l);
  });
  if(absorbed.length){
    const drop=new Set(absorbed);
    for(let i=ROWS.length-1;i>=0;i--) if(drop.has(ROWS[i])) ROWS.splice(i,1);
  }

  /* 2. observed traffic gains the rule that authorises it */
  seen.forEach(o=>{
    if(!o.dstPort) return;
    const match=rules.filter(rule=>
      (rule.proto||"").toUpperCase()===(o.proto||"").toUpperCase() &&
      rule.dstPort===o.dstPort &&
      /^Permitted/.test(rule.status||"") &&
      ipInScope(o.dest, rule.dest) && ipInScope(o.src, rule.src));
    if(!match.length) return;
    const ref=[...new Set(match.map(m=>m.isaRef).filter(Boolean))];
    if(ref.length && !o.isaRef){ o.isaRef=ref.join(", "); filledRef++; }
    if(!/permitted by/i.test(o.notes||"") && ref.length)
      o.notes=(o.notes?o.notes+" · ":"")+"permitted by "+ref.slice(0,2).join(", ");
    if(!o.dstHost){
      const dh=[...new Set(match.map(m=>m.dstHost).filter(Boolean))];
      if(dh.length===1){ o.dstHost=dh[0]; filledHost++; }
    }
  });

  /* 3. hostnames learned anywhere apply everywhere */
  rows.forEach(r=>{
    if(r.src && !r.srcHost && HOSTMAP.has(r.src)){ r.srcHost=HOSTMAP.get(r.src).name; filledHost++; }
    if(r.dest && !r.dstHost && HOSTMAP.has(r.dest)){ r.dstHost=HOSTMAP.get(r.dest).name; filledHost++; }
  });

  /* Anything derived from an endpoint has to be redone once that endpoint
     changes, or the register keeps the value it worked out from the gap. */
  let redone=0;
  touched.forEach(r=>{
    const enc=deriveEnclave(r);
    if(enc && enc!==r.enclave){ r.enclave=enc; redone++; }
    const b=deriveBoundary(r);
    if(b && b!==r.boundary){ r.boundary=b; redone++; }
    r.subPath   = submissionPath(r.boundary) || r.subPath;
    r.emassType = deriveType(r) || r.emassType;
    const sp=derivePoint(r.src, r.srcZone); if(sp) r.srcPoint=sp;
    const dp=derivePoint(r.dest, r.dstZone); if(dp) r.dstPoint=dp;
  });

  return {filledSrc, filledPort, filledRef, filledHost, confirmed, redone,
          absorbed:absorbed.length};
}

/* ---------------- rule vs traffic reconciliation ----------------
   The point of reading rules alongside traffic: a permitted flow nobody
   uses is a rule to remove, and an observed flow with no rule behind it
   is either shadow IT or a rule you have not collected. */
/* ---------------- rule coverage ----------------
   Matches every observed flow against every permit rule on all four of
   source scope, destination scope, protocol and port (single, range,
   list, or blank for any) — not just the port, which made any 443 rule
   anywhere "cover" every HTTPS flow. The result drives the review checks
   and the Coverage Report. */
function portInSpec(port, spec){
  const p=+port; if(!spec) return true;             // blank = any port
  if(!(p>0)) return false;
  return String(spec).split(/[;,]/).some(x=>{
    x=x.trim(); if(!x) return false;
    const m=x.match(/^(\d+)\s*-\s*(\d+)$/);
    if(m) return p>=+m[1] && p<=+m[2];
    return +x===p;
  });
}
function protoMatches(flowProto, ruleProto){
  const r=(ruleProto||"").toUpperCase(), f=(flowProto||"").toUpperCase();
  return !r || r==="IP" || r==="ANY" || !f || r===f;
}
function endpointInScope(ip, host, scope){
  if(!scope || /^any$/i.test(scope)) return true;
  if(ipInScope(ip, scope)) return true;
  // a rule written against a hostname or object name
  const sc=String(scope).toLowerCase().replace(/\.+$/,"");
  if(host && String(host).toLowerCase().replace(/\.+$/,"")===sc) return true;
  if(ip && typeof HOSTMAP!=="undefined" && HOSTMAP.has(ip)){
    const n=String(HOSTMAP.get(ip).name||"").toLowerCase().replace(/\.+$/,"");
    if(n && (n===sc || n.split(".")[0]===sc)) return true;
  }
  return false;
}
function ruleCovers(rule, flow){
  return protoMatches(flow.proto, rule.proto) &&
         portInSpec(flow.dstPort, rule.dstPort) &&
         endpointInScope(flow.src,  flow.srcHost, rule.src) &&
         endpointInScope(flow.dest, flow.dstHost, rule.dest);
}
function coverageReport(rows){
  rows = rows || ROWS;
  const isRule = r => String(r.origin||"").indexOf("firewall-rule")>=0 || /by rule$/.test(r.status||"");
  const rules=rows.filter(isRule), observed=rows.filter(r=>!isRule(r));
  const permits=rules.filter(r=>!/^Denied/.test(r.status||""));
  const denies =rules.filter(r=> /^Denied/.test(r.status||""));
  const used=new Map();                       // rule -> flows it covered
  const flows=[];
  observed.forEach(f=>{
    // a consolidated row carries several ports; every one must be covered
    const ports=String(f.dstPort||"").split(/[;,]/).map(x=>x.trim()).filter(Boolean);
    if(!ports.length){ flows.push({row:f, status:"no port", by:[]}); return; }
    const by=new Set(); let uncovered=[];
    ports.forEach(pt=>{
      const probe={...f, dstPort:pt};
      const hits=permits.filter(r=>ruleCovers(r,probe));
      if(!hits.length) uncovered.push(pt);
      hits.forEach(r=>{ by.add(r); if(!used.has(r)) used.set(r,new Set()); used.get(r).add(f); });
    });
    const deniedBy=denies.filter(r=>ports.some(pt=>ruleCovers(r,{...f,dstPort:pt})));
    let status = uncovered.length ? (uncovered.length===ports.length ? "no rule" : "partly covered") : "covered";
    if(uncovered.length && deniedBy.length) status="denied but seen";
    flows.push({row:f, status, by:[...by], deniedBy, uncovered});
  });
  const ruleRows=permits.map(r=>({row:r, flows:used.has(r)?used.get(r).size:0,
                                   status: used.has(r) ? "used" : "unused"}));
  const n=k=>flows.filter(x=>x.status===k).length;
  return {
    flows, rules: ruleRows,
    observed: observed.length, ruled: rules.length, permits: permits.length, denies: denies.length,
    covered: n("covered"), partly: n("partly covered"), noRule: n("no rule"), deniedSeen: n("denied but seen"),
    unusedRules: ruleRows.filter(x=>x.status==="unused" && x.row.dstPort).map(x=>x.row),
    unauthorised: flows.filter(x=>x.status==="no rule"||x.status==="denied but seen"||x.status==="partly covered").map(x=>x.row)
  };
}
/* Kept for the review checks and the self-tests; now scope-aware. */
function ruleTrafficReview(rows){
  const c=coverageReport(rows);
  return {observed:c.observed, ruled:c.ruled,
          unusedRules: c.permits ? c.unusedRules : [],
          unauthorised: c.permits ? c.unauthorised : []};
}

function renderCoverage(){
  const host=$("covBody"); if(!host) return;
  const c=coverageReport(ROWS);
  if(!c.ruled || !c.observed){
    host.innerHTML='<div class="dg-empty">Needs both a ruleset (ACL / policy export) and observed traffic in the register.</div>';
    if($("covSummary")) $("covSummary").innerHTML=""; return;
  }
  const pct=c.observed?Math.round(100*c.covered/c.observed):0;
  $("covSummary").innerHTML=
    `<span class="ep-pill"><b>${c.observed}</b> flows · <b>${c.permits}</b> permit rules</span>`+
    `<span class="ep-pill ${pct===100?"ok":""}"><b>${pct}%</b> of flows covered</span>`+
    `<span class="ep-pill ${c.noRule?"warn":"ok"}"><b>${c.noRule}</b> with no rule</span>`+
    (c.partly?`<span class="ep-pill warn"><b>${c.partly}</b> partly covered</span>`:"")+
    (c.deniedSeen?`<span class="ep-pill warn"><b>${c.deniedSeen}</b> denied but seen</span>`:"")+
    `<span class="ep-pill ${c.unusedRules.length?"":"ok"}"><b>${c.unusedRules.length}</b> rules nobody used</span>`;
  const row=(x)=>`<tr><td>${esc(x.status)}</td><td>${esc(x.row.srcHost||x.row.src||"any")}</td><td>${esc(x.row.dstHost||x.row.dest||"any")}</td><td>${esc(x.row.proto)}</td><td>${esc(x.row.dstPort)}</td><td>${esc(x.row.dataService)}</td><td>${esc(x.by?x.by.map(r=>r.isaRef||"(unnamed)").join("; "):(x.row.isaRef||""))}</td></tr>`;
  const bad=c.flows.filter(x=>x.status!=="covered").slice(0,200);
  const unused=c.rules.filter(x=>x.status==="unused").slice(0,200);
  host.innerHTML=
    `<h4 style="margin:8px 0 4px">Flows without a permitting rule ${bad.length?"("+bad.length+(c.flows.length-c.covered>200?" of "+(c.flows.length-c.covered):"")+")":"— none"}</h4>`+
    (bad.length?`<table class="dg"><thead><tr><th>Status</th><th>Source</th><th>Destination</th><th>Proto</th><th>Port</th><th>Service</th><th>Rule(s)</th></tr></thead><tbody>${bad.map(row).join("")}</tbody></table>`:"")+
    `<h4 style="margin:14px 0 4px">Permit rules no flow used ${unused.length?"("+unused.length+")":"— none"}</h4>`+
    (unused.length?`<table class="dg"><thead><tr><th>Status</th><th>Source</th><th>Destination</th><th>Proto</th><th>Port</th><th>Service</th><th>Rule</th></tr></thead><tbody>${unused.map(x=>row({...x,by:null})).join("")}</tbody></table>`:"");
}
function exportCoverageCsv(){
  const c=coverageReport(ROWS);
  if(!c.ruled || !c.observed) return flash("Coverage needs both a ruleset and observed traffic in the register.","warn");
  const H=["Kind","Status","Source","Source Host","Destination","Destination Host","Protocol","Port","Data Service","Rule(s)","Flows matched","Uncovered ports","Notes"];
  const lines=[H.map(csvCell).join(",")];
  c.flows.forEach(x=>lines.push(["Flow",x.status,x.row.src,x.row.srcHost,x.row.dest,x.row.dstHost,x.row.proto,x.row.dstPort,x.row.dataService,
    x.by.map(r=>r.isaRef||"(unnamed)").join("; ")+(x.deniedBy&&x.deniedBy.length?" · denied by "+x.deniedBy.map(r=>r.isaRef||"(unnamed)").join("; "):""),
    "", (x.uncovered||[]).join("; "), x.row.notes].map(v=>csvCell(asciiSafe(v))).join(",")));
  c.rules.forEach(x=>lines.push(["Rule",x.status,x.row.src||"any",x.row.srcHost,x.row.dest||"any",x.row.dstHost,x.row.proto||"any",x.row.dstPort||"any",x.row.dataService,
    x.row.isaRef, String(x.flows), "", x.row.notes].map(v=>csvCell(asciiSafe(v))).join(",")));
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-rule-coverage.csv","﻿"+lines.join("\r\n"),"text/csv;charset=utf-8");
  flash("Coverage report: "+c.flows.length+" flows, "+c.rules.length+" permit rules.","ok");
}

/* ---------------- register diff ----------------
   Last quarter's register beside this run. Both sides are exploded into
   atomic flows (one source, one destination, one port) so a consolidated
   "80; 443" row in the old file compares with two rows here. A flow is
   the same registration when source, destination, protocol and port
   match (same normalisation as Dedupe). Then:
     Added    — in the current register, not the previous
     Removed  — in the previous register, not the current
     Changed  — in both, but a tracked field differs
   Rules (firewall-rule rows) are left out; they are evidence, not entries. */
const DIFF_FIELDS=[["dataService","Data Service"],["boundary","Boundary"],["direction","Direction"],
  ["emassType","Type"],["appName","Application"],["vpn","VPN Traffic"],["justification","Purpose"],
  ["srcHost","Source Hostname"],["dstHost","Destination Hostname"]];
function explodeFlows(rows){
  const nz = v => String(v==null?"":v).trim().toLowerCase().replace(/\.+$/,"");
  const lst= v => String(v==null?"":v).split(/[;,]/).map(x=>x.trim()).filter(Boolean);
  const out=new Map();
  rows.forEach(r=>{
    if(String(r.origin||"").indexOf("firewall-rule")>=0 || /by rule$/.test(r.status||"")) return;
    const srcs=lst(r.src).length?lst(r.src):(lst(r.srcHost).length?lst(r.srcHost):[""]);
    const dsts=lst(r.dest).length?lst(r.dest):(lst(r.dstHost).length?lst(r.dstHost):[""]);
    const ports=lst(r.dstPort).length?lst(r.dstPort):[""];
    const svcs=lst(r.dataService);
    srcs.forEach(sv=>dsts.forEach(dv=>ports.forEach((pt,i)=>{
      const k=[nz(sv),nz(dv),nz(r.proto),nz(pt)].join("|");
      if(out.has(k)) return;
      out.set(k,{key:k, src:sv, dest:dv, proto:r.proto, port:pt,
        dataService: svcs.length>1 ? (svcs[i]||svcs[0]) : (r.dataService||""), row:r});
    })));
  });
  return out;
}
function diffRegisters(previous, current){
  const P=explodeFlows(previous), C=explodeFlows(current||ROWS);
  const added=[], removed=[], changed=[], same=[];
  const nz=v=>String(v==null?"":v).trim().toLowerCase();
  C.forEach((c,k)=>{
    const p=P.get(k);
    if(!p){ added.push(c); return; }
    const diffs=[];
    DIFF_FIELDS.forEach(([f,label])=>{
      const a = f==="dataService" ? p.dataService : p.row[f];
      const b = f==="dataService" ? c.dataService : c.row[f];
      const na = f==="dataService" ? nz(serviceDisplayName(a)) : (f==="boundary" ? nz(bndCode(a)||a) : nz(a));
      const nb = f==="dataService" ? nz(serviceDisplayName(b)) : (f==="boundary" ? nz(bndCode(b)||b) : nz(b));
      if(!na && !nb) return;
      // a blank on one side is a change only for the fields that define the
      // registration; derived fields (Type, Application, VPN, Purpose, names)
      // are filled at Finish and would otherwise show as noise
      if(!na || !nb){ if(f==="dataService"||f==="boundary"||f==="direction") diffs.push({field:label, previous:a||"", current:b||""}); return; }
      if(na!==nb) diffs.push({field:label, previous:a, current:b});
    });
    if(diffs.length) changed.push({...c, previous:p, diffs}); else same.push({...c, previous:p});
  });
  P.forEach((p,k)=>{ if(!C.has(k)) removed.push(p); });
  const byPort=(a,b)=>(a.dest||"").localeCompare(b.dest||"")||(+a.port||0)-(+b.port||0);
  return {added:added.sort(byPort), removed:removed.sort(byPort), changed:changed.sort(byPort), same,
          previousCount:P.size, currentCount:C.size};
}
let LAST_DIFF=null;
function renderDiff(d, label){
  const host=$("diffBody"); if(!host) return;
  LAST_DIFF=d;
  $("diffSummary").innerHTML=
    `<span class="ep-pill">previous <b>${d.previousCount}</b> · current <b>${d.currentCount}</b> flows</span>`+
    `<span class="ep-pill ${d.added.length?"warn":"ok"}"><b>${d.added.length}</b> added</span>`+
    `<span class="ep-pill ${d.removed.length?"warn":"ok"}"><b>${d.removed.length}</b> removed</span>`+
    `<span class="ep-pill ${d.changed.length?"":"ok"}"><b>${d.changed.length}</b> changed</span>`+
    `<span class="ep-pill ok"><b>${d.same.length}</b> unchanged</span>`;
  const tr=(kind,x,extra)=>`<tr><td>${kind}</td><td>${esc(x.src||"")}</td><td>${esc(x.dest||"")}</td><td>${esc(x.proto||"")}</td><td>${esc(x.port||"")}</td><td>${esc(x.dataService||"")}</td><td>${extra||""}</td></tr>`;
  const cap=a=>a.slice(0,300);
  const sec=(title,rows,fn)=>`<h4 style="margin:12px 0 4px">${title} ${rows.length?"("+rows.length+")":"— none"}</h4>`+
    (rows.length?`<table class="dg"><thead><tr><th>Change</th><th>Source</th><th>Destination</th><th>Proto</th><th>Port</th><th>Service</th><th>Detail</th></tr></thead><tbody>${cap(rows).map(fn).join("")}</tbody></table>`:"");
  host.innerHTML=
    `<p class="hint" style="margin:0 0 6px">Compared with: ${esc(label||"previous register")}</p>`+
    sec("Added since the previous register", d.added, x=>tr("Added",x,esc(x.row.origin||"")))+
    sec("Removed — in the previous register, not seen now", d.removed, x=>tr("Removed",x,esc(x.row.status||"")))+
    sec("Changed", d.changed, x=>tr("Changed",x,x.diffs.map(f=>`<b>${esc(f.field)}</b>: ${esc(f.previous||"(blank)")} → ${esc(f.current||"(blank)")}`).join("<br>")));
}
function exportDiffCsv(){
  const d=LAST_DIFF; if(!d) return flash("Load a previous register first.","warn");
  const H=["Change","Source","Destination","Protocol","Port","Data Service","Field","Previous","Current","Origin"];
  const lines=[H.map(csvCell).join(",")];
  const put=(kind,x,field,prev,cur)=>lines.push([kind,x.src,x.dest,x.proto,x.port,x.dataService,field,prev,cur,x.row.origin||x.row.status||""].map(v=>csvCell(asciiSafe(v))).join(","));
  d.added.forEach(x=>put("Added",x,"","",""));
  d.removed.forEach(x=>put("Removed",x,"","",""));
  d.changed.forEach(x=>x.diffs.forEach(f=>put("Changed",x,f.field,f.previous,f.current)));
  const m=meta();
  download(((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-register-diff.csv","﻿"+lines.join("\r\n"),"text/csv;charset=utf-8");
}
/* Mark current rows that the previous register already carried as
   Registered, so the new submission is the delta. */
function applyDiffStatus(){
  const d=LAST_DIFF; if(!d) return flash("Load a previous register first.","warn");
  const seen=new Set(); let n=0;
  d.same.concat(d.changed).forEach(x=>{ if(!seen.has(x.row)){ seen.add(x.row); if(x.row.status!=="Registered"){ x.row.status="Registered"; n++; } } });
  d.added.forEach(x=>{ if(x.row.status==="Registered"){ x.row.status="New"; n++; } });
  render(); flash(n+" row"+(n===1?"":"s")+" re-marked from the previous register.","ok");
}
function loadPreviousRegister(files){
  const arr=[...files]; if(!arr.length) return;
  DIFF_CAPTURE={rows:[], kinds:[], done:(rows,kinds)=>{
    if(!rows.length){ flash("No register entries could be read from that file.","warn"); return; }
    renderDiff(diffRegisters(rows, ROWS), arr.map(f=>f.name).join(", ")+" ("+[...new Set(kinds)].join(", ")+")");
    flash("Compared "+rows.length+" previous entries with the current register.","ok");
  }};
  handleFiles(arr);
}
