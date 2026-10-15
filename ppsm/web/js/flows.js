"use strict";
/* ============================================================
   PCAP / PCAPNG BINARY PARSER
   Handles: classic libpcap (us + ns), pcapng, gzip-less only.
   Link types: Ethernet, Raw IPv4/IPv6, Null/Loopback, Linux SLL/SLL2.
   Produces aggregated flows (4-tuple) with packet/byte counts.
   ============================================================ */

const IPPROTO = {1:"ICMP",2:"IGMP",6:"TCP",17:"UDP",41:"IPv6",47:"GRE",50:"ESP",51:"AH",
  58:"ICMPv6",89:"OSPF",103:"PIM",112:"VRRP",132:"SCTP"};

function isPcapMagic(b){
  if(!b || b.length<4) return false;
  const m = (b[0]<<24>>>0)|(b[1]<<16)|(b[2]<<8)|b[3];
  const u = m>>>0;
  return u===0xa1b2c3d4 || u===0xd4c3b2a1 || u===0xa1b23c4d || u===0x4d3cb2a1 || u===0x0a0d0d0a;
}

function pcapOpts(){
  return {
    minPkts: Math.max(1, +(CFG.pcapMinPkts||1)),
    icmp: !!CFG.pcapIcmp,
    other: !!CFG.pcapOtherProto,
    dropMcast: !!CFG.pcapDropMulticast,
    maxPkts: Math.max(1000, +(CFG.pcapMaxPackets||500000))
  };
}

function parsePcapBuffer(buf, fname){
  const b = new Uint8Array(buf);
  if(b.length<24) return {rows:[], note:"file too small to be a capture"};
  const m = ((b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3])>>>0;
  try{
    if(m===0x0a0d0d0a) return parsePcapNg(b);
    if(m===0xa1b2c3d4) return parsePcapClassic(b,false);
    if(m===0xa1b23c4d) return parsePcapClassic(b,false);
    if(m===0xd4c3b2a1) return parsePcapClassic(b,true);
    if(m===0x4d3cb2a1) return parsePcapClassic(b,true);
  }catch(e){ return {rows:[], note:"capture parse error: "+e.message}; }
  return {rows:[], note:"not a recognized pcap/pcapng file"};
}

function rd32(b,o,le){ return le ? (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0
                                 : ((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3])>>>0; }
function rd16(b,o,le){ return le ? (b[o]|(b[o+1]<<8)) : ((b[o]<<8)|b[o+1]); }

function parsePcapClassic(b, le){
  const linktype = rd32(b,20,le);
  const acc = newFlowAcc();
  const o = pcapOpts();
  let off=24, n=0;
  while(off+16<=b.length && n<o.maxPkts){
    const incl = rd32(b,off+8,le);
    if(incl<0 || off+16+incl > b.length) break;
    handlePacket(b, off+16, incl, linktype, acc, o);
    off += 16+incl; n++;
  }
  return finishFlows(acc, o, "pcap", n, linktype);
}

function parsePcapNg(b){
  const acc = newFlowAcc();
  const o = pcapOpts();
  let off=0, le=true, n=0;
  const ifLink=[];       // interface_id -> linktype
  while(off+12<=b.length && n<o.maxPkts){
    // determine endianness from each SHB
    const rawType = rd32(b,off,true);
    let type, tlen;
    if(rawType===0x0A0D0D0A){
      const bom = rd32(b,off+8,true);
      le = (bom>>>0)===0x1A2B3C4D;
      type=0x0A0D0D0A; tlen=rd32(b,off+4,le);
      ifLink.length=0;
    } else {
      type = rd32(b,off,le); tlen = rd32(b,off+4,le);
    }
    if(tlen<12 || off+tlen>b.length) break;
    if(type===0x00000001){                              // IDB
      ifLink.push(rd16(b,off+8,le));
    } else if(type===0x00000006){                       // EPB
      const iface = rd32(b,off+8,le);
      const cap   = rd32(b,off+20,le);
      const dstart= off+28;
      if(dstart+cap<=b.length){
        handlePacket(b,dstart,cap, ifLink[iface]!=null?ifLink[iface]:1, acc, o); n++;
      }
    } else if(type===0x00000003){                       // SPB
      const dstart = off+12;
      const cap = Math.min(rd32(b,off+8,le), tlen-16);
      if(cap>0 && dstart+cap<=b.length){
        handlePacket(b,dstart,cap, ifLink[0]!=null?ifLink[0]:1, acc, o); n++;
      }
    }
    off += tlen;
  }
  return finishFlows(acc, o, "pcapng", n, ifLink[0]);
}

/* ---- link-layer -> IP ---- */
function handlePacket(b, off, len, linktype, acc, o){
  const end = off+len;
  let p = off, ethertype = null;
  switch(linktype){
    case 1: {                                            // Ethernet
      if(p+14>end) return;
      ethertype = rd16(b,p+12,false); p+=14;
      while(ethertype===0x8100 || ethertype===0x88a8 || ethertype===0x9100){  // VLAN tags
        if(p+4>end) return;
        ethertype = rd16(b,p+2,false); p+=4;
      }
      if(ethertype===0x0800) return ipv4(b,p,end,acc,o);
      if(ethertype===0x86DD) return ipv6(b,p,end,acc,o);
      return;
    }
    case 0: {                                            // NULL / loopback
      if(p+4>end) return;
      const fam = b[p] | (b[p+1]<<8) | (b[p+2]<<16) | (b[p+3]<<24);
      const f = (fam===2||fam===0x02000000)?2:((fam===24||fam===28||fam===30)?24:0);
      p+=4;
      if(f===2) return ipv4(b,p,end,acc,o);
      if(f===24) return ipv6(b,p,end,acc,o);
      return ipAuto(b,p,end,acc,o);
    }
    case 101: case 12: case 14:                          // RAW IP
      return ipAuto(b,p,end,acc,o);
    case 228: return ipv4(b,p,end,acc,o);
    case 229: return ipv6(b,p,end,acc,o);
    case 113: {                                          // Linux SLL
      if(p+16>end) return;
      ethertype = rd16(b,p+14,false); p+=16;
      if(ethertype===0x0800) return ipv4(b,p,end,acc,o);
      if(ethertype===0x86DD) return ipv6(b,p,end,acc,o);
      return;
    }
    case 276: {                                          // Linux SLL2
      if(p+20>end) return;
      ethertype = rd16(b,p,false); p+=20;
      if(ethertype===0x0800) return ipv4(b,p,end,acc,o);
      if(ethertype===0x86DD) return ipv6(b,p,end,acc,o);
      return;
    }
    default:
      return ipAuto(b,p,end,acc,o);
  }
}

function ipAuto(b,p,end,acc,o){
  if(p>=end) return;
  const v = b[p]>>4;
  if(v===4) return ipv4(b,p,end,acc,o);
  if(v===6) return ipv6(b,p,end,acc,o);
}

function ip4str(b,o){ return b[o]+"."+b[o+1]+"."+b[o+2]+"."+b[o+3]; }
function ip6str(b,o){
  const parts=[];
  for(let i=0;i<8;i++) parts.push(((b[o+i*2]<<8)|b[o+i*2+1]).toString(16));
  let s=parts.join(":");
  s=s.replace(/(^|:)(0:){2,}/, m=>"::").replace(/:{3,}/,"::");
  return s;
}

function ipv4(b,p,end,acc,o){
  if(p+20>end) return;
  const ihl=(b[p]&0x0f)*4; if(ihl<20) return;
  const total=rd16(b,p+2,false);
  const proto=b[p+9];
  const src=ip4str(b,p+12), dst=ip4str(b,p+16);
  const L=p+ihl;
  transport(proto,b,L,end,src,dst,total||(end-p),acc,o);
}

function ipv6(b,p,end,acc,o){
  if(p+40>end) return;
  let next=b[p+6];
  const plen=rd16(b,p+4,false);
  const src=ip6str(b,p+8), dst=ip6str(b,p+24);
  let L=p+40, guard=0;
  const EXT={0:1,43:1,44:1,60:1,51:1,50:0};
  while(EXT[next]===1 && L+8<=end && guard++<8){
    const nh=b[L], hlen=(b[L+1]+1)*8;
    next=nh; L+=hlen;
  }
  transport(next,b,L,end,src,dst,plen+40,acc,o);
}

function transport(proto,b,L,end,src,dst,bytes,acc,o){
  const pname = IPPROTO[proto] || ("IP-"+proto);
  if(o.dropMcast && (/^(224\.|239\.|255\.255|ff0)/i.test(dst) || dst==="255.255.255.255")) return;
  if(proto===6 && L+14<=end){
    const sp=rd16(b,L,false), dp=rd16(b,L+2,false), flags=b[L+13];
    const syn=!!(flags&0x02), ack=!!(flags&0x10);
    addFlow(acc,"TCP",src,dst,sp,dp,bytes,{syn,ack});
  } else if(proto===17 && L+8<=end){
    const sp=rd16(b,L,false), dp=rd16(b,L+2,false);
    addFlow(acc,"UDP",src,dst,sp,dp,bytes,{});
  } else if((proto===1||proto===58) && o.icmp && L+2<=end){
    addFlow(acc,pname,src,dst,"", "type"+b[L], bytes,{icmp:true});
  } else if(o.other && proto!==1 && proto!==58){
    addFlow(acc,pname,src,dst,"","",bytes,{noport:true});
  }
}

/* ---- flow accumulation ---- */
function newFlowAcc(){ return {map:new Map()}; }

function addFlow(acc,proto,src,dst,sp,dp,bytes,fl){
  // canonical key ignores direction so both halves of a conversation merge
  const a = src+"|"+sp, z = dst+"|"+dp;
  const key = proto+"|"+(a<z ? a+"|"+z : z+"|"+a);
  let f = acc.map.get(key);
  if(!f){
    f = {proto, aIP:src, aPort:sp, zIP:dst, zPort:dp, pkts:0, bytes:0,
         synFrom:null, icmp:!!fl.icmp, noport:!!fl.noport};
    acc.map.set(key,f);
  }
  f.pkts++; f.bytes += bytes||0;
  if(fl.syn && !fl.ack && f.synFrom===null) f.synFrom = src+"|"+sp;   // client side identified
}

function finishFlows(acc, o, kind, pktCount, linktype){
  const rows=[];
  const coll = ($("impCollector") && $("impCollector").value.trim()) || "";
  acc.map.forEach(f=>{
    if(f.pkts < o.minPkts) return;
    let cIP,cPort,sIP,sPort;
    if(f.synFrom){
      const [ip,pt]=f.synFrom.split("|");
      if(ip===f.aIP && String(pt)===String(f.aPort)){ cIP=f.aIP;cPort=f.aPort;sIP=f.zIP;sPort=f.zPort; }
      else { cIP=f.zIP;cPort=f.zPort;sIP=f.aIP;sPort=f.aPort; }
    } else {
      const pick = orientPorts(f.aPort, f.zPort);
      if(pick==="a"){ cIP=f.zIP;cPort=f.zPort;sIP=f.aIP;sPort=f.aPort; }
      else          { cIP=f.aIP;cPort=f.aPort;sIP=f.zIP;sPort=f.zPort; }
    }
    rows.push(blank({
      src:cIP, dest:sIP, proto:f.proto,
      srcPort:f.noport||f.icmp?"":String(cPort),
      dstPort:f.icmp?String(sPort):(f.noport?"":String(sPort)),
      dataService: f.icmp?"icmp":(f.noport?f.proto.toLowerCase():guessService(sPort,f.proto)),
      direction:"Bidirectional", status:"New", origin:kind,
      collector: coll,
      pkts:String(f.pkts), bytes:String(f.bytes)
    }));
  });
  rows.sort((x,y)=>(+y.bytes||0)-(+x.bytes||0));
  const lt = linktype!=null ? (" · linktype "+linktype) : "";
  return {rows, note: pktCount+" packets read"+lt+" · "+rows.length+" unique flows"};
}

// which side is the server? returns "a" if aPort is the service port
function orientPorts(ap, zp){
  const a=+ap, z=+zp;
  const known=p=>(guessService(p)!=="")||(p>0&&p<(+CFG.wellKnownMax||1024));
  if(known(a)&&!known(z)) return "a";
  if(known(z)&&!known(a)) return "z";
  return a<=z ? "a" : "z";
}

/* ============================================================
   ADDITIONAL TEXT PARSERS
   show conn (ASA/FTD) · NetFlow cache (IOS-XE) · Zeek conn.log
   Windows Firewall log · tcpdump/tshark text · ASA syslog · pktmon
   ============================================================ */

/* ---- field validation ----
   Anything that reaches a register row has to actually look like network
   data. Without these guards a prose file parses as flows. */
function validPort(p){
  if(p===""||p==null) return false;
  const s=String(p).trim();
  if(!/^\d{1,5}$/.test(s)) return false;
  const n=+s;
  return n>=0 && n<=65535;
}
function validProto(p){
  return /^(tcp|udp|icmp|icmpv6|sctp|gre|esp|ah|igmp|ospf|pim|vrrp|ipv6|ip-\d+)$/i
    .test(String(p||"").trim());
}
function validEndpoint(v){
  if(!v) return false;
  const s=String(v).trim();
  if(s==="-"||s==="?") return false;
  if(/^any$/i.test(s)) return true;                 // rules legitimately say "any"
  if(/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s)) return true;   // a network
  if(isIP(s)) return true;
  // a hostname is acceptable, but it has to look like one
  return /^[A-Za-z0-9]([A-Za-z0-9\-_]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-_]*[A-Za-z0-9])?)+$/.test(s);
}
/* Both endpoints and at least one usable port, with a real protocol. */
function validFlowFields(src,dst,sp,dp,proto){
  if(!validEndpoint(src) || !validEndpoint(dst)) return false;
  if(!validProto(proto)) return false;
  if(!validPort(sp) && !validPort(dp)) return false;
  return true;
}
/* Last line of defence, applied to every parsed row before it is kept. */
function rowLooksReal(r){
  const isRule = String(r.origin||"").indexOf("firewall-rule")>=0 ||
                 String(r.origin||"").indexOf("win-connections")>=0;
  const hasEnd = validEndpoint(r.src) || validEndpoint(r.dest) || r.srcHost || r.dstHost;
  // a rule permitting a port from anywhere to anywhere has no endpoints but is
  // still a real registration
  if(!hasEnd && !(isRule && r.dstPort)) return false;
  if(r.dest && !validEndpoint(r.dest) && !isIP(r.dest)) return false;
  if(r.src  && !validEndpoint(r.src)  && !isIP(r.src))  return false;
  if(r.dstPort && !validPort(r.dstPort) && !/^\d+-\d+$/.test(String(r.dstPort))) return false;
  if(r.srcPort && !validPort(r.srcPort) && !/^\d+-\d+$/.test(String(r.srcPort))) return false;
  if(r.proto && !validProto(r.proto)) return false;
  return true;
}

function collNow(){ return ($("impCollector") && $("impCollector").value.trim()) || ""; }
function protoNum(n){
  const M={1:"ICMP",2:"IGMP",6:"TCP",17:"UDP",41:"IPv6",47:"GRE",50:"ESP",51:"AH",
    58:"ICMPv6",89:"OSPF",103:"PIM",112:"VRRP",132:"SCTP"};
  return M[+n] || String(n).toUpperCase();
}
// split "1.2.3.4:443" / "1.2.3.4/443" / "[fe80::1]:443" / "1.2.3.4.443"
function splitEndpoint(s){
  if(!s) return null;
  s=s.trim().replace(/,$/,"");
  let m=s.match(/^\[([0-9a-fA-F:.%]+)\][:.](\d+)$/);          if(m) return {ip:m[1],port:m[2]};
  m=s.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})[:\/](\d+)$/);   if(m) return {ip:m[1],port:m[2]};
  m=s.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\.(\d+)$/);      if(m) return {ip:m[1],port:m[2]};
  m=s.match(/^([0-9a-fA-F:]+:[0-9a-fA-F:]*)[.](\d+)$/);       if(m) return {ip:m[1],port:m[2]};
  m=s.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})$/);             if(m) return {ip:m[1],port:""};
  /* An ASA with "names" configured prints the object name instead of the
     address: "dmz wsus11:8530". Keep the name so it can be resolved against
     the DNS zones later, rather than dropping the connection. */
  m=s.match(/^([A-Za-z][A-Za-z0-9_.\-]*)[:\/](\d+)$/);         if(m) return {ip:m[1],host:m[1],port:m[2]};
  return null;
}
// orient a client/server pair using port heuristics
function orientPair(ip1,p1,ip2,p2){
  const a=+p1,z=+p2;
  const known=p=>(guessService(p)!=="")||(p>0&&p<(+CFG.wellKnownMax||1024));
  if(known(a)&&!known(z)) return {src:ip2,srcPort:String(p2||""),dest:ip1,dstPort:String(p1||"")};
  if(known(z)&&!known(a)) return {src:ip1,srcPort:String(p1||""),dest:ip2,dstPort:String(p2||"")};
  return (a<=z) ? {src:ip2,srcPort:String(p2||""),dest:ip1,dstPort:String(p1||"")}
                : {src:ip1,srcPort:String(p1||""),dest:ip2,dstPort:String(p2||"")};
}

/* ---------- Cisco ASA / FTD  "show conn [all]" ---------- */
function parseShowConn(text){
  const rows=[], seen=new Set(), coll=collNow();
  const lines=text.split(/\r?\n/);
  /* "show conn long" and "show conn detail" label the two ends Initiator and
     Responder, which settles which side is the listening service without
     having to guess from the port numbers. */
  const longForm=/Initiator:/i.test(text);
  if(longForm){
    const blocks=text.split(/\n(?=\s*(?:TCP|UDP|ICMP|SCTP)\s)/i);
    for(const blk of blocks){
      const pm=blk.match(/^\s*(TCP|UDP|ICMP|SCTP)\s/i);
      if(!pm) continue;
      const im=blk.match(/Initiator:\s*([0-9a-fA-F:.]+)[\s,]*(?:\((\S+?)\))?/i);
      const rm=blk.match(/Responder:\s*([0-9a-fA-F:.]+)[\s,]*(?:\((\S+?)\))?/i);
      const pr=blk.match(/(?:Responder|dest)\D{0,24}?port[:\s]+(\d+)/i) || blk.match(/:(\d+)\s*$/m);
      if(!im||!rm) continue;
      const proto=pm[1].toUpperCase();
      const dport=pr?pr[1]:"";
      const key=proto+"|"+im[1]+"|"+rm[1]+"|"+dport;
      if(seen.has(key)) continue; seen.add(key);
      const zones=blk.match(/([A-Za-z0-9_\-]+):[0-9a-fA-F:.]+\/\d+/g)||[];
      rows.push(blank({src:im[1], dest:rm[1], proto, dstPort:dport,
        dataService:guessService(dport,proto), direction:"Outbound", status:"New",
        origin:"show-conn", collector:coll,
        notes:"initiator/responder from show conn long"}));
    }
    if(rows.length) return {rows, note:"parsed "+rows.length+" connections (long form)"};
  }
  for(const raw of lines){
    const line=raw.trim();
    if(!line || /^\d+\s+in use|^Total|^TCP outside.*--More--/i.test(line)) continue;
    // PROTO [ifc1] ep1 [ifc2] ep2 , idle .., bytes N, flags XX
    let m=line.match(/^(TCP|UDP|ICMP|SCTP|GRE|ESP|IP)\s+(?:(\S+)\s+)?([0-9a-fA-F:.\[\]]+[:\/.]\d+|[A-Za-z][A-Za-z0-9_.\-]*[:\/]\d+|[0-9.]+)\s+(?:(\S+)\s+)?([0-9a-fA-F:.\[\]]+[:\/.]\d+|[A-Za-z][A-Za-z0-9_.\-]*[:\/]\d+|[0-9.]+)\s*(?:,|$)/i);
    if(!m) continue;
    const proto=m[1].toUpperCase();
    const if1=m[2]||"", e1=splitEndpoint(m[3]);
    const if2=m[4]||"", e2=splitEndpoint(m[5]);
    if(!e1||!e2) continue;
    const bytesM=line.match(/bytes\s+(\d+)/i);
    const flagsM=line.match(/flags\s+([A-Za-z\-]+)/i);
    const idleM =line.match(/idle\s+([\d:]+)/i);
    const flags=flagsM?flagsM[1]:"";
    let o;
    // ASA flag 'B' = initial SYN came from outside (ep1 side is the initiator)
    if(/B/.test(flags)) o={src:e1.ip,srcPort:e1.port,dest:e2.ip,dstPort:e2.port};
    else o=orientPair(e1.ip,e1.port,e2.ip,e2.port);
    const key=proto+"|"+o.src+"|"+o.dest+"|"+o.dstPort;
    if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({
      src:o.src, dest:o.dest, proto, srcPort:o.srcPort, dstPort:o.dstPort,
      dataService:guessService(o.dstPort,proto),
      direction:"Outbound", status:"New", origin:"show-conn", collector:coll,
      srcZone:(o.src===e1.ip?if1:if2), dstZone:(o.dest===e1.ip?if1:if2),
      bytes:bytesM?bytesM[1]:"", notes:idleM?("idle "+idleM[1]+(flags?" flags "+flags:"")):(flags?("flags "+flags):"")
    }));
  }
  return {rows,note:rows.length?("parsed "+rows.length+" connections"):""};
}

/* ---------- Cisco IOS-XE NetFlow cache (table / csv / record) ---------- */
function parseNetflowCache(text){
  const rows=[], seen=new Set(), coll=collNow();
  const lines=text.split(/\r?\n/);
  // ---- "record" style: repeated "FIELD: value" blocks ----
  if(/IPV4 SOURCE ADDRESS:|ipv4 source address:/i.test(text) && /:\s*\S/.test(text)){
    let cur={};
    const flush=()=>{
      if(cur.src&&cur.dst){
        const proto=protoNum(cur.prot||6);
        const key=proto+"|"+cur.src+"|"+cur.dst+"|"+(cur.dport||"");
        if(!seen.has(key)){ seen.add(key);
          rows.push(blank({src:cur.src,dest:cur.dst,proto,srcPort:cur.sport||"",dstPort:cur.dport||"",
            dataService:guessService(cur.dport,proto),direction:"Outbound",status:"New",
            origin:"netflow",collector:coll,pkts:cur.pkts||"",bytes:cur.bytes||""}));}
      }
      cur={};
    };
    for(const raw of lines){
      const l=raw.trim(); if(!l){ flush(); continue; }
      const m=l.match(/^([A-Za-z0-9 _\-]+):\s*(\S.*)$/); if(!m) continue;
      const k=m[1].toLowerCase().trim(), v=m[2].trim();
      if(/ipv[46] source address|source address/.test(k)) cur.src=v;
      else if(/ipv[46] destination address|destination address/.test(k)) cur.dst=v;
      else if(/source port/.test(k)) cur.sport=v;
      else if(/destination port/.test(k)) cur.dport=v;
      else if(/ip protocol|protocol/.test(k)) cur.prot=v;
      else if(/packets/.test(k)) cur.pkts=v;
      else if(/bytes/.test(k)) cur.bytes=v;
    }
    flush();
    if(rows.length) return {rows,note:"netflow record format"};
  }
  // ---- table / csv style with a NetFlow-ish header row ----
  let hdrIdx=-1, sep=null;
  for(let i=0;i<Math.min(lines.length,60);i++){
    const l=lines[i];
    if(/IPV4\s+SRC\s+ADDR|IPV4 SRC ADDR|ipv4 src addr/i.test(l)){ hdrIdx=i; sep=/,/.test(l)?",":null; break; }
  }
  if(hdrIdx<0) return {rows,note:""};
  const hdrLine=lines[hdrIdx];
  const cols = sep ? hdrLine.split(",").map(s=>s.trim().toLowerCase())
                   : hdrLine.trim().split(/\s{2,}/).map(s=>s.trim().toLowerCase());
  const idx=(...names)=>{for(const n of names){const i=cols.findIndex(c=>c.includes(n));if(i>=0)return i;}return -1;};
  const iS=idx("src addr","source addr"), iD=idx("dst addr","destination addr"),
        iSP=idx("src port","source port"), iDP=idx("dst port","destination port"),
        iPR=idx("ip prot","protocol"), iPK=idx("pkts","packets"), iBY=idx("bytes"),
        iIF=idx("intf input","input interface","interface input","ingress"),
        iOF=idx("intf output","output interface","interface output","egress");
  for(let i=hdrIdx+1;i<lines.length;i++){
    const l=lines[i]; if(!l.trim()) continue;
    if(/^[-=\s]+$/.test(l)) continue;
    const c = sep ? l.split(",").map(s=>s.trim()) : l.trim().split(/\s+/);
    if(c.length<3) continue;
    const src=c[iS], dst=c[iD];
    if(!/^[0-9a-fA-F:.]+$/.test(src||"")||!/^[0-9a-fA-F:.]+$/.test(dst||"")) continue;
    const proto=protoNum(iPR>=0?c[iPR]:6);
    const dport=iDP>=0?c[iDP]:"", sport=iSP>=0?c[iSP]:"";
    const key=proto+"|"+src+"|"+dst+"|"+dport;
    if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src,dest:dst,proto,srcPort:sport,dstPort:dport,
      dataService:guessService(dport,proto),direction:"Outbound",status:"New",
      origin:"netflow",collector:coll,pkts:iPK>=0?c[iPK]:"",bytes:iBY>=0?c[iBY]:"",
      srcZone:iIF>=0?c[iIF]:"", dstZone:iOF>=0?c[iOF]:""}));
  }
  return {rows,note:rows.length?("netflow cache · "+rows.length+" flows"):""};
}

/* ---------- Zeek / Bro conn.log (TSV and JSON lines) ---------- */
function parseZeek(text){
  const rows=[], seen=new Set(), coll=collNow();
  const lines=text.split(/\r?\n/);
  if(/^\s*\{/.test(text.trim())){                      // JSON lines
    for(const l of lines){
      const s=l.trim(); if(!s||s[0]!=="{") continue;
      let j; try{ j=JSON.parse(s); }catch(e){ continue; }
      const src=j["id.orig_h"], dst=j["id.resp_h"];
      if(!validFlowFields(src,dst,j["id.orig_p"],j["id.resp_p"],j.proto)) continue;
      const proto=(j.proto||"").toUpperCase();
      const dport=String(j["id.resp_p"]==null?"":j["id.resp_p"]);
      const key=proto+"|"+src+"|"+dst+"|"+dport; if(seen.has(key)) continue; seen.add(key);
      const un=/^(S0|REJ|RSTOS0|RSTRH|SH|SHR|OTH)$/.test(j.conn_state||"");
      rows.push(blank({src,dest:dst,proto,srcPort:String(j["id.orig_p"]||""),dstPort:dport,
        dataService:j.service||guessService(dport,proto),direction:"Outbound",
        status: un?"Unconfirmed":"New",
        notes: j.conn_state ? ("conn_state "+j.conn_state+(un?" — no response, not confirmed as a listening service":"")) : "",
        origin:"zeek",collector:coll,pkts:String((j.orig_pkts||0)+(j.resp_pkts||0)||""),
        bytes:String((j.orig_bytes||0)+(j.resp_bytes||0)||"")}));
    }
    return {rows,note:rows.length?("zeek json · "+rows.length+" flows"):""};
  }
  /* Tab-separated is the native form, but a log that has been through PDF,
     Word or a terminal paste arrives space-aligned. Fall back to whitespace
     splitting when no tabs survive. */
  const tabbed = lines.some(l=>l.indexOf("\t")>=0);
  const cut = l => tabbed ? l.split(/\t/) : l.trim().split(/\s+/);
  let fields=null;
  for(const raw of lines){
    if(raw.startsWith("#fields")){ fields=cut(raw).slice(1); continue; }
    if(raw.startsWith("#")||!raw.trim()) continue;
    const c=cut(raw);
    let src,dst,sp,dp,proto,svc,ob,rb,op,rp,cstate="",hist="";
    if(fields){
      const g=n=>{const i=fields.indexOf(n);return i>=0?c[i]:"";};
      src=g("id.orig_h");dst=g("id.resp_h");sp=g("id.orig_p");dp=g("id.resp_p");
      proto=g("proto");svc=g("service");ob=g("orig_bytes");rb=g("resp_bytes");
      op=g("orig_pkts");rp=g("resp_pkts");
      cstate=g("conn_state");hist=g("history");
      if(!validFlowFields(src,dst,sp,dp,proto)) continue;
    } else {
      /* No #fields header. Only the canonical conn.log column order is
         accepted, and every field is checked, because without this any
         whitespace-delimited prose parses as flows. */
      if(c.length<7) continue;
      src=c[2];sp=c[3];dst=c[4];dp=c[5];proto=c[6];svc=c[7]||"";
    }
    if(!validFlowFields(src,dst,sp,dp,proto)) continue;
    proto=(proto||"").toUpperCase();
    /* S0 = SYN with no reply, REJ = refused. Neither proves a listening
       service, so they are recorded but flagged rather than registered as
       though the port were open. */
    const unanswered = /^(S0|REJ|RSTOS0|RSTRH|SH|SHR|OTH)$/.test(cstate||"");
    const key=proto+"|"+src+"|"+dst+"|"+dp; if(seen.has(key)) continue; seen.add(key);
    const num=x=>(x&&x!=="-")?+x:0;
    rows.push(blank({src,dest:dst,proto,srcPort:sp==="-"?"":sp,dstPort:dp==="-"?"":dp,
      dataService:(svc&&svc!=="-")?svc:guessService(dp,proto),direction:"Outbound",
      status: unanswered ? "Unconfirmed" : "New",
      notes: cstate ? ("conn_state "+cstate+((hist&&hist!=="-")?" history "+hist:"")+
             (unanswered?" - no response, not confirmed as a listening service":"")) : "",
      origin:"zeek",collector:coll,
      pkts:String(num(op)+num(rp)||""),bytes:String(num(ob)+num(rb)||"")}));
  }
  return {rows,note:rows.length?("zeek conn.log · "+rows.length+" flows"):""};
}

/* ---------- Windows Firewall pfirewall.log (W3C) ---------- */
function parseWinFirewall(text){
  const rows=[], seen=new Set(), coll=collNow();
  const lines=text.split(/\r?\n/);
  let f=null;
  for(const raw of lines){
    if(/^#Fields:/i.test(raw)){ f=raw.replace(/^#Fields:\s*/i,"").trim().split(/\s+/); continue; }
    if(raw.startsWith("#")||!raw.trim()) continue;
    const c=raw.trim().split(/\s+/); if(c.length<8) continue;
    const g=n=>{ if(!f) return ""; const i=f.indexOf(n); return i>=0?(c[i]||""):""; };
    const act=g("action")||c[2], proto=(g("protocol")||c[3]||"").toUpperCase();
    const src=g("src-ip")||c[4], dst=g("dst-ip")||c[5];
    const sp=g("src-port")||c[6], dp=g("dst-port")||c[7];
    const path=g("path");
    if(!/^[0-9a-fA-F:.]+$/.test(src||"")||!/^[0-9a-fA-F:.]+$/.test(dst||"")) continue;
    if(CFG.wfwDropOnly && !/DROP/i.test(act)) { /* keep all by default */ }
    /* The log records the packet as it was seen, so a RECEIVE line lists the
       server first. Orient to client -> server so the same conversation does
       not appear twice, once from each end. */
    const o=orientPair(src,sp==="-"?"":sp,dst,dp==="-"?"":dp);
    const key=proto+"|"+o.src+"|"+o.dest+"|"+o.dstPort;
    if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src:o.src,dest:o.dest,proto,srcPort:o.srcPort,dstPort:o.dstPort,
      dataService:guessService(o.dstPort,proto),
      direction:/RECEIVE/i.test(path)?"Inbound":(/SEND/i.test(path)?"Outbound":""),
      status:"New",origin:"win-firewall",collector:coll,
      notes:act?("action "+act):""}));
  }
  return {rows,note:rows.length?("windows firewall log · "+rows.length+" flows"):""};
}

/* ---------- tcpdump / tshark text ---------- */
function parseTcpdumpText(text){
  const rows=[], seen=new Set(), coll=collNow();
  for(const raw of text.split(/\r?\n/)){
    const line=raw.trim(); if(!line) continue;
    // 10:00:00.123 IP 10.1.1.5.52341 > 10.2.2.7.443: Flags [S] ...
    let m=line.match(/\bIP6?\s+(\S+?)\s+>\s+(\S+?):\s*(.*)$/);
    if(!m) continue;
    const e1=splitEndpoint(m[1].replace(/[:,]$/,"")), e2=splitEndpoint(m[2].replace(/[:,]$/,""));
    if(!e1||!e2) continue;
    const tail=m[3]||"";
    let proto="TCP";
    if(/^UDP|\bUDP,/i.test(tail)) proto="UDP";
    else if(/ICMP/i.test(tail)) proto="ICMP";
    else if(/Flags\s*\[/i.test(tail)) proto="TCP";
    else if(/^ESP|\bESP\b/i.test(tail)) proto="ESP";
    let o;
    if(/Flags\s*\[S\]/.test(tail)) o={src:e1.ip,srcPort:e1.port,dest:e2.ip,dstPort:e2.port};
    else o=orientPair(e1.ip,e1.port,e2.ip,e2.port);
    const key=proto+"|"+o.src+"|"+o.dest+"|"+o.dstPort; if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src:o.src,dest:o.dest,proto,srcPort:o.srcPort,dstPort:o.dstPort,
      dataService:guessService(o.dstPort,proto),direction:"Outbound",status:"New",
      origin:"tcpdump",collector:coll}));
  }
  return {rows,note:rows.length?("tcpdump text · "+rows.length+" flows"):""};
}

/* ---------- ASA / FTD syslog "Built ... connection" ---------- */
function parseAsaSyslog(text){
  const rows=[], seen=new Set(), coll=collNow();
  for(const raw of text.split(/\r?\n/)){
    const line=raw.trim(); if(!line) continue;
    if(!/302013|302015|302020|Built (inbound|outbound)/i.test(line)) continue;
    const m=line.match(/Built\s+(inbound|outbound)\s+(TCP|UDP|ICMP)\s+connection\s+\d+\s+for\s+(\S+?):([0-9a-fA-F:.]+)\/(\d+)(?:\s*\([^)]*\))?\s+to\s+(\S+?):([0-9a-fA-F:.]+)\/(\d+)/i);
    if(!m) continue;
    const dir=m[1].toLowerCase(), proto=m[2].toUpperCase();
    const z1=m[3], ip1=m[4], p1=m[5], z2=m[6], ip2=m[7], p2=m[8];
    // "for X to Y": X is the source-side interface, Y the destination-side
    const o=orientPair(ip1,p1,ip2,p2);
    const key=proto+"|"+o.src+"|"+o.dest+"|"+o.dstPort; if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src:o.src,dest:o.dest,proto,srcPort:o.srcPort,dstPort:o.dstPort,
      dataService:guessService(o.dstPort,proto),
      direction:dir==="inbound"?"Inbound":"Outbound",status:"New",
      origin:"asa-syslog",collector:coll,
      srcZone:(o.src===ip1?z1:z2), dstZone:(o.dest===ip1?z1:z2)}));
  }
  return {rows,note:rows.length?("ASA syslog · "+rows.length+" flows"):""};
}

/* ---------- pktmon formatted text ---------- */
function parsePktmon(text){
  const rows=[], seen=new Set(), coll=collNow();
  for(const raw of text.split(/\r?\n/)){
    const line=raw.trim(); if(!line) continue;
    const m=line.match(/(?:TCP|UDP)[:,]?\s*([0-9.]+):(\d+)\s*(?:->|>|to)\s*([0-9.]+):(\d+)/i);
    if(!m) continue;
    const proto=/UDP/i.test(line)?"UDP":"TCP";
    const o=orientPair(m[1],m[2],m[3],m[4]);
    const key=proto+"|"+o.src+"|"+o.dest+"|"+o.dstPort; if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src:o.src,dest:o.dest,proto,srcPort:o.srcPort,dstPort:o.dstPort,
      dataService:guessService(o.dstPort,proto),direction:"Outbound",status:"New",
      origin:"pktmon",collector:coll}));
  }
  return {rows,note:rows.length?("pktmon · "+rows.length+" flows"):""};
}

/* ---------- iptables / UFW kernel log ---------- */
function parseIptables(text){
  const rows=[], seen=new Set(), coll=collNow();
  for(const raw of text.split(/\r?\n/)){
    if(!/SRC=/.test(raw)||!/DST=/.test(raw)) continue;
    const g=k=>{const m=raw.match(new RegExp(k+"=(\\S+)"));return m?m[1]:"";};
    const src=g("SRC"),dst=g("DST"),proto=(g("PROTO")||"").toUpperCase(),
          sp=g("SPT"),dp=g("DPT");
    if(!src||!dst) continue;
    const key=proto+"|"+src+"|"+dst+"|"+dp; if(seen.has(key)) continue; seen.add(key);
    rows.push(blank({src,dest:dst,proto,srcPort:sp,dstPort:dp,
      dataService:guessService(dp,proto),direction:"Outbound",status:"New",
      origin:"iptables",collector:coll}));
  }
  return {rows,note:rows.length?("iptables/ufw log · "+rows.length+" flows"):""};
}
