"use strict";
/* self-test: verifies the core engine in THIS browser, without touching your data */
function runSelfTest(){
  const R=[]; const t=(n,c)=>R.push({n,ok:!!c});
  const conns=$("conns"); const prev=conns?conns.checked:true; if(conns) conns.checked=true;
  try{
    t("Service lookup — 443 → https (code)", guessServiceCode(443)==="https");
    t("Service lookup — 443 → Hypertext Transfer Protocol Secure (HTTPS)", guessService(443)==="Hypertext Transfer Protocol Secure (HTTPS)");
    t("Service lookup — 3389 → Remote Desktop Protocol (RDP), not ms-wbt-server", guessService(3389)==="Remote Desktop Protocol (RDP)");
    t("Service lookup — 5985 → Windows Remote Management (WinRM)", guessService(5985)==="Windows Remote Management (WinRM)");
    t("Service names — a semicolon list of codes becomes names", serviceDisplayName("kerberos; ldap")==="Kerberos Authentication (KRB5); Lightweight Directory Access Protocol (LDAP)");
    t("Service names — a hand-typed name is left alone", serviceDisplayName("Our Custom App")==="Our Custom App");
    t("Service names — Nessus codes www/cifs are upgraded", serviceDisplayName("www")==="Hypertext Transfer Protocol (HTTP)" && serviceDisplayName("cifs")==="Server Message Block (SMB)");

    const nmap='<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><hostname name="h1.lan"/><ports>'+
      '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>'+
      '<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>'+
      '<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port></ports></host></nmaprun>';
    const n=parseFile("t.xml",nmap);
    t("nmap — open ports parsed, closed excluded", n.kind==="nmap XML" && n.rows.length===2);
    t("nmap — version banner captured", n.rows.some(r=>/OpenSSH 8\.9/.test(r.banner)));
    t("nmap — hostname (FQDN) resolved", n.rows.some(r=>/h1\.lan/.test(r.dstHost)));

    const ness='<?xml version="1.0"?><NessusClientData_v2><Report><ReportHost name="10.0.0.2">'+
      '<HostProperties><tag name="host-ip">10.0.0.2</tag><tag name="host-fqdn">h2.lan</tag></HostProperties>'+
      '<ReportItem port="22" svc_name="ssh" protocol="tcp" pluginID="22964" pluginName="Service Detection" pluginFamily="x"/>'+
      '<ReportItem port="0" svc_name="general" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"/>'+
      '<ReportItem port="0" svc_name="general" protocol="tcp" pluginID="64582" pluginName="Netstat Connection Information" pluginFamily="General">'+
      '<plugin_output>  TCP    10.0.0.2:50100   10.0.0.9:443   ESTABLISHED   5</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>';
    const ne=parseFile("t.nessus",ness);
    t("Nessus — inbound listener captured", ne.rows.some(r=>r.direction==="Inbound"&&r.dstPort==="22"));
    t("Nessus — host-level (port 0) finding dropped", !ne.rows.some(r=>r.dstPort==="0"));
    t("Nessus — outbound flow from netstat plugin", ne.rows.some(r=>r.direction==="Outbound"&&r.dest==="10.0.0.9"&&r.dstPort==="443"));

    const ns=parseFile("t.txt","  TCP    0.0.0.0:445   0.0.0.0:0   LISTENING   4\n  TCP    10.0.0.5:50000  10.0.0.9:1433  ESTABLISHED  9\n");
    t("netstat — listener captured", ns.rows.some(r=>r.dstPort==="445"));
    t("netstat — established connection captured", ns.rows.some(r=>r.origin==="netstat-conn"&&r.dstPort==="1433"));

    const csv=parseFile("t.csv","host,protocol,port,service\n10.0.0.1,TCP,80,http\n");
    t("CSV — row parsed with service", csv.rows.length===1 && csv.rows[0].dstPort==="80" && csv.rows[0].dataService==="http");

    t("Boundary flag — Interconnection flagged", FLAGGED("Interconnection")===true);
    t("Boundary flag — Internal only not flagged", FLAGGED("Internal only")===false);
    t("Banner color — SCI marking → yellow", bannerClassFor("TOP SECRET//SI/TK//NOFORN")==="sci");
    t("CSV escaping — commas quoted", csvCell("a,b")==='"a,b"');

    const xb=buildXlsx({system:"selftest"},[blank({dest:"10.0.0.1",proto:"TCP",dstPort:"443",dataService:"https",boundary:"Internal only"})]);
    t("Excel export — produces a valid .xlsx (PK zip signature)", xb && xb.length>500 && xb[0]===0x50 && xb[1]===0x4b);

    /* ---- v2 checks ---- */
    const sc=parseFile("show-conn.txt",
      "TCP outside 74.125.24.100:443 inside 10.1.1.50:54321, idle 0:00:02, bytes 5423, flags UIO\n"+
      "UDP outside 8.8.8.8:53 inside 10.1.1.50:51234, idle 0:00:10, bytes 128, flags -\n");
    t("show conn — connections parsed", sc.kind==="show-conn" && sc.rows.length===2);
    t("show conn — server side identified", sc.rows.some(r=>r.dest==="74.125.24.100"&&r.dstPort==="443"));
    t("show conn — firewall interface captured as zone", sc.rows.some(r=>r.srcZone==="inside"||r.dstZone==="outside"));

    const nf=parseFile("flows.csv","IPV4 SRC ADDR,IPV4 DST ADDR,TRNS SRC PORT,TRNS DST PORT,IP PROT,bytes,pkts\n10.1.1.5,10.2.2.7,52341,443,6,12345,89\n");
    t("NetFlow cache — CSV format parsed", nf.kind==="netflow" && nf.rows.length===1);
    t("NetFlow cache — protocol number 6 mapped to TCP", nf.rows[0] && nf.rows[0].proto==="TCP");

    const zk=parseFile("conn.log","#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n1\tC\t10.1.1.5\t52341\t10.2.2.7\t443\ttcp\tssl\n");
    t("Zeek conn.log — flow parsed with service", zk.kind==="zeek" && zk.rows.length===1 && zk.rows[0].dataService==="ssl");

    const wf=parseFile("pfirewall.log","#Software: Microsoft Windows Firewall\n#Fields: date time action protocol src-ip dst-ip src-port dst-port\n2026-01-01 10:00:00 ALLOW TCP 10.1.1.5 10.2.2.7 52341 443\n");
    t("Windows Firewall log — entry parsed", wf.kind==="win-firewall" && wf.rows.length===1);

    const as=parseFile("fw.log","%ASA-6-302013: Built outbound TCP connection 1 for outside:1.2.3.4/443 (1.2.3.4/443) to inside:10.0.0.5/52000 (10.0.0.5/52000)");
    t("ASA syslog — Built-connection parsed", as.kind==="asa-syslog" && as.rows.length===1);

    const td=parseFile("dump.txt","10:00:00.1 IP 10.1.1.5.52341 > 10.2.2.7.443: Flags [S], seq 1\n");
    t("tcpdump text — SYN identifies the client", td.rows.some(r=>r.src==="10.1.1.5"&&r.dstPort==="443"));

    // build a real 3-packet pcap in memory and parse it
    (function(){
      const pk=[];
      function mkpkt(sip,dip,sp,dp,flags){
        const b=new Uint8Array(54); const dv=new DataView(b.buffer);
        dv.setUint16(12,0x0800); b[14]=0x45; dv.setUint16(16,40); b[22]=64; b[23]=6;
        sip.split(".").forEach((o,i)=>b[26+i]=+o); dip.split(".").forEach((o,i)=>b[30+i]=+o);
        dv.setUint16(34,sp); dv.setUint16(36,dp); b[46]=0x50; b[47]=flags;
        return b;
      }
      pk.push(mkpkt("10.1.1.50","10.2.2.7",52341,443,0x02));
      pk.push(mkpkt("10.2.2.7","10.1.1.50",443,52341,0x12));
      pk.push(mkpkt("10.1.1.50","10.2.2.7",52341,443,0x10));
      const total=24+pk.reduce((a,p)=>a+16+p.length,0);
      const out=new Uint8Array(total); const dv=new DataView(out.buffer);
      dv.setUint32(0,0xa1b2c3d4,true); dv.setUint16(4,2,true); dv.setUint16(6,4,true);
      dv.setUint32(16,65535,true); dv.setUint32(20,1,true);
      let o=24;
      pk.forEach((p,i)=>{ dv.setUint32(o,1700000000+i,true); dv.setUint32(o+4,0,true);
        dv.setUint32(o+8,p.length,true); dv.setUint32(o+12,p.length,true);
        out.set(p,o+16); o+=16+p.length; });
      t("pcap — magic number recognised", isPcapMagic(out)===true);
      const pr=parsePcapBuffer(out.buffer,"selftest.pcap");
      t("pcap — packets aggregated into one flow", pr.rows.length===1);
      t("pcap — TCP SYN identifies client and server",
        pr.rows[0] && pr.rows[0].src==="10.1.1.50" && pr.rows[0].dest==="10.2.2.7" && pr.rows[0].dstPort==="443");
      t("pcap — packet count recorded", pr.rows[0] && pr.rows[0].pkts==="3");
    })();

    const savedSvc=JSON.parse(JSON.stringify(CFG.customServices||{}));
    CFG.customServices={"9997":"splunk-forwarder"};
    t("Custom service name overrides the built-in table", guessService(9997,"TCP")==="splunk-forwarder");
    CFG.customServices=savedSvc;

    CFG.customBoundaries=["Cross-domain solution"];
    t("Custom boundary tag appears in the boundary list",
      boundaryList().some(o=>(o&&o.value===undefined?o:o.value)==="Cross-domain solution"));
    CFG.customBoundaries=[];

    (function(){
      const saved=ROWS.slice();
      ROWS.length=0;
      ROWS.push(blank({enclave:"ALPHA",src:"10.1.1.5",dest:"10.2.2.7",proto:"TCP",dstPort:"443",
        dataService:"https",boundary:"Inter-enclave",collector:"CSS-WKS-01"}));
      const fm=svgFlowMap();
      t("Diagram — flow map renders valid SVG", /^<svg/.test(fm) && /<\/svg>$/.test(fm.trim()));
      t("Diagram — flow map reflects register content", fm.indexOf("ALPHA")>=0);
      const rf=svgReference();
      t("Diagram — 16-boundary reference renders", /^<svg/.test(rf) && rf.indexOf("DISN")>=0);
      ROWS.length=0; ROWS.push(...saved);
    })();

    t("Collector column present in the export model", COLS.some(c=>c[0]==="collector"));

    /* ---- what a Nessus / ACAS scan gives up ---- */
    (function(){
      const savedMap=new Map(HOSTMAP), savedAl=new Map(ALIASES);
      HOSTMAP.clear(); ALIASES.clear();
      const nx='<?xml version="1.0" ?><NessusClientData_v2><Report name="r">'+
        '<ReportHost name="10.9.9.12"><HostProperties>'+
        '<tag name="host-ip">10.9.9.12</tag><tag name="host-fqdn">db.lab.mil</tag>'+
        '<tag name="netbios-name">DB01</tag><tag name="operating-system">Oracle Linux 9</tag>'+
        '<tag name="system-type">general-purpose</tag></HostProperties>'+
        '<ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information">'+
        '<plugin_output>Credentialed checks : yes</plugin_output></ReportItem>'+
        '<ReportItem port="0" protocol="tcp" pluginID="24272" pluginName="Network Interfaces Enumeration (SSH)">'+
        '<plugin_output> - ens192 : IPAddress : 10.9.9.12\n - ens224 : IPAddress : 10.9.9.13</plugin_output></ReportItem>'+
        '<ReportItem port="1521" svc_name="oracle_tns" protocol="tcp" pluginID="22964" pluginName="Service Detection">'+
        '<plugin_output>An Oracle TNS Listener is running on this port.\nOracle Database 19c Enterprise Edition</plugin_output></ReportItem>'+
        '<ReportItem port="1521" svc_name="oracle_tns" protocol="tcp" pluginID="56984" pluginName="SSL / TLS Versions Supported">'+
        '<plugin_output>TLSv1.2</plugin_output></ReportItem>'+
        '</ReportHost>'+
        '<ReportHost name="10.9.9.44"><HostProperties><tag name="host-ip">10.9.9.44</tag>'+
        '<tag name="netbios-name">APP44</tag></HostProperties>'+
        '<ReportItem port="0" protocol="tcp" pluginID="19506" pluginName="Nessus Scan Information">'+
        '<plugin_output>Credentialed checks : no</plugin_output></ReportItem>'+
        '<ReportItem port="8443" svc_name="www" protocol="tcp" pluginID="22964" pluginName="Service Detection">'+
        '<plugin_output>A web server is running on this port through SSL.\nnginx/1.24.0</plugin_output></ReportItem>'+
        '</ReportHost></Report></NessusClientData_v2>';
      const r=parseNessus(nx);
      const byPort=pt=>r.rows.find(x=>x.dstPort===pt);
      t("Nessus — the FQDN is taken from HostProperties",
        (HOSTMAP.get("10.9.9.12")||{}).name==="db.lab.mil");
      t("Nessus — the operating system and system type are kept",
        (HOSTMAP.get("10.9.9.12")||{}).os==="Oracle Linux 9" &&
        (HOSTMAP.get("10.9.9.12")||{}).role==="general-purpose");
      t("Nessus — the NetBIOS name becomes an alias of the FQDN",
        ALIASES.get("db01")==="db.lab.mil");
      t("Nessus — a second interface resolves to the same host",
        (HOSTMAP.get("10.9.9.13")||{}).name==="db.lab.mil");
      t("Nessus — the product behind the port is identified, not the sentence about it",
        (byPort("1521")||{}).appName==="Oracle Database 19c Enterprise Edition");
      t("Nessus — a TLS plugin records that the service is encrypted",
        /TLS confirmed/.test((byPort("1521")||{}).notes||""));
      t("Nessus — a host scanned without credentials is marked as such",
        /uncredentialed/.test((byPort("8443")||{}).notes||"") &&
        !/uncredentialed/.test((byPort("1521")||{}).notes||""));
      t("Nessus — a host-level finding is not registered as a service",
        !r.rows.some(x=>x.dstPort==="0"));
      t("Nessus — the client side is the ephemeral range, since a scan finds listeners",
        !!(byPort("1521")||{}).srcPort && (byPort("1521")||{}).direction==="Inbound");

      const csv='"Plugin ID","Name","IP Address","DNS Name","Protocol","Port","Service","Plugin Output"\n'+
        '"22964","Service Detection","10.9.9.20","dc.lab.mil","tcp","636","ldaps","An LDAP server is running."\n'+
        '"19506","Nessus Scan Information","10.9.9.20","dc.lab.mil","tcp","0","general","x"\n';
      const tc=parseFile("findings.csv",csv);
      t("Tenable CSV — recognised as a findings export", tc.kind==="Tenable / ACAS export");
      t("Tenable CSV — one row per service, with the name from the DNS column",
        tc.rows.length===1 && tc.rows[0].dstPort==="636" && tc.rows[0].dstHost==="dc.lab.mil");
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
      ALIASES.clear(); savedAl.forEach((v,k)=>ALIASES.set(k,v));
    })();

    /* ---- consolidating ports onto one row ---- */
    (function(){
      const saved=ROWS.slice(); ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.5",srcHost:"a.lan",dest:"10.9.9.20",dstHost:"dc.lan",proto:"TCP",dstPort:"389",dataService:"ldap",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.5",srcHost:"a.lan",dest:"10.9.9.20",dstHost:"dc.lan",proto:"TCP",dstPort:"636",dataService:"ldaps",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.5",srcHost:"a.lan",dest:"10.9.9.20",dstHost:"dc.lan",proto:"TCP",dstPort:"88",dataService:"kerberos",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.9",srcHost:"b.lan",dest:"10.9.9.20",dstHost:"dc.lan",proto:"TCP",dstPort:"389",dataService:"ldap",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      const c=consolidateRows(ROWS);
      const row=ROWS.find(x=>x.src==="10.1.1.5");
      t("Consolidate — three ports for one pair become one row",
        c.into===1 && c.collapsed===2 && ROWS.length===2);
      t("Consolidate — ports are joined in numeric order with semicolons",
        row.dstPort==="88; 389; 636");
      t("Consolidate — data services line up with their ports",
        row.dataService==="kerberos; ldap; ldaps");
      t("Consolidate — a different source keeps its own row",
        ROWS.some(x=>x.src==="10.1.1.9"));
      // a different destination must not merge
      ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"TCP",dstPort:"389",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.21",proto:"TCP",dstPort:"389",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"}));
      t("Consolidate — different destinations stay separate",
        consolidateRows(ROWS).into===0 && ROWS.length===2);
      // source consolidation: several hosts -> one service becomes one row
      ROWS.length=0;
      ["10.1.1.5","10.1.1.6","10.1.1.7"].forEach(ip=>ROWS.push(blank({src:ip,dest:"10.9.9.20",dstHost:"dc.lan",proto:"TCP",dstPort:"636",dataService:"ldaps",boundary:INTERNAL_BND,direction:"Outbound",origin:"zeek"})));
      const sc=consolidateSources(ROWS);
      t("Consolidate sources — three hosts to one service become one row",
        sc.into===1 && ROWS.length===1);
      t("Consolidate sources — source IPs are joined in order",
        ROWS[0].src==="10.1.1.5; 10.1.1.6; 10.1.1.7");
      // a network source is left alone
      ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.20",proto:"TCP",dstPort:"636",boundary:INTERNAL_BND,direction:"Outbound",origin:"firewall-rule"}));
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.20",proto:"TCP",dstPort:"636",boundary:INTERNAL_BND,direction:"Outbound",origin:"firewall-rule"}));
      const scn=consolidateSources(ROWS);
      t("Consolidate sources — a CIDR source is not merged by this pass",
        !/;/.test(ROWS[0].src));
      ROWS.length=0; ROWS.push(...saved);
    })();

    /* ---- DNS export CSV (name / type / data / timestamp) ---- */
    (function(){
      const savedMap=new Map(HOSTMAP), savedAl=new Map(ALIASES);
      HOSTMAP.clear(); ALIASES.clear();
      const csv="name,type,data,timestamp\n"+
        "wsus11.lab.mil,A,10.9.9.11,2026-09-01T08:00:00Z\n"+
        "db12.lab.mil,A,10.9.9.12,2026-09-01T08:00:00Z\n"+
        "patch.lab.mil,CNAME,wsus11.lab.mil,2026-09-01T08:00:00Z\n"+
        "13.9.9.10.in-addr.arpa,PTR,mail.lab.mil,2026-09-01T08:00:00Z\n";
      const r=parseFile("dns-export.csv",csv);
      t("DNS CSV — a name/type/data/timestamp export is recognised", r.kind==="DNS export");
      t("DNS CSV — A records map hostname to address",
        (HOSTMAP.get("10.9.9.11")||{}).name==="wsus11.lab.mil" &&
        (HOSTMAP.get("10.9.9.12")||{}).name==="db12.lab.mil");
      t("DNS CSV — a CNAME is recorded as an alias", ALIASES.get("patch.lab.mil")==="wsus11.lab.mil");
      t("DNS CSV — a PTR resolves the arpa owner to its host",
        (HOSTMAP.get("10.9.9.13")||{}).name==="mail.lab.mil");
      // header variations
      HOSTMAP.clear();
      const r2=parseFile("x.csv","Name,Type,Data,Timestamp\nhostA.lab.mil,A,10.9.9.20,static\n");
      t("DNS CSV — capitalised headers are accepted",
        r2.kind==="DNS export" && (HOSTMAP.get("10.9.9.20")||{}).name==="hostA.lab.mil".toLowerCase() ||
        (HOSTMAP.get("10.9.9.20")||{}).name==="hostA.lab.mil");
      // PTR both orientations
      HOSTMAP.clear();
      parseFile("rev.csv","name,type,data,timestamp\n"+
        "h99.lab.mil,PTR,99.9.9.10.in-addr.arpa,t\n"+
        "77.9.9.10.in-addr.arpa,PTR,h77.lab.mil,t\n");
      t("DNS CSV — PTR works with arpa in either column",
        (HOSTMAP.get("10.9.9.99")||{}).name==="h99.lab.mil" &&
        (HOSTMAP.get("10.9.9.77")||{}).name==="h77.lab.mil");
      // gap-filling into existing rows
      HOSTMAP.clear(); ALIASES.clear(); ROWS.length=0;
      ROWS.push(blank({src:"10.9.9.50",dest:"10.9.9.11",proto:"TCP",dstPort:"8530",boundary:INTERNAL_BND,origin:"zeek"}));
      ROWS.push(blank({srcHost:"db12.lab.mil",dest:"10.9.9.11",proto:"TCP",dstPort:"443",boundary:INTERNAL_BND,origin:"zeek"}));
      parseFile("dns.csv","name,type,data,timestamp\nwsus11.lab.mil,A,10.9.9.11,t\ndb12.lab.mil,A,10.9.9.12,t\nsrv50.lab.mil,A,10.9.9.50,t\n");
      applyHostmap(true);
      t("DNS CSV — a bare IP in a row gains its hostname", ROWS[0].dstHost==="wsus11.lab.mil" && ROWS[0].srcHost==="srv50.lab.mil");
      t("DNS CSV — a hostname-only endpoint gains its address", ROWS[1].src==="10.9.9.12");
      // a plain .txt file with the same data
      HOSTMAP.clear();
      const rt=parseFile("dns.txt","name,type,data,timestamp\ntxt01.lab.mil,A,10.9.9.81,t\n");
      t("DNS text — a .txt export with the same columns is read",
        rt.kind==="DNS export" && (HOSTMAP.get("10.9.9.81")||{}).name==="txt01.lab.mil");
      // tab-delimited, no header
      HOSTMAP.clear();
      const rtab=parseFile("dns.txt","tab01.lab.mil\tA\t10.9.9.82\t2026\ntab02.lab.mil\tA\t10.9.9.83\t2026\n");
      t("DNS text — tab-delimited with no header row works",
        (HOSTMAP.get("10.9.9.82")||{}).name==="tab01.lab.mil" && (HOSTMAP.get("10.9.9.83")||{}).name==="tab02.lab.mil");
      // the standard Windows export header (data column not adjacent to type)
      HOSTMAP.clear();
      parseFile("w.csv","HostName,RecordType,Timestamp,TimeToLive,RecordData\nsrv9.lab.mil,A,0,01:00:00,10.9.9.84\n");
      t("DNS text — the standard Windows Export-Csv header is read",
        (HOSTMAP.get("10.9.9.84")||{}).name==="srv9.lab.mil");
      // space-delimited dump
      HOSTMAP.clear();
      parseFile("d.txt","sp01.lab.mil   A   10.9.9.85\nsp02.lab.mil   A   10.9.9.86\n");
      t("DNS text — space-delimited dump with no header works",
        (HOSTMAP.get("10.9.9.85")||{}).name==="sp01.lab.mil");
      // a BOM must not break detection
      HOSTMAP.clear();
      parseFile("b.csv","\uFEFFname,type,data,timestamp\nbom01.lab.mil,A,10.9.9.87,t\n");
      t("DNS text — a leading BOM does not break detection",
        (HOSTMAP.get("10.9.9.87")||{}).name==="bom01.lab.mil");
      // verbose Windows type names: "A Record", "Host (A)", "Pointer (PTR)"
      HOSTMAP.clear(); ALIASES.clear();
      parseFile("v.csv","name,type,data,timestamp\n"+
        "vh1.lab.mil,A Record,10.9.9.90,t\n"+
        "vh2.lab.mil,Host (A),10.9.9.91,t\n"+
        "93.9.9.10.in-addr.arpa,Pointer (PTR),vh3.lab.mil,t\n"+
        "www.lab.mil,Alias (CNAME),vh1.lab.mil,t\n");
      t("DNS — verbose type names (A Record / Host (A)) are understood",
        (HOSTMAP.get("10.9.9.90")||{}).name==="vh1.lab.mil" && (HOSTMAP.get("10.9.9.91")||{}).name==="vh2.lab.mil");
      t("DNS — a verbose PTR (Pointer (PTR)) resolves",
        (HOSTMAP.get("10.9.9.93")||{}).name==="vh3.lab.mil");
      t("DNS — a verbose CNAME (Alias (CNAME)) is recorded as an alias",
        ALIASES.get("www.lab.mil")==="vh1.lab.mil");
      // semicolon-delimited export
      HOSTMAP.clear();
      parseFile("s.csv","name;type;data;timestamp\nsemi01.lab.mil;A;10.9.9.92;t\n");
      t("DNS — a semicolon-delimited export is read",
        (HOSTMAP.get("10.9.9.92")||{}).name==="semi01.lab.mil");
      // a flow CSV must NOT be grabbed as DNS
      HOSTMAP.clear();
      t("DNS — a flow CSV with a Port column is not taken as DNS",
        parseFile("flow.csv","Source IP,Destination IP,Protocol,Port\n10.1.1.5,10.9.9.9,TCP,443\n").kind!=="DNS export");
      // the name/IP fallback: any table with a name column and an IP column,
      // whatever the type column looks like or if there is none
      HOSTMAP.clear();
      const f1=parseFile("f.csv","name,data,timestamp\nnf1.lab.mil,10.9.9.95,t\nnf2.lab.mil,10.9.9.96,t\n");
      t("Name/IP — a table with no recognizable type column still learns names",
        f1.kind==="name/IP list" && (HOSTMAP.get("10.9.9.95")||{}).name==="nf1.lab.mil");
      HOSTMAP.clear();
      const f2=parseFile("f.csv","ip,name\n10.9.9.97,nf3.lab.mil\n");
      t("Name/IP — columns in either order are matched",
        (HOSTMAP.get("10.9.9.97")||{}).name==="nf3.lab.mil");
      HOSTMAP.clear();
      const f3=parseFile("f.csv","FQDN,Address,Owner\nnf4.lab.mil,10.9.9.98,admin\n");
      t("Name/IP — unknown header names still work by content",
        (HOSTMAP.get("10.9.9.98")||{}).name==="nf4.lab.mil");
      // but a real flow CSV must still parse as flow, not a name list
      HOSTMAP.clear();
      t("Name/IP — a flow CSV with host/protocol/port/service still parses as flow",
        parseFile("t.csv","host,protocol,port,service\n10.9.9.1,TCP,80,http\n").rows.length===1);
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
      ALIASES.clear(); savedAl.forEach((v,k)=>ALIASES.set(k,v));
      ROWS.length=0;
    })();

    /* ---- application name -> service, and ephemeral exclusion ---- */
    (function(){
      const map=[["Microsoft SQL Server 2019","ms-sql-s","1433"],
        ["Oracle Database 19c Enterprise Edition","oracle","1521"],
        ["Apache/2.4.57 (Unix)","http","80"],["nginx/1.24.0","http","80"],
        ["OpenSSH_8.7","ssh","22"],["PostgreSQL 14.2","postgresql","5432"],
        ["Splunk Universal Forwarder","splunkd","8089"],["MongoDB 6.0","mongodb","27017"],
        ["Microsoft IIS/10.0","http","80"],["Samba 4.17","microsoft-ds","445"],
        ["ISC BIND 9.18","dns","53"],["VMware ESXi","https","443"],["HP JetDirect","jetdirect","9100"]];
      let ok=true;
      map.forEach(([app,svc,port])=>{ const m=serviceFromApp(app);
        if(!m || m.code!==svc || m.port!==port) ok=false; });
      t("App-to-service — common products map to the right service and port", ok);
      t("App-to-service — an unknown product returns no match", serviceFromApp("Acme Frobnicator 7")===null);
      t("App-to-service — version noise is ignored", (serviceFromApp("Apache/2.4.57")||{}).code==="http");
      // deriveServiceFromApp fills Data Service and a missing port
      const r1=blank({appName:"Microsoft SQL Server 2019",dest:"10.9.9.9",proto:"TCP"});
      deriveServiceFromApp(r1);
      t("App-to-service — Data Service and port are filled from the product",
        r1.dataService==="Microsoft SQL Server (MSSQL)" && r1.dstPort==="1433");
      const r2=blank({appName:"nginx/1.24.0",dest:"10.9.9.9",proto:"TCP",dstPort:"8443",dataService:"https-alt"});
      deriveServiceFromApp(r2);
      t("App-to-service — an existing Data Service is not overwritten",
        r2.dataService==="https-alt" && r2.dstPort==="8443");
      normaliseServiceNames([r2]);
      t("Service names — a leftover short code is upgraded when the register is finished",
        r2.dataService==="Hypertext Transfer Protocol Secure (HTTPS)");

      const savedCfg={s:CFG.excludeEphemeralSrc,d:CFG.excludeEphemeralDst,r:CFG.ephemeralRange};
      const saved=ROWS.slice(); ROWS.length=0;
      CFG.ephemeralRange="1024-65535"; CFG.excludeEphemeralSrc=true; CFG.excludeEphemeralDst=false;
      ROWS.push(blank({src:"10.1.1.5",srcPort:"52341",dest:"10.9.9.9",dstPort:"443",proto:"TCP",boundary:INTERNAL_BND,origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.6",srcPort:"443",dest:"10.9.9.9",dstPort:"58080",proto:"TCP",boundary:INTERNAL_BND,origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.9",dstPort:"55000",proto:"TCP",boundary:INTERNAL_BND,origin:"firewall-rule"}));
      const ex=excludeEphemeral(ROWS);
      t("Ephemeral — an ephemeral source port is cleared", ROWS[0].srcPort==="" && ex.blanked===1);
      t("Ephemeral — destination rows are kept when the option is off", ROWS.length===3 && ex.dropped===0);
      CFG.excludeEphemeralDst=true;
      const ex2=excludeEphemeral(ROWS);
      t("Ephemeral — an ephemeral destination row is dropped when the option is on",
        ex2.dropped===1 && !ROWS.some(x=>x.dstPort==="58080"));
      t("Ephemeral — a firewall-rule row is never dropped",
        ROWS.some(x=>x.origin==="firewall-rule" && x.dstPort==="55000"));
      t("Ephemeral — a custom range is honoured", (function(){
        CFG.ephemeralRange="40000-45000";
        return portIsEphemeral("42000") && !portIsEphemeral("52000"); })());
      CFG.excludeEphemeralSrc=savedCfg.s; CFG.excludeEphemeralDst=savedCfg.d; CFG.ephemeralRange=savedCfg.r;
      ROWS.length=0; ROWS.push(...saved);
    })();

    /* ---- reading an eMASS PPSM export back in ---- */
    (function(){
      const savedMap=new Map(HOSTMAP); HOSTMAP.clear();
      const csv=["***** CONTROLLED UNCLASSIFIED INFORMATION *****","System Name:,X",
        "#,Type,Application/Software Record Name,Protocol,Data Service,Port,Boundary,Direction,VPN / Encrypted Tunnel Traffic,VPN Tunnel Type,Source,Source Physical Location or Cloud Service Provider,Source IP Address,Source FQDN,Connection Logical Source Point,Destination,Destination Physical Location or Cloud Service Provider,Destination IP Address,Destination FQDN,Connection Logical Destination Point,Purpose",
        "1,Least Function,ldap,TCP,ldap,389; 636,18. Internal Use Only (DoD Network),Outbound,No,,,,10.1.1.5,a.lan,DoD Enclave (DoD Network),dc.lan,,10.9.9.20,dc.lan,DoD Enclave DMZ (DoD Network),Directory"].join("\n");
      const r=parseFile("emass.csv",csv);
      t("eMASS import — an eMASS PPSM export is recognised", r.kind==="eMASS PPSM export");
      t("eMASS import — its rows come in marked Registered",
        r.rows.length>=1 && r.rows.every(x=>x.status==="Registered"));
      t("eMASS import — a multi-port cell is split into separate ports",
        r.rows.length===2 && r.rows.some(x=>x.dstPort==="389") && r.rows.some(x=>x.dstPort==="636"));
      t("eMASS import — purpose and names are preserved",
        r.rows[0].justification==="Directory" && r.rows[0].dstHost==="dc.lan" && r.rows[0].dest==="10.9.9.20");
      t("eMASS import — the boundary resolves to a code", bndCode(r.rows[0].boundary)==="B18");
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
    })();

    /* ---- hiding addresses from the register ---- */
    (function(){
      const row=blank({src:"10.20.99.99",srcHost:"scanner99.range.mil",
                       dest:"172.22.40.11",dstHost:"wsus11.range2.mil",proto:"TCP",dstPort:"8530"});
      const m=(...l)=>matchesExclusion(row,l);
      t("Hide — an exact address matches either end", m("10.20.99.99") && m("172.22.40.11"));
      t("Hide — a network in CIDR matches", m("10.20.99.0/24") && !m("10.20.98.0/24"));
      t("Hide — a wildcard on a hostname matches", m("scanner*") && !m("splunk*"));
      t("Hide — a short name matches the full hostname", m("scanner99") && m("wsus11"));
      t("Hide — an unrelated address matches nothing", !m("203.0.113.5"));
      t("Hide — an empty list hides nothing", !matchesExclusion(row,[]));
      t("Hide — several entries are combined", m("203.0.113.5","10.20.99.99"));
    })();

    /* ---- Windows connection exports ---- */
    (function(){
      const tcp='"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess","Process"\n'+
        '"0.0.0.0","8530","0.0.0.0","0","Listen","984","wsusservice"\n'+
        '"10.9.9.10","49712","140.82.121.4","443","Established","2260","chrome"\n'+
        '"10.9.9.10","8530","10.1.1.5","51188","Established","984","wsusservice"\n';
      const r=parseFile("WSUS11-tcp.csv",tcp);
      t("Windows — a raw Get-NetTCPConnection export is recognised", r.kind==="Windows connections" && r.rows.length===3);
      t("Windows — a listener's own port is the service, attributed from the file name",
        r.rows.some(x=>x.dstPort==="8530" && x.dstHost==="WSUS11" && x.direction==="Inbound"));
      t("Windows — an outbound connection registers the remote service, not the client port",
        r.rows.some(x=>x.dest==="140.82.121.4" && x.dstPort==="443" && x.direction==="Outbound"));
      t("Windows — an inbound connection is turned round to face the service",
        r.rows.some(x=>x.src==="10.1.1.5" && x.dstPort==="8530"));
      t("Windows — the process name goes to Application, the service gets a name",
        r.rows.some(x=>x.dstPort==="8530" && x.appName==="wsusservice" && x.dataService==="Windows Server Update Services (WSUS)"));
      const col='"Source IP","Source Port","Destination IP","Destination Port","Protocol","Data Service / Application","Direction","Host","State","Process","PID","Collector"\n'+
        '"","","0.0.0.0","135","TCP","svchost","Inbound","TESTBOX","Listen","svchost","928","PowerShell 5.1.19041 / netstat"\n'+
        '"","","0.0.0.0","3389","TCP","svchost","Inbound","TESTBOX","Listen","svchost","1100","PowerShell 5.1.19041 / netstat"\n'+
        '"10.1.1.5","49700","10.9.9.10","443","TCP","chrome","Outbound","TESTBOX","Established","chrome","4321","PowerShell 5.1.19041 / netstat"\n'+
        '"10.1.1.5","3389","10.1.1.77","51188","TCP","svchost","Outbound","TESTBOX","Established","svchost","1100","PowerShell 5.1.19041 / netstat"\n'+
        '"","","0.0.0.0","123","UDP","svchost","Inbound","TESTBOX","Listen","svchost","1264","PowerShell 5.1.19041 / netstat"\n';
      const cr=parseFile("TESTBOX-connections.csv",col);
      t("Collector CSV — recognised as the collector's own output, not an eMASS export",
        cr.kind==="Windows connections (collector)" && cr.rows.length===5 && cr.rows.every(x=>x.status==="New"));
      t("Collector CSV — listeners are kept with their own port and host",
        cr.rows.some(x=>x.dstPort==="135" && x.direction==="Inbound" && x.dstHost==="TESTBOX" && x.proto==="TCP") &&
        cr.rows.some(x=>x.dstPort==="123" && x.proto==="UDP"));
      t("Collector CSV — an outbound connection keeps the remote service port",
        cr.rows.some(x=>x.src==="10.1.1.5" && x.dest==="10.9.9.10" && x.dstPort==="443" && x.direction==="Outbound"));
      t("Collector CSV — a client of a local listener is turned round to face the service",
        cr.rows.some(x=>x.src==="10.1.1.77" && x.dest==="10.1.1.5" && x.dstPort==="3389" && x.direction==="Inbound"));
      t("Collector CSV — the service is named, the process is the application",
        cr.rows.some(x=>x.dstPort==="3389" && x.dataService==="Remote Desktop Protocol (RDP)" && x.appName==="svchost"));
      t("Collector CSV — the PowerShell version and method are reported", /PowerShell 5\.1.*netstat/.test(cr.note));
      const udp='"LocalAddress","LocalPort","OwningProcess","Process"\n"0.0.0.0","514","712","syslogd"\n';
      const u=parseFile("WSUS11-udp.csv",udp);
      t("Windows — Get-NetUDPEndpoint is read as UDP listeners",
        u.rows.length===1 && u.rows[0].proto==="UDP" && u.rows[0].dstPort==="514");
      t("Windows — a UTF-8 BOM does not break the header",
        parseFile("x-tcp.csv","\ufeff"+tcp).rows.length===3);
    })();

    /* ---- name resolution across every source ---- */
    (function(){
      const savedMap=new Map(HOSTMAP), savedAl=new Map(ALIASES), savedRows=ROWS.slice();
      HOSTMAP.clear(); ALIASES.clear(); ROWS.length=0;

      const fwd=["$ORIGIN lab.mil.","@ IN SOA ns1 hm ( 1 2 3 4 5 )","web01  3600 IN A 10.9.9.10",
                 "db01   1h   IN A 10.9.9.20","mx01        IN A 10.9.9.35",
                 "            IN A 10.9.9.36","alias  IN CNAME web01",
                 "v6only IN AAAA fd00::10"].join("\n");
      const rev=["$ORIGIN 9.9.10.in-addr.arpa.","30 IN PTR mail01.lab.mil."].join("\n");
      const dnscmd=[";  Zone:   lab.mil","app01   [Aging:3712345] 1200 A 10.9.9.40"].join("\n");
      const csv="HostName,RecordType,ZoneName,IPv4Address,PtrDomainName,HostNameAlias\n"+
                "log01,A,lab.mil,10.9.9.50,,\n60,PTR,9.9.10.in-addr.arpa,,mon01.lab.mil.,\n";
      t("Names — a forward zone qualifies relative names with $ORIGIN",
        parseFile("x.zone",fwd).kind==="DNS zone" && (HOSTMAP.get("10.9.9.10")||{}).name==="web01.lab.mil");
      t("Names — a continuation line belongs to the previous owner",
        (HOSTMAP.get("10.9.9.36")||{}).name==="mx01.lab.mil");
      t("Names — an AAAA record is set aside in an IPv4-only register",
        !HOSTMAP.has("fd00::10"));
      t("Names — an IPv6 row never reaches the register",
        (function(){ const r=parseFile("v6.log",
          "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"+
          "1\tC1\t2001:db8::1\t5100\t2001:db8::2\t8530\ttcp\thttp\n");
          return r.rows.length===1 && isIPv6Addr(r.rows[0].dest); })());
      t("Names — a TTL with units is skipped", (HOSTMAP.get("10.9.9.20")||{}).name==="db01.lab.mil");
      t("Names — the SOA record's numbers are not mistaken for data",
        ![...HOSTMAP.keys()].some(k=>/^\d+$/.test(k)));
      t("Names — CNAME aliases are recorded", ALIASES.get("alias.lab.mil")==="web01.lab.mil");
      parseFile("x.rev",rev);
      t("Names — a reverse zone PTR is turned back into an address",
        (HOSTMAP.get("10.9.9.30")||{}).name==="mail01.lab.mil" && HOSTMAP.get("10.9.9.30").source==="dns-ptr");
      parseFile("x.txt",dnscmd);
      t("Names — Windows dnscmd output, zone taken from its header",
        (HOSTMAP.get("10.9.9.40")||{}).name==="app01.lab.mil");
      t("Names — a Windows DNS CSV export, including its PTR rows",
        parseFile("dns.csv",csv).kind==="DNS export" &&
        (HOSTMAP.get("10.9.9.50")||{}).name==="log01.lab.mil" && (HOSTMAP.get("10.9.9.60")||{}).name==="mon01.lab.mil");

      learnHost("10.9.9.10","oldbox","arp");
      t("Names — an authoritative source is not overwritten by a weaker one",
        HOSTMAP.get("10.9.9.10").name==="web01.lab.mil" && HOSTMAP.get("10.9.9.10").alt.indexOf("oldbox")>=0);
      learnHost("10.9.9.70","guess70","arp"); learnHost("10.9.9.70","real70.lab.mil","dns-ptr");
      t("Names — a stronger source replaces a weaker one, keeping it as an alias",
        HOSTMAP.get("10.9.9.70").name==="real70.lab.mil" && HOSTMAP.get("10.9.9.70").alt.indexOf("guess70")>=0);
      t("Names — ip neigh output is not read as a hosts file",
        (function(){ const r=parseFile("n.txt","10.9.9.80 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n");
                     return r.kind==="neighbour table" && !HOSTMAP.has("10.9.9.80"); })());

      ROWS.push(blank({src:"10.1.1.5", dest:"10.9.9.10", proto:"TCP", dstPort:"443"}));
      ROWS.push(blank({src:"10.1.1.5", dstHost:"db01", proto:"TCP", dstPort:"1521"}));
      ROWS.push(blank({src:"10.1.1.5", dest:"10.9.9.40", dstHost:"APP01", proto:"TCP", dstPort:"80"}));
      ROWS.push(blank({src:"10.1.1.5", dstHost:"alias.lab.mil", proto:"TCP", dstPort:"8443"}));
      applyHostmap(true);
      t("Names — an address gains its hostname", ROWS[0].dstHost==="web01.lab.mil");
      t("Names — a hostname gains its address", ROWS[1].dest==="10.9.9.20");
      t("Names — a row that gains an address gets its boundary worked out", ROWS[1].boundary==="Internal");
      t("Names — a short NetBIOS name is completed to the full name", ROWS[2].dstHost==="app01.lab.mil");
      t("Names — an alias leads to the address it points at", ROWS[3].dest==="10.9.9.10");

      learnHost("10.2.2.1","web.a.mil","dns-zone"); learnHost("10.2.2.2","web.b.mil","dns-zone");
      rebuildNameIndex();
      t("Names — a short name shared by two hosts is never guessed", lookupName("web")==="");

      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
      ALIASES.clear(); savedAl.forEach((v,k)=>ALIASES.set(k,v));
      ROWS.length=0; ROWS.push(...savedRows);
    })();

    /* ---- Excel input ---- */
    (function(){
      // round-trip through the tool's own exporter, so no fixture file is needed
      const rows=[blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"8530",dataService:"wsus"}),
                  blank({src:"10.1.1.6",dest:"10.9.9.20",proto:"UDP",dstPort:"123",dataService:"ntp"})];
      const xb=buildXlsx({system:"T"},rows);
      let book=null; try{ book=readXlsx(xb); }catch(e){}
      t("Excel — a workbook is unzipped and its sheets read", !!book && book.sheets.length>=1);
      const flat=book ? book.sheets[0].rows.map(r=>r.join("|")).join("\n") : "";
      t("Excel — cell text survives the round trip", /10\.9\.9\.10/.test(flat) && /8530/.test(flat));
      const csv=book ? sheetToCsv(book.sheets[0].rows) : "";
      t("Excel — title rows above the table are skipped", /^\S/.test(csv) && !/^PPSM/i.test(csv.split("\n")[0]));
      t("Excel — the zip reader rejects something that is not a workbook",
        (function(){ try{ readXlsx(new Uint8Array([0x50,0x4b,3,4,0,0])); return false; }catch(e){ return true; } })());
    })();

    /* ---- NetFlow top conversations ---- */
    (function(){
      const csv=["Top 100 Conversations","",
        "Rank,Source,Destination,Application,Protocol,Traffic,Packets",
        "1,analyst61.lan (10.1.1.61),oradb.lan (10.9.9.12),oracle (1521/TCP),TCP,12.4 MB,900",
        "2,10.1.1.62,10.9.9.30,ntp (123/UDP),UDP,480 B,12",
        "Total,,,,,12.4 MB,"].join("\n");
      const r=parseConversations(csv);
      t("Conversations — the report is found below its title rows", r.rows.length===2, r.rows.length);
      t("Conversations — 'name (address)' is split into both columns",
        r.rows[0].src==="10.1.1.61" && r.rows[0].srcHost==="analyst61.lan");
      t("Conversations — the port comes out of the application label",
        r.rows[0].dstPort==="1521" && r.rows[0].proto==="TCP" && r.rows[1].proto==="UDP");
      t("Conversations — '12.4 MB' becomes a byte count", r.rows[0].bytes==="12400000");
      t("Conversations — the Total line is not a conversation", !r.rows.some(x=>/total/i.test(x.src+x.srcHost)));
      t("Conversations — the tool's own register is not mistaken for one",
        parseConversations("Enclave,Source IP,Destination IP,Destination Port,Boundary Crossed,Bytes\nA,1.1.1.1,2.2.2.2,80,Internal,5").rows.length===0);
    })();

    /* ---- FMC access control policy from a PDF ---- */
    t("FMC ports — 'TCP (6):443', 'UDP (17):53' and 'HTTPS' all understood", (function(){
      const p=parseFmcPorts("TCP (6):443, UDP (17):53, HTTPS, TCP (6):8000-8010");
      return p.some(x=>x.proto==="TCP"&&x.port==="443") && p.some(x=>x.proto==="UDP"&&x.port==="53") &&
             p.some(x=>x.port==="8000-8010"); })());
    t("PDF positions — text comes out with where it sat on the page", (function(){
      const its=pdfItemsFromContent("BT /F1 8 Tf 1 0 0 1 100 700 Tm (Name) Tj ET BT /F1 8 Tf 1 0 0 1 300 700 Tm (Action) Tj ET "+
                                    "BT /F1 8 Tf 1 0 0 1 100 680 Tm (Allow-X) Tj ET", null);
      const ln=pdfLines(its);
      return its.length===3 && ln.length===2 && ln[0].items.length===2 && Math.round(ln[0].items[1].x)===300; })());
    t("PDF positions — a translated drawing state is honoured", (function(){
      const its=pdfItemsFromContent("q 1 0 0 1 50 50 cm BT /F1 8 Tf 10 10 Td (X) Tj ET Q", null);
      return its.length===1 && Math.round(its[0].x)===60 && Math.round(its[0].y)===60; })());
    t("Policy table — a wrapped header and a wrapped cell are read into the right rule", (function(){
      const I=(x,y,s)=>({x,y,s,size:7,page:0});
      const items=[
        I(250,500,"Source"),I(350,500,"Dest"),I(450,500,"Dest"),
        I(80,492,"#"),I(110,492,"Name"),I(250,492,"Networks"),I(350,492,"Networks"),I(450,492,"Ports"),I(550,492,"Action"),
        I(450,470,"TCP (6):636"),
        I(450,461,"TCP (6):389"),
        I(80,461,"1"),I(110,461,"Allow-Dir"),I(250,461,"10.1.1.0/24"),I(350,461,"10.9.9.20"),I(550,461,"Allow"),
        I(80,445,"2"),I(110,445,"Allow-Log"),I(250,445,"10.1.1.9"),I(350,445,"10.9.9.30"),I(450,445,"UDP (17):514"),I(550,445,"Allow")];
      const r=acpFromTable(items);
      if(!r || r.length!==2) return false;
      const a=acpRuleRows(r[0]).map(x=>x.dstPort).sort().join(","), b=acpRuleRows(r[1]).map(x=>x.dstPort).join(",");
      return a==="389,636" && b==="514"; })());
    t("Policy blocks — a label on one line and its value on the next are paired", (function(){
      const r=acpFromBlocks("Rule Name\nAllow-Web\nAction\nAllow\nDestination Networks\n10.9.9.10\nDestination Ports\nTCP (6):443");
      return r.length===1 && r[0].name==="Allow-Web" && /443/.test(r[0].portsText); })());
    t("Policy — Monitor does not count as permitting traffic", (function(){
      const rows=acpRuleRows({name:"M",action:"Monitor",portsText:"TCP (6):443",dstNets:"10.9.9.10"});
      return rows.length===1 && !/^Permitted/.test(rows[0].status); })());
    t("Policy — a named object resolves once a name source knows it", (function(){
      const saved=new Map(HOSTMAP); HOSTMAP.clear(); HOSTMAP.set("10.9.9.77",{name:"backup77.lan",src:"t"});
      const ip=resolveNetObject("BACKUP77");
      HOSTMAP.clear(); saved.forEach((v,k)=>HOSTMAP.set(k,v));
      return ip==="10.9.9.77"; })());
    t("The file picker does not filter out any file type",
      !document.getElementById("file").hasAttribute("accept"));

    /* ---- FMC report family ---- */
    (function(){
      const conn="Connection Events\nReport generated: 2026-01-01\n"+
        "First Packet,Action,Initiator IP,Responder IP,Security Zone (Initiator),Security Zone (Responder),"+
        "Source Port / ICMP Type,Destination Port / ICMP Code,Protocol,Application Protocol,"+
        "Access Control Rule,Initiator Bytes,Responder Bytes\n"+
        "2026-01-01 08:00,Allow,10.1.1.5,10.9.9.10,INSIDE,DMZ,51000,8530,TCP,HTTP,Allow-WSUS,100,200\n"+
        "2026-01-01 08:01,Block,10.1.1.9,10.9.9.10,INSIDE,DMZ,40000,3306,TCP,MySQL,Default Action,10,0\n";
      const r=parseFile("conn.csv",conn);
      t("FMC — connection events identified among the report family",
        r.kind==="FMC connection events" && r.rows.length===2);
      t("FMC — the export preamble is skipped to find the real header",
        r.rows[0].src==="10.1.1.5");
      t("FMC — initiator and responder settle direction without guessing",
        r.rows[0].src==="10.1.1.5" && r.rows[0].dest==="10.9.9.10");
      t("FMC — security zones and the access control rule are carried across",
        r.rows[0].srcZone==="INSIDE" && r.rows[0].dstZone==="DMZ" && r.rows[0].isaRef==="Allow-WSUS");
      t("FMC — a blocked connection is not registered as an approved service",
        /Blocked/.test(r.rows[1].status));
      t("FMC — byte counts are summed from both directions", r.rows[0].bytes==="300");
    })();

    (function(){
      const srv="Servers\nIP Address,Port,Protocol,Server,Vendor,Version\n"+
                "10.9.9.10,8530,6,wsus,Microsoft,10.0\n10.9.9.30,123,17,ntpd,,4.2.8\n";
      const r=parseFile("servers.csv",srv);
      t("FMC — servers report identified", r.kind==="FMC servers report" && r.rows.length===2);
      t("FMC — numeric protocol numbers resolved to names",
        r.rows[0].proto==="TCP" && r.rows[1].proto==="UDP");
      t("FMC — a discovered server is recorded as a listening service",
        r.rows[0].direction==="Inbound" && !!r.rows[0].srcPort);
      t("FMC — vendor and version become the banner", r.rows[0].banner==="Microsoft 10.0");
    })();

    (function(){
      const savedMap=new Map(HOSTMAP); HOSTMAP.clear();
      const hosts="Network Discovery - Hosts\nIP Address,NetBIOS Name,OS Vendor,OS Name\n"+
                  "10.9.9.10,WSUS10,Microsoft,Windows Server\n";
      const r=parseFile("hosts.csv",hosts);
      t("FMC — a discovery report is read as a name source, not as flows",
        r.kind==="FMC network discovery hosts" && r.rows.length===0 && r.names===1);
      t("FMC — the discovered name reaches the host inventory",
        HOSTMAP.has("10.9.9.10") && HOSTMAP.get("10.9.9.10").name==="WSUS10");
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
    })();

    t("FMC — an intrusion event is flagged rather than registered as approved", (function(){
      const ips="Intrusion Events\nTime,Inline Result,Source IP,Destination IP,"+
        "Source Port / ICMP Type,Destination Port / ICMP Code,Protocol,Message,Classification\n"+
        "2026-01-01,Blocked,10.1.1.9,10.9.9.10,40000,3306,TCP,SQLi,Web Attack\n";
      const r=parseFile("ips.csv",ips);
      return r.kind==="FMC intrusion events" && /Flagged/.test(r.rows[0].status); })());

    t("FMC — a VPN report raises the B15 or B16 decision", (function(){
      const v="Site-to-Site VPN\nVPN Topology,Local IP,Peer IP,Tunnel Status,Tunnel Type\n"+
              "T1,10.1.1.1,198.51.100.7,UP,IPSEC\n";
      const r=parseFile("vpn.csv",v);
      return r.kind==="FMC VPN report" && r.rows[0].vpn==="Yes" && /B15/.test(r.rows[0].notes); })());

    t("A discovered service folds into the traffic that used it", (function(){
      const saved=ROWS.slice();
      ROWS.length=0;
      ROWS.push(blank({dest:"10.9.9.10",proto:"TCP",dstPort:"8530",banner:"Microsoft 10.0",
        direction:"Inbound",origin:"fmc-servers"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"8530",origin:"zeek"}));
      const x=crossReference(ROWS);
      const ok = ROWS.length===1 && ROWS[0].src==="10.1.1.5" &&
                 ROWS[0].banner==="Microsoft 10.0" && x.absorbed===1;
      ROWS.length=0; ROWS.push(...saved);
      return ok; })());

    /* ---- cross-referencing the sources ---- */
    t("A network is treated as an address, not a hostname", (function(){
      const r=normalizeEndpoints(blank({src:"10.1.1.0/24"}));
      return r.src==="10.1.1.0/24" && !r.srcHost; })());
    t("An address is matched against a rule's network scope",
      ipInScope("10.1.1.55","10.1.1.0/24")===true &&
      ipInScope("10.9.9.9","10.1.1.0/24")===false &&
      ipInScope("10.9.9.9","")===true);

    (function(){
      const saved=ROWS.slice(), savedMap=new Map(HOSTMAP);
      ROWS.length=0;
      // a rule written against a network, and the one host that used it
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.10",proto:"TCP",dstPort:"443",
        origin:"firewall-rule",status:"Permitted by rule",isaRef:"ACL1"}));
      ROWS.push(blank({src:"10.1.1.55",srcHost:"wks55.lan",dest:"10.9.9.10",
        dstHost:"web10.lan",proto:"TCP",dstPort:"443",srcPort:"51000",origin:"zeek"}));
      // a rule nobody used keeps its network, because nothing proves otherwise
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.77",proto:"TCP",dstPort:"10000",
        origin:"firewall-rule",status:"Permitted by rule",isaRef:"ACL1"}));
      const x=crossReference(ROWS);
      const used=ROWS[0], unused=ROWS[2], seen=ROWS[1];
      t("A used rule gains the host that used it", used.src==="10.1.1.55");
      t("A used rule gains that host's name", used.srcHost==="wks55.lan");
      t("A used rule gains a source port", !!used.srcPort);
      t("A used rule gains the destination name", used.dstHost==="web10.lan");
      t("An unused rule keeps its network, rather than borrowing one",
        unused.src==="10.1.1.0/24" && !unused.srcPort);
      t("Observed traffic gains the rule that permits it", seen.isaRef==="ACL1");
      t("Cross-referencing reports what it filled in",
        x.filledSrc>0 && x.filledPort>0 && x.filledRef>0);
      ROWS.length=0; ROWS.push(...saved);
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
    })();

    /* ---- firewall rules ---- */
    (function(){
      const acl=[
        "object-group network SRVS",
        " network-object host 10.9.9.10",
        " network-object host 10.9.9.11",
        "object-group service WEB tcp",
        " port-object eq 443",
        " port-object eq 8443",
        "access-list TESTACL extended permit tcp 10.1.1.0 255.255.255.0 object-group SRVS object-group WEB",
        "access-list TESTACL extended permit udp any host 10.9.9.20 eq ntp",
        "access-list TESTACL extended deny ip any any"
      ].join("\n");
      const r=parseCiscoAcl(acl);
      t("ACL — object-groups expand to every host and port combination",
        r.rows.filter(x=>x.dest==="10.9.9.10"||x.dest==="10.9.9.11").length===4);
      t("ACL — netmask converted to CIDR notation",
        r.rows.some(x=>x.src==="10.1.1.0/24"));
      t("ACL — named port resolved to a number",
        r.rows.some(x=>x.dstPort==="123" && x.proto==="UDP"));
      t("ACL — permit and deny told apart",
        r.rows.some(x=>/^Permitted/.test(x.status)) && r.rows.some(x=>/^Denied/.test(x.status)));
      t("ACL — the access-list name is kept as the reference",
        r.rows.every(x=>x.isaRef==="TESTACL"));
      t("ACL — detected without being told the format",
        parseFile("x.txt",acl).kind==="firewall ACL");
    })();

    (function(){
      const acp="Rule Name,Action,Enabled,Source Networks,Destination Networks,Destination Ports\n"+
                "R1,Allow,True,10.1.1.0/24,10.9.9.10,TCP/443; TCP/8443\n"+
                "R2,Block,True,any,any,TCP/445\n";
      const r=parseAcpExport(acp);
      t("Access control policy — a multi-port rule becomes one row per port",
        r.rows.filter(x=>x.isaRef==="R1").length===2);
      t("Access control policy — a block rule is recorded as denied",
        r.rows.some(x=>x.isaRef==="R2" && /^Denied/.test(x.status)));
      t("Access control policy — detected ahead of the generic CSV reader",
        parseFile("policy.csv",acp).kind==="access control policy");
    })();

    (function(){
      const saved=ROWS.slice();
      ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"zeek"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",
        origin:"firewall-rule",status:"Permitted by rule",isaRef:"ACL1"}));
      ROWS.push(blank({dest:"10.9.9.99",proto:"TCP",dstPort:"10000",
        origin:"firewall-rule",status:"Permitted by rule",isaRef:"ACL1"}));
      ROWS.push(blank({src:"10.1.1.9",dest:"10.9.9.10",proto:"TCP",dstPort:"3389",origin:"zeek"}));
      const rt=ruleTrafficReview(ROWS);
      t("Rules and observations are kept apart, not merged",
        rt.observed===2 && rt.ruled===2);
      t("A rule nobody used is reported",
        rt.unusedRules.length===1 && rt.unusedRules[0].dstPort==="10000");
      t("Traffic with no rule behind it is reported",
        rt.unauthorised.length===1 && rt.unauthorised[0].dstPort==="3389");
      const before=ROWS.length; dedupeRows();
      t("Dedupe does not collapse a rule into an observation", ROWS.length===before);
      ROWS.length=0; ROWS.push(...saved);
    })();
    (function(){
      const saved=ROWS.slice(); ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"firewall-rule",status:"Permitted by rule",isaRef:"WEB-IN"}));
      ROWS.push(blank({src:"",dest:"10.9.9.20",proto:"TCP",dstPort:"3000-3100",origin:"firewall-rule",status:"Permitted by rule",isaRef:"APP-RANGE"}));
      ROWS.push(blank({src:"",dest:"",proto:"",dstPort:"53",origin:"firewall-rule",status:"Permitted by rule",isaRef:"DNS-ANY"}));
      ROWS.push(blank({src:"10.1.1.0/24",dest:"10.9.9.10",proto:"TCP",dstPort:"23",origin:"firewall-rule",status:"Denied by rule",isaRef:"NO-TELNET"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"zeek"}));          // covered by WEB-IN
      ROWS.push(blank({src:"10.2.2.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"zeek"}));          // wrong source: no rule
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"TCP",dstPort:"3050",origin:"zeek"}));         // in range
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.30",proto:"UDP",dstPort:"53",origin:"zeek"}));           // any/any rule
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"23",origin:"zeek"}));           // denied but seen
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443; 8443",origin:"zeek"}));    // partly covered
      const c=coverageReport(ROWS);
      const st=(src,port)=>(c.flows.find(x=>x.row.src===src && x.row.dstPort===port)||{}).status;
      t("Coverage — a flow inside the rule's source and destination scope is covered", st("10.1.1.5","443")==="covered");
      t("Coverage — a 443 rule for another source does not cover this one", st("10.2.2.5","443")==="no rule");
      t("Coverage — a port range in a rule is honoured", st("10.1.1.5","3050")==="covered");
      t("Coverage — an any/any rule with no protocol covers UDP too", st("10.1.1.5","53")==="covered");
      t("Coverage — traffic matched only by a deny rule is called out", st("10.1.1.5","23")==="denied but seen");
      t("Coverage — a consolidated row is only covered when every port is", st("10.1.1.5","443; 8443")==="partly covered");
      t("Coverage — rules are counted as used only when a flow matched them",
        c.unusedRules.length===0 && c.rules.find(x=>x.row.isaRef==="WEB-IN").flows===2);
      t("Coverage — summary counts add up", c.covered+c.partly+c.noRule+c.deniedSeen===c.observed);
      ROWS.length=0; ROWS.push(...saved);
    })();
    (function(){
      const prev=[
        blank({src:"10.1.1.5; 10.1.1.6",dest:"10.9.9.10",proto:"TCP",dstPort:"80; 443",dataService:"http; https",boundary:"B11",origin:"emass-export",status:"Registered"}),
        blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"TCP",dstPort:"3389",dataService:"ms-wbt-server",boundary:"B11",origin:"emass-export",status:"Registered"}),
        blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"firewall-rule",status:"Permitted by rule"})
      ];
      const cur=[
        blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",dataService:"Hypertext Transfer Protocol Secure (HTTPS)",boundary:"B11",origin:"zeek"}),
        blank({src:"10.1.1.6",dest:"10.9.9.10",proto:"tcp",dstPort:"80",dataService:"Hypertext Transfer Protocol (HTTP)",boundary:"B12",origin:"zeek"}),
        blank({src:"10.1.1.9",dest:"10.9.9.30",proto:"TCP",dstPort:"22",dataService:"Secure Shell (SSH)",boundary:"B11",origin:"zeek"})
      ];
      const d=diffRegisters(prev, cur);
      t("Diff — a consolidated previous row is compared port by port", d.previousCount===5);
      t("Diff — rules are not register entries", !d.removed.some(x=>x.row.origin==="firewall-rule"));
      t("Diff — a new flow is Added", d.added.length===1 && d.added[0].port==="22");
      t("Diff — flows no longer seen are Removed", d.removed.length===3 && d.removed.some(x=>x.port==="3389") && d.removed.some(x=>x.src==="10.1.1.6"&&x.port==="443"));
      t("Diff — a flow whose boundary moved is Changed", d.changed.length===1 && d.changed[0].diffs.some(f=>f.field==="Boundary" && f.previous==="B11" && f.current==="B12"));
      t("Diff — the same service under a code and under its name is not a change", d.same.length===1 && d.same[0].port==="443");
    })();
    (function(){
      const r=blank({src:"10.1.1.5",srcHost:"ws01.lan",dest:"10.9.9.20",dstHost:"dc01.lan",proto:"TCP",dstPort:"636",dataService:"Lightweight Directory Access Protocol over TLS (LDAPS)"});
      const j=draftJustification(r);
      t("Purpose draft — names the need, the service, both ends and the port",
        /directory lookup and authentication over TLS/.test(j) && /LDAPS/.test(j) && /ws01\.lan/.test(j) && /dc01\.lan/.test(j) && /TCP 636/.test(j));
      t("Purpose draft — is marked as a draft", /\[DRAFT/.test(j));
      const r2=blank({dest:"10.9.9.9",proto:"UDP",dstPort:"514"});
      t("Purpose draft — works from the port alone", /log forwarding/.test(draftJustification(r2)));
      const r3=blank({dest:"10.9.9.9",proto:"TCP",dstPort:"443"});
      enrichRows([r3], null, false);
      t("Purpose draft — never written by the automatic pass", !r3.justification);
      enrichRows([r3], ["justification"], false);
      t("Purpose draft — written when asked for under Fill In", /\[DRAFT/.test(r3.justification));
      t("Purpose draft — review check flags an unedited draft", PPSM_CHECKS.find(c=>c.id==="justdraft").test(r3));
    })();
    (function(){
      const keep={exportVpn:CFG.exportVpn, exportVpnOverwrite:CFG.exportVpnOverwrite, exportVpnType:CFG.exportVpnType,
                  exportVpnTypeOverwrite:CFG.exportVpnTypeOverwrite, srcLocation:CFG.srcLocation, dstLocation:CFG.dstLocation,
                  siteLocation:CFG.siteLocation, exportPurpose:CFG.exportPurpose};
      const I=8, J=9, L=11, Q=16, U=20;
      const r=blank({src:"10.1.1.5",srcHost:"ws01.lan",dest:"10.9.9.20",dstHost:"dc01.lan",proto:"TCP",dstPort:"636",
        dataService:"Lightweight Directory Access Protocol over TLS (LDAPS)",boundary:"B11",direction:"Outbound"});
      CFG.exportVpn=""; CFG.exportVpnType=""; CFG.exportPurpose=true; CFG.srcLocation=""; CFG.dstLocation=""; CFG.siteLocation="Bldg 1";
      let row=emassRow(r);
      t("eMASS export — Purpose is never blank: a statement is generated when none was written",
        /Required for directory lookup/.test(row[U]) && /ws01\.lan/.test(row[U]) && !/DRAFT/.test(row[U]));
      r.justification="Mission database access [DRAFT — confirm the mission need and edit before submission]";
      row=emassRow(r);
      t("eMASS export — a written purpose is used and the [DRAFT] marker is stripped", row[U]==="Mission database access");
      CFG.exportPurpose=false; r.justification="";
      t("eMASS export — generated Purpose can be turned off in Settings", emassRow(r)[U]==="");
      CFG.exportPurpose=true;
      // VPN traffic
      CFG.exportVpn="Yes"; CFG.exportVpnOverwrite=false; r.vpn="";
      t("eMASS export — VPN / Encrypted Tunnel Traffic can be set to Yes for the export", emassRow(r)[I]==="Yes");
      r.vpn="No";
      t("eMASS export — a per-row VPN value wins unless overwrite is ticked", emassRow(r)[I]==="No");
      CFG.exportVpnOverwrite=true;
      t("eMASS export — overwrite applies the export VPN value to every row", emassRow(r)[I]==="Yes");
      CFG.exportVpn="No"; CFG.exportVpnOverwrite=true;
      t("eMASS export — VPN can be set to No for the export", emassRow(r)[I]==="No");
      CFG.exportVpn=""; CFG.exportVpnOverwrite=false; r.vpn="";
      // tunnel type
      CFG.exportVpnType="Type-1  Encrypted Tunnel"; CFG.exportVpnTypeOverwrite=false; r.vpn="Yes"; r.vpnType="";
      t("eMASS export — VPN Tunnel Type from Settings is written where a row has none, exactly as the Glossary spells it",
        emassRow(r)[J]==="Type-1  Encrypted Tunnel" && EMASS_VPNTYPE.indexOf(emassRow(r)[J])>=0);
      r.vpnType="GRE Tunnel";
      t("eMASS export — a per-row tunnel type wins unless overwrite is ticked", emassRow(r)[J]==="GRE Tunnel");
      CFG.exportVpnTypeOverwrite=true;
      t("eMASS export — overwrite applies the tunnel type to every row", emassRow(r)[J]==="Type-1  Encrypted Tunnel");
      r.vpn="No"; r.vpnType="";
      t("eMASS export — no tunnel type is forced onto a row whose VPN traffic is No", emassRow(r)[J]==="");
      CFG.exportVpnType=""; CFG.exportVpnTypeOverwrite=false;
      // physical locations
      r.srcLoc=""; r.dstLoc="";
      CFG.srcLocation="Bldg 2 (clients)"; CFG.dstLocation="Bldg 3 (data center)";
      row=emassRow(r);
      t("eMASS export — Source Physical Location comes from Settings for our own addresses", row[L]==="Bldg 2 (clients)");
      t("eMASS export — Destination Physical Location comes from Settings for our own addresses", row[Q]==="Bldg 3 (data center)");
      r.srcLoc="Bldg 9, Schriever SFB";
      t("eMASS export — a per-row Source Physical Location (grid or Bulk-apply) wins", emassRow(r)[L]==="Bldg 9, Schriever SFB");
      CFG.srcLocation=""; CFG.dstLocation="";
      t("eMASS export — with no per-end location the enclave location is used", emassRow(r)[Q]==="Bldg 1");
      // the workbook itself carries the values
      CFG.exportVpn="Yes"; CFG.exportVpnType="AF VPN"; CFG.exportVpnOverwrite=true; CFG.exportVpnTypeOverwrite=true; r.justification="";
      const xb=buildEmassXlsx({system:"T"},[r]);
      const book=readXlsx(new Uint8Array(xb));
      const sh=book.sheets.find(x=>/ppsm/i.test(x.name))||book.sheets[0];
      const data=sh.rows.find(rw=>rw && rw[12]==="10.1.1.5");
      t("eMASS workbook — VPN, tunnel type, locations and Purpose land in columns I, J, L, Q and U",
        !!data && data[8]==="Yes" && data[9]==="AF VPN" && data[11]==="Bldg 9, Schriever SFB" && data[16]==="Bldg 1" && /Required for/.test(data[20]||""));
      Object.assign(CFG, keep);
      // bulk-apply offers the new fields with the Glossary list
      const opts=[...$("bulkField").options].map(o=>o.value);
      t("Bulk-apply — Source/Destination Physical Location, VPN and VPN Tunnel Type can be set on selected rows",
        ["srcLoc","dstLoc","vpn","vpnType"].every(k=>opts.indexOf(k)>=0));
      const prevField=$("bulkField").value; $("bulkField").value="vpnType"; bulkControl();
      t("Bulk-apply — VPN Tunnel Type is chosen from the template's Glossary list", [...$("bulkVal").options].some(o=>o.value==="JRSS RA VPN"));
      $("bulkField").value=prevField; bulkControl();
    })();
    (function(){
      const keep={emassOnePerPort:CFG.emassOnePerPort, emassIpOnly:CFG.emassIpOnly, emassSortByPort:CFG.emassSortByPort, exportPurpose:CFG.exportPurpose};
      CFG.emassOnePerPort=true; CFG.emassIpOnly=true; CFG.emassSortByPort=true; CFG.exportPurpose=true;
      const savedMap=new Map(HOSTMAP); HOSTMAP.set("10.9.9.77",{name:"app01.lan",sources:new Set(["test"])}); rebuildNameIndex();
      const rows=[
        blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",dataService:"Hypertext Transfer Protocol Secure (HTTPS)",appName:"Microsoft IIS/10.0",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.6",dest:"10.9.9.20",proto:"TCP",dstPort:"443",dataService:"Transport Layer Security (TLS/SSL)",appName:"microsoft iis 10",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"TCP",dstPort:"443",dataService:"Hypertext Transfer Protocol Secure (HTTPS)",appName:"nginx/1.24",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.5",dest:"app01.lan",proto:"TCP",dstPort:"22",dataService:"Secure Shell (SSH)",appName:"OpenSSH",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.5",dest:"10.9.9.30",proto:"UDP",dstPort:"53",dataService:"Domain Name System (DNS)",appName:"BIND",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.9",dest:"10.9.9.10",proto:"TCP",dstPort:"443",dataService:"Hypertext Transfer Protocol Secure (HTTPS)",appName:"Microsoft IIS/10.0",boundary:"B11",direction:"Inbound"})
      ];
      const out=emassShape(rows);
      const r443=out.filter(r=>r.dstPort==="443");
      t("eMASS shape — one row per port: four 443 flows become one", r443.length===1);
      t("eMASS shape — every service on the port is named in that row",
        r443[0].dataService==="Hypertext Transfer Protocol Secure (HTTPS); Transport Layer Security (TLS/SSL)");
      t("eMASS shape — every source and destination on the port is carried",
        r443[0].src==="10.1.1.5; 10.1.1.6; 10.1.1.9" && r443[0].dest==="10.9.9.10; 10.9.9.20");
      t("eMASS shape — an application is named once, whatever the version string",
        r443[0].appName==="Microsoft IIS/10.0; nginx/1.24");
      t("eMASS shape — a port is listed once: both directions fold into one Bi-Directional row",
        out.filter(r=>r.dstPort==="443").length===1 && emassDirectionOf(out.find(r=>r.dstPort==="443"))==="Bi-Directional");
      t("eMASS shape — rows run from lowest port to highest", out.map(r=>+r.dstPort).join(",")==="22,53,443");
      const r22=out.find(r=>r.dstPort==="22");
      t("eMASS shape — a hostname in the address cell is replaced by its address", r22.dest==="10.9.9.77");
      const cells22=emassRow(r22);
      t("eMASS export — Source/Destination and FQDN columns carry addresses only",
        cells22[10]==="10.1.1.5" && cells22[13]==="10.1.1.5" && cells22[15]==="10.9.9.77" && cells22[18]==="10.9.9.77" &&
        !emassRow(r443[0]).some(v=>/app01|\.lan/.test(String(v))));
      t("eMASS export — a joined Application cell is not truncated to 40 characters",
        emassRow(r443[0])[2]==="Microsoft IIS/10.0; nginx/1.24");
      t("eMASS shape — the register itself is untouched", rows.length===6 && rows[3].dest==="app01.lan");
      // the workbook reads back in port order with one 443 row per direction
      const xb=buildEmassXlsx({system:"T"}, out);
      const book=readXlsx(new Uint8Array(xb)); const sh=book.sheets.find(x=>/ppsm/i.test(x.name))||book.sheets[0];
      const ports=sh.rows.slice(8).filter(rw=>rw&&rw[5]).map(rw=>String(rw[5]));
      t("eMASS workbook — written in port order, one row per port", ports.join(",")==="22,53,443");
      // TCP and UDP on one port are one line reading TCP/UDP
      const dual=[
        blank({src:"10.1.1.5",dest:"10.9.9.30",proto:"TCP",dstPort:"53",dataService:"Domain Name System (DNS)",appName:"BIND 9.11",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.6",dest:"10.9.9.30",proto:"UDP",dstPort:"53",dataService:"Domain Name System (DNS)",appName:"bind 9.11.26",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.5",dest:"10.9.9.31",proto:"udp",dstPort:"88",dataService:"Kerberos Authentication (KRB5)",boundary:"B11",direction:"Outbound"}),
        blank({src:"10.1.1.5",dest:"10.9.9.31",proto:"TCP",dstPort:"88",dataService:"Kerberos Authentication (KRB5)",boundary:"B12",direction:"Outbound"})
      ];
      const d2=emassShape(dual);
      t("eMASS shape — TCP and UDP on the same port become one row", d2.length===2);
      t("eMASS shape — the combined row's protocol reads TCP/UDP", d2.find(r=>r.dstPort==="53").proto==="TCP/UDP" && emassRow(d2.find(r=>r.dstPort==="53"))[3]==="TCP/UDP");
      t("eMASS shape — the combined row names the application once and keeps every source",
        d2.find(r=>r.dstPort==="53").appName==="BIND 9.11" && d2.find(r=>r.dstPort==="53").src==="10.1.1.5; 10.1.1.6");
      t("eMASS shape — a port seen across two boundaries carries both, semicolon-joined",
        /11\. .*; 12\. /.test(emassRow(d2.find(r=>r.dstPort==="88"))[6]));
      t("eMASS shape — a consolidated register row is split so each port is listed once",
        (function(){ const rows=[
          blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"80; 443",dataService:"Hypertext Transfer Protocol (HTTP); Hypertext Transfer Protocol Secure (HTTPS)",boundary:"B11",direction:"Outbound"}),
          blank({src:"10.1.1.7",dest:"10.9.9.11",proto:"TCP",dstPort:"443",dataService:"Hypertext Transfer Protocol Secure (HTTPS)",boundary:"B11",direction:"Outbound"})];
          const o=emassShape(rows); const p443=o.find(r=>r.dstPort==="443");
          return o.length===2 && o.map(r=>r.dstPort).join(",")==="80,443" && p443.src==="10.1.1.5; 10.1.1.7" &&
                 p443.dataService==="Hypertext Transfer Protocol Secure (HTTPS)" && o.find(r=>r.dstPort==="80").dataService==="Hypertext Transfer Protocol (HTTP)"; })());
      t("eMASS shape — with one-per-port off, TCP and UDP stay separate",
        (function(){ const k=CFG.emassOnePerPort; CFG.emassOnePerPort=false; const n=emassShape(dual).length; CFG.emassOnePerPort=k; return n===4; })());
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v)); rebuildNameIndex();
      Object.assign(CFG, keep);
    })();
    (function(){
      const saved=ROWS.slice(); ROWS.length=0;
      const savedMap=new Map(HOSTMAP); HOSTMAP.set("10.9.9.77",{name:"app01.lan",sources:new Set(["test"])}); rebuildNameIndex();
      ROWS.push(blank({src:"ws01",dest:"app01.lan",proto:"TCP",dstPort:"22"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"APP01.LAN; 10.9.9.30",proto:"TCP",dstPort:"443"}));
      applyHostmap(true);
      t("Resolve — a hostname typed in the address cell becomes the address, the name kept beside it",
        ROWS[0].dest==="10.9.9.77" && ROWS[0].dstHost==="app01.lan");
      t("Resolve — a mixed address/name list is resolved name by name", ROWS[1].dest==="10.9.9.30; 10.9.9.77");
      t("Resolve — a name no source knows is left in place and reported", ROWS[0].src==="ws01" && UNRESOLVED.has("ws01"));
      ROWS.length=0; ROWS.push(...saved); HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v)); rebuildNameIndex();
    })();
    (function(){
      const savedInv=new Map(SOFTWARE_INV); SOFTWARE_INV.clear();
      const win='The following software are installed on the remote host :\n\n'+
        'Microsoft SQL Server 2019 (64-bit)  [version 15.0.2000.5]  [installed on 2021/03/02]\n'+
        'Microsoft Visual C++ 2015-2019 Redistributable (x64)  [version 14.28.29913]\n'+
        'Splunk Universal Forwarder  [version 9.1.2]\n'+
        'Tenable Nessus Agent  [version 10.4.1]\n';
      const items=softwareFromPlugin("Microsoft Windows Installed Software Enumeration (credentialed check)", win);
      t("ACAS inventory — Windows installed-software list is read with versions",
        items.length===4 && items[0].name==="Microsoft SQL Server 2019 (64-bit)" && items[0].version==="15.0.2000.5");
      const rpm='Here is the list of packages installed on the remote CentOS Linux system :\n\n'+
        '  httpd-2.4.37-47.module_el8.6.0+1111+ce6f4ceb.x86_64|(none)|1\n'+
        '  openssh-server-8.0p1-13.el8.x86_64|(none)|1\n'+
        '  bind-9.11.26-6.el8.x86_64|32|1\n';
      const r=softwareFromPlugin("Software Enumeration (SSH)", rpm);
      t("ACAS inventory — RPM package lines give name and version",
        r.length===3 && r[0].name==="httpd" && r[0].version==="2.4.37" && r[1].name==="openssh-server" && r[2].name==="bind");
      const cpe='The remote operating system matched the following CPE :\n\n  cpe:/o:microsoft:windows_server_2019\n'+
        'Following application CPE\'s matched on the remote system :\n\n  cpe:/a:apache:http_server:2.4.37\n  cpe:/a:openbsd:openssh:8.0\n';
      const c=softwareFromPlugin("Common Platform Enumeration (CPE)", cpe);
      t("ACAS inventory — CPE entries become product names", c.some(x=>x.name==="Apache Http Server" && x.version==="2.4.37") && c.some(x=>/Openssh/i.test(x.name)));
      // a .nessus file carries the inventory beside the ports
      const nx='<?xml version="1.0"?><NessusClientData_v2><Report name="t"><ReportHost name="10.9.9.40">'+
        '<HostProperties><tag name="host-ip">10.9.9.40</tag><tag name="host-fqdn">sql01.lan</tag></HostProperties>'+
        '<ReportItem port="0" svc_name="general" protocol="tcp" pluginID="20811" pluginName="Microsoft Windows Installed Software Enumeration (credentialed check)"><plugin_output>'+win.replace(/&/g,"&amp;")+'</plugin_output></ReportItem>'+
        '<ReportItem port="1433" svc_name="mssql" protocol="tcp" pluginID="22964" pluginName="Service Detection"/>'+
        '<ReportItem port="8089" svc_name="www" protocol="tcp" pluginID="22964" pluginName="Service Detection"/>'+
        '<ReportItem port="5985" svc_name="www" protocol="tcp" pluginID="22964" pluginName="Service Detection"/>'+
        '</ReportHost></Report></NessusClientData_v2>';
      const res=parseNessus(nx);
      t("ACAS inventory — read from the .nessus file and kept per host", SOFTWARE_INV.has("10.9.9.40") && SOFTWARE_INV.get("10.9.9.40").items.length===4 && /inventoried on 1 host/.test(res.note));
      const rows=res.rows; enrichRows(rows, null, false);
      const p1433=rows.find(x=>x.dstPort==="1433"), p8089=rows.find(x=>x.dstPort==="8089"), p5985=rows.find(x=>x.dstPort==="5985");
      t("ACAS inventory — the product behind the port fills Application/Software Record Name",
        p1433.appName==="Microsoft SQL Server 2019 (64-bit) 15.0.2000.5" && /software from ACAS inventory/.test(p1433.notes));
      t("ACAS inventory — matched by the service the product implies, not only by port",
        p8089.appName==="Splunk Universal Forwarder 9.1.2");
      t("ACAS inventory — a port no installed product accounts for is noted for review",
        !p5985.appName || isWeakAppName(p5985.appName,p5985) ? /no matching software/.test(p5985.notes) : true);
      t("ACAS inventory — the review check picks that row up", PPSM_CHECKS.find(x=>x.id==="swgap").test(p5985));
      // a process name from a collector is replaced by the installed product; a real product name is kept
      const c1=blank({dest:"10.9.9.40",proto:"TCP",dstPort:"1433",appName:"sqlservr",dataService:"Microsoft SQL Server (MSSQL)"});
      const c2=blank({dest:"10.9.9.40",proto:"TCP",dstPort:"1433",appName:"Microsoft SQL Server 2019 Enterprise",dataService:"Microsoft SQL Server (MSSQL)"});
      applySoftwareInventory([c1,c2]);
      t("ACAS inventory — a bare process name (sqlservr) is replaced by the installed product", /Microsoft SQL Server 2019/.test(c1.appName) && c1.appName!=="sqlservr");
      t("ACAS inventory — a product name already in the row is left alone", c2.appName==="Microsoft SQL Server 2019 Enterprise");
      // a host with no inventory is untouched
      const c3=blank({dest:"10.9.9.41",proto:"TCP",dstPort:"1433",appName:"sqlservr"});
      applySoftwareInventory([c3]);
      t("ACAS inventory — hosts the scan did not inventory are not touched", c3.appName==="sqlservr" && !/ACAS inventory/.test(c3.notes||""));
      // the Tenable CSV export carries the same plugin
      const csv='"Plugin ID","CVE","Risk","Host","Protocol","Port","Name","Plugin Output"\n'+
        '"20811","","None","10.9.9.42","tcp","0","Microsoft Windows Installed Software Enumeration (credentialed check)","'+win.replace(/"/g,'""')+'"\n'+
        '"22964","","None","10.9.9.42","tcp","1433","Service Detection","A MSSQL server is running on this port."\n';
      const tr=parseFile("findings.csv", csv);
      t("ACAS inventory — read from a Tenable CSV findings export, multi-line Plugin Output included",
        SOFTWARE_INV.has("10.9.9.42") && SOFTWARE_INV.get("10.9.9.42").items.length===4 && tr.rows.some(x=>x.dstPort==="1433"));
      SOFTWARE_INV.clear(); savedInv.forEach((v,k)=>SOFTWARE_INV.set(k,v));
    })();
    (function(){
      const saved=ROWS.slice(); ROWS.length=0;
      // exact duplicate from two tools, one with enclave filled, hostname case differs
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"TCP",dstPort:"443",origin:"netstat",direction:"Outbound"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.10",proto:"tcp",dstPort:"443",origin:"showconn",direction:"Inbound",enclave:"DMZ",appName:"nginx"}));
      ROWS.push(blank({srcHost:"WS01.lan.",dest:"10.9.9.10",proto:"TCP",dstPort:"22",origin:"zeek"}));
      ROWS.push(blank({srcHost:"ws01.lan",dest:"10.9.9.10",proto:"TCP",dstPort:"22",origin:"netflow"}));
      let removed=dedupeRows();
      t("Dedupe — same flow from two tools is one row", removed===2 && ROWS.length===2);
      const k=ROWS.find(r=>r.dstPort==="443");
      t("Dedupe — the kept row is filled from the dropped one", k && k.enclave==="DMZ" && k.appName==="nginx");
      t("Dedupe — origin tools are merged", k && k.origin.indexOf("netstat")>=0 && k.origin.indexOf("showconn")>=0);
      t("Dedupe — hostnames match regardless of case and trailing dot", ROWS.filter(r=>r.dstPort==="22").length===1);
      // contained rows after consolidation
      ROWS.length=0;
      ROWS.push(blank({src:"10.1.1.5; 10.1.1.6",dest:"10.9.9.20",proto:"TCP",dstPort:"80; 443",origin:"netflow"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"TCP",dstPort:"443",origin:"netstat"}));
      ROWS.push(blank({dest:"10.9.9.20",proto:"TCP",dstPort:"80",origin:"netstat-listen",direction:"Inbound"}));
      ROWS.push(blank({src:"10.1.1.7",dest:"10.9.9.20",proto:"TCP",dstPort:"443",origin:"netstat"}));
      ROWS.push(blank({src:"10.1.1.5",dest:"10.9.9.20",proto:"UDP",dstPort:"443",origin:"netstat"}));
      removed=dedupeRows();
      t("Dedupe — a row already covered by a consolidated row is removed", removed===2 && ROWS.length===3);
      t("Dedupe — a source the wide row does not carry keeps its row", ROWS.some(r=>r.src==="10.1.1.7"));
      t("Dedupe — a different protocol keeps its row", ROWS.some(r=>r.proto==="UDP"));
      ROWS.length=0; ROWS.push(...saved);
    })();

    /* ---- v3: XML safety, boundaries, eMASS, environment diagram ---- */
    t("Control characters stripped for XML output",
      xmlClean("a\u0000b\u001Bc\u000Bd")==="abcd");
    t("ANSI terminal escape sequences removed",
      xmlClean("\u001B[32mTCP outside\u001B[0m")==="TCP outside");
    (function(){
      const dirty=blank({dest:"10.0.0.1",proto:"TCP",dstPort:"443",boundary:"B18",
        notes:"\u001B[1;33mflags UIO\u001B[0m", banner:"srv\u0000\u0008x"});
      const xb=buildXlsx({system:"selftest"},[dirty]);
      t("Excel export survives terminal/binary junk in the data",
        xb && xb.length>500 && xb[0]===0x50 && xb[1]===0x4b);
      const txt=new TextDecoder().decode(xb);
      t("Excel package carries no XML-illegal control characters",
        !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(txt.replace(/[\s\S]*?<sheetData>/,"").split("</sheetData>")[0]||""));
    })();

    t("Official boundary set has 19 entries", BND_DEFS.length===19);
    t("Boundary code accepted in every written form",
      bndCode("B11")==="B11" && bndCode("11")==="B11" &&
      bndCode("11. Enclave GW to Enclave (In)")==="B11");
    t("Legacy 'Internal only' now resolves to Internal, not a B number",
      bndCode("Internal only")===INTERNAL_BND);
    t("Internal traffic carries no B number", !/^B\d/.test(bndCode("Internal")));
    t("Internal-to-internal derives as Internal, never a DISN boundary",
      deriveBoundary(blank({src:"10.1.1.5",dest:"10.2.2.7"}))===INTERNAL_BND);
    t("A public destination still derives a crossing",
      deriveBoundary(blank({src:"10.1.1.5",dest:"8.8.8.8"}))==="B14");
    t("Firewall zone names no longer force a boundary on internal traffic",
      deriveBoundary(blank({src:"10.1.1.5",dest:"10.2.2.7",srcZone:"inside",dstZone:"dmz"}))===INTERNAL_BND);
    t("Internal Use Only boundaries are not flagged as crossings",
      FLAGGED("B18")===false && FLAGGED("B11")===true);

    (function(){
      const r=blank({src:"10.20.10.50",srcHost:"wks-050.range.mil",dest:"10.20.30.15",
        dstHost:"sql01.range.mil",proto:"TCP",dstPort:"1433",dataService:"ms-sql-s",
        boundary:"B11",justification:"Mission database access"});
      const er=emassRow(r);
      t("eMASS — the template's 21 columns, A to U", er.length===21 && EMASS_HEADERS.length===21);
      t("eMASS — the columns are in the template's own order",
        EMASS_HEADERS[6]==="Boundary" && EMASS_HEADERS[7]==="Direction" &&
        EMASS_HEADERS[10]==="Source" && EMASS_HEADERS[15]==="Destination" &&
        EMASS_HEADERS[19]==="Connection Logical Destination Point" && EMASS_HEADERS[20]==="Purpose");
      t("eMASS — the boundary is written as the official string",
        er[6]==="11. Enclave GW to Enclave (In)");
      t("eMASS — with IP addresses only (the default) Source/Destination and FQDN carry the address",
        er[10]==="10.20.10.50" && er[13]==="10.20.10.50" && er[15]==="10.20.30.15" && er[18]==="10.20.30.15");
      (function(){ const k=CFG.emassIpOnly; CFG.emassIpOnly=false; const en=emassRow(r); CFG.emassIpOnly=k;
        t("eMASS — with IP-only off, source and destination carry the name, with the FQDN beside them",
          en[10]==="wks-050.range.mil" && en[13]==="wks-050.range.mil" && en[15]==="sql01.range.mil" && en[18]==="sql01.range.mil"); })();
      t("eMASS — a direction is always given, since the importer requires one",
        /^(Inbound|Outbound|Bi-Directional)$/.test(er[7]));
      t("eMASS — character limits from the Instructions sheet are enforced", (function(){
        const long=blank({dest:"10.9.9.9",proto:"TCP",dstPort:"443",
          appName:"x".repeat(80), justification:"y".repeat(1200)});
        const e=emassRow(long);
        return e[2].length===40 && e[20].length===1000; })());
      t("eMASS — an internal row exports as an Internal Use boundary, not a blank", (function(){
        const e=emassRow(blank({src:"10.1.1.5",dest:"10.1.1.6",proto:"TCP",dstPort:"445",
          boundary:INTERNAL_BND}));
        return /Internal Use/i.test(e[6]); })());
      const xb=buildEmassXlsx({system:"selftest"},[r]);
      t("eMASS — the workbook builds with all three sheets",
        xb && xb.length>2000 && xb[0]===0x50 && xb[1]===0x4b);
      // the register cells carry Excel dropdowns, via defined names so they
      // render in every version
      const xml=new TextDecoder().decode(xb);
      const zip=new TextDecoder().decode(xb);
      t("eMASS — seven dropdown columns are declared", (function(){
        const s=inflateFromXlsx(xb,"xl/worksheets/sheet1.xml");
        return s && (s.match(/<dataValidation /g)||[]).length===7; })());
      t("eMASS — short lists are inline, long lists reference the Glossary", (function(){
        const s=inflateFromXlsx(xb,"xl/worksheets/sheet1.xml");
        return s && /formula1>"External Services,Least Function"/.test(s) &&   // Type inline
               /formula1>"Bi-Directional,Inbound,Outbound"/.test(s) &&          // Direction inline
               /Glossary!\$G\$2:\$G\$24/.test(s) &&                          // VPN type range
               /Glossary!\$C\$2:\$C\$27/.test(s); })());                     // source point range
      t("eMASS — dropdowns use the Excel-native shape (sqref first, showDropDown 0)", (function(){
        const s=inflateFromXlsx(xb,"xl/worksheets/sheet1.xml");
        return s && /<dataValidation sqref="[^"]+" showDropDown="0"/.test(s); })());
      t("eMASS — the workbook is deflate-compressed, as Excel writes it", (function(){
        // local file header at offset 0: bytes 8-9 are the compression method (8 = deflate)
        return xb[8]===8 && xb[9]===0; })());
      t("eMASS — the header row carries Excel filter dropdowns", (function(){
        const s=inflateFromXlsx(xb,"xl/worksheets/sheet1.xml");
        // filter on row 8 across all 21 columns, placed before dataValidations
        return s && /<autoFilter ref="A8:U\d+"\/>/.test(s) &&
               s.indexOf("<autoFilter")<s.indexOf("<dataValidations"); })());
      t("eMASS — Protocol never exports a '?' or a number", (function(){
        const e=emassRow(blank({dest:"10.9.9.9",proto:"?",dstPort:"443"}));
        const e2=emassRow(blank({dest:"10.9.9.9",proto:"6",dstPort:"443"}));
        return e[3]==="" && e2[3]==="TCP"; })());
      t("eMASS — a consolidated Port cell is not truncated at 20 chars", (function(){
        const e=emassRow(blank({dest:"10.9.9.9",proto:"TCP",dstPort:"443; 8443; 8530; 8531; 9997"}));
        return e[5]==="443; 8443; 8530; 8531; 9997"; })());
    })();

    (function(){
      const saved=ROWS.slice();
      ROWS.length=0;
      ROWS.push(blank({enclave:"ALPHA",src:"10.1.1.5",dest:"10.2.2.7",proto:"TCP",dstPort:"1433",boundary:"B11"}),
                blank({enclave:"ALPHA",src:"10.1.1.5",dest:"10.3.3.3",proto:"TCP",dstPort:"443",boundary:"B8"}));
      const em=envModel(ROWS);
      t("Environment diagram maps boundaries to connection points",
        em.pts.has("ENCGW") && em.pts.has("ENC") && em.pts.has("DISN"));
      t("Environment diagram omits connection points with no traffic", !em.pts.has("DODGW"));
      const sv=svgEnvironment();
      t("Environment diagram renders valid SVG from the register",
        /^<svg/.test(sv) && sv.indexOf("ALPHA")>=0 && /<\/svg>$/.test(sv.trim()));
      ROWS.length=0; ROWS.push(...saved);
    })();

    (function(){
      const spaced="#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service\n"+
                   "1 C1 10.1.1.5 52341 10.2.2.7 443 tcp ssl\n";
      const z=parseZeek(spaced);
      t("Zeek log still parses when tabs were lost (PDF/Word round trip)",
        z.rows.length===1 && z.rows[0].dstPort==="443");
    })();
    t("PDF upload is identified and explained rather than failing vaguely",
      /PDF, not a log file/.test(diagnoseFile("conn.pdf","%PDF-1.7\n%\u00e2\u00e3\u00cf\u00d3\n")));

    /* ---- hostname / endpoint discovery ---- */
    t("Hostname columns present in the export model",
      COLS.some(c=>c[0]==="srcHost") && COLS.some(c=>c[0]==="dstHost"));
    t("IP and hostname told apart", isIP("10.1.1.5")===true && isIP("srv01.lan")===false);
    t("Combined 'IP (host)' value splits into two fields", (function(){
      const r=normalizeEndpoints(blank({dest:"10.2.2.7 (web01.lan)"}));
      return r.dest==="10.2.2.7" && r.dstHost==="web01.lan"; })());

    (function(){
      const savedMap=new Map(HOSTMAP);
      HOSTMAP.clear();
      const hf=parseHostsFile("127.0.0.1 localhost\n10.20.30.15 sql01.range.mil\n10.20.10.50 wks-050.range.mil\n");
      t("hosts file — names learned, loopback ignored", hf.names===2 && !HOSTMAP.has("127.0.0.1"));
      HOSTMAP.clear();
      const dz=parseDnsZone("$ORIGIN range.mil.\nsql01 IN A 10.20.30.15\n");
      t("DNS zone — record learned with origin appended",
        dz.names===1 && HOSTMAP.get("10.20.30.15").name==="sql01.range.mil");
      HOSTMAP.clear();
      const dl=parseDhcpLeases('lease 10.20.10.60 {\n client-hostname "wks-060";\n}\n');
      t("DHCP leases — client hostname learned", dl.names===1);
      HOSTMAP.clear();
      const inv=parseInventoryCsv("Name,DNSHostName,IPv4Address,OperatingSystem\nSQL01,sql01.range.mil,10.20.30.15,Windows Server 2022\n");
      t("Inventory CSV — hostname and OS learned",
        inv.names===1 && HOSTMAP.get("10.20.30.15").os==="Windows Server 2022");
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
    })();

    (function(){
      const saved=ROWS.slice(), savedMap=new Map(HOSTMAP);
      ROWS.length=0; HOSTMAP.clear();
      ROWS.push(blank({src:"10.20.10.50",dest:"10.20.30.15",proto:"TCP",dstPort:"1433",dataService:"ms-sql-s"}));
      ROWS.push(blank({src:"10.20.10.77",dest:"10.20.30.15",proto:"TCP",dstPort:"1433",dataService:"ms-sql-s"}));
      parseHostsFile("10.20.30.15 sql01.range.mil\n");
      const n=applyHostmap(true);
      t("Host inventory resolves names into the register", n===2 && ROWS[0].dstHost==="sql01.range.mil");
      const eps=buildEndpoints();
      t("Endpoint discovery — distinct systems identified", eps.length===3);
      const srv=eps.find(e=>e.ip==="10.20.30.15");
      t("Endpoint discovery — server role and peer count correct",
        srv && srv.role==="Server" && srv.peers.size===2);
      t("Endpoint discovery — services offered captured",
        srv && [...srv.services.keys()].some(k=>k.indexOf("1433")>=0));
      const st=endpointStats(eps);
      t("Endpoint discovery — identification coverage reported",
        st.total===3 && st.named===1 && st.unnamed===2);
      ROWS.length=0; ROWS.push(...saved);
      HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
    })();

    /* ---- hostnames in the register, resolved through DNS exports ---- */
    (function(){
      const saved=ROWS.slice(), savedMap=new Map(HOSTMAP), savedAl=new Map(ALIASES);
      ROWS.length=0; HOSTMAP.clear(); ALIASES.clear();
      try{
        const em=parseFile("register.csv",
          "Type,Application/Software Record Name,Protocol,Data Service,Port,Boundary,Direction,VPN / Encrypted Tunnel Traffic,VPN Tunnel Type,Source IP Address,Source FQDN,Connection Logical Source Point,Destination IP Address,Destination FQDN,Connection Logical Destination Point,Source Physical Location or Cloud Service Provider,Destination Physical Location or Cloud Service Provider,Purpose\n"+
          "Local Service,WSUS,TCP,wsus,8530,18,Inbound,No,,analyst61,analyst61.range2.mil,Enclave,wsus11,wsus11.range2.mil,Enclave,B1,B1,Patching\n"+
          "Local Service,LDAP,TCP,ldaps,636,18,Inbound,No,,analyst61; analyst63,,Enclave,addc20.range2.mil,,Enclave,B1,B1,Auth\n"+
          "Local Service,Syslog,UDP,syslog,514,18,Inbound,No,,FWD70,,Enclave,SYSLOG05.RANGE2.MIL.,,Enclave,B1,B1,Logs\n");
        t("Register with hostnames in the address columns — read as an eMASS export, not a NetFlow report",
          em.kind==="eMASS PPSM export" && em.rows.length>=4);
        t("Register with hostnames — name kept when it sits in the IP column",
          em.rows.some(r=>r.srcHost==="analyst61.range2.mil" && r.dstHost==="wsus11.range2.mil" && !r.src && !r.dest));
        t("Register with hostnames — semicolon-joined sources become one endpoint each",
          em.rows.filter(r=>r.dstHost==="addc20.range2.mil").length===2);
        t("Register with hostnames — trailing dot and upper case normalised",
          em.rows.some(r=>r.dstHost==="syslog05.range2.mil"));

        const sc=parseFile("fw-showconn.txt",
          "TCP dmz wsus11:8530 inside analyst61:51616, idle 0:00:01, bytes 10240, flags UIO\n");
        t("show conn with 'names' configured — hostnames read in place of addresses",
          sc.kind==="show-conn" && sc.rows.length===1 && sc.rows[0].dest==="wsus11" && sc.rows[0].dstPort==="8530");

        const dm=parseFile("dns-manager-export.csv",
          "Name,Type,Data,Timestamp\nwsus11,Host (A),172.22.40.11,static\naddc20,Host (A),172.22.40.20,static\n"+
          "rr,Host (A),\"172.22.40.50; 172.22.40.51\",static\npatch,Alias (CNAME),wsus11.range2.mil.,static\nupdates,Alias (CNAME),patch,static\n"+
          "(same as parent folder),Start of Authority (SOA),\"[5], addc20.range2.mil., hostmaster.range2.mil.\",static\n");
        t("DNS Manager export — zone inferred from the SOA row, short names qualified",
          dm.kind==="DNS export" && HOSTMAP.get("172.22.40.11") && HOSTMAP.get("172.22.40.11").name==="wsus11.range2.mil");
        t("DNS Manager export — a round-robin name with two addresses learns both",
          HOSTMAP.has("172.22.40.50") && HOSTMAP.has("172.22.40.51"));
        t("DNS export — a CSV cell with spaces is not split into words", splitDnsLine("x,Start of Authority (SOA),y").length===3);
        rebuildNameIndex();
        t("CNAME chain — updates -> patch -> wsus11 resolves to the address", lookupName("updates.range2.mil")==="172.22.40.11");

        HOSTMAP.clear(); ALIASES.clear();
        const fz=parseFile("range2.mil.csv","Name,Type,Data\nntp30,A,172.22.40.30\n");
        t("DNS export — zone taken from a file named after the zone",
          fz.kind==="DNS export" && HOSTMAP.get("172.22.40.30") && HOSTMAP.get("172.22.40.30").name==="ntp30.range2.mil");

        HOSTMAP.clear(); ALIASES.clear(); ROWS.length=0;
        parseFile("range2.mil.csv","Name,Type,Data\nanalyst61,A,172.22.14.61\nanalyst63,A,172.22.14.63\naddc20,A,172.22.40.20\nanalyst62,A,172.22.14.62\n");
        ROWS.push(blank({srcHost:"analyst61; analyst63",dstHost:"addc20",proto:"TCP",dstPort:"636"}));
        ROWS.push(blank({srcHost:"mystery01",dstHost:"addc20.range2.mil",proto:"TCP",dstPort:"88"}));
        ROWS.push(blank({src:"172.22.14.62",srcHost:"analyst99",dest:"172.22.40.20",dstHost:"addc20.range2.mil",proto:"TCP",dstPort:"389"}));
        applyHostmap(true);
        t("Resolve — semicolon-joined hostnames become semicolon-joined addresses", ROWS[0].src==="172.22.14.61; 172.22.14.63" && ROWS[0].dest==="172.22.40.20");
        t("Resolve — a name no source knows is reported, not guessed", !ROWS[1].src && UNRESOLVED.has("mystery01") && LAST_RESOLVE.unresolved===1);
        t("Resolve — a hostname that disagrees with DNS for its address is flagged, not rewritten",
          ROWS[2].srcHost==="analyst99" && /name\/address check/.test(ROWS[2].notes) && LAST_RESOLVE.conflicts===1);
        const eps=buildEndpoints();
        const nameOnly=eps.find(e=>e.noAddr && /mystery01/i.test(e.host));
        t("Endpoints — a hostname with no address is listed as a system to resolve", !!nameOnly && endpointStats(eps).noAddr===1);
        t("Review check — hostname with no IP address raised", PPSM_CHECKS.find(c=>c.id==="noaddr").test(ROWS[1])===true);
        t("Review check — name/DNS disagreement raised", PPSM_CHECKS.find(c=>c.id==="namecheck").test(ROWS[2])===true);
      } finally {
        ROWS.length=0; ROWS.push(...saved);
        HOSTMAP.clear(); savedMap.forEach((v,k)=>HOSTMAP.set(k,v));
        ALIASES.clear(); savedAl.forEach((v,k)=>ALIASES.set(k,v));
        rebuildNameIndex();
      }
    })();
  }catch(err){ t("Unexpected error: "+err.message, false); }
  if(conns) conns.checked=prev;

  const pass=R.filter(r=>r.ok).length, fail=R.length-pass;
  $("stBody").innerHTML=
    `<div class="st-summary ${fail?'bad':'ok'}">${fail?('✗ '+fail+' of '+R.length+' checks FAILED — see below'):('✓ All '+R.length+' checks passed — the tool is working in this browser')}</div>`+
    `<div class="st-meta">${esc(navigator.userAgent)}</div>`+
    R.map(r=>`<div class="st-row ${r.ok?'ok':'bad'}"><span>${r.ok?'\u2713':'\u2717'}</span>${esc(r.n)}</div>`).join("");
  $("stModal").hidden=false;
}
$("stBtn").onclick=runSelfTest;
$("stClose").onclick=()=>$("stModal").hidden=true;
$("stModal").addEventListener("click",e=>{ if(e.target===$("stModal")) $("stModal").hidden=true; });
