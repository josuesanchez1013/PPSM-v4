"use strict";
/* ---------------- state ---------------- */
let ROWS = [];
const SELECTED = new Set();   // row ids checked for bulk operations
let rid = 0;

/* Official PPSM boundary set. Codes B1-B16 are the sixteen directional
   crossings from the PPSM Network Boundary Definitions; B17-B19 are the
   Internal Use Only forms the eMASS import template adds. `emass` is the exact
   string eMASS expects, `from`/`to` are the connection points the crossing
   joins, and `ao` marks the crossings that are always AO responsibility. */
const BND_DEFS = [
  {code:"B1", emass:"1. Ext to DoD GW (In)",              from:"EXT",  to:"DODGW"},
  {code:"B2", emass:"2. DoD GW to Ext (Out)",             from:"DODGW",to:"EXT"},
  {code:"B3", emass:"3. DoD GW to DoD DMZ or RDTE (In)",  from:"DODGW",to:"DODDMZ"},
  {code:"B4", emass:"4. DoD DMZ or RDTE to DoD GW (Out)", from:"DODDMZ",to:"DODGW"},
  {code:"B5", emass:"5. DoD GW to DISN (In)",             from:"DODGW",to:"DISN"},
  {code:"B6", emass:"6. DISN to DoD GW (Out)",            from:"DISN", to:"DODGW"},
  {code:"B7", emass:"7. DISN to Enclave GW (In)",         from:"DISN", to:"ENCGW"},
  {code:"B8", emass:"8. Enclave GW to DISN (Out)",        from:"ENCGW",to:"DISN"},
  {code:"B9", emass:"9. Enclave GW to Enclave DMZ (In)",  from:"ENCGW",to:"ENCDMZ", ao:true},
  {code:"B10",emass:"10. Enclave DMZ to Enclave GW (Out)",from:"ENCDMZ",to:"ENCGW", ao:true},
  {code:"B11",emass:"11. Enclave GW to Enclave (In)",     from:"ENCGW",to:"ENC",    ao:true},
  {code:"B12",emass:"12. Enclave to Enclave GW (Out)",    from:"ENC",  to:"ENCGW",  ao:true},
  {code:"B13",emass:"13. Ext ISP to Enclave GW (In)",     from:"ISP",  to:"ENCGW",  ao:true, waiver:true},
  {code:"B14",emass:"14. Enclave GW to Ext ISP (Out)",    from:"ENCGW",to:"ISP",    ao:true, waiver:true},
  {code:"B15",emass:"15. Multiple AO E2E Tunnel",         from:"ENCGW",to:"ENCGW",  tunnel:true},
  {code:"B16",emass:"16. Single AO E2E Tunnel",           from:"ENCGW",to:"ENCGW",  tunnel:true, ao:true},
  {code:"B17",emass:"17. Internal Use Only (Closed Environment – No Network)", from:"ENC", to:"ENC", internal:true},
  {code:"B18",emass:"18. Internal Use Only (DoD Network)",                     from:"ENC", to:"ENC", internal:true},
  {code:"B19",emass:"19. Internal Use Only (External Network)",                from:"ENC", to:"ENC", internal:true}
];
const BND_BY_CODE = {}; BND_DEFS.forEach(b=>BND_BY_CODE[b.code]=b);

/* Accepts a code (B11), a bare number (11), the full eMASS string, or one of
   the legacy tags earlier versions wrote, and returns the canonical code. */
function bndCode(v){
  if(!v) return "";
  const s=String(v).trim();
  if(/^internal$/i.test(s) || /^internal only$/i.test(s)) return INTERNAL_BND;
  if(BND_BY_CODE[s.toUpperCase()]) return s.toUpperCase();
  let m=s.match(/^B?(\d{1,2})\b/i);
  if(m && BND_BY_CODE["B"+m[1]]) return "B"+m[1];
  return "";
}
function isInternalBnd(v){ return bndCode(v)===INTERNAL_BND; }
function bndLabel(v){
  if(isInternalBnd(v)) return "Internal (no CAL boundary crossed)";
  const b=BND_BY_CODE[bndCode(v)]; return b?b.emass:(v||"");
}
function bndShort(v){ const b=BND_BY_CODE[bndCode(v)];
  return b? (b.code+" — "+b.emass.replace(/^\d+\.\s*/,"")) : (v||""); }

/* value is the bare code so nothing but ASCII reaches the data; the label
   carries the full official wording for the person reading the dropdown. */
/* "Internal" is the honest answer for traffic that never crosses a
   CAL-defined boundary, and it is deliberately not a B number. Per the PPSM
   boundary definitions, internal means not crossing any CAL boundary,
   including the Enclave Gateway (11/12) and the Enclave DMZ (9/10). */
const INTERNAL_BND = "Internal";
const BOUNDARIES = [{value:"",label:"— not set —"},
  {value:INTERNAL_BND, label:"Internal — no CAL boundary crossed"}].concat(
  BND_DEFS.map(b=>({value:b.code, label:b.code+" \u2014 "+b.emass.replace(/^\d+\.\s*/,"")})));

/* Connection point display names, used by the environment diagram */
const CP_NAME = {EXT:"External Network", DODGW:"DoD Gateway", DODDMZ:"DoD-level DMZ",
  RDTE:"RDT&E", DISN:"DISN", ENCGW:"Enclave Gateway", ENCDMZ:"Enclave DMZ",
  ENC:"Enclave", ISP:"Commercial ISP / Approved Gateway"};
const CROSS_DISN = new Set(["B1","B2","B3","B4","B5","B6","B7","B8","B15"]);
// Flagged crossings: between enclaves, across an approved system interconnection, or over the DISN.
/* A crossing that leaves the enclave is what reviewers focus on. The three
   Internal Use Only boundaries stay inside it, so they are not flagged. */
/* Only a real boundary crossing is worth a reviewer's attention. Internal
   traffic is not one. */
function FLAGGED(b){
  const c=bndCode(b);
  if(c===INTERNAL_BND) return false;
  if(!c){
    // tags written by older versions: not internal, so still worth reviewing
    return b==="Inter-enclave" || b==="Interconnection";
  }
  return !(BND_BY_CODE[c]||{}).internal;
}
const CLASS = ["",
  "UNCLASSIFIED",
  "UNCLASSIFIED//FOUO",
  "CUI",
  "CONFIDENTIAL",
  "CONFIDENTIAL//NOFORN",
  "CONFIDENTIAL//REL TO USA, FVEY",
  "SECRET",
  "SECRET//NOFORN",
  "SECRET//ORCON",
  "SECRET//ORCON/NOFORN",
  "SECRET//PROPIN",
  "SECRET//RELIDO",
  "SECRET//IMCON/NOFORN",
  "SECRET//FISA",
  "SECRET//REL TO USA, FVEY",
  "SECRET//SI//NOFORN",
  "SECRET//SI/TK//NOFORN",
  "SECRET//SAR-[PROGRAM]//NOFORN",
  "TOP SECRET",
  "TOP SECRET//NOFORN",
  "TOP SECRET//ORCON/NOFORN",
  "TOP SECRET//SI//NOFORN",
  "TOP SECRET//TK//NOFORN",
  "TOP SECRET//SI/TK//NOFORN",
  "TOP SECRET//SI/TK//ORCON/NOFORN",
  "TOP SECRET//SI/TK//REL TO USA, FVEY",
  "TOP SECRET//HCS//NOFORN",
  "TOP SECRET//HCS-O//ORCON/NOFORN",
  "TOP SECRET//HCS/SI/TK//ORCON/NOFORN",
  "TOP SECRET//SI-G [COMPARTMENT]//NOFORN",
  "TOP SECRET//KDK//NOFORN",
  "TOP SECRET//SI/TK//SAR-[NICKNAME]//ORCON/NOFORN"];
/* superseded by ASSURANCE_LIST (CAL colour designations); kept so older
   sessions that stored one of these strings still load without loss */
const ASSURANCE_LEGACY = ["","Acceptable","Acceptable w/ mitigation","Emerging","Unacceptable","Unassigned"];
const ASSURANCE = ASSURANCE_LEGACY;
const STATUS = ["New","Registered","Pending VA","Pending CLSA","Exception"];
const DIRECTION = ["","Inbound","Outbound","Bidirectional","Listening"];
const CAL = ["","Y","N","Pending"];

/* ---------------- helpers ---------------- */
const $ = id => document.getElementById(id);
function esc(s){return (s==null?"":String(s)).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

/* XML 1.0 forbids most control characters. Terminal session logs (ANSI colour
   codes), pcap banners and binary-ish scan output all carry them, and a single
   one makes Excel refuse the whole workbook with "unreadable content". Strip
   them everywhere a value can reach a file. */
const XML_ILLEGAL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uFFFE\uFFFF]/g;
function xmlClean(s){
  if(s==null) return "";
  return String(s)
    .replace(/\u001B\[[0-9;?]*[ -\/]*[@-~]/g, "")   // ANSI/VT escape sequences
    .replace(/\r\n?/g, "\n")                        // normalise line endings
    .replace(XML_ILLEGAL, "")                        // anything still illegal
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, "")   // lone high surrogate
    .replace(/(?:^|[^\uD800-\uDBFF])([\uDC00-\uDFFF])/g, "$1".replace(/./,"")); // lone low
}
/* escape for XML output, control characters removed first */
function xesc(s){ return esc(xmlClean(s)); }

/* Typographic characters survive UTF-8 fine but render as "?" in Excel on a
   lot of DoD desktops, so register exports fold them to ASCII by default.
   The eMASS template keeps its exact official wording. */
const ASCII_FOLD = [[/[\u2014\u2013\u2212]/g,"-"],[/[\u2018\u2019\u201B]/g,"'"],
  [/[\u201C\u201D]/g,'"'],[/\u2026/g,"..."],[/[\u00B7\u2022]/g,"-"],
  [/\u2192/g,"->"],[/\u00A0/g," "],[/[\u2264]/g,"<="],[/[\u2265]/g,">="]];
function asciiSafe(s){
  let v=xmlClean(s);
  if(CFG.asciiExports===false) return v;
  ASCII_FOLD.forEach(([re,to])=>{ v=v.replace(re,to); });
  return v.replace(/[^\x09\x0A\x0D\x20-\x7E]/g,"");
}
/* Protocol arrives as a name, an IANA number, or "?" / "unknown" from a
   scanner that could not tell. Map the common numbers, and treat anything it
   does not recognise as blank rather than carrying a "?" into the register. */
const PROTO_NUM={"1":"ICMP","2":"IGMP","6":"TCP","17":"UDP","41":"IPv6","47":"GRE",
  "50":"ESP","51":"AH","58":"ICMPv6","89":"OSPF","103":"PIM","112":"VRRP","132":"SCTP"};
function normProto(v){
  let s=String(v==null?"":v).trim().toUpperCase();
  if(!s || s==="?" || s==="UNKNOWN" || s==="N/A" || s==="-") return "";
  if(PROTO_NUM[s]) return PROTO_NUM[s];
  s=s.replace(/[^A-Z0-9]/g,"");                 // drop a stray "?" glued to a name
  if(PROTO_NUM[s]) return PROTO_NUM[s];
  return s;
}

/* ============================================================
   APPLICATION / SOFTWARE NAME -> COMMON SERVICE NAME
   A scan reports a product ("Microsoft SQL Server 2019",
   "Apache/2.4.57", "OpenSSH_8.7") in the Application/Software Record
   Name. PPSM wants the common service name in Data Service. This maps
   the product to the service, and gives the service its usual port
   where the row has none.

   Matching is case-insensitive, on a normalised form (letters and
   digits only), longest pattern first, so "microsoft sql server"
   wins over a bare "sql". The table is deliberately broad: web and
   app servers, databases, directory and auth, mail, remote access,
   management and monitoring, virtualisation and containers, data
   stores and brokers, VoIP, file and print, backup, security tooling,
   and the DoD/enterprise products that turn up on government networks.
   ============================================================ */

/* pattern (normalised substring)  ->  [service, default port or ""] */
const APP_SERVICE_TABLE = [
  // ---- web / application servers ----
  ["microsoftiis",        ["http","80"]], ["internetinformationservices",["http","80"]],
  ["apachetomcat",        ["http","8080"]], ["apachehttpd",["http","80"]], ["apachehttp",["http","80"]],
  ["apache",              ["http","80"]], ["nginx",["http","80"]], ["lighttpd",["http","80"]],
  ["openresty",           ["http","80"]], ["jetty",["http","8080"]], ["jboss",["http","8080"]],
  ["wildfly",             ["http","8080"]], ["glassfish",["http","4848"]], ["weblogic",["http","7001"]],
  ["websphere",           ["http","9080"]], ["caddy",["http","80"]], ["gunicorn",["http","8000"]],
  ["kestrel",             ["http","5000"]], ["nodejs",["http","3000"]], ["node.js",["http","3000"]],
  ["express",             ["http","3000"]], ["haproxy",["http","80"]], ["traefik",["http","80"]],
  ["varnish",             ["http","80"]], ["squid",["squid-proxy","3128"]],
  // ---- databases ----
  ["microsoftsqlserver",  ["ms-sql-s","1433"]], ["mssqlserver",["ms-sql-s","1433"]], ["sqlserver",["ms-sql-s","1433"]],
  ["oracledatabase",      ["oracle","1521"]], ["oracletns",["oracle","1521"]], ["oraclexe",["oracle","1521"]],
  ["oracle",              ["oracle","1521"]], ["mysql",["mysql","3306"]], ["mariadb",["mysql","3306"]],
  ["percona",             ["mysql","3306"]], ["postgresql",["postgresql","5432"]], ["postgres",["postgresql","5432"]],
  ["mongodb",             ["mongodb","27017"]], ["redis",["redis","6379"]], ["memcached",["memcached","11211"]],
  ["cassandra",           ["cassandra","9042"]], ["couchdb",["couchdb","5984"]], ["couchbase",["couchbase","8091"]],
  ["elasticsearch",       ["elasticsearch","9200"]], ["opensearch",["elasticsearch","9200"]],
  ["influxdb",            ["influxdb","8086"]], ["db2",["db2","50000"]], ["sybase",["sybase","2638"]],
  ["saphana",             ["saphana","30015"]], ["cockroachdb",["postgresql","26257"]], ["neo4j",["neo4j","7474"]],
  ["clickhouse",          ["clickhouse","8123"]], ["firebird",["firebird","3050"]],
  // ---- directory / auth / identity ----
  ["activedirectory",     ["ldap","389"]], ["domaincontroller",["ldap","389"]],
  ["openldap",            ["ldap","389"]], ["389directory",["ldap","389"]], ["freeipa",["ldap","389"]],
  ["kerberos",            ["kerberos","88"]], ["keycloak",["http","8080"]], ["okta",["https","443"]],
  ["pingfederate",        ["https","9031"]], ["adfs",["https","443"]], ["radius",["radius","1812"]],
  ["freeradius",          ["radius","1812"]], ["tacacs",["tacacs","49"]], ["ciscoise",["radius","1812"]],
  ["vaultbyhashicorp",    ["vault","8200"]], ["hashicorpvault",["vault","8200"]], ["cyberark",["https","443"]],
  // ---- remote access / display ----
  ["openssh",             ["ssh","22"]], ["opensshserver",["ssh","22"]], ["dropbear",["ssh","22"]],
  ["sshd",                ["ssh","22"]], ["telnet",["telnet","23"]],
  ["remotedesktop",       ["ms-wbt-server","3389"]], ["terminalservices",["ms-wbt-server","3389"]],
  ["rdp",                 ["ms-wbt-server","3389"]], ["xrdp",["ms-wbt-server","3389"]],
  ["vnc",                 ["vnc","5900"]], ["realvnc",["vnc","5900"]], ["tightvnc",["vnc","5900"]],
  ["ultravnc",            ["vnc","5900"]], ["tigervnc",["vnc","5900"]], ["teamviewer",["teamviewer","5938"]],
  ["anydesk",             ["https","443"]], ["pcanywhere",["pcanywhere","5631"]], ["radmin",["radmin","4899"]],
  ["citrix",              ["citrix-ica","1494"]], ["citrixica",["citrix-ica","1494"]],
  ["vmwarehorizon",       ["https","443"]], ["x11",["x11","6000"]], ["xorg",["x11","6000"]],
  // ---- mail ----
  ["microsoftexchange",   ["https","443"]], ["exchangeserver",["https","443"]], ["postfix",["smtp","25"]],
  ["sendmail",            ["smtp","25"]], ["exim",["smtp","25"]], ["qmail",["smtp","25"]],
  ["dovecot",             ["imap","143"]], ["cyrusimap",["imap","143"]], ["zimbra",["https","443"]],
  ["courierimap",         ["imap","143"]], ["smtp",["smtp","25"]],
  // ---- file / print / sharing ----
  ["samba",               ["microsoft-ds","445"]], ["smb",["microsoft-ds","445"]], ["cifs",["microsoft-ds","445"]],
  ["nfs",                 ["nfs","2049"]], ["vsftpd",["ftp","21"]], ["proftpd",["ftp","21"]],
  ["pureftpd",            ["ftp","21"]], ["filezillaserver",["ftp","21"]], ["ftp",["ftp","21"]],
  ["tftp",                ["tftp","69"]], ["rsync",["rsync","873"]], ["cups",["ipp","631"]],
  ["ipp",                 ["ipp","631"]], ["jetdirect",["jetdirect","9100"]], ["hpjetdirect",["jetdirect","9100"]],
  ["lpd",                 ["printer","515"]], ["afpovertcp",["afp","548"]], ["netatalk",["afp","548"]],
  ["iscsitarget",         ["iscsi-target","3260"]], ["iscsi",["iscsi","860"]],
  // ---- management / monitoring / orchestration ----
  ["snmp",                ["snmp","161"]], ["netsnmp",["snmp","161"]], ["splunk",["splunkd","8089"]],
  ["splunkforwarder",     ["splunkd","8089"]], ["splunkuniversalforwarder",["splunkd","8089"]],
  ["universalforwarder",  ["splunkd","8089"]], ["nagios",["http","80"]], ["nrpe",["nrpe","5666"]],
  ["zabbixagent",         ["zabbix-agent","10050"]], ["zabbixserver",["zabbix-server","10051"]],
  ["zabbix",              ["zabbix-agent","10050"]], ["prometheus",["prometheus","9090"]],
  ["nodeexporter",        ["prometheus","9100"]], ["grafana",["http","3000"]], ["kibana",["kibana","5601"]],
  ["ganglia",             ["ganglia","8649"]], ["cacti",["http","80"]], ["librenms",["http","80"]],
  ["solarwinds",          ["https","443"]], ["prtg",["https","443"]], ["opsview",["http","80"]],
  ["ansible",             ["ssh","22"]], ["puppet",["puppet","8140"]], ["saltstack",["salt","4505"]],
  ["salt",                ["salt","4505"]], ["chef",["https","443"]], ["jenkins",["http","8080"]],
  ["gitlab",              ["http","80"]], ["githubenterprise",["https","443"]], ["bitbucket",["http","7990"]],
  ["sonarqube",           ["sonarqube","9000"]], ["nexusrepository",["http","8081"]], ["artifactory",["http","8081"]],
  ["wsus",                ["wsus","8530"]], ["windowsserverupdate",["wsus","8530"]], ["sccm",["https","443"]],
  ["configurationmanager",["https","443"]], ["bigfix",["https","52311"]], ["landesk",["https","443"]],
  ["ivanti",              ["https","443"]], ["intune",["https","443"]],
  // ---- virtualisation / containers / cloud ----
  ["vmwareesxi",          ["https","443"]], ["vmwarevsphere",["vmware-vsphere","8222"]], ["esxi",["https","443"]],
  ["vcenter",             ["https","443"]], ["vmwareauthenticationdaemon",["vmware-auth","902"]],
  ["hyperv",              ["https","443"]], ["proxmox",["https","8006"]], ["xenserver",["https","443"]],
  ["docker",              ["docker","2375"]], ["dockerdaemon",["docker","2375"]], ["kubernetes",["kube-apiserver","6443"]],
  ["kubeapiserver",       ["kube-apiserver","6443"]], ["kubelet",["kubelet","10250"]], ["etcd",["etcd","2379"]],
  ["openshift",           ["https","443"]], ["rancher",["https","443"]], ["nomad",["http","4646"]],
  ["consul",              ["consul","8500"]], ["portainer",["https","9443"]],
  // ---- data brokers / streaming / queues ----
  ["apachekafka",         ["kafka","9092"]], ["kafka",["kafka","9092"]], ["rabbitmq",["amqp","5672"]],
  ["activemq",            ["activemq","8161"]], ["mosquitto",["mqtt","1883"]], ["mqtt",["mqtt","1883"]],
  ["zookeeper",           ["zookeeper","2181"]], ["apachespark",["spark","7077"]], ["hadoop",["http","9870"]],
  ["nifi",                ["https","8443"]], ["logstash",["logstash","5044"]], ["fluentd",["fluentd","24224"]],
  ["rsyslog",             ["syslog","514"]], ["syslogng",["syslog","514"]], ["graylog",["http","9000"]],
  // ---- VoIP / collaboration / realtime ----
  ["asterisk",            ["sip","5060"]], ["freeswitch",["sip","5060"]], ["sip",["sip","5060"]],
  ["ciscocallmanager",    ["sip","5060"]], ["cucm",["sip","5060"]], ["skypeforbusiness",["https","443"]],
  ["jabber",              ["xmpp-client","5222"]], ["xmpp",["xmpp-client","5222"]], ["ejabberd",["xmpp-client","5222"]],
  ["mattermost",          ["http","8065"]], ["rocketchat",["http","3000"]],
  // ---- security tooling ----
  ["nessus",              ["nessus","8834"]], ["tenable",["nessus","8834"]], ["nexpose",["https","3780"]],
  ["qualys",              ["https","443"]], ["openvas",["https","9392"]], ["gvm",["https","9392"]],
  ["trellix",             ["https","443"]], ["mcafeeepo",["https","8443"]], ["epolicyorchestrator",["https","8443"]],
  ["symantecendpoint",    ["symantec-av","2967"]], ["symantec",["symantec-av","2967"]],
  ["crowdstrike",         ["https","443"]], ["sentinelone",["https","443"]], ["carbonblack",["https","443"]],
  ["defenderforendpoint", ["https","443"]], ["wazuh",["wazuh","1514"]], ["ossec",["ossec","1514"]],
  ["snort",               ["snort",""]], ["suricata",["suricata",""]], ["zeek",["zeek",""]], ["bro",["zeek",""]],
  // ---- backup / storage ----
  ["veeam",               ["https","443"]], ["commvault",["commvault","8400"]], ["netbackup",["netbackup","13724"]],
  ["bacula",              ["bacula","9101"]], ["bareos",["bacula","9101"]], ["rubrik",["https","443"]],
  ["cohesity",            ["https","443"]], ["networker",["networker","7937"]], ["tsm",["tsm","1500"]],
  // ---- misc enterprise / web apps ----
  ["sharepoint",          ["https","443"]], ["confluence",["http","8090"]], ["jira",["http","8080"]],
  ["servicenow",          ["https","443"]], ["drupal",["http","80"]], ["wordpress",["http","80"]],
  ["joomla",              ["http","80"]], ["tomcat",["http","8080"]], ["webmin",["webmin","10000"]],
  ["cpanel",              ["cpanel","2082"]], ["plesk",["https","8443"]], ["phpmyadmin",["http","80"]],
  ["owa",                 ["https","443"]], ["outlookwebaccess",["https","443"]],
  // ---- directory of bare protocol words, so a banner that is just the
  //      protocol still resolves ----
  ["https",["https","443"]], ["http",["http","80"]], ["ssh",["ssh","22"]], ["ftp",["ftp","21"]],
  ["ldaps",["ldaps","636"]], ["ldap",["ldap","389"]], ["dns",["dns","53"]], ["ntp",["ntp","123"]],
  ["ntpd",["ntp","123"]], ["bind",["dns","53"]], ["named",["dns","53"]], ["dnsmasq",["dns","53"]],
  ["iscdhcp",["dhcps","67"]], ["dhcpd",["dhcps","67"]], ["dhcp",["dhcps","67"]],
  ["imaps",["imaps","993"]], ["imap",["imap","143"]], ["pop3s",["pop3s","995"]], ["pop3",["pop3","110"]],
  ["smtps",["smtps","465"]], ["snmptrap",["snmptrap","162"]], ["rdp",["ms-wbt-server","3389"]]
];

/* Normalise a product string to letters+digits for matching, dropping
   version numbers and punctuation: "Apache/2.4.57 (Unix)" -> "apache". */
function normAppName(s){
  return String(s||"").toLowerCase().replace(/[^a-z0-9]+/g,"");
}

/* Service name from an application/software product name. Returns
   {service, port} or null. Longest pattern wins. */
let APP_SERVICE_SORTED = null;
function serviceFromApp(app){
  if(!app) return null;
  const norm=normAppName(app);
  if(!norm) return null;
  if(!APP_SERVICE_SORTED)
    APP_SERVICE_SORTED = APP_SERVICE_TABLE.slice().sort((a,b)=>b[0].length-a[0].length);
  for(const [pat,val] of APP_SERVICE_SORTED){
    if(norm.indexOf(pat)>=0) return {service:serviceDisplayName(val[0]), code:val[0], port:val[1]};
  }
  return null;
}

/* ---------------- service display names ----------------
   The register is read by people and by eMASS reviewers, so Data Service /
   Application carries the service's NAME, not the IANA short code or an
   acronym on its own: "Remote Desktop Protocol (RDP)" rather than
   "ms-wbt-server", "Lightweight Directory Access Protocol (LDAP)" rather than
   "ldap". The short codes stay internal (port lookups, Nessus service
   column, zeek service field, custom overrides) and are turned into names at
   the point they land in a row. Unknown codes pass through untouched, so a
   user-supplied name is never rewritten. */
const SERVICE_NAMES = {
  "echo":"Echo Protocol (ECHO)", "discard":"Discard Protocol", "daytime":"Daytime Protocol",
  "qotd":"Quote of the Day (QOTD)", "chargen":"Character Generator (CHARGEN)",
  "ftp-data":"File Transfer Protocol Data Channel (FTP-DATA)", "ftp":"File Transfer Protocol (FTP)",
  "ssh":"Secure Shell (SSH)", "ssh-alt":"Secure Shell (SSH)", "telnet":"Telnet",
  "smtp":"Simple Mail Transfer Protocol (SMTP)", "smtps":"Simple Mail Transfer Protocol over TLS (SMTPS)",
  "submission":"Mail Submission (SMTP Submission)", "time":"Time Protocol", "nameserver":"Host Name Server",
  "whois":"WHOIS", "tacacs":"Terminal Access Controller Access-Control System (TACACS+)",
  "dns":"Domain Name System (DNS)", "domain":"Domain Name System (DNS)",
  "dhcps":"Dynamic Host Configuration Protocol Server (DHCP)", "dhcpc":"Dynamic Host Configuration Protocol Client (DHCP)",
  "dhcp":"Dynamic Host Configuration Protocol (DHCP)", "bootps":"Dynamic Host Configuration Protocol Server (DHCP)",
  "bootpc":"Dynamic Host Configuration Protocol Client (DHCP)",
  "dhcpv6-client":"DHCPv6 Client", "dhcpv6-server":"DHCPv6 Server",
  "tftp":"Trivial File Transfer Protocol (TFTP)", "gopher":"Gopher", "finger":"Finger",
  "http":"Hypertext Transfer Protocol (HTTP)", "www":"Hypertext Transfer Protocol (HTTP)",
  "http-alt":"Hypertext Transfer Protocol (HTTP)", "http-proxy":"HTTP Proxy", "https":"Hypertext Transfer Protocol Secure (HTTPS)",
  "https-alt":"Hypertext Transfer Protocol Secure (HTTPS)", "ssl":"Transport Layer Security (TLS/SSL)", "tls":"Transport Layer Security (TLS/SSL)",
  "kerberos":"Kerberos Authentication (KRB5)", "kpasswd":"Kerberos Password Change (KPASSWD)", "krb524":"Kerberos 5-to-4 Translation (KRB524)",
  "iso-tsap":"ISO Transport Service (ISO-TSAP)", "pop3":"Post Office Protocol v3 (POP3)", "pop3s":"Post Office Protocol v3 over TLS (POP3S)",
  "rpcbind":"ONC Remote Procedure Call Portmapper (RPCBIND)", "sunrpc":"ONC Remote Procedure Call Portmapper (RPCBIND)",
  "ident":"Identification Protocol (IDENT)", "nntp":"Network News Transfer Protocol (NNTP)", "nntps":"Network News Transfer Protocol over TLS (NNTPS)",
  "ntp":"Network Time Protocol (NTP)", "msrpc":"Microsoft Remote Procedure Call (MSRPC)", "epmap":"Microsoft Remote Procedure Call Endpoint Mapper (MSRPC)",
  "msrpc-dynamic":"Microsoft Remote Procedure Call Dynamic Port (MSRPC)",
  "netbios-ns":"NetBIOS Name Service (NetBIOS-NS)", "netbios-dgm":"NetBIOS Datagram Service (NetBIOS-DGM)",
  "netbios-ssn":"NetBIOS Session Service (NetBIOS-SSN)", "imap":"Internet Message Access Protocol (IMAP)",
  "imaps":"Internet Message Access Protocol over TLS (IMAPS)", "snmp":"Simple Network Management Protocol (SNMP)",
  "snmptrap":"Simple Network Management Protocol Trap (SNMP-TRAP)", "xdmcp":"X Display Manager Control Protocol (XDMCP)",
  "bgp":"Border Gateway Protocol (BGP)", "irc":"Internet Relay Chat (IRC)", "irc-ssl":"Internet Relay Chat over TLS (IRCS)",
  "appletalk":"AppleTalk", "bgmp":"Border Gateway Multicast Protocol (BGMP)", "ldap":"Lightweight Directory Access Protocol (LDAP)",
  "ldaps":"Lightweight Directory Access Protocol over TLS (LDAPS)", "globalcat-ldap":"Active Directory Global Catalog (LDAP)",
  "globalcat-ldaps":"Active Directory Global Catalog over TLS (LDAPS)", "adws":"Active Directory Web Services (ADWS)",
  "snpp":"Simple Network Paging Protocol (SNPP)", "microsoft-ds":"Server Message Block (SMB)", "cifs":"Server Message Block (SMB)",
  "smb":"Server Message Block (SMB)", "retrospect":"Retrospect Backup", "isakmp":"Internet Key Exchange (IKE/ISAKMP)",
  "ipsec-nat-t":"IPsec NAT Traversal (IPSEC-NAT-T)", "exec":"Remote Execution (REXEC)", "login":"Remote Login (RLOGIN)",
  "shell":"Remote Shell (RSH)", "syslog":"System Logging Protocol (SYSLOG)", "syslog-tls":"System Logging Protocol over TLS (SYSLOG-TLS)",
  "printer":"Line Printer Daemon (LPD)", "rip":"Routing Information Protocol (RIP)", "ripng":"Routing Information Protocol Next Generation (RIPng)",
  "uucp":"Unix-to-Unix Copy (UUCP)", "afp":"Apple Filing Protocol (AFP)", "rtsp":"Real Time Streaming Protocol (RTSP)",
  "rmonitor":"Remote Monitor (RMONITOR)", "ipp":"Internet Printing Protocol (IPP)", "msdp":"Multicast Source Discovery Protocol (MSDP)",
  "ldp":"Label Distribution Protocol (LDP)", "msexchange":"Microsoft Exchange Routing", "ipmi":"Intelligent Platform Management Interface (IPMI)",
  "http-rpc-epmap":"HTTP RPC Endpoint Mapper (RPC over HTTP)", "iscsi":"Internet Small Computer Systems Interface (iSCSI)",
  "iscsi-target":"Internet Small Computer Systems Interface Target (iSCSI)", "rsync":"Remote Sync (RSYNC)",
  "vmware-auth":"VMware Authentication Daemon", "vmware-vsphere":"VMware vSphere", "ftps-data":"FTP over TLS Data Channel (FTPS-DATA)",
  "ftps":"File Transfer Protocol over TLS (FTPS)", "socks":"SOCKS Proxy", "rmi-registry":"Java Remote Method Invocation Registry (RMI)",
  "openvpn":"OpenVPN", "nessus":"Tenable Nessus Vulnerability Scanner", "dell-omsa":"Dell OpenManage Server Administrator (OMSA)",
  "lotusnotes":"IBM Lotus Notes / Domino", "ms-sql-s":"Microsoft SQL Server (MSSQL)", "ms-sql-m":"Microsoft SQL Server Browser (MSSQL)",
  "mssql":"Microsoft SQL Server (MSSQL)", "citrix-ica":"Citrix Independent Computing Architecture (ICA)", "oracle":"Oracle Database Listener (TNS)",
  "oracle-ssl":"Oracle Database Listener over TLS (TNS)", "oracle-xdb":"Oracle XML Database (XDB)", "radius":"Remote Authentication Dial-In User Service (RADIUS)",
  "radius-acct":"RADIUS Accounting", "l2tp":"Layer 2 Tunneling Protocol (L2TP)", "h323":"H.323 Call Signalling", "pptp":"Point-to-Point Tunneling Protocol (PPTP)",
  "ms-streaming":"Microsoft Media Streaming (MMS)", "mqtt":"Message Queuing Telemetry Transport (MQTT)", "upnp":"Universal Plug and Play (UPnP)",
  "ssdp":"Simple Service Discovery Protocol (SSDP)", "cisco-sccp":"Cisco Skinny Client Control Protocol (SCCP)", "nfs":"Network File System (NFS)",
  "cpanel":"cPanel", "cpanel-ssl":"cPanel over TLS", "zookeeper":"Apache ZooKeeper", "docker":"Docker Engine API", "docker-ssl":"Docker Engine API over TLS",
  "etcd":"etcd Key-Value Store", "sybase":"SAP Sybase Database", "symantec-av":"Symantec Endpoint Protection", "node-dev":"Node.js Development Server",
  "squid-proxy":"Squid Web Proxy", "mysql":"MySQL Database", "ms-wbt-server":"Remote Desktop Protocol (RDP)", "rdp":"Remote Desktop Protocol (RDP)",
  "stun":"Session Traversal Utilities for NAT (STUN)", "svn":"Apache Subversion (SVN)", "blizzard":"Blizzard Battle.net", "icq":"ICQ Messaging",
  "udt":"UDP-based Data Transfer (UDT)", "tram":"TRAM", "e-mail":"Email Service", "gearman":"Gearman Job Server",
  "smart-install":"Cisco Smart Install", "glassfish":"GlassFish Application Server", "radmin":"Remote Administrator (Radmin)",
  "airport-admin":"Apple AirPort Administration", "mmcc":"Multimedia Conference Control (MMCC)", "sip":"Session Initiation Protocol (SIP)",
  "sip-tls":"Session Initiation Protocol over TLS (SIPS)", "tinymsg":"TinyMessage", "xmpp-client":"Extensible Messaging and Presence Protocol Client (XMPP)",
  "xmpp-server":"Extensible Messaging and Presence Protocol Server (XMPP)", "xmpp":"Extensible Messaging and Presence Protocol (XMPP)",
  "mdns":"Multicast Domain Name System (mDNS)", "wsdapi":"Web Services for Devices (WSD)", "ws-discovery":"Web Services Dynamic Discovery (WS-Discovery)",
  "postgresql":"PostgreSQL Database", "freeciv":"Freeciv", "kibana":"Elastic Kibana", "pcanywhere":"Symantec pcAnywhere",
  "nrpe":"Nagios Remote Plugin Executor (NRPE)", "amqp":"Advanced Message Queuing Protocol (AMQP)", "amqps":"Advanced Message Queuing Protocol over TLS (AMQPS)",
  "coap":"Constrained Application Protocol (CoAP)", "vnc":"Virtual Network Computing (VNC)", "vnc-http":"Virtual Network Computing over HTTP (VNC)",
  "teamviewer":"TeamViewer", "couchdb":"Apache CouchDB", "wsman-http":"Windows Remote Management (WinRM)", "wsman-https":"Windows Remote Management over TLS (WinRM)",
  "winrm":"Windows Remote Management (WinRM)", "x11":"X Window System (X11)", "redis":"Redis", "kube-apiserver":"Kubernetes API Server",
  "cassandra":"Apache Cassandra", "cassandra-jmx":"Apache Cassandra JMX", "cassandra-cql":"Apache Cassandra Query Language (CQL)",
  "cassandra-thrift":"Apache Cassandra Thrift", "weblogic":"Oracle WebLogic Server", "realserver":"RealNetworks RealServer",
  "spark":"Apache Spark", "neo4j":"Neo4j Graph Database", "cwmp":"CPE WAN Management Protocol (CWMP/TR-069)", "ajp13":"Apache JServ Protocol (AJP)",
  "tomcat-shutdown":"Apache Tomcat Shutdown Port", "influxdb":"InfluxDB", "radan-http":"RADAN HTTP", "splunkd":"Splunk Management (splunkd)",
  "splunk-forwarder":"Splunk Universal Forwarder", "puppet":"Puppet Agent/Server", "activemq":"Apache ActiveMQ", "vault":"HashiCorp Vault",
  "bitcoin":"Bitcoin P2P", "consul":"HashiCorp Consul", "wsus":"Windows Server Update Services (WSUS)", "wsus-ssl":"Windows Server Update Services over TLS (WSUS)",
  "ganglia":"Ganglia Monitoring", "jmx":"Java Management Extensions (JMX)", "sonarqube":"SonarQube", "tor-orport":"Tor Onion Router",
  "prometheus":"Prometheus Monitoring", "kafka":"Apache Kafka", "jetdirect":"HP JetDirect Printing (RAW/9100)", "elasticsearch":"Elasticsearch REST API",
  "elasticsearch-node":"Elasticsearch Node Transport", "git":"Git Protocol", "wildfly-mgmt":"WildFly / JBoss Management", "abyss":"Abyss Web Server",
  "webmin":"Webmin", "zabbix-agent":"Zabbix Agent", "zabbix-server":"Zabbix Server", "memcached":"Memcached", "mongodb":"MongoDB",
  "mongodb-shard":"MongoDB Shard", "mongodb-config":"MongoDB Config Server", "mongodb-web":"MongoDB Web Status", "db2":"IBM Db2 Database",
  "logstash":"Elastic Logstash (Beats)", "fluentd":"Fluentd", "ossec":"OSSEC Agent", "wazuh":"Wazuh Agent", "snort":"Snort IDS",
  "suricata":"Suricata IDS", "zeek":"Zeek Network Monitor", "commvault":"Commvault Backup", "netbackup":"Veritas NetBackup",
  "bacula":"Bacula Backup", "networker":"Dell EMC NetWorker", "tsm":"IBM Spectrum Protect (TSM)", "icmp":"Internet Control Message Protocol (ICMP)",
  "general":"", "unknown":"", "?":""
};
/* Turn a short code (or a semicolon-joined list of them) into display names.
   Anything not in the table is returned as it came, so hand-typed names
   survive. Case-insensitive on the code. */
function serviceDisplayName(code){
  if(code==null) return "";
  const s=String(code).trim();
  if(!s) return "";
  if(s.indexOf(";")>=0){
    const out=[]; const seen=new Set();
    s.split(";").forEach(part=>{ const d=serviceDisplayName(part); if(d && !seen.has(d)){ seen.add(d); out.push(d); } });
    return out.join("; ");
  }
  const k=s.toLowerCase();
  if(Object.prototype.hasOwnProperty.call(SERVICE_NAMES,k)) return SERVICE_NAMES[k];
  return s;
}
/* Is this string a short code the table knows (so it needs upgrading)? */
function isServiceCode(s){
  const k=String(s||"").trim().toLowerCase();
  return !!k && Object.prototype.hasOwnProperty.call(SERVICE_NAMES,k);
}
/* Rewrite any short codes left in Data Service across the rows. Runs in
   enrichRows so every ingest path (Nessus "www"/"cifs", zeek "ssl", a CSV
   that carried "http") ends up with the same names. */
function normaliseServiceNames(rows){
  let changed=0;
  (rows||ROWS).forEach(r=>{
    const v=r.dataService; if(!v) return;
    const parts=String(v).split(";").map(x=>x.trim()).filter(Boolean);
    if(!parts.some(isServiceCode)) return;
    const d=serviceDisplayName(v);
    if(d!==v){ r.dataService=d; changed++; }
  });
  return changed;
}

/* Service by port. Returns the display name (see SERVICE_NAMES). A custom
   override under Settings wins and is returned exactly as the user typed it. */
function guessService(port, proto){
  const ov = (typeof CFG!=="undefined" && CFG.customServices) ? serviceOverride(port, proto) : "";
  if(ov) return ov;
  return serviceDisplayName(guessServiceCode(port, proto));
}
/* IANA-style short code by port — internal; use guessService for a name. */
function guessServiceCode(port, proto){
  const map={7:"echo",9:"discard",13:"daytime",17:"qotd",19:"chargen",20:"ftp-data",21:"ftp",22:"ssh",
    23:"telnet",25:"smtp",37:"time",42:"nameserver",43:"whois",49:"tacacs",53:"dns",67:"dhcps",68:"dhcpc",
    69:"tftp",70:"gopher",79:"finger",80:"http",81:"http-alt",88:"kerberos",102:"iso-tsap",110:"pop3",
    111:"rpcbind",113:"ident",119:"nntp",123:"ntp",135:"msrpc",137:"netbios-ns",138:"netbios-dgm",
    139:"netbios-ssn",143:"imap",161:"snmp",162:"snmptrap",177:"xdmcp",179:"bgp",194:"irc",201:"appletalk",
    264:"bgmp",389:"ldap",443:"https",444:"snpp",445:"microsoft-ds",464:"kpasswd",465:"smtps",497:"retrospect",
    500:"isakmp",512:"exec",513:"login",514:"syslog",515:"printer",520:"rip",521:"ripng",540:"uucp",
    546:"dhcpv6-client",547:"dhcpv6-server",548:"afp",554:"rtsp",560:"rmonitor",563:"nntps",587:"submission",
    591:"http-alt",593:"http-rpc-epmap",623:"ipmi",631:"ipp",636:"ldaps",639:"msdp",646:"ldp",691:"msexchange",
    860:"iscsi",873:"rsync",902:"vmware-auth",989:"ftps-data",990:"ftps",993:"imaps",995:"pop3s",
    1025:"msrpc",1027:"msrpc",1080:"socks",1099:"rmi-registry",1194:"openvpn",1241:"nessus",1311:"dell-omsa",
    1352:"lotusnotes",1433:"ms-sql-s",1434:"ms-sql-m",1494:"citrix-ica",1521:"oracle",1604:"citrix-ica",
    1645:"radius",1646:"radius-acct",1701:"l2tp",1720:"h323",1723:"pptp",1755:"ms-streaming",1812:"radius",
    1813:"radius-acct",1883:"mqtt",1900:"upnp",2000:"cisco-sccp",2049:"nfs",2082:"cpanel",2083:"cpanel-ssl",
    2100:"oracle-xdb",2181:"zookeeper",2222:"ssh-alt",2375:"docker",2376:"docker-ssl",2379:"etcd",2483:"oracle",
    2484:"oracle-ssl",2638:"sybase",2967:"symantec-av",3000:"node-dev",3001:"node-dev",3128:"squid-proxy",
    3260:"iscsi-target",3268:"globalcat-ldap",3269:"globalcat-ldaps",3306:"mysql",3389:"ms-wbt-server",
    3478:"stun",3690:"svn",3724:"blizzard",4000:"icq",4022:"udt",4444:"krb524",4500:"ipsec-nat-t",4567:"tram",
    4711:"e-mail",4730:"gearman",4786:"smart-install",4848:"glassfish",4899:"radmin",5000:"upnp",
    5009:"airport-admin",5050:"mmcc",5060:"sip",5061:"sip-tls",5104:"tinymsg",5222:"xmpp-client",
    5269:"xmpp-server",5353:"mdns",5357:"wsdapi",5432:"postgresql",5555:"freeciv",5601:"kibana",5631:"pcanywhere",
    5666:"nrpe",5671:"amqps",5672:"amqp",5683:"coap",5800:"vnc-http",5900:"vnc",5938:"teamviewer",
    5984:"couchdb",5985:"wsman-http",5986:"wsman-https",6000:"x11",6001:"x11",6379:"redis",6443:"kube-apiserver",
    6514:"syslog-tls",6660:"irc",6667:"irc",6697:"irc-ssl",7000:"cassandra",7001:"weblogic",7070:"realserver",
    7077:"spark",7199:"cassandra-jmx",7474:"neo4j",7547:"cwmp",7680:"ws-discovery",8000:"http-alt",
    8005:"tomcat-shutdown",8008:"http-alt",8009:"ajp13",8080:"http-proxy",8081:"http-alt",8086:"influxdb",
    8088:"radan-http",8089:"splunkd",8140:"puppet",8161:"activemq",8200:"vault",8222:"vmware-vsphere",
    8333:"bitcoin",8443:"https-alt",8500:"consul",8530:"wsus",8531:"wsus-ssl",8649:"ganglia",8686:"jmx",
    8888:"http-alt",9000:"sonarqube",9001:"tor-orport",9042:"cassandra-cql",9090:"prometheus",9092:"kafka",
    9100:"jetdirect",9160:"cassandra-thrift",9200:"elasticsearch",9300:"elasticsearch-node",9389:"adws",
    9418:"git",9443:"https-alt",9990:"wildfly-mgmt",9999:"abyss",10000:"webmin",10050:"zabbix-agent",
    10051:"zabbix-server",11211:"memcached",27017:"mongodb",27018:"mongodb-shard",27019:"mongodb-config",
    28017:"mongodb-web",49152:"msrpc-dynamic",50000:"db2"};
  return map[+port]||"";
}
