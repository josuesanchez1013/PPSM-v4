"use strict";
/* ======= v2 MODULES ======= */
/* ============================================================
   CONFIGURATION / CUSTOMIZATION ENGINE
   CFG drives parser behaviour, service naming, columns, and the
   diagram. Everything here is user-editable and saved with the
   session (or exported as a standalone profile).
   ============================================================ */

const CFG_DEFAULTS = {
  /* ---- parsing ---- */
  wellKnownMax: 1024,          // ports below this are treated as "service" ports
  ephemeralRange: "1024-65535",
  excludeEphemeralDst: false,  // drop rows whose DESTINATION port is ephemeral
  excludeEphemeralSrc: true,   // blank an ephemeral SOURCE port (it is never the service)
  internalRanges: "",          // extra CIDRs counted as inside the boundary
  subnetEnclaves: "",          // CIDR = enclave name, one per line
  serviceAssurance: {},        // service or port -> assurance category
  autoEnrich: true,            // derive what we can as data comes in
  autoResolveHosts: true,      // apply learned hostnames after every import
  autoEnclaveFromSubnet: true, // label the enclave by /24 when no map is set
  ipv4Only: true,              // most enclaves are v4 only; v6 rows are noise
  consolidatePorts: true,      // one row per src->dest, ports joined with ;
  consolidateSources: true,    // one row per service, sources joined with ;
  internalExportBoundary: "B18", // the template has no "Internal": pick one
  dnsDomain: "",               // completes a short name into an FQDN
  siteLocation: "",            // physical location of this enclave's kit
  externalCsp: "External (non-DoD)", // what to put for an address outside it
  vpnTypeNone: "",             // what a non-tunnelled flow puts in VPN Tunnel Type
  /* ---- eMASS export defaults (Settings > eMASS template) ---- */
  exportVpn: "",               // "" = per row (derived from boundary) | "Yes" | "No"
  exportVpnOverwrite: false,   // apply the export VPN value over an existing per-row value
  exportVpnType: "",           // VPN Tunnel Type to write where a row has none ("" = leave)
  exportVpnTypeOverwrite: false,
  srcLocation: "",             // Source Physical Location for our own addresses (falls back to siteLocation)
  dstLocation: "",             // Destination Physical Location for our own addresses (falls back to siteLocation)
  exportPurpose: true,         // write a generated Purpose on rows that have none, so column U is never blank
  emassOnePerPort: true,       // one exported row per protocol/port (+boundary/direction), services and ends joined
  emassIpOnly: true,           // addresses only in the export: no hostnames in Source/Destination, FQDN carries the address
  emassSortByPort: true,       // exported rows ordered lowest port to highest
  autoFinish: true,            // run the finish pass automatically on import
  asciiExports: true,          // fold typographic characters in register exports
  includeConns: true,
  airgapDefault: true,
  /* ---- pcap ---- */
  pcapMinPkts: 1,
  pcapIcmp: true,
  pcapOtherProto: true,
  pcapDropMulticast: false,
  pcapMaxPackets: 500000,
  /* ---- misc parser ---- */
  wfwDropOnly: false,
  /* ---- service naming ---- */
  customServices: {},          // {"9997":"splunk-fwd", "TCP/8443":"vendor-app"}
  /* ---- register ---- */
  customBoundaries: [],        // extra boundary tags beyond the built-ins
  hiddenCols: ["appName","emassType","srcLoc","dstLoc","srcPoint","dstPoint","vpn","vpnType"],
  defaultStatus: "New",
  defaultEnclave: "",
  defaultCollector: "",
  /* ---- diagram ---- */
  dgMode:"flow", dgGroup:"boundary", dgTheme:"dark", dgWidth:1100, dgRowH:62,
  dgMaxEdges:24, dgPortCount:4, dgShowPorts:true, dgShowCounts:true,
  dgScope:"all", dgScale:2, dgTitle:""
};
let CFG = JSON.parse(JSON.stringify(CFG_DEFAULTS));

/* custom service lookup layered over the built-in map */
function serviceOverride(port, proto){
  if(!port) return "";
  const p=String(port).trim();
  const withProto=((proto||"").toUpperCase())+"/"+p;
  if(CFG.customServices[withProto]) return CFG.customServices[withProto];
  if(CFG.customServices[p]) return CFG.customServices[p];
  return "";
}

function boundaryList(){
  const extra=(CFG.customBoundaries||[]).filter(Boolean).map(b=>({value:b,label:b}));
  return BOUNDARIES.concat(extra);
}

/* ---------- settings modal wiring ---------- */
function openSettings(){
  $("cfg_wellKnown").value   = CFG.wellKnownMax;
  $("cfg_ephem").value       = CFG.ephemeralRange;
  $("cfg_exephsrc").checked  = CFG.excludeEphemeralSrc!==false;
  $("cfg_exephdst").checked  = CFG.excludeEphemeralDst===true;
  $("cfg_pcapMin").value     = CFG.pcapMinPkts;
  $("cfg_pcapMax").value     = CFG.pcapMaxPackets;
  $("cfg_pcapIcmp").checked  = !!CFG.pcapIcmp;
  $("cfg_pcapOther").checked = !!CFG.pcapOtherProto;
  $("cfg_pcapMcast").checked = !!CFG.pcapDropMulticast;
  $("cfg_defEnclave").value  = CFG.defaultEnclave||"";
  $("cfg_defCollector").value= CFG.defaultCollector||"";
  $("cfg_bounds").value      = (CFG.customBoundaries||[]).join("\n");
  $("cfg_subnets").value     = CFG.subnetEnclaves||"";
  $("cfg_ascii").checked     = CFG.asciiExports!==false;
  $("cfg_ipv4").checked      = CFG.ipv4Only!==false;
  $("cfg_consol").checked    = CFG.consolidatePorts!==false;
  $("cfg_consolsrc").checked = CFG.consolidateSources!==false;
  $("cfg_dnsdom").value      = CFG.dnsDomain||"";
  $("cfg_site").value        = CFG.siteLocation||"";
  $("cfg_csp").value         = CFG.externalCsp||"";
  $("cfg_vpnnone").value     = CFG.vpnTypeNone||"";
  $("cfg_srcloc").value      = CFG.srcLocation||"";
  $("cfg_dstloc").value      = CFG.dstLocation||"";
  $("cfg_expvpn").value      = CFG.exportVpn||"";
  $("cfg_expvpnow").checked  = !!CFG.exportVpnOverwrite;
  (function(){ const sel=$("cfg_expvpntype");
    sel.innerHTML='<option value="">Per row — leave as entered</option>'+
      [...new Set(EMASS_VPNTYPE)].map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join("");
    sel.value=CFG.exportVpnType||""; })();
  $("cfg_expvpntypeow").checked = !!CFG.exportVpnTypeOverwrite;
  $("cfg_exppurpose").checked= CFG.exportPurpose!==false;
  $("cfg_autofinish").checked= CFG.autoFinish!==false;
  $("cfg_oneperport").checked= CFG.emassOnePerPort!==false;
  $("cfg_iponly").checked    = CFG.emassIpOnly!==false;
  $("cfg_sortport").checked  = CFG.emassSortByPort!==false;
  $("cfg_services").value    = Object.entries(CFG.customServices||{})
                                 .map(([k,v])=>k+" = "+v).join("\n");
  const box=$("cfg_cols"); box.innerHTML="";
  COLS.forEach(([k,label])=>{
    const id="colv_"+k;
    const wrap=document.createElement("label"); wrap.className="opt";
    wrap.innerHTML=`<input type="checkbox" id="${id}" ${CFG.hiddenCols.includes(k)?"":"checked"}><span>${esc(label)}</span>`;
    box.appendChild(wrap);
  });
}

function applySettings(){
  CFG.wellKnownMax    = Math.max(1,+$("cfg_wellKnown").value||1024);
  CFG.ephemeralRange  = $("cfg_ephem").value.trim()||"1024-65535";
  CFG.excludeEphemeralSrc = $("cfg_exephsrc").checked;
  CFG.excludeEphemeralDst = $("cfg_exephdst").checked;
  CFG.pcapMinPkts     = Math.max(1,+$("cfg_pcapMin").value||1);
  CFG.pcapMaxPackets  = Math.max(1000,+$("cfg_pcapMax").value||500000);
  CFG.pcapIcmp        = $("cfg_pcapIcmp").checked;
  CFG.pcapOtherProto  = $("cfg_pcapOther").checked;
  CFG.pcapDropMulticast=$("cfg_pcapMcast").checked;
  CFG.defaultEnclave  = $("cfg_defEnclave").value.trim();
  CFG.defaultCollector= $("cfg_defCollector").value.trim();
  CFG.customBoundaries= $("cfg_bounds").value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  CFG.subnetEnclaves  = $("cfg_subnets").value;
  CFG.asciiExports    = $("cfg_ascii").checked;
  CFG.ipv4Only        = $("cfg_ipv4").checked;
  CFG.consolidatePorts= $("cfg_consol").checked;
  CFG.consolidateSources= $("cfg_consolsrc").checked;
  CFG.dnsDomain       = $("cfg_dnsdom").value.trim();
  CFG.siteLocation    = $("cfg_site").value.trim();
  CFG.externalCsp     = $("cfg_csp").value.trim();
  CFG.vpnTypeNone     = $("cfg_vpnnone").value.trim();
  CFG.srcLocation     = $("cfg_srcloc").value.trim();
  CFG.dstLocation     = $("cfg_dstloc").value.trim();
  CFG.exportVpn       = $("cfg_expvpn").value;
  CFG.exportVpnOverwrite = $("cfg_expvpnow").checked;
  CFG.exportVpnType   = $("cfg_expvpntype").value;
  CFG.exportVpnTypeOverwrite = $("cfg_expvpntypeow").checked;
  CFG.exportPurpose   = $("cfg_exppurpose").checked;
  CFG.emassOnePerPort = $("cfg_oneperport").checked;
  CFG.emassIpOnly     = $("cfg_iponly").checked;
  CFG.emassSortByPort = $("cfg_sortport").checked;
  CFG.autoFinish      = $("cfg_autofinish").checked;

  const svc={};
  $("cfg_services").value.split(/\r?\n/).forEach(l=>{
    const m=l.match(/^\s*([A-Za-z]*\/?\d+)\s*[=:,]\s*(.+?)\s*$/);
    if(m) svc[m[1].toUpperCase().replace(/^\//,"")]=m[2];
  });
  CFG.customServices=svc;

  const hidden=[];
  COLS.forEach(([k])=>{ const el=$("colv_"+k); if(el&&!el.checked) hidden.push(k); });
  CFG.hiddenCols=hidden;

  if($("ephem")) $("ephem").value=CFG.ephemeralRange;
  if(CFG.defaultEnclave && $("impEnclave") && !$("impEnclave").value) $("impEnclave").value=CFG.defaultEnclave;
  if(CFG.defaultCollector && $("impCollector") && !$("impCollector").value) $("impCollector").value=CFG.defaultCollector;

  applyColumnVisibility();
  render();
  flash("Settings applied.","ok");
}

function resetSettings(){
  CFG=JSON.parse(JSON.stringify(CFG_DEFAULTS));
  applyColumnVisibility(); openSettings(); render();
  flash("Settings reset to defaults.","ok");
}

/* hide/show table columns to match CFG.hiddenCols */
function applyColumnVisibility(){
  const tbl=$("tbl"); if(!tbl) return;
  const offset=2;                                   // checkbox + row-number columns
  COLS.forEach(([k],i)=>{
    const hide=CFG.hiddenCols.includes(k);
    const n=offset+i+1;
    tbl.querySelectorAll(`thead th:nth-child(${n}), tbody td:nth-child(${n})`)
       .forEach(el=>el.style.display=hide?"none":"");
  });
}

function visibleCols(){ return COLS.filter(([k])=>!CFG.hiddenCols.includes(k)); }

/* ---------- profile import / export ---------- */
function exportProfile(){
  download("ppsm-profile.json", JSON.stringify(CFG,null,2), "application/json");
}
function importProfile(file){
  const rd=new FileReader();
  rd.onload=()=>{
    try{
      const d=JSON.parse(rd.result);
      CFG=Object.assign(JSON.parse(JSON.stringify(CFG_DEFAULTS)),d);
      applyColumnVisibility(); render();
      flash("Profile loaded.","ok");
    }catch(e){ flash("Invalid profile file: "+e.message,"err"); }
  };
  rd.readAsText(file);
}
