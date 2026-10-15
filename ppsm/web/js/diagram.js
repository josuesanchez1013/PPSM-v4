"use strict";
/* ============================================================
   BOUNDARY DIAGRAM GENERATOR
   Builds an SVG that correlates to the PPSM register contents.
   Modes:  "flow"      – enclave/zone flow map derived from the rows
           "reference" – DoD PPSM 16-boundary reference, lit up where data exists
   ============================================================ */

const BND_LABEL = {
  "B1":"Ext Network → DoD GW (In)",        "B2":"DoD GW → Ext Network (Out)",
  "B3":"DoD GW → DoD-level DMZ (In)",      "B4":"DoD-level DMZ → DoD GW (Out)",
  "B5":"DoD GW → DISN (In)",               "B6":"DISN → DoD GW (Out)",
  "B7":"DISN → Enclave GW (In)",           "B8":"Enclave GW → DISN (Out)",
  "B9":"Enclave GW → Enclave DMZ (In)",    "B10":"Enclave DMZ → Enclave GW (Out)",
  "B11":"Enclave GW → Enclave (In)",       "B12":"Enclave → Enclave GW (Out)",
  "B13":"Ext Network (ISP/AG) → Enclave GW (In)", "B14":"Enclave GW → Ext Network (Out)",
  "B15":"Enclave GW ↔ Enclave GW Tunnel (Multi-AO)",
  "B16":"Enclave GW ↔ Enclave GW Tunnel (Single AO)"
};

function dgOpt(id, dflt){ const e=$(id); if(!e) return dflt;
  return e.type==="checkbox" ? e.checked : (e.value||dflt); }

function diagramRows(){
  return dgOpt("dgScope","all")==="filtered" ? getFiltered() : ROWS;
}

/* group rows into edges keyed by boundary (+ optional zone pair) */
function buildEdges(rows){
  const groupBy = dgOpt("dgGroup","boundary");
  const map=new Map();
  rows.forEach(r=>{
    let a,z,key,bnd=r.boundary||"(unset)";
    if(groupBy==="enclave"){ a=r.enclave||"(no enclave)"; z=bnd; }
    else if(groupBy==="zone"){ a=r.srcZone||r.enclave||"(source)"; z=r.dstZone||"(destination)"; }
    else if(groupBy==="collector"){ a=r.collector||"(no collector)"; z=bnd; }
    else { a=r.enclave||"(no enclave)"; z=bnd; }
    key=a+"\u0001"+z;
    let e=map.get(key);
    if(!e){ e={a,z,bnd,count:0,ports:new Map(),flagged:FLAGGED(bnd),rows:[]}; map.set(key,e); }
    e.count++; e.rows.push(r);
    const p=(r.proto?r.proto+"/":"")+(r.dstPort||"");
    if(r.dstPort) e.ports.set(p,(e.ports.get(p)||0)+1);
  });
  return [...map.values()].sort((x,y)=>y.count-x.count);
}

function topPorts(e,n){
  return [...e.ports.entries()].sort((a,b)=>b[1]-a[1]).slice(0,n).map(x=>x[0]);
}

/* ---------------- flow-map mode ---------------- */
function svgFlowMap(){
  const rows=diagramRows();
  const edges=buildEdges(rows).slice(0, +dgOpt("dgMaxEdges","24"));
  const showPorts=dgOpt("dgShowPorts",true), showCounts=dgOpt("dgShowCounts",true);
  const title=dgOpt("dgTitle","")|| (meta().system? meta().system+" — PPSM Boundary Flow Map" : "PPSM Boundary Flow Map");
  const theme=THEMES[dgOpt("dgTheme","dark")]||THEMES.dark;
  const nPorts=+dgOpt("dgPortCount","4");

  const leftNames=[...new Set(edges.map(e=>e.a))];
  const rightNames=[...new Set(edges.map(e=>e.z))];
  const rowH=Math.max(52,+dgOpt("dgRowH","62"));
  const H=Math.max(leftNames.length,rightNames.length)*rowH+150;
  const W=+dgOpt("dgWidth","1100");
  const lx=40, lw=250, rx=W-40-300, rw=300;
  const posL={}, posR={};
  leftNames.forEach((n,i)=>posL[n]=110+i*rowH);
  rightNames.forEach((n,i)=>posR[n]=110+i*rowH);

  let s=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="Segoe UI, Arial, sans-serif">`;
  s+=`<rect width="${W}" height="${H}" fill="${theme.bg}"/>`;
  s+=`<text x="${W/2}" y="42" fill="${theme.title}" font-size="21" font-weight="700" text-anchor="middle">${esc(title)}</text>`;
  const sub=`${rows.length} register entries · ${edges.length} boundary groups · generated ${new Date().toISOString().slice(0,10)}`;
  s+=`<text x="${W/2}" y="66" fill="${theme.sub}" font-size="12" text-anchor="middle">${esc(sub)}</text>`;
  s+=`<text x="${lx}" y="96" fill="${theme.sub}" font-size="11" font-weight="700" letter-spacing="1">SOURCE</text>`;
  s+=`<text x="${rx}" y="96" fill="${theme.sub}" font-size="11" font-weight="700" letter-spacing="1">BOUNDARY / DESTINATION</text>`;

  // edges first (behind nodes)
  edges.forEach(e=>{
    const y1=posL[e.a]+22, y2=posR[e.z]+22;
    const col=e.flagged?theme.warn:(e.bnd==="Internal only"?theme.accent:theme.line);
    const wgt=Math.min(6,1+Math.log2(e.count+1));
    const mx=(lx+lw+rx)/2;
    s+=`<path d="M${lx+lw},${y1} C${mx},${y1} ${mx},${y2} ${rx},${y2}" fill="none" stroke="${col}" stroke-width="${wgt.toFixed(1)}" opacity="0.75"/>`;
    if(showCounts){
      s+=`<circle cx="${mx}" cy="${(y1+y2)/2}" r="13" fill="${theme.bg}" stroke="${col}" stroke-width="1.5"/>`;
      s+=`<text x="${mx}" y="${(y1+y2)/2+4}" fill="${col}" font-size="10.5" font-weight="700" text-anchor="middle">${e.count}</text>`;
    }
  });

  const box=(x,y,w,label,detail,col)=>{
    let o=`<rect x="${x}" y="${y}" width="${w}" height="44" rx="7" fill="${theme.node}" stroke="${col}" stroke-width="1.5"/>`;
    o+=`<text x="${x+12}" y="${y+19}" fill="${theme.text}" font-size="13" font-weight="600">${esc(String(label).slice(0,34))}</text>`;
    if(detail) o+=`<text x="${x+12}" y="${y+34}" fill="${theme.sub}" font-size="10.5">${esc(String(detail).slice(0,44))}</text>`;
    return o;
  };
  leftNames.forEach(n=>{
    const tot=edges.filter(e=>e.a===n).reduce((a,b)=>a+b.count,0);
    s+=box(lx,posL[n],lw,n,tot+" flow"+(tot===1?"":"s"),theme.accent);
  });
  rightNames.forEach(n=>{
    const es=edges.filter(e=>e.z===n);
    const flagged=es.some(e=>e.flagged);
    const ports=showPorts?[...new Set(es.flatMap(e=>topPorts(e,nPorts)))].slice(0,nPorts).join("  "):"";
    const lbl=BND_LABEL[n]?`${n} · ${BND_LABEL[n]}`:n;
    s+=box(rx,posR[n],rw,lbl,ports,flagged?theme.warn:theme.line);
  });

  // legend
  const ly=H-34;
  s+=`<line x1="${lx}" y1="${ly-14}" x2="${W-40}" y2="${ly-14}" stroke="${theme.grid}" stroke-width="1"/>`;
  s+=`<circle cx="${lx+6}" cy="${ly+2}" r="5" fill="${theme.warn}"/><text x="${lx+18}" y="${ly+6}" fill="${theme.sub}" font-size="11">crossing to review</text>`;
  s+=`<circle cx="${lx+165}" cy="${ly+2}" r="5" fill="${theme.accent}"/><text x="${lx+177}" y="${ly+6}" fill="${theme.sub}" font-size="11">internal only</text>`;
  s+=`<text x="${W-40}" y="${ly+6}" fill="${theme.sub}" font-size="10.5" text-anchor="end">line weight = relative flow count</text>`;
  s+=`</svg>`;
  return s;
}

/* ---------------- DoD 16-boundary reference mode ---------------- */
function svgReference(){
  const rows=diagramRows();
  const used=new Map();
  rows.forEach(r=>{ if(r.boundary) used.set(r.boundary,(used.get(r.boundary)||0)+1); });
  const theme=THEMES[dgOpt("dgTheme","dark")]||THEMES.dark;
  const title=dgOpt("dgTitle","")||(meta().system? meta().system+" — PPSM 16 Network Boundaries" : "PPSM 16 Network Boundaries");
  const W=1180,H=760;
  const on=b=>used.has(b), cnt=b=>used.get(b)||0;
  const eCol=b=>on(b)?(FLAGGED(b)?theme.warn:theme.accent):theme.grid;
  const eW=b=>on(b)?2.6:1.1;

  let s=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="Segoe UI, Arial, sans-serif">`;
  s+=`<rect width="${W}" height="${H}" fill="${theme.bg}"/>`;
  s+=`<text x="${W/2}" y="36" fill="${theme.title}" font-size="21" font-weight="700" text-anchor="middle">${esc(title)}</text>`;
  s+=`<text x="${W/2}" y="58" fill="${theme.sub}" font-size="12" text-anchor="middle">${esc(rows.length+" register entries · boundaries with traffic are highlighted")}</text>`;

  const ell=(x,y,rx2,ry,label,sub2)=>{
    let o=`<ellipse cx="${x}" cy="${y}" rx="${rx2}" ry="${ry}" fill="${theme.node}" stroke="${theme.line}" stroke-width="1.5"/>`;
    o+=`<text x="${x}" y="${y+(sub2?-2:5)}" fill="${theme.text}" font-size="12.5" font-weight="600" text-anchor="middle">${esc(label)}</text>`;
    if(sub2) o+=`<text x="${x}" y="${y+14}" fill="${theme.sub}" font-size="10" text-anchor="middle">${esc(sub2)}</text>`;
    return o;
  };
  const rect=(x,y,w,h,label,sub2)=>{
    let o=`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6" fill="${theme.node}" stroke="${theme.line}" stroke-width="1.5"/>`;
    o+=`<text x="${x+w/2}" y="${y+(sub2?h/2-2:h/2+5)}" fill="${theme.text}" font-size="12" font-weight="600" text-anchor="middle">${esc(label)}</text>`;
    if(sub2) o+=`<text x="${x+w/2}" y="${y+h/2+13}" fill="${theme.sub}" font-size="10" text-anchor="middle">${esc(sub2)}</text>`;
    return o;
  };
  const gw=(x,y,label)=>`<ellipse cx="${x}" cy="${y}" rx="52" ry="20" fill="${theme.gw}" stroke="${theme.line}" stroke-width="1.5"/>`+
    `<text x="${x}" y="${y+4}" fill="${theme.text}" font-size="11.5" font-weight="700" text-anchor="middle">${esc(label)}</text>`;
  const fw=(x,y,vert)=>vert
    ? `<rect x="${x-5}" y="${y-16}" width="10" height="32" fill="${theme.fw}" stroke="${theme.fwline}" stroke-width="1"/>`
    : `<rect x="${x-16}" y="${y-5}" width="32" height="10" fill="${theme.fw}" stroke="${theme.fwline}" stroke-width="1"/>`;
  const link=(x1,y1,x2,y2,b,lx2,ly2)=>{
    let o=`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${eCol(b)}" stroke-width="${eW(b)}" marker-end="url(#ah)"/>`;
    const t=b+(on(b)?" ("+cnt(b)+")":"");
    o+=`<text x="${lx2}" y="${ly2}" fill="${on(b)?eCol(b):theme.sub}" font-size="10.5" font-weight="${on(b)?"700":"400"}" text-anchor="middle">${esc(t)}</text>`;
    return o;
  };
  s+=`<defs><marker id="ah" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">`+
     `<path d="M0,0 L0,6 L7,3 z" fill="${theme.line}"/></marker></defs>`;

  // --- topology ---
  s+=ell(150,150,92,40,"Nested Enclave","");
  s+=ell(400,130,80,36,"DoD Enclave A","");
  s+=ell(980,130,80,36,"DoD Enclave B","");
  s+=gw(400,275,"Gateway");
  s+=gw(980,275,"Gateway");
  s+=rect(600,250,150,50,"Enclave DMZ","Services");
  s+=rect(790,250,150,50,"Enclave DMZ","Services");
  s+=ell(140,275,105,40,"Commercial ISP /","Approved GW (waiver)");
  s+=ell(590,430,240,42,"DISN","");
  s+=gw(560,540,"Gateway");
  s+=rect(680,515,180,52,"DoD-level DMZ","DNS · Web · Proxy");
  s+=ell(960,540,80,34,"RDT&E","(e.g. DREN)");
  s+=ell(700,680,300,44,"External Network","Internet · Mission Partners");
  s+=ell(150,680,110,40,"DoD External","Enclave X (waiver)");

  s+=fw(400,205,true)+fw(400,320,true)+fw(980,205,true)+fw(980,320,true);
  s+=fw(555,275,false)+fw(770,275,false)+fw(265,275,false);
  s+=fw(560,600,true)+fw(660,540,false)+fw(890,540,false)+fw(290,680,false);

  // --- boundary edges ---
  s+=link(400,175,400,255,"B11",352,215);
  s+=link(400,255,400,175,"B12",448,215);
  s+=link(980,175,980,255,"B11",932,215);
  s+=link(980,255,980,175,"B12",1028,215);
  s+=link(452,275,600,275,"B9",520,262);
  s+=link(600,290,452,290,"B10",520,306);
  s+=link(940,275,1032,275,"B9",905,262);
  s+=link(940,290,1032,290,"B10",905,306);
  s+=link(245,275,290,275,"B13",268,258);
  s+=link(290,292,245,292,"B14",268,312);
  s+=link(400,295,480,410,"B8",412,360);
  s+=link(480,410,400,295,"B7",470,360);
  s+=link(980,295,760,412,"B8",900,360);
  s+=link(760,412,980,295,"B7",880,384);
  s+=link(560,470,560,520,"B5",524,498);
  s+=link(600,470,600,520,"B6",640,498);
  s+=link(612,540,680,540,"B3",645,528);
  s+=link(680,556,612,556,"B4",645,572);
  s+=link(860,540,920,540,"B3",890,528);
  s+=link(920,556,860,556,"B4",890,572);
  s+=link(560,562,560,650,"B1",524,610);
  s+=link(600,650,600,562,"B2",640,610);
  s+=link(255,680,420,680,"B13",340,666);
  s+=link(420,694,255,694,"B14",340,712);
  s+=rect(880,400,270,54,"Tunnels — VPN · IPSEC · NSA Type1","MPLS · GRE");
  s+=link(880,427,830,430,"B15",860,414);
  s+=link(880,441,830,444,"B16",860,462);

  // extra buckets for non-numbered tags
  const extras=[INTERNAL_BND,"Internal only","Inter-enclave","Interconnection","(unset)"].filter(b=>used.has(b));
  let ey=H-70;
  if(extras.length){
    s+=`<text x="40" y="${ey-14}" fill="${theme.sub}" font-size="11" font-weight="700">DOES NOT CROSS A DISN BOUNDARY</text>`;
    extras.forEach((b,i)=>{
      const x=40+i*250;
      s+=`<rect x="${x}" y="${ey}" width="230" height="26" rx="5" fill="${theme.node}" stroke="${FLAGGED(b)?theme.warn:theme.accent}" stroke-width="1.4"/>`;
      s+=`<text x="${x+10}" y="${ey+17}" fill="${theme.text}" font-size="11">${esc(b)} — ${cnt(b)}</text>`;
    });
  }
  s+=`</svg>`;
  return s;
}

const THEMES={
  dark:  {bg:"#0d1117",node:"#161b22",gw:"#1f2933",fw:"#7d2d2d",fwline:"#c96a6a",text:"#e6edf3",
          sub:"#8b949e",title:"#36c2a8",accent:"#36c2a8",warn:"#e3b341",line:"#4a5568",grid:"#2d333b"},
  light: {bg:"#ffffff",node:"#f4f6f8",gw:"#e3e8ee",fw:"#f0c9c9",fwline:"#b04545",text:"#12181f",
          sub:"#5a6675",title:"#0f6e5c",accent:"#0f8a72",warn:"#a9750c",line:"#93a1b0",grid:"#dde3e9"},
  print: {bg:"#ffffff",node:"#ffffff",gw:"#f0f0f0",fw:"#e8e8e8",fwline:"#333333",text:"#000000",
          sub:"#444444",title:"#000000",accent:"#0b6b3a",warn:"#8a5a00",line:"#000000",grid:"#bbbbbb"}
};

/* ============================================================
   ENVIRONMENT DIAGRAM
   Replaces the fixed reference drawing. Nodes are the PPSM connection
   points that actually appear in the register, named with the enclave
   and system names from the data. Edges are the boundary crossings the
   register contains, weighted by flow count and labelled with the ports
   that cross them.
   ============================================================ */

/* which connection points are in play, and what to call them */
function envModel(rows){
  const pts=new Map();            // id -> {id, label, names:Set, count}
  const edges=new Map();          // "from|to|code" -> {from,to,code,count,ports:Map,rows:[]}
  const unmapped=new Map();       // boundary values that carry no code

  const touch=(id,name)=>{
    if(!id) return;
    let p=pts.get(id);
    if(!p){ p={id, label:CP_NAME[id]||id, names:new Set(), count:0}; pts.set(id,p); }
    p.count++;
    if(name) p.names.add(name);
    return p;
  };

  let internalCount=0;
  const internalPorts=new Map();
  rows.forEach(r=>{
    const code=bndCode(r.boundary);
    if(code===INTERNAL_BND){
      // stays inside the enclave; it crosses no CAL boundary, so it is drawn
      // as a loop on the enclave rather than against a numbered boundary
      internalCount++;
      touch("ENC", r.enclave||"");
      if(r.dstPort){
        const p=(r.proto?r.proto+"/":"")+r.dstPort;
        internalPorts.set(p,(internalPorts.get(p)||0)+1);
      }
      return;
    }
    if(!code){
      const k=r.boundary||"(no boundary set)";
      unmapped.set(k,(unmapped.get(k)||0)+1);
      return;
    }
    const d=BND_BY_CODE[code];
    // the enclave name from the data labels whichever end is the enclave
    const encName=r.enclave||"";
    touch(d.from, d.from==="ENC"||d.from==="ENCGW"||d.from==="ENCDMZ" ? encName : "");
    touch(d.to,   d.to==="ENC"||d.to==="ENCGW"||d.to==="ENCDMZ"     ? encName : "");
    const key=d.from+"|"+d.to+"|"+code;
    let e=edges.get(key);
    if(!e){ e={from:d.from,to:d.to,code,def:d,count:0,ports:new Map(),hosts:new Set()}; edges.set(key,e); }
    e.count++;
    if(r.dstPort) e.ports.set((r.proto?r.proto+"/":"")+r.dstPort,
      (e.ports.get((r.proto?r.proto+"/":"")+r.dstPort)||0)+1);
    if(r.dstHost) e.hosts.add(r.dstHost);
  });

  return {pts, edges:[...edges.values()].sort((a,b)=>b.count-a.count), unmapped,
          internalCount, internalPorts};
}

/* fixed vertical ordering: outside the DoD at the top, the enclave at the bottom */
const CP_ORDER = ["EXT","ISP","DODGW","DODDMZ","RDTE","DISN","ENCGW","ENCDMZ","ENC"];

function svgEnvironment(){
  const rows = diagramRows();
  const {pts, edges, unmapped, internalCount, internalPorts} = envModel(rows);
  const theme = THEMES[dgOpt("dgTheme","dark")]||THEMES.dark;
  const showPorts = dgOpt("dgShowPorts",true);
  const showCounts = dgOpt("dgShowCounts",true);
  const nPorts = +dgOpt("dgPortCount","4");
  const title = dgOpt("dgTitle","") ||
    ((meta().system? meta().system+" — " : "")+"PPSM Environment Boundary Diagram");

  const present = CP_ORDER.filter(id=>pts.has(id));
  if(!present.length){
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 200" width="900" height="200">
      <rect width="900" height="200" fill="${theme.bg}"/>
      <text x="450" y="95" fill="${theme.sub}" font-size="15" text-anchor="middle">No rows carry a boundary yet.</text>
      <text x="450" y="120" fill="${theme.sub}" font-size="12.5" text-anchor="middle">Set the Boundary column — Internal for traffic that stays inside, a B number only where it genuinely crosses one.</text>
    </svg>`;
  }

  const W = +dgOpt("dgWidth","1120");
  const laneH = 96, topY = 118;
  const H = topY + present.length*laneH + 90 + (unmapped.size?70:0);
  const nodeW = 300, nodeX = 60;
  const railX = nodeX + nodeW + 70;          // where crossing arrows live
  const y = {};
  present.forEach((id,i)=> y[id] = topY + i*laneH);

  let s=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" font-family="Segoe UI, Arial, sans-serif">`;
  s+=`<rect width="${W}" height="${H}" fill="${theme.bg}"/>`;
  s+=`<text x="${W/2}" y="42" fill="${theme.title}" font-size="21" font-weight="700" text-anchor="middle">${esc(title)}</text>`;
  s+=`<text x="${W/2}" y="66" fill="${theme.sub}" font-size="12" text-anchor="middle">${
    esc(rows.length+" register entries · "+present.length+" connection points in use · "+
        edges.length+" boundary crossing"+(edges.length===1?"":"s")+" · generated "+new Date().toISOString().slice(0,10))}</text>`;
  s+=`<text x="${nodeX}" y="98" fill="${theme.sub}" font-size="11" font-weight="700" letter-spacing="1">CONNECTION POINTS IN YOUR ENVIRONMENT</text>`;
  s+=`<text x="${railX+30}" y="98" fill="${theme.sub}" font-size="11" font-weight="700" letter-spacing="1">BOUNDARY CROSSINGS FROM YOUR DATA</text>`;

  s+=`<defs>
    <marker id="ar" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="${theme.line}"/></marker>
    <marker id="arw" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="${theme.warn}"/></marker>
    <marker id="ara" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="${theme.accent}"/></marker>
  </defs>`;

  // connection point nodes, labelled with the real names from the register
  present.forEach(id=>{
    const p=pts.get(id);
    const names=[...p.names].filter(Boolean);
    const sub = names.length ? names.slice(0,2).join(", ")+(names.length>2?" +"+(names.length-2):"")
                             : (id==="ENC"?"this enclave":"");
    const yy=y[id];
    const isEnc = id==="ENC"||id==="ENCGW"||id==="ENCDMZ";
    s+=`<rect x="${nodeX}" y="${yy}" width="${nodeW}" height="58" rx="9" fill="${theme.node}" `+
       `stroke="${isEnc?theme.accent:theme.line}" stroke-width="${isEnc?2:1.4}"/>`;
    s+=`<text x="${nodeX+14}" y="${yy+24}" fill="${theme.text}" font-size="13.5" font-weight="600">${esc(p.label)}</text>`;
    if(sub) s+=`<text x="${nodeX+14}" y="${yy+42}" fill="${theme.sub}" font-size="10.5">${esc(sub.slice(0,42))}</text>`;
    s+=`<text x="${nodeX+nodeW-12}" y="${yy+24}" fill="${theme.sub}" font-size="10.5" text-anchor="end">${p.count} entr${p.count===1?"y":"ies"}</text>`;
  });

  // crossings, drawn as arrows between the lanes they actually join
  const laneSlots={};
  edges.slice(0,+dgOpt("dgMaxEdges","24")).forEach((e,i)=>{
    const y1=y[e.from], y2=y[e.to];
    if(y1==null||y2==null) return;
    const flagged=FLAGGED(e.code);
    const col = e.def.internal ? theme.accent : (flagged?theme.warn:theme.line);
    const mk  = e.def.internal ? "ara" : (flagged?"arw":"ar");
    const slotKey=Math.min(y1,y2)+"-"+Math.max(y1,y2);
    laneSlots[slotKey]=(laneSlots[slotKey]||0)+1;
    const lane=railX + (laneSlots[slotKey]-1)*186;
    const a=y1+29, b=y2+29;
    const wgt=Math.min(5,1.2+Math.log2(e.count+1));

    if(e.from===e.to){
      // a loop: tunnel or internal-use traffic that starts and ends at the same point
      s+=`<path d="M${lane},${a-14} C${lane+52},${a-30} ${lane+52},${a+30} ${lane},${a+14}" `+
         `fill="none" stroke="${col}" stroke-width="${wgt.toFixed(1)}" marker-end="url(#${mk})"/>`;
    } else {
      s+=`<path d="M${lane},${a} C${lane+46},${a} ${lane+46},${b} ${lane},${b}" `+
         `fill="none" stroke="${col}" stroke-width="${wgt.toFixed(1)}" marker-end="url(#${mk})"/>`;
      s+=`<line x1="${nodeX+nodeW}" y1="${a}" x2="${lane}" y2="${a}" stroke="${col}" stroke-width="1" opacity="0.45"/>`;
      s+=`<line x1="${lane}" y1="${b}" x2="${nodeX+nodeW}" y2="${b}" stroke="${col}" stroke-width="1" opacity="0.45" marker-end="url(#${mk})"/>`;
    }
    const my=(a+b)/2, mx=lane+58;
    let lbl=e.code+(showCounts?" · "+e.count:"");
    s+=`<text x="${mx}" y="${my-3}" fill="${col}" font-size="11.5" font-weight="700">${esc(lbl)}</text>`;
    const detail=[];
    if(e.def.ao) detail.push("AO");
    if(e.def.waiver) detail.push("DoDIN waiver");
    if(e.def.tunnel) detail.push("tunnel");
    if(showPorts){
      const tp=[...e.ports.entries()].sort((x,z)=>z[1]-x[1]).slice(0,nPorts).map(x=>x[0]);
      if(tp.length) detail.push(tp.join(" "));
    }
    if(detail.length)
      s+=`<text x="${mx}" y="${my+12}" fill="${theme.sub}" font-size="10">${esc(detail.join(" · ").slice(0,46))}</text>`;
  });

  // internal traffic: a loop on the enclave, with no boundary number
  if(internalCount && y["ENC"]!=null){
    const ey=y["ENC"]+29, ex=nodeX+nodeW;
    s+=`<path d="M${ex},${ey-12} C${ex+62},${ey-34} ${ex+62},${ey+34} ${ex},${ey+12}" `+
       `fill="none" stroke="${theme.accent}" stroke-width="2.4" marker-end="url(#ara)"/>`;
    s+=`<text x="${ex+74}" y="${ey-4}" fill="${theme.accent}" font-size="11.5" font-weight="700">`+
       `Internal \u00b7 ${internalCount}</text>`;
    const tp=[...internalPorts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,nPorts).map(x=>x[0]);
    s+=`<text x="${ex+74}" y="${ey+11}" fill="${theme.sub}" font-size="10">`+
       `${esc(("no CAL boundary crossed"+(tp.length?" \u00b7 "+tp.join(" "):"")).slice(0,54))}</text>`;
  }

  // anything whose boundary is not a recognised code
  let by=topY+present.length*laneH+14;
  if(unmapped.size){
    s+=`<text x="${nodeX}" y="${by}" fill="${theme.warn}" font-size="11" font-weight="700" letter-spacing="1">NOT YET MAPPED TO A PPSM BOUNDARY</text>`;
    by+=18;
    [...unmapped.entries()].slice(0,4).forEach(([k,v],i)=>{
      const x=nodeX+i*250;
      s+=`<rect x="${x}" y="${by}" width="234" height="26" rx="5" fill="${theme.node}" stroke="${theme.warn}" stroke-width="1.3"/>`;
      s+=`<text x="${x+10}" y="${by+17}" fill="${theme.text}" font-size="11">${esc(String(k).slice(0,24))} — ${v}</text>`;
    });
    by+=42;
  }

  // legend
  s+=`<line x1="${nodeX}" y1="${by+4}" x2="${W-40}" y2="${by+4}" stroke="${theme.grid}" stroke-width="1"/>`;
  const ly=by+24;
  s+=`<circle cx="${nodeX+6}" cy="${ly-4}" r="5" fill="${theme.warn}"/><text x="${nodeX+18}" y="${ly}" fill="${theme.sub}" font-size="11">leaves the enclave — reviewer focus</text>`;
  s+=`<circle cx="${nodeX+290}" cy="${ly-4}" r="5" fill="${theme.accent}"/><text x="${nodeX+302}" y="${ly}" fill="${theme.sub}" font-size="11">internal \u2014 no CAL boundary crossed</text>`;
  s+=`<text x="${W-40}" y="${ly}" fill="${theme.sub}" font-size="10.5" text-anchor="end">arrow weight = relative flow count · built from the register, not a template</text>`;
  s+=`</svg>`;
  return s;
}

/* ---------------- render + export ---------------- */
function currentDiagramSvg(){
  const m=dgOpt("dgMode","environment");
  if(m==="reference") return svgReference();
  if(m==="flow") return svgFlowMap();
  return svgEnvironment();
}
function renderDiagram(){
  const host=$("dgCanvas"); if(!host) return;
  if(!ROWS.length){ host.innerHTML='<div class="dg-empty">No register entries yet — import data first, then generate the diagram.</div>'; return; }
  try{ host.innerHTML=currentDiagramSvg(); }
  catch(e){ host.innerHTML='<div class="dg-empty">Diagram error: '+esc(e.message)+'</div>'; }
}
function dgFilename(ext){
  const m=meta(); return ((m.system||"ppsm").replace(/[^\w.\-]+/g,"_"))+"-boundary-diagram."+ext;
}
function exportDiagramSvg(){
  if(!ROWS.length) return flash("Nothing to diagram — import register data first.","warn");
  download(dgFilename("svg"), currentDiagramSvg(), "image/svg+xml");
}
function exportDiagramPng(){
  if(!ROWS.length) return flash("Nothing to diagram — import register data first.","warn");
  const svg=currentDiagramSvg();
  const m=svg.match(/width="(\d+)"\s+height="(\d+)"/);
  const w=m?+m[1]:1100, h=m?+m[2]:700, scale=+dgOpt("dgScale","2");
  const img=new Image();
  const blob=new Blob([svg],{type:"image/svg+xml;charset=utf-8"});
  const url=URL.createObjectURL(blob);
  img.onload=()=>{
    const c=document.createElement("canvas"); c.width=w*scale; c.height=h*scale;
    const ctx=c.getContext("2d"); ctx.scale(scale,scale); ctx.drawImage(img,0,0);
    URL.revokeObjectURL(url);
    c.toBlob(b=>{
      if(!b) return flash("PNG export failed — use SVG instead.","err");
      const a=document.createElement("a"); a.href=URL.createObjectURL(b);
      a.download=dgFilename("png"); document.body.appendChild(a); a.click();
      setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},400);
      flash("Diagram exported as PNG.","ok");
    },"image/png");
  };
  img.onerror=()=>{ URL.revokeObjectURL(url); flash("PNG render failed — use SVG instead.","err"); };
  img.src=url;
}
function printDiagram(){
  if(!ROWS.length) return flash("Nothing to diagram — import register data first.","warn");
  const w=window.open("","_blank");
  const doc=`<!doctype html><html><head><meta charset="utf-8"><title>${esc(dgFilename("svg"))}</title>
    <style>body{margin:0;padding:18px;background:#fff;font-family:Segoe UI,Arial,sans-serif}
    svg{max-width:100%;height:auto}@media print{body{padding:0}}</style></head>
    <body>${currentDiagramSvg()}<script>window.onload=()=>setTimeout(()=>window.print(),250)<\/script></body></html>`;
  if(w){ w.document.write(doc); w.document.close(); }
  else download(dgFilename("html"), doc, "text/html");
}
