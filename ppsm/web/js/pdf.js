"use strict";
/* ============================================================
   PDF TEXT EXTRACTION
   Pulls the text back out of a PDF so a log that was printed or
   pasted into one can still be imported. Self-contained: a small
   DEFLATE decoder plus a content-stream scanner. No libraries,
   no network, works offline.
   ============================================================ */

/* ---------------- raw DEFLATE / zlib inflate ---------------- */
function inflateRaw(data){
  let bitPos=0, bytePos=0;
  const out=[];
  const bits=n=>{ let v=0;
    for(let i=0;i<n;i++){
      if(bytePos>=data.length) throw new Error("truncated stream");
      v |= ((data[bytePos]>>bitPos)&1)<<i;
      if(++bitPos===8){ bitPos=0; bytePos++; }
    }
    return v; };
  const build=lens=>{
    const max=Math.max(...lens), bl=new Array(max+1).fill(0);
    lens.forEach(l=>{ if(l) bl[l]++; });
    const offs=new Array(max+1).fill(0);
    for(let i=1;i<max;i++) offs[i+1]=offs[i]+bl[i];
    const sorted=new Array(lens.length);
    lens.forEach((l,i)=>{ if(l) sorted[offs[l]++]=i; });
    return {counts:bl, symbols:sorted};
  };
  const decode=h=>{
    let code=0, first=0, index=0;
    for(let len=1;len<=15;len++){
      code |= bits(1);
      const count=h.counts[len]||0;
      if(code-first<count) return h.symbols[index+(code-first)];
      index+=count; first=(first+count)<<1; code<<=1;
    }
    throw new Error("bad huffman code");
  };
  const LBASE=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
  const LEXT=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
  const DBASE=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
  const DEXT=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];

  let fixedL=null, fixedD=null;
  for(;;){
    const last=bits(1), type=bits(2);
    if(type===0){                                   // stored
      if(bitPos){ bitPos=0; bytePos++; }
      const len=data[bytePos]|(data[bytePos+1]<<8); bytePos+=4;
      for(let i=0;i<len;i++) out.push(data[bytePos++]);
    } else {
      let lh,dh;
      if(type===1){
        if(!fixedL){
          const l=new Array(288);
          for(let i=0;i<144;i++) l[i]=8;
          for(let i=144;i<256;i++) l[i]=9;
          for(let i=256;i<280;i++) l[i]=7;
          for(let i=280;i<288;i++) l[i]=8;
          fixedL=build(l); fixedD=build(new Array(30).fill(5));
        }
        lh=fixedL; dh=fixedD;
      } else if(type===2){
        const nlen=bits(5)+257, ndist=bits(5)+1, ncode=bits(4)+4;
        const ORD=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
        const cl=new Array(19).fill(0);
        for(let i=0;i<ncode;i++) cl[ORD[i]]=bits(3);
        const ch=build(cl);
        const lens=[];
        while(lens.length<nlen+ndist){
          const sym=decode(ch);
          if(sym<16) lens.push(sym);
          else if(sym===16){ const p=lens[lens.length-1], n=3+bits(2); for(let i=0;i<n;i++) lens.push(p); }
          else if(sym===17){ const n=3+bits(3); for(let i=0;i<n;i++) lens.push(0); }
          else { const n=11+bits(7); for(let i=0;i<n;i++) lens.push(0); }
        }
        lh=build(lens.slice(0,nlen)); dh=build(lens.slice(nlen));
      } else throw new Error("bad block type");

      for(;;){
        const sym=decode(lh);
        if(sym<256) out.push(sym);
        else if(sym===256) break;
        else {
          const i=sym-257;
          if(i>=LBASE.length) throw new Error("bad length code");
          const len=LBASE[i]+bits(LEXT[i]);
          const ds=decode(dh);
          const dist=DBASE[ds]+bits(DEXT[ds]);
          let p=out.length-dist;
          if(p<0) throw new Error("bad distance");
          for(let k=0;k<len;k++) out.push(out[p+k]);
        }
      }
    }
    if(last) break;
    if(bytePos>data.length) break;
  }
  return new Uint8Array(out);
}

function inflateAuto(data){
  // strip a zlib wrapper if present
  if(data.length>2 && (data[0]&0x0f)===8 && ((data[0]<<8|data[1])%31)===0)
    return inflateRaw(data.subarray(2));
  return inflateRaw(data);
}

/* ---------------- ASCII pre-filters ---------------- */
function ascii85Decode(bytes){
  const out=[];
  let tuple=0, count=0, i=0;
  // skip a leading <~ if present
  if(bytes.length>1 && bytes[0]===0x3c && bytes[1]===0x7e) i=2;
  for(; i<bytes.length; i++){
    const c=bytes[i];
    if(c===0x7e) break;                       // ~> terminator
    if(c===0x7a && count===0){ out.push(0,0,0,0); continue; }   // 'z'
    if(c<0x21 || c>0x75) continue;            // whitespace and anything else
    tuple = tuple*85 + (c-0x21); count++;
    if(count===5){
      out.push((tuple>>>24)&255,(tuple>>>16)&255,(tuple>>>8)&255,tuple&255);
      tuple=0; count=0;
    }
  }
  if(count>0){
    for(let k=count;k<5;k++) tuple=tuple*85+84;
    const full=[(tuple>>>24)&255,(tuple>>>16)&255,(tuple>>>8)&255,tuple&255];
    for(let k=0;k<count-1;k++) out.push(full[k]);
  }
  return new Uint8Array(out);
}
function asciiHexDecode(bytes){
  const out=[]; let hi=null;
  for(let i=0;i<bytes.length;i++){
    const c=String.fromCharCode(bytes[i]);
    if(c===">") break;
    if(!/[0-9a-fA-F]/.test(c)) continue;
    if(hi===null) hi=c; else { out.push(parseInt(hi+c,16)); hi=null; }
  }
  if(hi!==null) out.push(parseInt(hi+"0",16));
  return new Uint8Array(out);
}
function runLengthDecode(bytes){
  const out=[]; let i=0;
  while(i<bytes.length){
    const l=bytes[i++];
    if(l===128) break;
    if(l<128){ for(let k=0;k<=l;k++) out.push(bytes[i++]); }
    else { const b=bytes[i++]; for(let k=0;k<257-l;k++) out.push(b); }
  }
  return new Uint8Array(out);
}

/* Filters are applied in the order the /Filter array lists them. */
function applyFilters(data, dict){
  const m=dict.match(/\/Filter\s*(\[[^\]]*\]|\/\w+)/);
  if(!m) return data;
  const names=(m[1].match(/\/(\w+)/g)||[]).map(x=>x.slice(1));
  let d=data;
  for(const f of names){
    if(f==="ASCII85Decode")      d=ascii85Decode(d);
    else if(f==="ASCIIHexDecode")d=asciiHexDecode(d);
    else if(f==="FlateDecode")   d=inflateAuto(d);
    else if(f==="RunLengthDecode") d=runLengthDecode(d);
    else throw new Error("unsupported filter "+f);
  }
  return d;
}

/* ---------------- PDF container ---------------- */
function pdfFindStreams(bytes){
  const streams=[];
  const find=(needle,from)=>{
    const n=needle.length;
    outer: for(let i=from;i<=bytes.length-n;i++){
      for(let j=0;j<n;j++) if(bytes[i+j]!==needle.charCodeAt(j)) continue outer;
      return i;
    }
    return -1;
  };
  let pos=0;
  while(pos<bytes.length){
    let s=find("stream",pos);
    // "endstream" also contains "stream" — step past those
    while(s>=3 && bytes[s-3]===0x65 && bytes[s-2]===0x6e && bytes[s-1]===0x64){
      s=find("stream", s+6);
    }
    if(s<0) break;
    // the dictionary immediately before tells us the filter
    const dictStart=Math.max(0,s-600);
    let dict="";
    for(let i=dictStart;i<s;i++) dict+=String.fromCharCode(bytes[i]);
    let d=s+6;
    if(bytes[d]===0x0d) d++;
    if(bytes[d]===0x0a) d++;
    const e=find("endstream",d);
    if(e<0) break;
    let end=e;
    while(end>d && (bytes[end-1]===0x0a||bytes[end-1]===0x0d)) end--;
    streams.push({data:bytes.subarray(d,end), dict});
    pos=e+9;
  }
  return streams;
}

/* ---------------- font encoding (/ToUnicode CMap) ----------------
   Word, Excel and many report writers embed subset fonts with custom
   encodings. Without the CMap the bytes in a text string are glyph ids, and
   the extracted "text" comes out as gibberish. Parse the bfchar/bfrange
   tables so those documents read correctly. */
function parseToUnicode(str){
  const map=new Map();
  /* the CMap declares its own code width; <0000> <FFFF> means 2-byte codes */
  const csr=str.match(/begincodespacerange([\s\S]*?)endcodespacerange/);
  if(csr){
    const first=csr[1].match(/<([0-9a-fA-F]+)>/);
    if(first && first[1].length>=4) map.wide=true;
  }
  const hex=h=>{
    let out="";
    for(let i=0;i+3<h.length||i+3===h.length;i+=4) out+=String.fromCharCode(parseInt(h.substr(i,4),16));
    return out || String.fromCharCode(parseInt(h,16)||0);
  };
  let m;
  const charRe=/beginbfchar([\s\S]*?)endbfchar/g;
  while((m=charRe.exec(str))){
    const pairs=m[1].match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/g)||[];
    pairs.forEach(pr=>{
      const g=pr.match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/);
      if(g) map.set(parseInt(g[1],16), hex(g[2]));
    });
  }
  const rangeRe=/beginbfrange([\s\S]*?)endbfrange/g;
  while((m=rangeRe.exec(str))){
    const body=m[1];
    const simple=body.match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/g)||[];
    simple.forEach(pr=>{
      const g=pr.match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>/);
      if(!g) return;
      const lo=parseInt(g[1],16), hi=parseInt(g[2],16), base=parseInt(g[3],16);
      for(let c=lo;c<=hi && c-lo<65535;c++) map.set(c, String.fromCharCode(base+(c-lo)));
    });
    const arr=body.match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\[([\s\S]*?)\]/g)||[];
    arr.forEach(pr=>{
      const g=pr.match(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\[([\s\S]*?)\]/);
      if(!g) return;
      const lo=parseInt(g[1],16);
      const items=g[3].match(/<([0-9a-fA-F]+)>/g)||[];
      items.forEach((it,i)=>{
        const h=it.replace(/[<>]/g,"");
        map.set(lo+i, hex(h));
      });
    });
  }
  return map;
}

/* Does the recovered text look like text, or like glyph soup? */
function textLooksReadable(t){
  if(!t) return false;
  const s=t.replace(/\s/g,"");
  if(s.length<10) return false;
  const printable=(s.match(/[A-Za-z0-9.,:;'"()\/\-_@#%+=\[\]]/g)||[]).length;
  const ratio=printable/s.length;
  const words=(t.match(/[A-Za-z]{3,}/g)||[]).length;
  const digits=(t.match(/\d/g)||[]).length;
  return ratio>0.75 && (words>=3 || digits>=12);
}

/* ---------------- content stream -> text ---------------- */
function pdfTextFromContent(str, fonts){
  /* Identity-H and most subset encodings use 2-byte CIDs, so when the map
     contains any code above 0xFF the string is read as wide characters. */
  const applyMap = (raw, fontKey) => {
    const cmap = fonts && fontKey && fonts.get(fontKey);
    if(!cmap || !cmap.size) return raw;
    let wide = !!cmap.wide;
    if(!wide){ for(const k of cmap.keys()){ if(k>0xFF){ wide=true; break; } } }
    if(!wide && raw.length>1){
      // a 2-byte stream shows NULs in the high byte of most code points
      let nul=0;
      for(let k=0;k<raw.length;k+=2) if(raw.charCodeAt(k)===0) nul++;
      if(nul > raw.length/4) wide=true;
    }
    let out="";
    if(wide){
      for(let k=0;k+1<raw.length;k+=2){
        const c=(raw.charCodeAt(k)<<8)|raw.charCodeAt(k+1);
        out += cmap.has(c) ? cmap.get(c) : "";
      }
    } else {
      for(let k=0;k<raw.length;k++){
        const c=raw.charCodeAt(k);
        out += cmap.has(c) ? cmap.get(c) : raw[k];
      }
    }
    return out;
  };
  let out="", i=0, lastY=null, lastX=null, pendingNL=false;
  const n=str.length;
  const rdString=()=>{                       // ( ... ) with escapes
    let depth=1, s=""; i++;
    while(i<n && depth>0){
      const c=str[i];
      if(c==="\\"){
        const nx=str[i+1];
        const map={"n":"\n","r":"\r","t":"\t","b":"","f":"","(":"(",")":")","\\":"\\"};
        if(nx in map){ s+=map[nx]; i+=2; }
        else if(nx>="0"&&nx<="7"){
          let oct=""; i++;
          while(oct.length<3 && str[i]>="0" && str[i]<="7"){ oct+=str[i]; i++; }
          s+=String.fromCharCode(parseInt(oct,8));
        } else { i+=2; }
      } else if(c==="("){ depth++; s+=c; i++; }
      else if(c===")"){ depth--; if(depth) s+=c; i++; }
      else { s+=c; i++; }
    }
    return s;
  };
  const rdHex=()=>{
    let s="", h=""; i++;
    while(i<n && str[i]!==">"){ if(/[0-9a-fA-F]/.test(str[i])) h+=str[i]; i++; }
    i++;
    for(let k=0;k+1<h.length;k+=2) s+=String.fromCharCode(parseInt(h.substr(k,2),16));
    return s;
  };
  const nums=[];
  let token="", curFont=null;
  const flushTok=()=>{
    if(!token) return;
    const t=token; token="";
    if(/^-?[\d.]+$/.test(t)){ nums.push(parseFloat(t)); return; }
    // positioning operators decide where line breaks go
    if(t==="Tf"){ /* the operand before the size is the font name */ }
    if(t==="Td"||t==="TD"){
      const y=nums[nums.length-1], x=nums[nums.length-2];
      if(lastY!==null && Math.abs(y)>0.01) pendingNL=true;
      lastY=y; lastX=x;
    } else if(t==="Tm"){
      const y=nums[nums.length-1], x=nums[nums.length-2];
      if(lastY!==null && Math.abs(y-lastY)>1.5) pendingNL=true;
      else if(lastX!==null && x-lastX>18) out+="  ";     // wide gap = column break
      lastY=y; lastX=x;
    } else if(t==="T*"||t==="'"||t==='"'){ pendingNL=true; }
    else if(t==="ET"){ pendingNL=true; }
    nums.length=0;
  };
  const emit=s=>{
    if(!s) return;
    if(pendingNL){ out+="\n"; pendingNL=false; }
    out+=s;
  };
  while(i<n){
    const c=str[i];
    if(c==="/"){ // font selection: /F3 8 Tf
      let nm="/"; i++;
      while(i<n && !/[\s\/\[\]<>()]/.test(str[i])){ nm+=str[i]; i++; }
      curFont=nm; token=""; continue;
    }
    if(c==="("){ flushTok(); emit(applyMap(rdString(), curFont)); }
    else if(c==="<" && str[i+1]!=="<"){ flushTok(); emit(applyMap(rdHex(), curFont)); }
    else if(c==="["){ flushTok(); i++; }
    else if(c==="]"){ flushTok(); i++; }
    else if(/\s/.test(c)){ flushTok(); i++; }
    else { token+=c; i++; }
  }
  flushTok();
  return out;
}

/* ---------------- public entry ---------------- */
function extractPdfText(buf){
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const streams = pdfFindStreams(bytes);
  if(!streams.length) return {text:"", pages:0, note:"no content streams found"};
  let text="", used=0, failed=0, garbled=0;
  const allItems=[];

  /* First pass: any stream that is a ToUnicode CMap gives us a glyph map.
     Resource names are per-page, so a single shared table is an approximation
     that works for the single-font log exports this is aimed at. */
  const fonts=new Map();
  const shared=new Map();
  /* The /ToUnicode reference lives in the font object, not in the CMap
     stream's own dictionary, so identify CMaps by their decoded content. */
  const decoded=[];
  for(const s of streams){
    if(/(DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode|LZWDecode)/.test(s.dict)){ decoded.push(null); continue; }
    try{
      const d=applyFilters(s.data, s.dict);
      let t=""; for(let k=0;k<d.length;k++) t+=String.fromCharCode(d[k]);
      decoded.push(t);
      if(/beginbfchar|beginbfrange/.test(t))
        parseToUnicode(t).forEach((v,k)=>shared.set(k,v));
    }catch(e){ decoded.push(null); failed++; }
  }
  for(let si=0; si<streams.length; si++){
    const str = decoded[si];
    if(str===null || str===undefined) continue;
    if(/beginbfchar|beginbfrange/.test(str)) continue;      // that was a CMap
    if(!/(\bTj\b|\bTJ\b|\bBT\b)/.test(str)) continue;   // not a text content stream
    try{ pdfItemsFromContent(str, shared).forEach(it=>{ it.page=si; allItems.push(it); }); }catch(e){}
    let t=pdfTextFromContent(str, null);
    if(!textLooksReadable(t) && shared.size){
      // retry through the font map — this is the subset-font case
      const fm=new Map([["*",shared]]);
      const t2=pdfTextFromContent(str, {get:()=>shared, size:shared.size});
      if(textLooksReadable(t2)) t=t2;
    }
    if(t.trim()){
      if(textLooksReadable(t)){ text += (text?"\n":"") + t; used++; }
      else garbled++;
    }
  }
  text = text.replace(/[ \t]+\n/g,"\n").replace(/\n{3,}/g,"\n\n").trim();
  return {text, pages:used, failed, garbled, items:allItems,
    note: used ? ("text recovered from "+used+" content stream"+(used===1?"":"s")+
                  (garbled?" · "+garbled+" stream"+(garbled===1?"":"s")+" unreadable and skipped":""))
               : (garbled ? "the text in this PDF uses an embedded subset font with no usable character map, so it cannot be recovered as readable text — export the original log instead"
                 : (failed ? "streams present but could not be decoded"
                           : "no extractable text — the PDF is probably a scan or image export"))};
}
