"use strict";
/* Pages and autosave. The engine (core.js .. ui.js) is a single in-memory
   model; this file shows one page of it at a time and keeps the server copy
   of the session current. */

/* ---------------- pages ---------------- */
const PAGES = ["setup","register","review","endpoints","diagram","compare","export","settings","guide"];
const PAGE_PATH = p => p==="setup" ? "/" : "/"+p;
function pageFromPath(path){
  const p = path.replace(/^\/+|\/+$/g,"");
  return PAGES.includes(p) ? p : "setup";
}
function showPage(p){
  document.querySelectorAll(".page").forEach(el=>{ el.hidden = el.dataset.page!==p; });
  document.querySelectorAll("#nav a").forEach(a=>a.classList.toggle("on", a.dataset.page===p));
  if(p==="settings") openSettings();
  if(p==="endpoints" && ROWS.length) renderEndpoints();
  if(p==="diagram" && ROWS.length && !$("dgCanvas").querySelector("svg")) renderDiagram();
  document.title = (p==="setup" ? "PPSM Builder" : p[0].toUpperCase()+p.slice(1)+" · PPSM Builder");
  window.scrollTo(0,0);
}
function go(p, push){
  if(push!==false) history.pushState({page:p}, "", PAGE_PATH(p));
  showPage(p);
}
document.addEventListener("click", e=>{
  const a = e.target.closest("a[data-page]");
  if(!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
  e.preventDefault(); go(a.dataset.page);
});
window.addEventListener("popstate", ()=>showPage(pageFromPath(location.pathname)));

/* ---------------- autosave ---------------- */
let SAVE_TIMER=null, SAVE_PAUSED=true, SAVE_DIRTY=false;
function saveState(txt, cls){ const el=$("saveState"); if(el){ el.textContent=txt; el.className="savestate "+(cls||""); } }
function scheduleSave(){
  if(SAVE_PAUSED) return;
  SAVE_DIRTY=true; saveState("unsaved","dirty");
  clearTimeout(SAVE_TIMER); SAVE_TIMER=setTimeout(saveNow, 1200);
}
async function saveNow(){
  if(!SAVE_DIRTY) return;
  clearTimeout(SAVE_TIMER); SAVE_DIRTY=false;
  try{
    const r = await fetch("/api/session",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(sessionSnapshot())});
    if(!r.ok) throw new Error(r.status+" "+r.statusText);
    saveState("saved","ok");
  }catch(e){ SAVE_DIRTY=true; saveState("not saved: "+e.message,"bad"); }
}
/* every path that changes the model ends in one of these */
["render","renderEndpoints","setBanner"].forEach(name=>{
  const orig = window[name];
  window[name] = function(){ const r = orig.apply(this, arguments); scheduleSave(); return r; };
});
const _renderPage = window.render;
window.render = function(){ const r=_renderPage.apply(this, arguments); $("navCount").textContent = ROWS.length ? String(ROWS.length) : ""; return r; };
document.querySelector('[data-page="setup"]').addEventListener("input", e=>{ if(e.target.id && e.target.id.startsWith("m_")) scheduleSave(); });
window.addEventListener("beforeunload", ()=>{
  if(!SAVE_DIRTY) return;
  clearTimeout(SAVE_TIMER);
  navigator.sendBeacon("/api/session", new Blob([JSON.stringify(sessionSnapshot())],{type:"application/json"}));
});
$("newSession").onclick = async ()=>{
  if(!confirm("Discard the current session and start empty?")) return;
  SAVE_PAUSED=true;
  await fetch("/api/session",{method:"DELETE"});
  location.href="/";
};

/* ---------------- start ---------------- */
(async function start(){
  if(new URLSearchParams(location.search).has("selftest")) runSelfTestHeadless();
  try{
    const r = await fetch("/api/session");
    const d = r.ok ? await r.json() : null;
    if(d && d.rows) restoreSession(d);
  }catch(e){ console.warn("session not restored:", e); }
  SAVE_PAUSED=false; saveState("saved","ok");
  showPage(pageFromPath(location.pathname));
  history.replaceState({page:pageFromPath(location.pathname)}, "", location.pathname);
})();

/* ?selftest runs the engine checks on load and leaves the verdict on <body>, for headless test runs */
function runSelfTestHeadless(){
  try{ runSelfTest(); }catch(e){ window.__errors.push("selftest: "+e.message); }
  const bad=[...document.querySelectorAll("#stBody .st-row.bad")].map(e=>e.textContent);
  const sum=document.querySelector("#stBody .st-summary");
  document.body.dataset.selftest = (bad.length || !sum || window.__errors.length) ? "fail" : "pass";
  document.body.dataset.selftestSummary = (sum?sum.textContent:"no result") + bad.map(b=>"\n"+b).join("") + window.__errors.map(e=>"\nERROR "+e).join("");
}
