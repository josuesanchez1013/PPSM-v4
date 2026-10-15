#!/usr/bin/env python3
"""GUI smoke test in headless Chrome: load, ingest the examples, tour the
pages, export, autosave, reload, settings, and the engine's self-tests.

    python3 tests/gui_smoke.py              # starts its own server
    CHROME=/path/to/chrome python3 tests/gui_smoke.py
"""
import base64, json, os, pathlib, sys, tempfile, threading, time, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
from cdp import Chrome  # noqa: E402
from ppsm.server import make_server  # noqa: E402

EXAMPLES = sorted(p for p in (REPO / "examples").rglob("*") if p.is_file() and p.suffix != ".md")

ok = True
def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(detail)) if detail else ""))
    ok = ok and bool(cond)

def page(c):
    return c.js("document.querySelector('.page:not([hidden])').dataset.page")

def main():
    tmp = tempfile.TemporaryDirectory()
    server = make_server("127.0.0.1", 0, tmp.name, quiet=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    def api(path):
        with urllib.request.urlopen(base + path) as r:
            return json.loads(r.read())

    c = Chrome(profile=os.path.join(tmp.name, "chrome"))
    try:
        c.goto(base + "/")
        check("no load errors", c.js("window.__errors.length") == 0, c.js("window.__errors"))
        check("setup page shown", page(c) == "setup")
        check("register starts empty", c.js("ROWS.length") == 0)

        files = [{"name": p.name, "b64": base64.b64encode(p.read_bytes()).decode()} for p in EXAMPLES]
        c.js("""
          window.__files = %s.map(f => new File([Uint8Array.from(atob(f.b64), ch => ch.charCodeAt(0))], f.name));
          $("m_system").value = "SMOKE-ENCLAVE"; $("m_system").dispatchEvent(new Event("input", {bubbles:true}));
          handleFiles(window.__files); true
        """ % json.dumps(files))
        time.sleep(2.5)
        rows = c.js("ROWS.length")
        check("example files produced register rows", rows > 0, rows)
        check("no errors after ingest", c.js("window.__errors.length") == 0, c.js("window.__errors"))
        check("hostnames resolved from DNS examples", c.js("ROWS.filter(r => /range2\\.mil/i.test(r.srcHost+r.dstHost)).length") > 0)
        check("no import-error modal", c.js("$('errModal').hidden") is True, c.js("$('errBody').textContent.slice(0,300)"))

        for name, sel in [("register", "#tbody tr"), ("review", "#chkBody"), ("endpoints", "#epBody .ep-tbl"),
                          ("diagram", "#dgCanvas svg"), ("compare", "#diffBody"), ("export", "#expEmassXlsx"),
                          ("settings", "#cfg_cols .opt"), ("guide", ".guide")]:
            c.js("document.querySelector('#nav a[data-page=\"%s\"]').click(); true" % name)
            time.sleep(0.3)
            n = c.js("document.querySelectorAll('.page:not([hidden]) %s').length" % sel)
            check("page %s at %s" % (name, c.js("location.pathname")), page(c) == name and n > 0, "%d x %s" % (n, sel))
        check("no errors after page tour", c.js("window.__errors.length") == 0, c.js("window.__errors"))
        check("nav count shows rows", c.js("$('navCount').textContent") == str(rows))

        c.js("renderPpsmChecks(); true")
        check("review checks render", c.js("document.querySelectorAll('#chkBody .chk').length") > 0)
        check("endpoints listed", c.js("renderEndpoints(); document.querySelectorAll('#epBody tbody tr').length") > 0)
        xlsx = c.js("(function(){const b=buildEmassXlsx(meta(), emassShape(ROWS)); return [b.length, b[0], b[1]];})()")
        check("eMASS xlsx builds", xlsx[0] > 1000 and xlsx[1] == 0x50 and xlsx[2] == 0x4B, xlsx)

        time.sleep(2)
        sess = api("/api/session")
        check("session autosaved", len(sess.get("rows", [])) == rows and sess["meta"]["system"] == "SMOKE-ENCLAVE")
        check("save indicator says saved", c.js("$('saveState').textContent") == "saved")

        c.goto(base + "/register")
        check("direct URL opens register", page(c) == "register")
        check("rows restored after reload", c.js("ROWS.length") == rows)
        check("system name restored", c.js("$('m_system').value") == "SMOKE-ENCLAVE")
        check("table rendered after restore", c.js("document.querySelectorAll('#tbody tr').length") > 0)

        c.goto(base + "/settings")
        c.js("$('cfg_dnsdom').value='range2.mil'; $('cfg_autofinish').checked=false; applySettings(); true")
        time.sleep(2)
        cfg = api("/api/session")["cfg"]
        check("settings autosaved", cfg.get("dnsDomain") == "range2.mil" and cfg.get("autoFinish") is False)
        c.goto(base + "/settings")
        check("settings restored into form", c.js("$('cfg_dnsdom').value") == "range2.mil" and c.js("$('cfg_autofinish').checked") is False)

        c.goto(base + "/?selftest=1")
        check("engine self-test", c.js("document.body.dataset.selftest") == "pass", c.js("document.body.dataset.selftestSummary"))
    finally:
        c.close()
        server.shutdown()
        tmp.cleanup()
    print("\nSMOKE " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
