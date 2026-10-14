"""Tiny Chrome DevTools Protocol client (stdlib only) for driving headless Chrome."""
import base64, json, os, socket, struct, subprocess, tempfile, time, urllib.request

CHROME = os.environ.get("CHROME") or next((p for p in [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
] if os.path.exists(p)), "google-chrome")


class WS:
    def __init__(self, url):
        _, rest = url.split("://", 1)
        hostport, path = rest.split("/", 1)
        host, port = hostport.split(":")
        self.s = socket.create_connection((host, int(port)))
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(4096)
        assert b" 101 " in buf.split(b"\r\n")[0], buf
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, text):
        data = text.encode()
        hdr = bytes([0x81])
        n = len(data)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.s.sendall(hdr + mask + masked)

    def recv(self):
        msg = b""
        while True:
            b0, b1 = self._read(2)
            fin, op = b0 & 0x80, b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            if b1 & 0x80:
                mask = self._read(4)
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read(n)))
            else:
                payload = self._read(n)
            if op == 0x8:
                raise ConnectionError("closed by peer")
            if op == 0x9:  # ping
                continue
            msg += payload
            if fin:
                return msg.decode()


class Chrome:
    def __init__(self, port=9333, profile=None):
        profile = profile or os.path.join(tempfile.mkdtemp(), "profile")
        self.proc = subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", f"--remote-debugging-port={port}",
                                      f"--user-data-dir={profile}", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                page = next(t for t in targets if t["type"] == "page")
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("chrome did not start")
        self.ws = WS(page["webSocketDebuggerUrl"])
        self.id = 0
        self.call("Page.enable")
        self.call("Runtime.enable")

    def call(self, method, **params):
        self.id += 1
        self.ws.send(json.dumps({"id": self.id, "method": method, "params": params}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.id:
                if "error" in m:
                    raise RuntimeError(m["error"])
                return m.get("result", {})

    def goto(self, url, settle=1.0):
        self.call("Page.navigate", url=url)
        # wait for load event
        deadline = time.time() + 15
        while time.time() < deadline:
            m = json.loads(self.ws.recv())
            if m.get("method") == "Page.loadEventFired":
                break
        time.sleep(settle)

    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        res = r["result"]
        if "exceptionDetails" in r:
            ex = r["exceptionDetails"]
            raise RuntimeError(ex.get("exception", {}).get("description") or ex.get("text"))
        return res.get("value")

    def close(self):
        try:
            self.call("Browser.close")
        except Exception:
            pass
        self.proc.terminate()
