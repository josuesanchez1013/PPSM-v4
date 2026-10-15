"""Local web server for PPSM Builder.

Serves the single-page GUI, its static files, and a JSON session the GUI
autosaves to. Standard library only; binds to localhost unless told otherwise.
"""
import json
import mimetypes
import os
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent / "web"
PAGES = {"", "register", "review", "endpoints", "diagram", "compare", "export", "settings", "guide"}
MAX_SESSION_BYTES = 256 * 1024 * 1024


class SessionStore:
    """One session.json in the data folder, written atomically."""

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "session.json"

    def load(self):
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return b"{}"

    def save(self, body):
        json.loads(body)  # refuse anything that is not JSON
        self.data_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, prefix=".session-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(body)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def clear(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "PPSMBuilder/4"
    store = None  # set on the server class by make_server

    def log_message(self, fmt, *args):
        if self.server.quiet:
            return
        super().log_message(fmt, *args)

    # ---- helpers
    def _send(self, status, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _static(self, rel):
        base = WEB_DIR.resolve()
        target = (base / rel).resolve()
        if base not in target.parents or not target.is_file():
            return self._send(HTTPStatus.NOT_FOUND, b"not found")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(HTTPStatus.OK, target.read_bytes(), ctype)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_SESSION_BYTES:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"session too large")
            return None
        return self.rfile.read(length)

    # ---- routes
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/session":
            return self._send(HTTPStatus.OK, self.server.store.load(), "application/json; charset=utf-8")
        if path == "/api/health":
            return self._send(HTTPStatus.OK, b'{"ok":true}', "application/json; charset=utf-8")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path.strip("/") in PAGES:
            return self._static("index.html")
        self._send(HTTPStatus.NOT_FOUND, b"not found")

    do_HEAD = do_GET

    def do_PUT(self):
        if self.path != "/api/session":
            return self._send(HTTPStatus.NOT_FOUND, b"not found")
        body = self._body()
        if body is None:
            return
        try:
            self.server.store.save(body)
        except ValueError:
            return self._send(HTTPStatus.BAD_REQUEST, b"session must be JSON")
        self._send(HTTPStatus.NO_CONTENT)

    do_POST = do_PUT  # sendBeacon on page unload can only POST

    def do_DELETE(self):
        if self.path != "/api/session":
            return self._send(HTTPStatus.NOT_FOUND, b"not found")
        self.server.store.clear()
        self._send(HTTPStatus.NO_CONTENT)


def make_server(host="127.0.0.1", port=33506, data_dir=None, quiet=False):
    data_dir = data_dir or default_data_dir()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.store = SessionStore(data_dir)
    server.quiet = quiet
    return server


def default_data_dir():
    return Path(os.environ.get("PPSM_DATA") or Path.home() / ".ppsm")
