import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ppsm.server import make_server  # noqa: E402


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.server = make_server("127.0.0.1", 0, cls.tmp.name, quiet=True)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def req(self, path, method="GET", body=None):
        r = urllib.request.Request(self.base + path, data=body, method=method)
        if body is not None:
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type", ""), e.read()

    def test_pages_serve_the_shell(self):
        for path in ["/", "/register", "/review", "/endpoints", "/diagram", "/compare", "/export", "/settings", "/guide"]:
            status, ctype, body = self.req(path)
            self.assertEqual(status, 200, path)
            self.assertIn("text/html", ctype)
            self.assertIn(b'data-page="register"', body)

    def test_unknown_page_is_404(self):
        self.assertEqual(self.req("/nope")[0], 404)
        self.assertEqual(self.req("/api/nope")[0], 404)

    def test_static_files(self):
        status, ctype, body = self.req("/static/js/core.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", ctype)
        self.assertIn(b"use strict", body)
        status, ctype, _ = self.req("/static/css/ppsm.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", ctype)

    def test_every_script_in_the_shell_exists(self):
        _, _, html = self.req("/")
        import re
        srcs = re.findall(rb'src="(/static/[^"]+)"', html) + re.findall(rb'href="(/static/[^"]+)"', html)
        self.assertGreater(len(srcs), 10)
        for src in srcs:
            self.assertEqual(self.req(src.decode())[0], 200, src)

    def test_static_cannot_escape_web_dir(self):
        self.assertEqual(self.req("/static/../server.py")[0], 404)
        self.assertEqual(self.req("/static/%2e%2e/server.py")[0], 404)

    def test_session_round_trip(self):
        self.assertEqual(json.loads(self.req("/api/session")[2]), {})
        doc = {"meta": {"system": "X"}, "rows": [{"dest": "10.0.0.1"}]}
        status, _, _ = self.req("/api/session", "PUT", json.dumps(doc).encode())
        self.assertEqual(status, 204)
        self.assertEqual(json.loads(self.req("/api/session")[2]), doc)
        self.assertTrue((Path(self.tmp.name) / "session.json").exists())
        # sendBeacon on unload can only POST
        doc["meta"]["system"] = "Y"
        self.assertEqual(self.req("/api/session", "POST", json.dumps(doc).encode())[0], 204)
        self.assertEqual(json.loads(self.req("/api/session")[2])["meta"]["system"], "Y")
        self.assertEqual(self.req("/api/session", "DELETE")[0], 204)
        self.assertEqual(json.loads(self.req("/api/session")[2]), {})

    def test_session_rejects_non_json(self):
        status, _, _ = self.req("/api/session", "PUT", b"not json")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
