#!/usr/bin/env python3
"""Start PPSM Builder and open it in the browser.

    python3 ppsm.py                 # http://127.0.0.1:33506, opens a browser tab
    python3 ppsm.py --port 9000
    python3 ppsm.py --no-browser
    python3 ppsm.py --data ./work   # where the session is autosaved (default ~/.ppsm)
"""
import argparse
import sys
import threading
import webbrowser

from ppsm.server import make_server


def main(argv=None):
    ap = argparse.ArgumentParser(description="PPSM Builder")
    ap.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    ap.add_argument("--port", type=int, default=33506)
    ap.add_argument("--data", help="folder the session is autosaved to (default: ~/.ppsm or $PPSM_DATA)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    ap.add_argument("--quiet", action="store_true", help="no request log")
    args = ap.parse_args(argv)

    try:
        server = make_server(args.host, args.port, args.data, args.quiet)
    except OSError as e:
        print(f"cannot listen on {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1

    url = f"http://{args.host}:{args.port}/"
    print(f"PPSM Builder at {url}")
    print(f"session autosaved to {server.store.path}")
    print("Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
