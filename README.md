# PPSM Builder

Builds a Ports, Protocols and Services Management (PPSM) register from
collected network data and writes the eMASS import template. It reads host
socket listings, firewall connection tables and rulesets, NetFlow, Zeek,
packet captures, Nessus/ACAS scans and DNS exports, cross-references them,
and produces `allow.xlsx`.

Everything runs on your machine. Nothing is uploaded.

## Run

```
python3 ppsm.py
```

Python 3.8 or later, no packages. It serves the GUI on
http://127.0.0.1:33506 and opens a browser tab. Options: `--port`,
`--no-browser`, `--data DIR` (where the session is autosaved; default
`~/.ppsm`).

Or with Docker:

```
docker build -t ppsm .
docker run --rm -p 33506:33506 -v "$PWD/ppsm-data:/data" ppsm
```

## Use

1. **Setup**: fill in the system header, then drop the collection folder on
   the ingest box.
2. **Register**: review the rows and set a Boundary on each.
3. **Review**: fill in what can be derived, run the checks, compare flows
   with the ruleset.
4. **Endpoints**: name anything still unidentified.
5. **Export**: eMASS Import (allow.xlsx).

Work is autosaved after every change. The Guide page lists everything the
tool reads; `docs/user-guide.md` has the per-host collection commands.

## Collect

| Where | Script |
|---|---|
| Windows (local or fleet over WinRM) | `collectors/ppsm-collect.ps1` |
| Linux (local or over SSH) | `collectors/ppsm-collect.sh` |
| Whole fleet with Ansible, including Cisco devices | `collectors/ppsm.yml` |

Each writes one results folder. Drop the folder on the ingest box.

## Layout

```
ppsm.py            start here
ppsm/server.py     localhost HTTP server and session store
ppsm/web/          the GUI: index.html, css/, js/ (parsers, register, export, ...)
collectors/        collection scripts
examples/          small sample inputs
docs/              user guide
tests/             server tests and a headless-Chrome GUI smoke test
```

## Test

```
python3 -m unittest discover -s tests            # server
python3 tests/gui_smoke.py                       # needs Chrome; runs the 329 engine self-tests and an ingest/export pass
```

The Self-Test button in the GUI runs the same engine checks in your browser.
