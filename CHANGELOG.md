# Changelog

## v4

- Runs as a local Python app (`python3 ppsm.py`) instead of a single HTML file.
- The GUI is split into pages: Setup, Register, Review, Endpoints, Diagram,
  Compare, Export, Settings, Guide.
- The session is autosaved to a data folder after every change and restored
  on reload. Save Session still writes a portable copy.
- Simple mode removed. The finish pass after import is a setting, on by default.
- Engine split into modules under `ppsm/web/js/`. Logic unchanged; the 329
  self-tests pass.
- Collectors moved to `collectors/`, sample inputs to `examples/`, the guide
  to `docs/user-guide.md`. Dockerfile and tests added.

## v3.7

- eMASS sheet groups by port alone: TCP and UDP on one port are one row
  (`TCP/UDP`), a port seen both ways is `Bi-Directional`, several boundaries
  are semicolon-joined. A consolidated register row is split back to its
  ports first, so a port never appears twice.

## v3.6

- Installed software read from `.nessus` and Tenable CSV exports (plugins
  20811, 22869, 45590, 44401), kept per address, shown on the Endpoints page.
- Fill In replaces a blank or bare process name in Application/Software
  Record Name with the installed product serving that port. A port no
  installed product accounts for is flagged by the checks.
- Tenable CSV exports with quoted multi-line Plugin Output are split correctly.

## v3.5

- eMASS export shaping, all on by default: one row per protocol/port, every
  application named once, IP addresses only, rows in port order. The working
  register is not changed; shaping happens on export.
- A hostname typed or imported into an address cell is recognised, moved
  beside the address and resolved.

## v3.4

- `ppsm-collect.ps1` collects hosts in parallel (`-ThrottleLimit`), probes
  WinRM first so unreachable hosts are skipped in seconds, and runs on
  PowerShell 3.0 to 7 on both ends.
- eMASS export controls: generated Purpose where blank, VPN / Encrypted
  Tunnel Traffic and VPN Tunnel Type for the whole export, per-end Physical
  Location. Bulk-apply gained the same fields.

## v3.3

- Rule coverage: observed flows matched against permit rules on source,
  destination, protocol and port. Unmatched flows and unused rules listed.
- Compare with a previous register: added, removed, changed; Mark
  Registered / New.
- Mission Justification drafts, marked [DRAFT] and flagged by the checks.
- Network device collection from the Windows and Ansible collectors.

## v3.2

- Collector connections CSV and Get-NetTCPConnection / Get-NetUDPEndpoint
  exports read directly. Windows Firewall log and rule exports read.
- Consolidation of like endpoints (ports joined) and like sources.

## v3.1

- Registers that carry hostnames in the address columns are read as
  registers and resolved through DNS exports. DNS exports in any delimiter,
  any column order; zone inferred from SOA, file name, shared suffix or the
  configured domain. Load Host Inventory accepts several files at once.
- Checks for hostnames with no address and names that disagree with DNS.

## v3

- eMASS PPSM Boundary Information Import Template reproduced exactly: 21
  columns, header block, Glossary and Instructions sheets, dropdowns,
  AutoFilter, character limits.
- About 30 input formats detected by content, including Nessus/ACAS, FMC
  reports, NetFlow, Zeek, pcap, firewall rulesets, DNS, AD, hosts files.
- Hostname and IP resolution across every source, ranked by authority.
- Boundary model that never auto-assigns a DISN crossing.
- PowerShell, bash and Ansible collectors. In-browser self-tests.
