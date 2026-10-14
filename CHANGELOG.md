# Changelog

All notable changes to the PPSM Builder. Dates are approximate; this project
is developed iteratively and versioned by capability rather than release tags.

## v3.7 — eMASS sheet: a port is listed once

- The eMASS sheet now groups by **port alone**: TCP and UDP on the same
  port are one row reading `TCP/UDP`; a port seen both ways is
  `Bi-Directional`; a port seen across several boundaries carries them
  semicolon-joined. A consolidated register row (`80; 443`) is split back
  to its ports first, so a port can never appear twice. 6 new self-tests
  (329 total).

## v3.6 — ACAS software inventory fills Application/Software Record Name

- Installed software is read from `.nessus` and Tenable CSV exports
  (plugins 20811 Windows installed software, 22869 SSH package list,
  45590 CPE, 44401 Windows services) and kept per address; the Endpoints
  table shows a Software count per host with the list on hover.
- During enrichment the installed product that serves a row's port replaces
  a blank, a bare process name (`svchost`, `sqlservr`) or a service-copy in
  Application/Software Record Name — matched by the product's usual port,
  the service it implies, or the process it runs as. A real product name is
  never replaced; hosts with no inventory are not touched.
- A port on an inventoried host that no installed product accounts for is
  noted on the row and listed by the review checks (*No installed software
  matches this port*, worth a look).
- Tenable CSV exports are now split into records with quoted newlines
  honoured — the multi-line Plugin Output column used to break findings
  across lines.
- Inventory is saved and loaded with the session. 12 new self-tests
  (323 total).

## v3.5 — the eMASS sheet: one row per port, addresses only, in port order

### eMASS export shaping (Settings › eMASS template, all on by default)
- **One row per protocol/port** (within boundary and direction): every
  service, application, source and destination seen on that port is joined
  into the one row. Previously the sheet carried one row per flow, so a port
  reached from several sources or carrying several services showed up
  several times.
- **Every application named once** — version strings are ignored when
  comparing, so `Microsoft IIS/10.0` and `microsoft iis 10` are one entry;
  a joined Application cell is no longer cut at 40 characters.
- **IP addresses only**: Source/Destination carry the address, the FQDN
  columns carry the address, and a hostname sitting in an address cell is
  resolved through the inventory on the way out. The export reports any
  name no source could resolve.
- **Rows ordered lowest port to highest.**
- The working register is not changed by any of this; the shaping happens
  on the way out (Excel and CSV alike).

### Resolution
- A hostname typed or imported into an address cell (`wsus11`,
  `APP01.LAN; 10.9.9.30`) is now recognised as a name, moved beside the
  address and resolved; previously only the hostname cell was resolved.
- 15 new self-tests (311 total).

## v3.4 — parallel collection, eMASS export controls

### ppsm-collect.ps1
- **Hosts are collected in parallel** (`-ThrottleLimit`, 32 at once): one
  `Invoke-Command` fans out over the reachable list instead of a host-by-host
  loop.
- **Unreachable hosts are skipped in seconds.** Every remote host's WinRM
  port is probed at the same time (`-ProbeTimeout`, 5 s); a host that does
  not answer is listed as unreachable and never waited on. A host that
  answers but stalls is bounded by `-ConnectTimeout` (20 s) and
  `-HostTimeout` (180 s). Per-host failures are error records, not stops.
  `-UseSSL`/`-WinRmPort` for 5986, `-SkipProbe` to go straight to WinRM.
- **PowerShell 3.0–5.1 and 7 on both ends**, with the version-specific
  choices made explicitly: ports via NetTCPIP cmdlets or `netstat -ano`,
  OS name via CIM or WMI, CSV encoding `UTF8` (5.1, BOM) or `utf8BOM` (7)
  so Excel opens both the same way. `#Requires -Version 3.0`.

### eMASS export (Settings › eMASS template)
- **Purpose is filled on every row**: a row with no Mission Justification
  gets a generated statement (service need, both ends, port); a written one
  is used as is with any `[DRAFT]` marker removed. Can be turned off.
- **VPN / Encrypted Tunnel Traffic** can be set to Yes or No for the whole
  export, with an overwrite option; otherwise per row from the boundary.
- **VPN Tunnel Type** chosen from the template's Glossary list, written where
  a row has none (or everywhere with overwrite), never onto a `No` row.
- **Source and Destination Physical Location** per end for the enclave's own
  addresses, in addition to the per-row cells.
- Bulk-apply gained Source/Destination Physical Location, VPN / Encrypted
  Tunnel Traffic and VPN Tunnel Type (Glossary dropdown).
- 18 new self-tests (296 total).

## v3.3 — coverage, diffing, purpose drafts, network devices, self-test

### Rule coverage
- Observed flows are matched against permit rules on **source scope,
  destination scope, protocol and port** (single, range, list or any),
  replacing the port-only match that let any 443 rule cover every HTTPS
  flow. A consolidated row is covered only when every port is; traffic
  matched only by a deny rule is reported as *denied but seen*.
- *Run Coverage* in the review card shows flows with no permitting rule
  and permit rules nothing used; *Coverage Report* writes both to one CSV
  with the rule references and per-rule usage counts. The existing
  "no rule behind it" / "rule nobody used" checks now use the same engine.

### Compare with previous register
- New card: load last quarter's `allow.xlsx`, an eMASS export, a register
  CSV or a saved session and get **Added / Removed / Changed** against the
  current register, flow by flow (a consolidated `80; 443` row compares
  with two rows; a service as a code then and a name now is not a change;
  rules are left out). *Diff Report* writes it to CSV; *Mark Registered /
  New* sets Status so the submission is the delta.
- The ingest reader gained a capture mode so a file can be parsed without
  being merged into the register.

### Mission Justification drafts
- Opt-in under Fill In (off by default, never run by the automatic pass):
  rows with no purpose get a sentence from the service need, both ends and
  the port, marked `[DRAFT …]`. ~90 services have a stated need
  (`SERVICE_PURPOSE`); others fall back to the data description.
- New review check: *Mission justification is still a draft*.

### Collectors
- `ppsm-collect.ps1 -NetworkDevices fw01:asa,core01:ios -NetworkUser u`
  pulls `show conn all`, the access-list/object-group config and the
  switch NetFlow cache over the Windows OpenSSH client (commands fed on
  stdin with a forced tty, paging off). READ-ME.txt lists what came back,
  and only says "collect by hand" when nothing was asked for.
- `ppsm-collect.ps1 -SelfTest` collects the local machine the normal way
  and forced through the netstat fallback, compares the listener sets and
  writes `ppsm-selftest\SELFTEST.txt` with a PASS/CHECK verdict — the way
  to prove the fallback on a PowerShell 5.1 host before a fleet run.
- Comma-joined `-Computers a,b` / `-NetworkDevices a,b` work from cmd.exe
  and `-File` as well as from a PowerShell prompt.
- 20 new self-tests (278 total).

## v3.2 — collector output read correctly, names not codes, stricter dedupe

### Fixed
- **The collectors' own connections CSV was misread.** `ppsm-collect.ps1`
  and the Windows play in `ppsm.yml` write `Source IP / Destination Port /
  Data Service / Direction` headers, which the eMASS-export detector
  claimed first: every listener was dropped, the *source* port was taken
  as the service port, and the rows came in as `Registered`. A dedicated
  reader now claims that file (`Windows connections (collector)`), keeps
  the listeners, and faces each established connection toward the service
  using the listener list in the same file.
- `ppsm.yml`: the Windows DNS-zone export piped a `foreach` *statement*
  into `ConvertTo-Csv`, which PowerShell rejects, so no DNS export ever
  came back through Ansible. The READ-ME timestamp was always blank
  (no facts gathered in that play) and named a file that does not exist.
- Collectors: an inbound client of a local listener was written as
  `Outbound` with the client's ephemeral port as the destination. Both
  collectors now turn it round.

### PowerShell version awareness
- `ppsm-collect.ps1` and the `win_shell` block in `ppsm.yml` read
  `$PSVersionTable` on every host and test for `Get-NetTCPConnection`.
  Where it is missing — or present but failing — ports and connections
  are parsed from `netstat -ano` instead. The shell version, edition and
  method used are reported per host on the console, in READ-ME.txt and in
  a new `Collector` column of each connections CSV; the builder shows it
  in the ingest log.

### Service names
- **Data Service / Application now carries the service's name, not an
  IANA code or a bare acronym**: `Remote Desktop Protocol (RDP)` instead
  of `ms-wbt-server`, `Lightweight Directory Access Protocol (LDAP)`
  instead of `ldap`, `Server Message Block (SMB)` instead of
  `microsoft-ds`/`cifs`. ~230 codes covered (`SERVICE_NAMES`). Codes that
  arrive from Nessus (`www`, `cifs`, `epmap`), Zeek (`ssl`) or a CSV are
  upgraded when the register is finished; a hand-typed name is left alone.
- A Windows process name (`svchost`, `wsusservice`) is an *application*:
  it now lands in Application/Software Record Name and the service is
  named from the product directory or the port.

### Dedupe
- Rows are the same registration when they share source, destination,
  protocol and port(s); enclave, direction-as-seen, origin tool and
  counters no longer keep two rows apart. Hostnames and addresses are
  compared trimmed, case-folded and without a trailing dot.
- The most complete row is kept and its blanks are filled from the rows
  that go; origin tools are merged, counters added.
- A row already covered by a consolidated row (`80; 443` from
  `10.1.1.5; 10.1.1.6` covers `10.1.1.5 → 443`) is removed; so is a bare
  listener covered by an observed flow to that port.
- The ingest merge key uses the same normalisation, so duplicates are
  caught as files are dropped, not only at Finish.
- 19 new self-tests (258 total).

## v3.1 — hostnames in the register, resolved from DNS exports

### Input
- A register that carries **hostnames where the addresses should be** — an
  eMASS export or a PPSM kept in the template's column layout with names in
  the Source/Destination IP columns, several sources joined by semicolons,
  trailing dots or upper case — is now read as a register. Previously its
  "VPN / Encrypted Tunnel Traffic" column read as a traffic-volume column and
  the file was taken for a NetFlow top-conversations report, keeping one row
  in four.
- `show conn` from an ASA with `names` configured (object names in place of
  addresses) is read; the names resolve against the DNS zones afterwards.
- DNS exports: the **zone is inferred** when the file has no zone column —
  from the SOA/NS row the export carries, from a file named after the zone
  (`range2.mil.csv`, `zone-range2.mil.txt`), from the suffix most rows share,
  or from the DNS domain under Settings — so DNS Manager and
  `dnscmd /enumrecords` output yields `wsus11.range2.mil`, not `wsus11`.
  `(same as parent folder)` rows are understood; a round-robin name with
  several addresses learns all of them; CNAME chains are followed.
- A CSV cell containing spaces (`Start of Authority (SOA)`) is no longer
  split into words, which used to shift every column after it.
- **Load Host Inventory** accepts several files at once and reads every
  format the ingest box does, including Excel and `.nessus`.

### Processing
- Resolution fills the **address from the hostname** on every row, including
  semicolon-joined names (`analyst61; analyst63` → `172.22.14.61;
  172.22.14.63`), and reports the names no source could resolve.
- A row whose hostname **disagrees with DNS** for the same address (and is
  not a CNAME or a name a scan/inventory also gave it) is annotated, not
  rewritten.

### Review
- New checks: *Hostname with no IP address* (must fix — the template needs
  both ends) and *Hostname disagrees with DNS for that address*.
- Endpoints Discovered lists hostnames that have no address, with a field to
  type the address against the name; the Unidentified Work List carries them
  too, and loads back in once filled.
- 16 new self-tests (239 total).

## v3

### Export
- eMASS **PPSM Boundary Information Import Template** reproduced exactly: 21
  columns A–U in template order, the seven-row CUI/system header block, and the
  Glossary and Instructions sheets.
- Output named `<System>.allow.xlsx`.
- **AutoFilter** on the header row (row 8) so every column can be filtered in
  Excel.
- **Dropdowns** on the lookup columns (Type, Boundary, Direction, VPN Traffic,
  VPN Tunnel Type, both Connection Logical Points) — inline lists where they
  fit, Glossary ranges where they don't.
- Workbook written with DEFLATE compression for maximum Excel compatibility.
- Character limits from the template's Instructions sheet enforced per field;
  consolidated (semicolon-joined) cells exempted so ports are not truncated.

### Input
- ~30 formats auto-detected by content: flow data, rules/policy, scans, and
  name sources.
- **DNS exports** as CSV **or** text, detected by content — any delimiter
  (comma, semicolon, tab, pipe, space), any/no header, any column order,
  verbose record-type labels (`A Record`, `Host (A)`, `Pointer (PTR)`).
- **Name/IP catch-all**: any table pairing hostnames with IP addresses is
  learned, even with no record-type column.
- **eMASS PPSM export** read back in for reconciliation (CSV or `.xlsx`
  "PPSM Info" tab), rows marked `Registered`.
- **Nessus/ACAS** extraction: names (FQDN/rDNS/NetBIOS), OS and type, all host
  interfaces, product behind each port, TLS confirmation, credentialed-scan
  status, and the host's own connection table.
- **Tenable/ACAS CSV** findings export.
- `Get-NetTCPConnection` / `Get-NetUDPEndpoint` CSV exports.
- Protocol normalisation (IANA numbers → names; `?`/`unknown` → blank).

### Processing
- Hostname ↔ IP resolution across every source, both directions, ranked by
  source authority.
- **Application → service name** mapping from a broad product directory.
- **Port consolidation** — one row per source→destination, ports joined.
- **Source consolidation** — one row per service, source IPs joined.
- **Ephemeral port handling** — clear ephemeral source ports; optionally drop
  ephemeral-destination (reversed-capture) rows, keeping rule/registered rows.
- Boundary model that never auto-assigns a DISN crossing; Internal is a
  first-class value.
- IPv4-only mode (default) with an opt-out for dual-stack enclaves.
- Address-exclusion filter and permanent removal for scanners/monitors.

### Collection
- PowerShell, bash, Python (3.6+), and Ansible collectors — all dependency-free
  and compatible with RHEL 8/9 and Windows 10/11.
- DNS zone export (Windows and BIND), AD computer export, host/socket
  collection with `# ppsm-host:` attribution.

### Quality
- 200+ in-browser self-tests (**Self-Test** button).
