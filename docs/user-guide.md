# PPSM Builder user guide

A PPSM register has to say, for every service an enclave uses: what protocol
and port, on which system, crossing which boundary, permitted by what, and
why. That data is scattered across hosts, firewalls, switches, scanners and
DNS in formats that do not agree. This tool collects it, cross-references it,
and writes the eMASS PPSM import template.

Everything runs on your machine. The GUI is served on localhost by
`ppsm.py`; files are parsed in the browser and the session is written to a
local data folder. Nothing is sent anywhere.

## Platforms

| | |
|---|---|
| Builder | Python 3.8+. Chrome, Edge or Firefox. |
| `ppsm-collect.ps1` | Windows PowerShell 3.0 to 5.1, or PowerShell 7. No modules. RSAT adds the AD export, DnsServer adds the zones. Hosts without `Get-NetTCPConnection` are read with `netstat -ano`. |
| `ppsm-collect.sh` | bash 4.4+ (RHEL 8 and 9). Uses `ss` and `ip`; net-tools not needed. |
| `ppsm.yml` | ansible-core 2.12+ with `ansible.windows`, `ansible.netcommon`, `cisco.asa`, `cisco.ios`. |

PowerShell 5.1 writes UTF-8 with a BOM; UTF-16 from a plain redirect is read
too.

## Collecting

Run host commands elevated. Without Administrator or sudo the process behind
each port is missing, and that is what proves a port is a real service.

### Scripted

1. **Windows host**: `.\ppsm-collect.ps1`, or `-ComputerListFile hosts.txt`
   to reach the other Windows hosts in the same run.
2. **Domain controller**: run `.\ppsm-collect.ps1` once there. It exports
   every computer account and every DNS zone. Check that
   `inventory\ad-computers.csv` and `inventory\dns-records.csv` came out.
3. **Linux host**: `sudo ./ppsm-collect.sh`, or `-H hosts.txt -u svc-ppsm`
   for the others over SSH.
4. **Ansible**: `ansible-playbook -i inventory.ini ppsm.yml` replaces 1, 3
   and the network steps if the inventory covers everything.
5. **Firewall**, in one session:
   ```
   terminal pager 0
   show conn all                          -> network\firewall-showconn.txt
   show running-config access-list        -> network\firewall-acl.txt
   show running-config object-group       -> (same file)
   ```
   Take the object-groups or a rule written against a group cannot be
   expanded.
6. **FMC console**, if the firewall is FMC-managed. Export as CSV; the policy
   report is also read as PDF.
   - Connection Events: Analysis, Connections, Events
   - Servers: Analysis, Hosts, Servers
   - Hosts: Analysis, Hosts, Network Map
   - Access control policy: Policies, Access Control, report icon
   - Site-to-site VPN: Devices, VPN, Site To Site
7. **Switch**, per switch: `show flow monitor <name> cache format csv` into
   `network\<switch>-netflow.csv`. `show flow monitor ?` listing nothing
   means NetFlow is not configured there. A NetFlow analyser's Top
   Conversations report for the last 30 days as `.xlsx` covers every switch
   at once.
8. **Your workstation**: export the ACAS scan as `.nessus` into the results
   folder, then drop the folder on the ingest box.

### Manual

Create `ppsm-results\hosts\`, `inventory\`, `network\`.

**Windows host**, ports and connections, into `hosts\`:
```
Get-NetTCPConnection |
  Select-Object *,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Export-Csv -NoTypeInformation "$env:COMPUTERNAME-tcp.csv"
Get-NetUDPEndpoint |
  Select-Object *,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Export-Csv -NoTypeInformation "$env:COMPUTERNAME-udp.csv"
```
Or, where `Get-NetTCPConnection` is not recognised or process names are not
needed: `netstat -ano > "$env:COMPUTERNAME-netstat.txt"` (elevated,
`netstat -anob` adds the executable). Name the files after the host; that is
how a service on 0.0.0.0 is attributed.

**Domain controller**, once, into `inventory\`:
```
Get-ADComputer -Filter * -Properties DNSHostName,IPv4Address,OperatingSystem |
  Where-Object IPv4Address |
  Select-Object Name,DNSHostName,IPv4Address,OperatingSystem |
  Export-Csv -NoTypeInformation ad-computers.csv

Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated } | ForEach-Object {
  $z = $_.ZoneName
  Get-DnsServerResourceRecord -ZoneName $z |
    Where-Object RecordType -in 'A','PTR','CNAME' |
    Select-Object HostName, RecordType, @{n='ZoneName';e={$z}},
      @{n='IPv4Address';e={$_.RecordData.IPv4Address.IPAddressToString}},
      @{n='PtrDomainName';e={$_.RecordData.PtrDomainName}},
      @{n='HostNameAlias';e={$_.RecordData.HostNameAlias}}
} | Export-Csv -NoTypeInformation dns-records.csv
```
The record data has to be expanded like that; a plain `Export-Csv` writes
the type name where the address should be. `dnscmd /zoneprint <zone>` and
DNS Manager's right-click export are read as well.

**Windows host**, hosts file: copy `%SystemRoot%\System32\drivers\etc\hosts`
to `inventory\hosts-file.txt`.

**Linux host**, into `hosts/`:
```
H=$(hostname -s)
{ echo "# ppsm-host: $H"; sudo ss -tuanp; } > $H-sockets.txt
```
The `ppsm-host` line is how a service on 0.0.0.0 is attributed. Name sources
into `inventory/`: `/etc/hosts`, `ip neigh > arp-table.txt`, and BIND zone
files (`/var/named/*.zone`, `*.rev`, `/etc/bind/db.*`, forward and reverse,
leaving out `db.local`, `db.127`, `db.root`).

Firewall, FMC and switch steps are as above.

Short on time: one host group plus the firewall connection table. Everything
else improves the result rather than making it possible.

## What is read

Every file is identified by content, not name, and the import line says what
it was taken to be. Anything below can arrive as CSV, `.xlsx` or a text-based
PDF. Not readable: binary `.xls` (save as `.xlsx`), scanned PDFs, zip
archives.

**Required**

- Host ports and connections: `<host>-connections.csv`, `-netstat.txt` or
  `-sockets.txt`.
- Firewall connection table: `show conn`, or FMC Connection Events. The
  interface names set the Boundary column.
- A name source: AD export or DNS zones. Without one the register is bare
  addresses.

**Recommended**: DNS zones forward and reverse; the firewall ruleset or FMC
policy report; the `.nessus` scan; NetFlow; FMC Servers and Hosts.

**Situational**: FMC intrusion and VPN reports, Zeek `conn.log`, pcap and
pcapng, tcpdump and pktmon text, `pfirewall.log`, `Get-NetFirewallRule`
exports, ASA syslog, `iptables-save`, Palo Alto config, nmap XML, DHCP
leases, neighbour tables, CMDB exports, a filled-in work list.

### Which end is which

PPSM registers the listening service, never the client. The end offering the
service becomes the Destination and whoever reached it becomes the Source.
Addresses that point nowhere are handled as follows.

| Address | Treatment |
|---|---|
| 0.0.0.0, `*` | Attributed to the machine the file came from, via the `ppsm-host` line or the file name. |
| 127.0.0.1 | Loopback crosses no boundary. Skipped, with the count on the import line. |
| IPv6 | Set aside; the register is IPv4 only unless changed under Settings. |
| Ephemeral destination port | Usually a capture read backwards. Flagged by the checks. |
| A network | Stays a network: a valid rule source, never gains a hostname. |

### How the sources combine

- **Names.** Every name source feeds one inventory applied to every row in
  both directions. Short names are completed, CNAMEs followed. Where sources
  disagree the most authoritative wins: reverse DNS, forward DNS and AD, the
  host itself, scans, hosts files, FMC discovery, DHCP, NetFlow labels, ARP.
  A short name shared by two hosts is never guessed.
- **Rules and traffic.** A rule gains the host that used it; a flow gains the
  rule that permits it. A rule nobody used is reported separately.
- **Scans and flows.** A listening service found by a scan folds into the
  traffic that used it, so one row carries the banner and the client. A scan
  alone leaves Source blank; the firewall connection table fills it best.
- **Repeat sightings** merge into one row, with every tool that saw the flow
  listed in Origin.
- **Software inventory.** Installed software from a credentialed scan fills
  Application/Software Record Name where it is blank or a bare process name.

Data Service carries the service's name, not a code: "Remote Desktop
Protocol (RDP)" rather than ms-wbt-server. Codes from scans and CSVs are
upgraded when the register is finished. A name you type is left as typed.

## Boundaries

Traffic that stays inside the enclave is **Internal** and carries no B
number; that includes the Enclave Gateway (B11/B12) and the Enclave DMZ
(B9/B10). Inside to outside your ranges is B14, outside to inside is B13.
Anything the data cannot tell is left blank.

The tool never assigns a DISN boundary (B1 to B8, B15). Nothing in host
output, a connection table or a flow cache can prove a DISN crossing. Set
those yourself and confirm them with your AO or ISSM. If the enclave uses
address space outside RFC1918, set Internal ranges under Settings first or
internal traffic picks up a B14.

## What is left for you

Three fields are judgements, so no tool can fill them. Internal rows need
none of them.

- **Mission Justification**: why the flow needs to exist. A reviewer reads
  this first. Fill In can write a draft marked [DRAFT]; the checks flag it
  until edited.
- **CAL / VA Reference**: look the service up before registering.
- **Assurance Category**: the CAL entry, or your own CLSA for a local
  service.

Submission path by boundary: B1 to B8 and B15 go to VA through the PPSM CCB;
B9 to B14 and B16 are CLSA; B13 and B14 also need a DoDIN waiver; Internal
needs no submission.

## The eMASS template

The export matches the PPSM Boundary Information Import Template: 21 columns
in order, the header block, the Glossary and Instructions sheets, dropdowns
on the lookup columns, and the template's character limits. Its instructions
say every field except Purpose is required.

Set once under Settings: DNS domain, physical location, external label, VPN
Tunnel Type when there is no tunnel. Fill in the eMASS template header on the
Setup page. On export the tool names any required field still empty.

Shaping, all on by default: one row per port (TCP and UDP joined, several
boundaries semicolon-joined, a consolidated register row split back out),
IP addresses only, rows in port order, a generated Purpose where blank. The
working register is not changed.

Do not restructure the workbook. The importer reads columns by position.

## Review

Must fix: no boundary, ephemeral destination port, no CAL/VA reference,
anything Red or Banned, observed traffic with no rule behind it, a hostname
with no address. Should fix: uncredentialed scan, no data service, no
assurance category, no justification, HTTP/HTTPS on a non-standard port,
B13/B14 with no waiver noted, a permit rule never used. Worth a look: unnamed
internal destinations, duplicates, a port no installed software accounts
for.

Rule coverage reads every observed flow against the ruleset on source,
destination, protocol and port, and lists unmatched flows, partly covered
rows, denied-but-seen flows, and permit rules never used.

Compare loads last quarter's `allow.xlsx`, an eMASS export or a saved
session and lists added, removed and changed rows. Mark Registered / New
sets Status so what you submit is the delta.

## Reading and trimming the register

Hide addresses leaves rows out of the view by address, network, hostname or
wildcard (`scanner*`), matching either end. Remove hidden deletes them.
Consolidate joins ports for the same source and destination, and sources for
the same service; it also runs on export.

## Settings worth knowing

| Setting | |
|---|---|
| IPv4 only | On. Turn off only for a dual-stack enclave. |
| Internal ranges | Extra CIDRs counted as inside, beyond RFC1918. |
| Custom service names | `9997 = splunk-forwarder` or `TCP/8443 = vendor-gui`. Overrides the port table everywhere. |
| Subnet to enclave map | Without it the Enclave column falls back to the observed /24. |
| Minimum packets per flow | Three or five strips single-packet probes from a capture. |
| Well-known port ceiling | When nothing says which side opened a connection, the better-known port is the server. |
| Finish after import | Resolve, fill in, dedupe and run the checks after every import. |

## Troubleshooting

- **A file imports as zero entries.** Read the import line. Usually the wrong
  export: nmap normal output instead of `-oX`, Tenable HTML instead of
  `.nessus`.
- **Excel file refused.** Binary `.xls`. Save as `.xlsx`.
- **PDF gives nothing.** No text in it. Export the original; for a policy, CSV.
- **Hostnames missing.** Add the DNS zones. Names apply to rows already
  present.
- **Internal traffic shows B13 or B14.** Add the enclave's ranges under
  Settings and import again.
- **Client and server look backwards.** Fix with Bulk apply; the
  ephemeral-port check flags the likely rows.
- **N entries, 0 shown.** A filter is hiding them.
- **Anything else.** Run Self-Test. All green means the input is the problem.

The tool assembles a register. It does not certify compliance; the inputs,
boundaries and assurance analysis remain the assessor's responsibility.
