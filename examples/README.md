# Examples

Small invented inputs that exercise the name-resolution path. Drop the whole
folder on the ingest box.

| File | What it is |
|---|---|
| `dns/dns-manager-export.csv` | Windows DNS Manager right-click export of `range2.mil` |
| `dns/dnscmd-enum.txt` | `dnscmd /enumrecords` output for the same zone |
| `dns/dns-export.xlsx` | The same records as an Excel workbook |
| `firewall/showconn-names.txt` | ASA `show conn` with `names` configured, so object names appear in place of addresses |
| `registers/register-mixed.csv` | A hand-kept register with hostnames where addresses should be |
| `registers/ppsm-hostnames.csv` | An eMASS PPSM export in the template's column layout, names in the IP columns |

Together they produce a register of seven rows with every internal address
resolved through the DNS exports, one short name completed under
`range2.mil`, and `mystery01` left for the Endpoints page because no source
knows it.
