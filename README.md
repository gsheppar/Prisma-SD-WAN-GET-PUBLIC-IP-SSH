# query_circuit_ips.py

Walks every branch site in Prisma SD-WAN, enumerates WAN circuits, and reports the current IP address for each circuit's physical interface. For circuits with private IPs, SSHes to the element's management interface and runs `curl --interface` to resolve the public-facing IP.

---

## Output

CSV file (`circuit_ips.csv` by default) with one row per circuit:

| Column | Description |
|---|---|
| `site_name` | Branch site name |
| `element_name` | ION device name |
| `circuit_name` | WAN interface / circuit label |
| `addr_type` | `static` or `dhcp` |
| `oper_state` | Live operational state from the status API |
| `ip_address` | IP address on the physical interface |
| `public_ip` | Public IP (copied directly if already public; resolved via SSH if private) |

---

## Prerequisites

### Python packages

```bash
pip install prisma-sase netmiko
```

`netmiko` is optional — the script runs without it, but SSH-based public IP lookup will be skipped.

### Credentials

Fill in `prismasase_settings.py` in the same directory:

```python
# Prisma SASE API (required)
PRISMASASE_CLIENT_ID     = "..."
PRISMASASE_CLIENT_SECRET = "..."
PRISMASASE_TSG_ID        = "..."

# SSH credentials for ION elements (required for public IP lookup)
SSH_USERNAME = "admin"
SSH_PASSWORD = "your-password"
```

SSH credentials can also be passed as CLI flags (see below).

---

## Usage

```bash
# Basic run — outputs circuit_ips.csv
python query_circuit_ips.py

# Custom output file
python query_circuit_ips.py --output my_report.csv

# Pass SSH credentials at the command line
python query_circuit_ips.py --ssh-user admin --ssh-pass secret

# Increase SSH timeout (default: 10s)
python query_circuit_ips.py --ssh-timeout 20

# Dry run — see which SSH connections would be made without connecting
python query_circuit_ips.py --dry-run
```

---

## How It Works

1. **Load sites and elements** — fetches all sites and filters to branch/spoke sites only (excludes hub, DC, and controller roles).

2. **Resolve active ION for HA pairs** — for sites with two elements, queries `spokeclusters/status` to identify the active member and skips the backup.

3. **Enumerate circuits** — for each active ION, fetches WAN interfaces (circuit labels) and maps each one to its physical interface.

4. **Get IP address** — for static interfaces, reads from config; for DHCP interfaces, queries the live `interfaces/status` API.

5. **Resolve public IPs** — circuits that already have a public IP are copied directly into the `public_ip` column. Circuits with private IPs trigger an SSH connection to the element's management interface, which runs `curl --interface {if_name} ifconfig.me` to get the public-facing IP.

---

## SSH Behavior

- **Management IP** is resolved from the element's LAN global interface (`used_for=lan`, `scope=global`).
- SSH connections use `netmiko` with `device_type=generic`.
- Per-connection timeout is set via `--ssh-timeout` (default 10s). A `banner_timeout` of +5s is added automatically.
- **Auth failure abort** — if credentials are rejected 3 times in a row, the script stops SSH attempts and prints a clear message. This avoids hammering every site with bad credentials.
- **Dry run** (`--dry-run`) — prints the exact SSH host IP and curl command that would be used for each private-IP circuit, without making any connections. Useful for validating before you have SSH access.

### SSH error types

| Error | Output |
|---|---|
| Connection timeout | `TIMEOUT` |
| Wrong credentials | `AUTH FAILED` |
| Connected but curl returned no valid IP | `(connected but no IP in curl output)` |
| Any other exception | `ERROR: <message>` |

A summary line is printed at the end: `SSH summary: X resolved | Y timed out | Z no host | ...`

---

## Notes

- Hub sites, DC sites, and controller elements are automatically excluded.
- HA backup IONs are automatically excluded — only the active member is queried.
- Circuits with no matching physical interface are still included in the CSV with `oper_state=NO_INTERFACE` and blank IP fields.
- The CSV is sorted by `site_name` then `circuit_name`.
