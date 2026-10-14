#!/usr/bin/env python3
"""
Circuit IP Address Report

For every site, enumerates configured WAN circuits (WAN interfaces), resolves
which physical interface on the active ION carries each circuit, then queries
the live interface status API to capture the current IP address.

For circuits with private IPs, SSHes to the element's management interface and
runs 'curl --interface {if_name} ifconfig.me' to resolve the public IP.

GET /sdwan/v3.9/api/sites/{site_id}/elements/{element_id}/interfaces/{if_id}/status

Output CSV columns:
    site_name, element_name, circuit_name, addr_type, oper_state, ip_address, public_ip

Usage:
    python query_circuit_ips.py
    python query_circuit_ips.py --output circuit_ips.csv
    python query_circuit_ips.py --ssh-user admin --ssh-pass secret
"""

import prisma_sase
import argparse
import sys
import os
import csv
import ipaddress
from collections import defaultdict

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    HAS_NETMIKO = True
except ImportError:
    HAS_NETMIKO = False

sys.path.append(os.getcwd())

try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID
except ImportError:
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None

try:
    from prismasase_settings import SSH_USERNAME, SSH_PASSWORD
except ImportError:
    SSH_USERNAME = None
    SSH_PASSWORD = None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login() -> prisma_sase.API:
    session = prisma_sase.API()
    session.interactive.login_secret(
        client_id=PRISMASASE_CLIENT_ID,
        client_secret=PRISMASASE_CLIENT_SECRET,
        tsg_id=PRISMASASE_TSG_ID,
    )
    return session


# ---------------------------------------------------------------------------
# Step 1: Site + element maps (active ION only, branch sites only)
# ---------------------------------------------------------------------------

def _is_branch_site(site: dict) -> bool:
    """Returns True for spoke/branch sites; False for hub, DC, or controller sites."""
    role = (site.get("element_cluster_role") or "").lower()
    return "hub" not in role and "controller" not in role


def _is_branch_element(elem: dict) -> bool:
    role = (elem.get("cluster_role") or "").lower()
    return "hub" not in role and "controller" not in role


def _active_element_ids(cgx, site_id: str, elem_ids: list, site_name: str) -> list:
    """Return only the active ION from an HA pair; pass-through for single-element sites."""
    if len(elem_ids) <= 1:
        return elem_ids

    sc_resp = cgx.get.spokeclusters(site_id)
    if not sc_resp.cgx_status:
        print(f"  [{site_name}] SKIP — spokeclusters API failed")
        return []

    clusters = sc_resp.cgx_content.get("items", [])
    if not clusters:
        print(f"  [{site_name}] SKIP — no spoke cluster for multi-element site")
        return []

    active_ids = []
    for cluster in clusters:
        cluster_id = cluster.get("id", "")
        if not cluster_id:
            continue
        st_resp = cgx.get.spokeclusters_status(site_id, cluster_id)
        if not st_resp.cgx_status:
            print(f"  [{site_name}] SKIP — spokeclusters_status failed")
            return []
        content = st_resp.cgx_content
        members = (
            content.get("cluster_member_status")   # primary field name in SD-WAN API
            or content.get("cluster_members")
            or content.get("elements")
            or content.get("element_status")
            or []
        )
        for m in members:
            status = (
                m.get("cluster_member_role")        # primary field name in SD-WAN API
                or m.get("status")
                or m.get("role")
                or m.get("state")
                or ""
            ).lower()
            eid = m.get("element_id") or m.get("id") or ""
            if status == "active" and eid in elem_ids:
                active_ids.append(eid)

    if not active_ids:
        print(f"  [{site_name}] SKIP — no active member found in spoke cluster")
    return active_ids


def build_maps(cgx):
    print("Loading sites...")
    sites_resp = cgx.get.sites()
    sites = sites_resp.cgx_content.get("items", []) if sites_resp.cgx_status else []
    site_map = {s["id"]: s for s in sites}
    print(f"  {len(site_map)} sites")

    print("Loading elements...")
    elements_resp = cgx.get.elements()
    elements = elements_resp.cgx_content.get("items", []) if elements_resp.cgx_status else []
    all_elems = {e["id"]: e for e in elements}

    raw_by_site: dict[str, list] = defaultdict(list)
    hub_skipped = 0
    for e in elements:
        sid = e.get("site_id", "")
        if not sid:
            continue
        if _is_branch_element(e):
            raw_by_site[sid].append(e["id"])
        else:
            hub_skipped += 1

    print(f"  {len(all_elems)} total elements; {hub_skipped} hub/DC elements skipped")
    print("  Resolving active ION for HA sites...")

    active_elem_map: dict[str, dict] = {}
    site_elements: dict[str, list] = defaultdict(list)
    hub_sites_skipped = 0

    for site_id, elem_ids in raw_by_site.items():
        site = site_map.get(site_id, {})
        site_name = site.get("name", site_id)
        if not _is_branch_site(site):
            hub_sites_skipped += 1
            continue
        active_ids = _active_element_ids(cgx, site_id, elem_ids, site_name)
        for eid in active_ids:
            active_elem_map[eid] = all_elems[eid]
            site_elements[site_id].append(eid)

    ha_excluded = sum(len(v) for v in raw_by_site.values()) - len(active_elem_map) - hub_sites_skipped
    print(f"  {hub_sites_skipped} hub/DC sites skipped")
    print(f"  {len(active_elem_map)} active branch IONs across {len(site_elements)} branch sites ({ha_excluded} HA-backup excluded)")
    return site_map, active_elem_map, site_elements


# ---------------------------------------------------------------------------
# Step 2: For each site, fetch WAN interfaces (circuits) and physical interfaces,
#         then get IP from config (static) or status API (DHCP)
# ---------------------------------------------------------------------------

def _ip_from_config(iface: dict) -> str:
    """Extract IP from a static interface config object."""
    ipv4_cfg = iface.get("ipv4_config") or {}
    ip = ipv4_cfg.get("static_config", {}).get("address") or ""
    return str(ip) if ip else ""


def _ip_from_status(cgx, site_id: str, elem_id: str, if_id: str) -> str:
    """Query the live status endpoint and extract the DHCP-assigned IP."""
    resp = cgx.get.interfaces_status(site_id, elem_id, if_id)
    if not resp.cgx_status:
        return ""
    content = resp.cgx_content

    ip = content.get("ipv4_address") or content.get("ip_address") or ""
    if ip:
        return str(ip)

    ipv4_cfg = content.get("ipv4_config") or {}
    ip = (
        ipv4_cfg.get("dhcp_config", {}).get("ip_address")
        or ipv4_cfg.get("ip_address")
        or ""
    )
    if ip:
        return str(ip)

    addrs = content.get("ipv4_addresses") or content.get("addresses") or []
    if isinstance(addrs, list) and addrs:
        return str(addrs[0])

    return ""


def collect_records(cgx, site_map, active_elem_map, site_elements) -> list:
    print("\nCollecting circuit IP addresses...")
    records = []

    for site_id, elem_ids in sorted(site_elements.items()):
        site_name = site_map.get(site_id, {}).get("name", site_id)

        wan_resp = cgx.get.waninterfaces(site_id)
        if not wan_resp.cgx_status:
            print(f"  [{site_name}] SKIP — waninterfaces API failed")
            continue

        wan_ifaces = {
            w["id"]: w
            for w in wan_resp.cgx_content.get("items", [])
            if w.get("id")
        }
        if not wan_ifaces:
            continue

        for elem_id in elem_ids:
            elem_name = active_elem_map.get(elem_id, {}).get("name", elem_id)

            if_resp = cgx.get.interfaces(site_id, elem_id)
            if not if_resp.cgx_status:
                print(f"  [{site_name}/{elem_name}] SKIP — interfaces API failed")
                continue

            interfaces = if_resp.cgx_content.get("items", [])

            wan_to_phys: dict[str, dict] = {}
            for iface in interfaces:
                for wid in (iface.get("site_wan_interface_ids") or []):
                    if wid in wan_ifaces and wid not in wan_to_phys:
                        wan_to_phys[wid] = iface

            for wan_id, wan_iface in wan_ifaces.items():
                circuit_name = wan_iface.get("name", wan_id)
                phys = wan_to_phys.get(wan_id)

                if not phys:
                    records.append({
                        "site_name":    site_name,
                        "element_name": elem_name,
                        "circuit_name": circuit_name,
                        "addr_type":    "unknown",
                        "oper_state":   "NO_INTERFACE",
                        "ip_address":   "",
                        "_site_id":     site_id,
                        "_elem_id":     elem_id,
                        "_if_name":     "",
                    })
                    continue

                if_id = phys.get("id", "")
                if_name = phys.get("name", "")
                addr_type = ((phys.get("ipv4_config") or {}).get("type") or "").lower()

                st_resp = cgx.get.interfaces_status(site_id, elem_id, if_id)
                if not st_resp.cgx_status:
                    oper = "UNKNOWN"
                else:
                    content = st_resp.cgx_content
                    oper = str(
                        content.get("operational_state")
                        or content.get("oper_state")
                        or content.get("status")
                        or "UNKNOWN"
                    ).upper()

                if addr_type == "static":
                    ip = _ip_from_config(phys)
                else:
                    ip = _ip_from_status(cgx, site_id, elem_id, if_id) if st_resp.cgx_status else ""

                print(f"  [{site_name}] {circuit_name} ({if_name}) [{addr_type or 'unknown'}] → {oper}  {ip or '(no IP)'}")
                records.append({
                    "site_name":    site_name,
                    "element_name": elem_name,
                    "circuit_name": circuit_name,
                    "addr_type":    addr_type or "unknown",
                    "oper_state":   oper,
                    "ip_address":   ip,
                    "_site_id":     site_id,
                    "_elem_id":     elem_id,
                    "_if_name":     if_name,
                })

    print(f"\n  {len(records)} circuit records collected")
    return records


# ---------------------------------------------------------------------------
# Step 3: Public IP lookup via SSH for private-IP circuits
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    ip = ip.split("/")[0].strip()
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _get_ssh_host(cgx, site_id: str, elem_id: str, cache: dict) -> str:
    """
    Returns the management IP for SSH: the interface with used_for=="lan"
    and scope=="global". Caches results by elem_id.
    """
    if elem_id in cache:
        return cache[elem_id]

    resp = cgx.get.interfaces(site_id, elem_id)
    if not resp.cgx_status:
        cache[elem_id] = ""
        return ""

    for iface in resp.cgx_content.get("items", []):
        if iface.get("used_for") == "lan" and iface.get("scope") == "global":
            addr = (iface.get("ipv4_config") or {}).get("static_config", {}).get("address") or ""
            host = str(addr).split("/")[0].strip()
            if host:
                cache[elem_id] = host
                return host

    cache[elem_id] = ""
    return ""


def _get_public_ip_via_ssh(
    host_ip: str, if_name: str, username: str, password: str, timeout: int = 10
) -> tuple[str, str]:
    """
    SSH to host_ip and run 'curl --interface {if_name} ifconfig.me'.
    Returns (public_ip, error_type).
    error_type is "" on success, or one of: "timeout", "auth_error", "no_ip", "error".
    """
    try:
        conn = ConnectHandler(
            device_type="generic",
            host=host_ip,
            username=username,
            password=password,
            conn_timeout=timeout,
            banner_timeout=timeout + 5,
        )
        output = conn.send_command(
            f"curl --interface {if_name} ifconfig.me",
            read_timeout=15,
        )
        conn.disconnect()
        for line in output.splitlines():
            line = line.strip()
            try:
                ipaddress.ip_address(line)
                return line, ""
            except ValueError:
                continue
        return "", "no_ip"
    except NetmikoTimeoutException:
        return "", "timeout"
    except NetmikoAuthenticationException:
        return "", "auth_error"
    except Exception as exc:
        return "", f"error: {exc}"


def enrich_public_ips(
    cgx, records: list, username: str, password: str,
    dry_run: bool = False, ssh_timeout: int = 10,
):
    """
    For every record with a private ip_address, SSH to the element's management
    interface and curl ifconfig.me on the circuit interface to get the public IP.
    Mutates records in place, setting the 'public_ip' key.

    With dry_run=True, prints what would happen without making any SSH connections.
    Aborts early if SSH credentials are rejected to avoid repeating bad creds across all sites.
    """
    # For circuits that already have a public IP, carry it straight into the column.
    for r in records:
        ip = r.get("ip_address", "")
        if ip and not _is_private_ip(ip):
            r["public_ip"] = ip

    private_records = [r for r in records if _is_private_ip(r.get("ip_address", ""))]

    if not private_records:
        print("\nNo private IPs found — skipping public IP lookup.")
        return

    if dry_run:
        print(f"\n[DRY RUN] Would SSH for {len(private_records)} private-IP circuits:")
        ssh_host_cache: dict[str, str] = {}
        for rec in private_records:
            site_id      = rec.get("_site_id", "")
            elem_id      = rec.get("_elem_id", "")
            if_name      = rec.get("_if_name", "")
            site_name    = rec["site_name"]
            circuit_name = rec["circuit_name"]
            private_ip   = rec["ip_address"]
            host_ip = _get_ssh_host(cgx, site_id, elem_id, ssh_host_cache)
            if host_ip:
                print(f"  [{site_name}] {circuit_name} ({private_ip}) → SSH {host_ip}, curl --interface {if_name} ifconfig.me")
            else:
                print(f"  [{site_name}] {circuit_name} ({private_ip}) → no SSH host IP found")
        return

    if not HAS_NETMIKO:
        print("\nnetmiko not installed — skipping public IP lookup.")
        print("  Install with: pip install netmiko")
        return

    if not username or not password:
        print("\nSSH credentials not provided — skipping public IP lookup.")
        print("  Use --ssh-user / --ssh-pass or set SSH_USERNAME/SSH_PASSWORD in prismasase_settings.py")
        return

    print(f"\nLooking up public IPs for {len(private_records)} private-IP circuits (timeout={ssh_timeout}s)...")
    ssh_host_cache: dict[str, str] = {}
    stats = {"success": 0, "timeout": 0, "no_ip": 0, "no_host": 0, "error": 0}
    consecutive_auth_failures = 0

    for i, rec in enumerate(private_records, 1):
        site_id  = rec.get("_site_id", "")
        elem_id  = rec.get("_elem_id", "")
        if_name  = rec.get("_if_name", "")
        site_name    = rec["site_name"]
        circuit_name = rec["circuit_name"]

        host_ip = _get_ssh_host(cgx, site_id, elem_id, ssh_host_cache)
        if not host_ip:
            print(f"  [{i}/{len(private_records)}] [{site_name}] {circuit_name} — no SSH host IP found")
            stats["no_host"] += 1
            continue

        print(f"  [{i}/{len(private_records)}] [{site_name}] {circuit_name} — SSH {host_ip}...", end="", flush=True)
        public_ip, err = _get_public_ip_via_ssh(host_ip, if_name, username, password, timeout=ssh_timeout)

        if err == "auth_error":
            print(" AUTH FAILED")
            consecutive_auth_failures += 1
            stats["error"] += 1
            if consecutive_auth_failures >= 3:
                print(f"\n  Aborting — SSH credentials rejected 3 times in a row.")
                print(f"  Check --ssh-user / --ssh-pass or SSH_USERNAME/SSH_PASSWORD in prismasase_settings.py")
                break
        elif err == "timeout":
            print(" TIMEOUT")
            stats["timeout"] += 1
            consecutive_auth_failures = 0
        elif err == "no_ip":
            print(" (connected but no IP in curl output)")
            stats["no_ip"] += 1
            consecutive_auth_failures = 0
        elif err:
            print(f" ERROR: {err}")
            stats["error"] += 1
            consecutive_auth_failures = 0
        else:
            rec["public_ip"] = public_ip
            print(f" {public_ip}")
            stats["success"] += 1
            consecutive_auth_failures = 0

    print(f"\n  SSH summary: {stats['success']} resolved | {stats['timeout']} timed out | "
          f"{stats['no_host']} no host | {stats['no_ip']} no curl result | {stats['error']} errors")


# ---------------------------------------------------------------------------
# Step 4: Write CSV
# ---------------------------------------------------------------------------

FIELDNAMES = [
    "site_name", "element_name", "circuit_name", "addr_type",
    "oper_state", "ip_address", "public_ip",
]


def write_csv(records: list, output_path: str):
    records.sort(key=lambda r: (r["site_name"], r["circuit_name"]))
    for r in records:
        r.setdefault("public_ip", "")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print(f"\nCSV written: {output_path} ({len(records)} rows)")

    no_ip    = sum(1 for r in records if not r["ip_address"])
    with_pub = sum(1 for r in records if r.get("public_ip"))
    print(f"  {len(records) - no_ip} circuits with IP  |  {no_ip} with no IP resolved  |  {with_pub} public IPs resolved")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def go():
    parser = argparse.ArgumentParser(
        description="Export current IP address per circuit for all branch sites.",
    )
    parser.add_argument(
        "--output", default="circuit_ips.csv",
        help="Output CSV filename (default: circuit_ips.csv)",
    )
    parser.add_argument(
        "--ssh-user", default=SSH_USERNAME,
        help="SSH username for public IP lookup (or set SSH_USERNAME in prismasase_settings.py)",
    )
    parser.add_argument(
        "--ssh-pass", default=SSH_PASSWORD,
        help="SSH password for public IP lookup (or set SSH_PASSWORD in prismasase_settings.py)",
    )
    parser.add_argument(
        "--ssh-timeout", type=int, default=10,
        help="SSH connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show which SSH connections would be made without actually connecting",
    )
    args = parser.parse_args()

    print("Logging in to Prisma SASE...")
    cgx = login()

    site_map, active_elem_map, site_elements = build_maps(cgx)
    records = collect_records(cgx, site_map, active_elem_map, site_elements)

    if not records:
        print("No records collected.")
        return

    enrich_public_ips(cgx, records, args.ssh_user, args.ssh_pass, dry_run=args.dry_run, ssh_timeout=args.ssh_timeout)
    write_csv(records, args.output)
    print("\nDone.")


if __name__ == "__main__":
    go()
