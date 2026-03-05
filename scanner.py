#!/usr/bin/env python3
# NOT SAFE FOR WORK YET!
# ----------------------------------------------------------------------------- #
#                    scanner.py — masscan + parse + confirm + nmap + eyewitness #
#                         by x41 and the praktikant  (v1.7)                     #
# ----------------------------------------------------------------------------- #
# Stages:
#   1. masscan     — full port discovery (1-65535)
#   2. parse       — extract hosts/ports from masscan XML
#   3. confirm     — parallel nmap TCP connect, filters SYN proxy false positives
#   4. deep        — nmap -sT -sV -sC -O per confirmed host on confirmed ports
#                    produces per-host XMLs + merged nmap_combined.xml
#   5. eyewitness  — screenshots web services from combined nmap XML (-x)
#                    correct service labels guaranteed by scaled timeouts
#                    (calc_timeout ensures nmap finishes before eyewitness runs)
#
# Usage:
#   sudo python3 scanner.py --profile <safe|normal|fast|lab> <TARGET>
#   sudo python3 scanner.py --profile <safe|normal|fast|lab> --iL <FILE>
#
# Skip masscan, reuse existing XML (for testing/dev):
#   sudo python3 scanner.py --profile normal --from-xml <masscan.xml>
# ----------------------------------------------------------------------------- #

import argparse
import csv
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Lock

# ----------------------------------------------------------------------------- #
# Profiles
# ----------------------------------------------------------------------------- #
PROFILES = {
    "safe": {
        "rate":            10_000,
        "retries":         0,
        "confirm":         True,
        "bw":              "~3.2 Mbit/s",
        "desc":            "healthcare / critical infra",
        "confirm_workers": 10,
        "confirm_timeout": 5,
        "nmap_workers":    3,
        "nmap_timeout":    300,
    },
    "normal": {
        "rate":            50_000,
        "retries":         1,
        "confirm":         False,
        "bw":              "~16 Mbit/s",
        "desc":            "standard corporate / SMB",
        "confirm_workers": 25,
        "confirm_timeout": 2,
        "nmap_workers":    20,
        "nmap_timeout":    120,
    },
    "fast": {
        "rate":            100_000,
        "retries":         1,
        "confirm":         False,
        "bw":              "~32 Mbit/s",
        "desc":            "large orgs / pentest VLAN",
        "confirm_workers": 50,
        "confirm_timeout": 2,
        "nmap_workers":    30,
        "nmap_timeout":    90,
    },
    "lab": {
        "rate":            500_000,
        "retries":         2,
        "confirm":         False,
        "bw":              "~160 Mbit/s",
        "desc":            "your lab only — never on customer networks",
        "confirm_workers": 100,
        "confirm_timeout": 1,
        "nmap_workers":    30,
        "nmap_timeout":    60,
    },
}

PROBE_PREFER = [22, 445, 80, 443, 389, 3389, 21, 25, 8080, 8443, 8888, 9090, 9443, 5986]


# ----------------------------------------------------------------------------- #
# Helpers
# ----------------------------------------------------------------------------- #
def sort_ips(ips: list[str]) -> list[str]:
    return sorted(ips, key=lambda x: ip_address(x))


def estimate_hosts(target: str) -> int:
    try:
        net = ip_network(target, strict=False)
        n = net.num_addresses
        return max(1, n - 2) if n > 2 else n
    except ValueError:
        return 1


def estimate_hosts_from_file(path: str) -> int:
    total = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += estimate_hosts(line)
    return total


def format_time(seconds: int) -> str:
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def select_probe(ports: set[int]) -> int:
    for p in PROBE_PREFER:
        if p in ports:
            return p
    return min(ports)


def validate_target(target: str) -> None:
    try:
        net = ip_network(target, strict=False)
        if net.num_addresses == 1:
            print(f"[!] Target {target} is a single host (/32).")
            print(f"    masscan on a single host may miss ports due to self-routing load.")
            print(f"    For single hosts, nmap is more reliable.")
            answer = input("    Continue anyway? (yes/no): ").strip()
            if answer != "yes":
                print("[!] Aborted.")
                sys.exit(1)
    except ValueError:
        print(f"[!] Invalid target: {target}")
        sys.exit(1)


def confirm_safe_profile() -> None:
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  SAFE profile active. Before continuing confirm:        │")
    print("  │  • Written authorization obtained for this target       │")
    print("  │  • Fragile / medical devices identified and excluded    │")
    print("  └─────────────────────────────────────────────────────────┘")
    print()
    answer = input("  Type 'yes' to continue: ").strip()
    if answer != "yes":
        print("[!] Aborted.")
        sys.exit(1)
    print()


# ----------------------------------------------------------------------------- #
# Dependency checks
# ----------------------------------------------------------------------------- #
def check_dependencies(skip_masscan: bool) -> dict[str, bool]:
    print("[*] Checking dependencies")

    required = ["nmap"]
    if not skip_masscan:
        required.append("masscan")

    for tool in required:
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        status = "✓" if found else "✗"
        print(f"  {status}  {tool:<20} {'found' if found else 'NOT FOUND (required)'}")
        if not found:
            print(f"[!] {tool} is required but not installed. Aborting.")
            sys.exit(1)

    optional = {"eyewitness": False}
    for tool in optional:
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        optional[tool] = found
        status = "✓" if found else "?"
        note   = "found" if found else "not found (optional — stage will be skipped)"
        print(f"  {status}  {tool:<20} {note}")
        if not found:
            answer = input(f"    {tool} not installed. Continue without it? (yes/no): ").strip()
            if answer != "yes":
                print("[!] Aborted.")
                sys.exit(1)

    print()
    return optional


# ----------------------------------------------------------------------------- #
# Stage 1: masscan
# ----------------------------------------------------------------------------- #
def run_masscan(
    profile:    dict,
    target:     str,
    il_file:    str,
    port_range: str,
    exclude:    str,
    outfile:    Path,
) -> None:
    cmd = [
        "masscan",
        "-p", port_range,
        "--rate", str(profile["rate"]),
        "--retries", str(profile["retries"]),
        "--open-only",
        "-oX", str(outfile),
    ]

    if il_file:
        cmd += ["-iL", il_file]
    else:
        cmd.append(target)

    if exclude:
        if os.path.isfile(exclude):
            cmd += ["--excludefile", exclude]
        else:
            cmd += ["--exclude", exclude]

    print(f"[*] Running: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[!] masscan exited with code {result.returncode}")
        sys.exit(1)


# ----------------------------------------------------------------------------- #
# Stage 2: parse masscan XML
# ----------------------------------------------------------------------------- #
def parse_masscan_xml(path: Path) -> dict[str, set[int]]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] Failed to parse masscan XML: {e}")
        sys.exit(1)

    root = tree.getroot()
    portmap: dict[str, set[int]] = defaultdict(set)

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        if not ip:
            continue
        for port_el in host.findall(".//port[@protocol='tcp']"):
            state_el = port_el.find("state[@state='open']")
            if state_el is None:
                continue
            portid = port_el.get("portid")
            if portid and portid.isdigit():
                portmap[ip].add(int(portid))

    return portmap


def write_parse_outputs(portmap: dict[str, set[int]], outdir: Path) -> None:
    sorted_hosts = sort_ips(list(portmap.keys()))
    all_ports    = sorted(set(p for ports in portmap.values() for p in ports))
    union_csv    = ",".join(str(p) for p in all_ports)
    probes       = {ip: select_probe(portmap[ip]) for ip in sorted_hosts}

    alive_path   = outdir / "masscan_alive_hosts.txt"
    portmap_path = outdir / "masscan_ports_map.csv"
    union_path   = outdir / "masscan_union_ports.txt"
    probes_path  = outdir / "masscan_confirmation_probes.txt"
    summary_path = outdir / "masscan_summary.txt"

    with open(alive_path, "w") as f:
        for ip in sorted_hosts:
            f.write(ip + "\n")

    with open(portmap_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "ports"])
        for ip in sorted_hosts:
            writer.writerow([ip, ",".join(str(p) for p in sorted(portmap[ip]))])

    with open(union_path, "w") as f:
        for port in all_ports:
            f.write(str(port) + "\n")

    with open(probes_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "probe_port"])
        for ip in sorted_hosts:
            writer.writerow([ip, probes[ip]])

    lines = [
        "=== masscan parse summary ===",
        "",
        f"Alive hosts (masscan)  : {len(sorted_hosts)}",
        f"Unique ports           : {len(all_ports)}",
        f"Confirmation probes    : {len(probes)}",
        f"Union ports            : {union_csv}",
        "",
        "--- Per-host breakdown (ports / probe) ---",
    ]
    for ip in sorted_hosts:
        ports_str = ",".join(str(p) for p in sorted(portmap[ip]))
        lines.append(f"  {ip:<20}  ports: {ports_str:<60}  probe: {probes[ip]}")

    summary = "\n".join(lines)
    print(summary)

    with open(summary_path, "w") as f:
        f.write(summary + "\n")

    print(f"\n  Masscan outputs:")
    for p in [alive_path, portmap_path, union_path, probes_path, summary_path]:
        print(f"    {p}")
    print()


# ----------------------------------------------------------------------------- #
# Stage 3: parallel nmap TCP connect confirmation
# ----------------------------------------------------------------------------- #
def parse_nmap_open_ports(xml_output: str) -> set[int]:
    confirmed = set()
    try:
        root = ET.fromstring(xml_output)
        for port_el in root.findall(".//port"):
            state_el = port_el.find("state[@state='open']")
            if state_el is not None:
                portid = port_el.get("portid")
                if portid and portid.isdigit():
                    confirmed.add(int(portid))
    except ET.ParseError:
        pass
    return confirmed


def confirm_single_host(
    ip:      str,
    ports:   set[int],
    timeout: int,
) -> tuple[str, set[int]]:
    ports_arg = ",".join(str(p) for p in sorted(ports))
    cmd = [
        "nmap",
        "-sT", "-Pn", "-n",
        "--open",
        "--max-retries", "0",
        "--host-timeout", f"{timeout}s",
        "-p", ports_arg,
        "-oX", "-",
        ip,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return ip, parse_nmap_open_ports(result.stdout)
    except subprocess.TimeoutExpired:
        return ip, set()
    except Exception:
        return ip, set()


def confirm_hosts(
    portmap: dict[str, set[int]],
    profile: dict,
    outdir:  Path,
) -> dict[str, set[int]]:
    sorted_hosts     = sort_ips(list(portmap.keys()))
    total            = len(sorted_hosts)
    workers          = profile["confirm_workers"]
    timeout          = profile["confirm_timeout"]
    confirmed_map:   dict[str, set[int]] = {}
    dropped:         list[str] = []

    counter      = {"n": 0}
    counter_lock = Lock()
    print_lock   = Lock()

    print(f"[*] Stage 3: confirming {total} hosts  "
          f"(workers: {workers}, timeout: {timeout}s per host)")
    print()

    def task(ip: str) -> tuple[str, set[int]]:
        return confirm_single_host(ip, portmap[ip], timeout)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(task, ip): ip for ip in sorted_hosts}
        for future in as_completed(futures):
            ip, confirmed_ports = future.result()
            with counter_lock:
                counter["n"] += 1
                n = counter["n"]
            with print_lock:
                if confirmed_ports:
                    conf_str = ",".join(str(p) for p in sorted(confirmed_ports))
                    print(f"  [{n}/{total}] {ip:<20} ✓  {conf_str}")
                    confirmed_map[ip] = confirmed_ports
                else:
                    print(f"  [{n}/{total}] {ip:<20} ✗  dropped")
                    dropped.append(ip)

    print()

    confirmed_hosts_path = outdir / "confirmed_hosts.txt"
    confirmed_ports_path = outdir / "confirmed_ports_map.csv"
    confirmed_summary    = outdir / "confirmed_summary.txt"

    confirmed_sorted    = sort_ips(list(confirmed_map.keys()))
    all_confirmed_ports = sorted(set(
        p for ports in confirmed_map.values() for p in ports
    ))
    union_confirmed_csv = ",".join(str(p) for p in all_confirmed_ports)

    with open(confirmed_hosts_path, "w") as f:
        for ip in confirmed_sorted:
            f.write(ip + "\n")

    with open(confirmed_ports_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "ports"])
        for ip in confirmed_sorted:
            writer.writerow([ip, ",".join(str(p) for p in sorted(confirmed_map[ip]))])

    lines = [
        "=== confirmation summary ===",
        "",
        f"Hosts in (masscan)     : {total}",
        f"Hosts confirmed alive  : {len(confirmed_sorted)}",
        f"Hosts dropped          : {len(dropped)}",
        f"Unique confirmed ports : {len(all_confirmed_ports)}",
        f"Union confirmed ports  : {union_confirmed_csv}",
        "",
        "--- Confirmed per-host ---",
    ]
    for ip in confirmed_sorted:
        ports_str = ",".join(str(p) for p in sorted(confirmed_map[ip]))
        lines.append(f"  {ip:<20}  {ports_str}")

    if dropped:
        lines += ["", "--- Dropped (SYN proxy / not alive) ---"]
        for ip in sort_ips(dropped):
            lines.append(f"  {ip}")

    summary = "\n".join(lines)
    print(summary)

    with open(confirmed_summary, "w") as f:
        f.write(summary + "\n")

    print(f"\n  Confirmation outputs:")
    for p in [confirmed_hosts_path, confirmed_ports_path, confirmed_summary]:
        print(f"    {p}")
    print()

    return confirmed_map


# ----------------------------------------------------------------------------- #
# Stage 4: nmap deep dive
# ----------------------------------------------------------------------------- #
def _merge_nmap_xmls(xml_paths: list[Path], out_path: Path) -> None:
    if not xml_paths:
        return

    host_blocks: list[str] = []
    base_attribs: dict     = {}

    for path in xml_paths:
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            if not base_attribs:
                base_attribs = root.attrib.copy()
            for host_el in root.findall("host"):
                host_blocks.append(ET.tostring(host_el, encoding="unicode"))
        except ET.ParseError:
            continue

    with open(out_path, "w") as f:
        f.write('<?xml version="1.0"?>\n')
        f.write(
            f'<nmaprun scanner="nmap" args="scanner.py combined" '
            f'start="{base_attribs.get("start", "")}" '
            f'version="{base_attribs.get("version", "")}" '
            f'xmloutputversion="{base_attribs.get("xmloutputversion", "1.04")}">\n'
        )
        for block in host_blocks:
            f.write(block + "\n")
        f.write("</nmaprun>\n")


def calc_timeout(port_count: int, base: int) -> int:
    """
    Scale nmap host-timeout with the number of ports being scanned.
    -sV/-sC/-O on many ports takes significantly longer than on a few —
    a flat timeout causes false timeouts on hosts like Veeam, Exchange,
    or anything with 20+ open ports and slow service responses.

    Formula: base + (port_count * 3 seconds), capped at 20 minutes.
    Examples at base=120:
      3  ports ->  129s  (~2 min)
      10 ports ->  150s  (~2.5 min)
      20 ports ->  180s  (~3 min)
      32 ports ->  216s  (~3.5 min)  — Veeam case
      50 ports ->  270s  (~4.5 min)
    """
    return min(base + (port_count * 3), 1200)


def run_nmap_deep_dive(
    confirmed_map: dict[str, set[int]],
    profile:       dict,
    outdir:        Path,
) -> Path:
    sorted_hosts = sort_ips(list(confirmed_map.keys()))
    total        = len(sorted_hosts)
    workers      = profile["nmap_workers"]
    base_timeout = profile["nmap_timeout"]

    nmap_dir = outdir / "nmap"
    nmap_dir.mkdir(exist_ok=True)

    print(f"[*] Stage 4: nmap deep dive — {total} hosts  "
          f"(workers: {workers}, base timeout: {base_timeout}s + 3s/port, cap: 1200s)")
    print()

    counter      = {"n": 0}
    counter_lock = Lock()
    print_lock   = Lock()

    def scan_host(ip: str) -> tuple[str, Path | None]:
        ports     = confirmed_map[ip]
        ports_arg = ",".join(str(p) for p in sorted(ports))
        timeout   = calc_timeout(len(ports), base_timeout)
        safe_ip   = ip.replace(".", "_")
        xml_path  = nmap_dir / f"{safe_ip}.xml"

        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "-O",
            "--system-dns",
            "-Pn",
            "--open",
            "--max-retries", "1",
            "--host-timeout", f"{timeout}s",
            "-p", ports_arg,
            "-oX", str(xml_path),
            ip,
        ]

        with counter_lock:
            counter["n"] += 1
            n = counter["n"]

        with print_lock:
            print(f"  [{n}/{total}] {ip:<20} ports: {len(ports):<4} timeout: {timeout}s")

        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
            return ip, xml_path if xml_path.exists() else None
        except subprocess.TimeoutExpired:
            with print_lock:
                print(f"  [!] {ip} timed out")
            return ip, None
        except Exception as e:
            with print_lock:
                print(f"  [!] {ip} error: {e}")
            return ip, None

    results: list[tuple[str, Path | None]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in sorted_hosts}
        for future in as_completed(futures):
            results.append(future.result())

    print()

    successful = [(ip, p) for ip, p in results if p is not None]
    failed     = [ip for ip, p in results if p is None]

    combined_xml = outdir / "nmap_combined.xml"
    _merge_nmap_xmls([p for _, p in successful], combined_xml)

    print(f"  Scanned    : {len(successful)}/{total} hosts")
    if failed:
        print(f"  Failed     : {', '.join(sort_ips(failed))}")
    print(f"  Per-host   : {nmap_dir}/")
    print(f"  Combined   : {combined_xml}")
    print()

    return combined_xml


# ----------------------------------------------------------------------------- #
# Stage 5: EyeWitness
# ----------------------------------------------------------------------------- #
def run_eyewitness(combined_xml: Path, outdir: Path) -> None:
    """
    Run EyeWitness against the merged nmap XML using -x.
    Correct service labels are guaranteed because calc_timeout ensures
    nmap finishes cleanly before this stage runs.
    """
    ew_dir = outdir / "eyewitness"
    if ew_dir.exists():
        import shutil
        shutil.rmtree(ew_dir)

    cmd = [
        "eyewitness",
        "-x", str(combined_xml),
        "--web",
        "--no-prompt",
        "-d", str(ew_dir),
    ]

    print(f"[*] Stage 5: EyeWitness")
    print(f"[*] Running: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"[!] EyeWitness exited with code {result.returncode}")
    else:
        print(f"\n  EyeWitness output : {ew_dir}/")
        report = ew_dir / "report.html"
        if report.exists():
            print(f"  Report            : {report}")
    print()


# ----------------------------------------------------------------------------- #
# Main
# ----------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "scanner.py — masscan + nmap + EyeWitness pipeline\n"
            "by x41 and the praktikant\n"
            "\n"
            "Stages:\n"
            "  1. masscan   full TCP port discovery (1-65535)\n"
            "  2. parse     extract hosts/ports from masscan XML\n"
            "  3. confirm   parallel nmap connect, filters SYN proxy false positives\n"
            "  4. nmap      -sV -sC -O per host on confirmed ports only\n"
            "               timeout scales automatically with port count\n"
            "  5. eyewitness screenshots web services (optional, if installed)\n"
            "\n"
            "Profiles:\n"
            "  safe   —  10k pps  ~3.2 Mbit/s  healthcare / critical infra\n"
            "             confirmation stage enabled, lowest worker counts\n"
            "  normal —  50k pps  ~16  Mbit/s  standard corporate / SMB\n"
            "  fast   — 100k pps  ~32  Mbit/s  large orgs / pentest VLAN\n"
            "  lab    — 500k pps  ~160 Mbit/s  your lab only — never on customers\n"
            "\n"
            "Examples:\n"
            "  sudo python3 scanner.py --profile normal 192.168.1.0/24\n"
            "  sudo python3 scanner.py --profile fast --iL targets.txt\n"
            "  sudo python3 scanner.py --profile normal 10.0.0.0/8 --exclude 10.0.0.1\n"
            "  sudo python3 scanner.py --profile normal 10.0.0.0/16 --workers 30\n"
            "  sudo python3 scanner.py --profile safe --iL targets.txt --ports 80,443,8080-8090\n"
            "  sudo python3 scanner.py --profile normal --from-xml masscan.xml --outdir results/\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target (mutually exclusive: positional or --iL)
    target_group = parser.add_argument_group("target (provide one)")
    target_group.add_argument(
        "target",
        nargs="?",
        default=None,
        metavar="TARGET",
        help="IP address, range or CIDR  (e.g. 192.168.1.0/24, 10.0.0.1-254)"
    )
    target_group.add_argument(
        "--iL",
        dest="il_file",
        default=None,
        metavar="FILE",
        help="File containing one target per line (IPs, CIDRs, ranges)"
    )

    # Scan options
    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument(
        "--profile",
        required=True,
        choices=PROFILES.keys(),
        metavar="PROFILE",
        help="Scan profile: safe | normal | fast | lab  (see above for details)"
    )
    scan_group.add_argument(
        "--ports",
        default="1-65535",
        metavar="PORTS",
        help="masscan port range  (default: 1-65535)\n"
             "examples: 80,443  |  1-1024  |  1-65535"
    )
    scan_group.add_argument(
        "--exclude",
        default="",
        metavar="CIDR|FILE",
        help="Exclude a CIDR range or a file of ranges from the scan\n"
             "examples: 192.168.1.1  |  10.0.0.0/8  |  /path/to/exclude.txt"
    )
    scan_group.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Override nmap deep-dive worker count from profile\n"
             "profile defaults: safe=3  normal=20  fast=30  lab=30\n"
             "higher = faster but more load on target network"
    )

    # Output options
    out_group = parser.add_argument_group("output options")
    out_group.add_argument(
        "--outdir",
        default=None,
        metavar="DIR",
        help="Output directory  (default: scan_<target>_<timestamp>/)"
    )

    # Developer options
    dev_group = parser.add_argument_group("developer options")
    dev_group.add_argument(
        "--from-xml",
        default=None,
        metavar="MASSCAN_XML",
        help="Skip masscan stage, use existing masscan XML file\n"
             "useful for re-running parse/confirm/nmap without rescanning"
    )

    return parser.parse_args()


def main() -> None:
    if os.geteuid() != 0:
        print("[!] Requires root. Run: sudo python3 scanner.py ...")
        sys.exit(1)

    args    = parse_args()
    profile = PROFILES[args.profile].copy()

    # --workers overrides the profile's nmap_workers at runtime
    if args.workers is not None:
        if args.workers < 1:
            print("[!] --workers must be >= 1")
            sys.exit(1)
        profile["nmap_workers"] = args.workers
        print(f"[*] nmap workers overridden to {args.workers}")

    optional             = check_dependencies(skip_masscan=args.from_xml is not None)
    run_eyewitness_stage = optional.get("eyewitness", False)

    print(f"[*] Working directory : {Path.cwd()}")
    print()

    if args.from_xml:
        if not os.path.isfile(args.from_xml):
            print(f"[!] XML file not found: {args.from_xml}")
            sys.exit(1)
        masscan_xml = Path(args.from_xml)
        outdir      = Path(args.outdir) if args.outdir else masscan_xml.parent
        outdir.mkdir(parents=True, exist_ok=True)
        print(f"\n[*] --from-xml: skipping masscan, using {masscan_xml}")
        print(f"[*] Output dir : {outdir}/\n")

    else:
        if not args.il_file and not args.target:
            print("[!] Provide a target or --iL <file>")
            sys.exit(1)
        if args.il_file and not os.path.isfile(args.il_file):
            print(f"[!] File not found: {args.il_file}")
            sys.exit(1)
        if args.target:
            validate_target(args.target)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.outdir:
            outdir = Path(args.outdir)
        else:
            safe   = re.sub(r"[/:\ ]", "_", args.il_file or args.target)
            safe   = re.sub(r"[^A-Za-z0-9._-]", "", safe)
            outdir = Path(f"scan_{safe}_{ts}")

        outdir.mkdir(parents=True, exist_ok=True)
        masscan_xml = outdir / f"masscan_{ts}.xml"

        if args.il_file:
            host_count     = estimate_hosts_from_file(args.il_file)
            display_target = f"iL:{args.il_file}"
        else:
            host_count     = estimate_hosts(args.target)
            display_target = args.target

        est_secs = (65535 * host_count) // profile["rate"]

        print()
        print(f"  Profile    : {args.profile} — {profile['desc']}")
        print(f"  Rate       : {profile['rate']:,} pps  ({profile['bw']})")
        print(f"  Retries    : {profile['retries']}")
        print(f"  Target     : {display_target}")
        print(f"  Hosts est. : {host_count:,}")
        print(f"  Ports      : {args.ports}")
        print(f"  Est. time  : ~{format_time(est_secs)}")
        print(f"  Output     : {outdir}/")
        if args.exclude:
            print(f"  Exclude    : {args.exclude}")
        print()

        if profile["confirm"]:
            confirm_safe_profile()

        print("[*] Stage 1: masscan")
        print()
        run_masscan(
            profile    = profile,
            target     = args.target or "",
            il_file    = args.il_file or "",
            port_range = args.ports,
            exclude    = args.exclude,
            outfile    = masscan_xml,
        )

        if not masscan_xml.exists() or masscan_xml.stat().st_size == 0:
            print("[!] masscan produced no output.")
            sys.exit(1)

    # Stage 2
    print("[*] Stage 2: parsing masscan output")
    print()
    portmap = parse_masscan_xml(masscan_xml)

    if not portmap:
        print("[!] No open TCP ports found.")
        sys.exit(0)

    write_parse_outputs(portmap, outdir)

    # Stage 3
    confirmed_map = confirm_hosts(portmap, profile, outdir)

    if not confirmed_map:
        print("[!] No hosts survived confirmation.")
        sys.exit(0)

    # Stage 4
    combined_xml = run_nmap_deep_dive(confirmed_map, profile, outdir)

    # Stage 5
    if run_eyewitness_stage:
        run_eyewitness(combined_xml, outdir)
    else:
        print(f"[*] Skipping stage 5: eyewitness not available")
        print(f"    Run manually: eyewitness -x {combined_xml} --web --no-prompt -d {outdir}/eyewitness")
        print()

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        subprocess.run(["chown", "-R", f"{sudo_user}:{sudo_user}", str(outdir)],
                       capture_output=True)
        print(f"[*] Ownership set to {sudo_user}")

    print("[*] Pipeline complete.")
    print(f"[*] Confirmed hosts : {len(confirmed_map)}")
    print(f"[*] Output dir      : {outdir}/")
    print(f"[*] Combined XML    : {combined_xml}")
    if run_eyewitness_stage:
        print(f"[*] EyeWitness      : {outdir}/eyewitness/report.html")
    print()


if __name__ == "__main__":
    main()
