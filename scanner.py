#!/usr/bin/env python3
# NOT SAFE FOR WORK YET!
# ----------------------------------------------------------------------------- #
#                    scanner.py — masscan + parse + confirm + nmap + eyewitness #
#                         by x41 and the praktikant  (v2.0)                     #
# ----------------------------------------------------------------------------- #
# Stages:
#   1. masscan     — full port discovery (1-65535)
#   2. parse       — extract hosts/ports from masscan XML
#   3. confirm     — parallel nmap TCP connect, filters SYN proxy false positives
#   4. deep        — nmap -sT -sV -sC -O per confirmed host on confirmed ports
#                    produces per-host XMLs + merged nmap_combined.xml
#   5. eyewitness  — screenshots web services from combined nmap XML (-x)
#                    correct service labels guaranteed by scaled timeouts
#                    flat timeout per profile ensures nmap finishes cleanly
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
        "nmap_timeout":    300,  # flat — iLO/embedded devices slow regardless of port count
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
        "nmap_timeout":    400,  # flat — 2x real-world max observed (182s)
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
        "nmap_timeout":    400,
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
        "nmap_timeout":    400,
    },
}

PROBE_PREFER = [22, 445, 80, 443, 389, 3389, 21, 25, 8080, 8443, 8888, 9090, 9443, 5986]


# ----------------------------------------------------------------------------- #
# Progress bar
# ----------------------------------------------------------------------------- #
def _bar(n: int, total: int, width: int = 35, label: str = "") -> str:
    """Return an animated progress bar string for in-place terminal updates."""
    pct   = n / total if total else 1
    filled = int(width * pct)
    bar   = "█" * filled + "░" * (width - filled)
    suffix = f" {label}" if label else ""
    return f"  [{bar}] {n}/{total}{suffix}"


def _print_bar(n: int, total: int, label: str = "") -> None:
    """Print progress bar in-place (overwrites current line)."""
    print(f"\r{_bar(n, total, label=label)}", end="", flush=True)


def _end_bar(total: int, label: str = "") -> None:
    """Complete the bar at 100% and move to next line."""
    print(f"\r{_bar(total, total, label=label)}")


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
    required = ["nmap"]
    if not skip_masscan:
        required.append("masscan")

    for tool in required:
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        if not found:
            print(f"[!] required tool not found: {tool}")
            sys.exit(1)

    optional = {"eyewitness": False}
    for tool in optional:
        found = subprocess.run(["which", tool], capture_output=True).returncode == 0
        optional[tool] = found
        if not found:
            answer = input(f"[?] {tool} not installed — continue without it? (yes/no): ").strip()
            if answer != "yes":
                print("[!] Aborted.")
                sys.exit(1)

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

    # Run masscan with stderr piped so we can parse its progress lines.
    # masscan writes status to stderr in the form:
    #   rate:  49983; found: 234; remaining: 00:01:22; waiting...
    # We parse "remaining" to show a live progress bar.
    import re as _re
    import threading

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    found_count = {"n": 0}
    rate_str    = {"v": ""}
    done_event  = threading.Event()

    def read_stderr():
        for line in proc.stderr:
            line = line.strip()
            # rate:  49983; found: 234; remaining: 00:01:22; waiting...
            m_found = _re.search(r"found:\s*(\d+)", line)
            m_rate  = _re.search(r"rate:\s*([\d,]+)", line)
            m_rem   = _re.search(r"remaining:\s*(\S+)", line)
            if m_found:
                found_count["n"] = int(m_found.group(1))
            if m_rate:
                rate_str["v"] = m_rate.group(1).replace(",", "")
            if m_rem:
                rem = m_rem.group(1)
                label = f"found: {found_count['n']}  remaining: {rem}  rate: {rate_str['v']} pps"
                print(f"\r  [masscan] {label:<70}", end="", flush=True)
        done_event.set()

    t = threading.Thread(target=read_stderr, daemon=True)
    t.start()
    proc.wait()
    done_event.wait(timeout=5)
    print(f"\r  [+] masscan done — {found_count['n']} open ports found{' ' * 40}")

    if proc.returncode not in (0, 1):  # masscan exits 1 on Ctrl+C partial runs
        print(f"[!] masscan exited with code {proc.returncode}")
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


def write_parse_outputs(portmap: dict[str, set[int]], outdir: Path) -> tuple[Path, Path]:
    """Write masscan parse outputs. Returns (portmap_path, debug_dir) for summary use."""
    sorted_hosts = sort_ips(list(portmap.keys()))
    all_ports    = sorted(set(p for ports in portmap.values() for p in ports))
    probes       = {ip: select_probe(portmap[ip]) for ip in sorted_hosts}

    # Important output — confirmed ports map used by nmap stage
    portmap_path = outdir / "masscan_ports_map.csv"
    with open(portmap_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "ports"])
        for ip in sorted_hosts:
            writer.writerow([ip, ",".join(str(p) for p in sorted(portmap[ip]))])

    # Debug outputs — useful for troubleshooting, not needed day-to-day
    debug_dir = outdir / "debug"
    debug_dir.mkdir(exist_ok=True)

    with open(debug_dir / "masscan_alive_hosts.txt", "w") as f:
        for ip in sorted_hosts:
            f.write(ip + "\n")

    with open(debug_dir / "masscan_union_ports.txt", "w") as f:
        for port in all_ports:
            f.write(str(port) + "\n")

    with open(debug_dir / "masscan_confirmation_probes.txt", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "probe_port"])
        for ip in sorted_hosts:
            writer.writerow([ip, probes[ip]])

    lines = [
        "=== masscan parse summary ===",
        "",
        f"Alive hosts (masscan)  : {len(sorted_hosts)}",
        f"Unique ports           : {len(all_ports)}",
        "",
        "--- Per-host breakdown (ports / probe) ---",
    ]
    for ip in sorted_hosts:
        ports_str = ",".join(str(p) for p in sorted(portmap[ip]))
        lines.append(f"  {ip:<20}  ports: {ports_str:<60}  probe: {probes[ip]}")

    with open(debug_dir / "masscan_summary.txt", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  [+] masscan: {len(sorted_hosts)} hosts, {len(all_ports)} unique ports")
    return portmap_path, debug_dir


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
    debug:   bool = False,
) -> dict[str, set[int]]:
    sorted_hosts   = sort_ips(list(portmap.keys()))
    total          = len(sorted_hosts)
    workers        = profile["confirm_workers"]
    timeout        = profile["confirm_timeout"]
    confirmed_map: dict[str, set[int]] = {}
    dropped:       list[str] = []

    counter      = {"n": 0}
    counter_lock = Lock()
    print_lock   = Lock()

    _print_bar(0, total)

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
                    confirmed_map[ip] = confirmed_ports
                    if debug:
                        conf_str = ",".join(str(p) for p in sorted(confirmed_ports))
                        print(f"\n  {ip:<20} ✓  {conf_str}")
                else:
                    dropped.append(ip)
                    if debug:
                        print(f"\n  {ip:<20} ✗  dropped")
                _print_bar(n, total)

    _end_bar(total)

    confirmed_sorted    = sort_ips(list(confirmed_map.keys()))
    all_confirmed_ports = sorted(set(p for ports in confirmed_map.values() for p in ports))

    # Always write confirmed ports map — important output used by nmap stage
    confirmed_ports_path = outdir / "confirmed_ports_map.csv"
    with open(confirmed_ports_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "ports"])
        for ip in confirmed_sorted:
            writer.writerow([ip, ",".join(str(p) for p in sorted(confirmed_map[ip]))])

    # Debug outputs
    debug_dir = outdir / "debug"
    debug_dir.mkdir(exist_ok=True)

    with open(debug_dir / "confirmed_hosts.txt", "w") as f:
        for ip in confirmed_sorted:
            f.write(ip + "\n")

    lines = [
        "=== confirmation summary ===",
        "",
        f"Hosts in (masscan)     : {total}",
        f"Hosts confirmed alive  : {len(confirmed_sorted)}",
        f"Hosts dropped          : {len(dropped)}",
        f"Unique confirmed ports : {len(all_confirmed_ports)}",
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
    with open(debug_dir / "confirmed_summary.txt", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"  [+] confirmed: {len(confirmed_sorted)} alive, {len(dropped)} dropped")
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


def run_nmap_deep_dive(
    confirmed_map: dict[str, set[int]],
    profile:       dict,
    outdir:        Path,
    debug:         bool = False,
) -> tuple[Path, list[str]]:
    sorted_hosts = sort_ips(list(confirmed_map.keys()))
    total        = len(sorted_hosts)
    workers      = profile["nmap_workers"]
    timeout      = profile["nmap_timeout"]

    nmap_dir = outdir / "nmap"
    nmap_dir.mkdir(exist_ok=True)

    _print_bar(0, total)

    counter      = {"n": 0}
    counter_lock = Lock()
    print_lock   = Lock()

    def scan_host(ip: str) -> tuple[str, Path | None]:
        ports     = confirmed_map[ip]
        ports_arg = ",".join(str(p) for p in sorted(ports))
        safe_ip   = ip.replace(".", "_")
        # -oA produces .xml + .nmap + .gnmap
        oA_base   = nmap_dir / safe_ip

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
            "-oA", str(oA_base),
            ip,
        ]

        with counter_lock:
            counter["n"] += 1
            n = counter["n"]

        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
            xml_path = Path(str(oA_base) + ".xml")
            result_path = xml_path if xml_path.exists() else None
        except subprocess.TimeoutExpired:
            result_path = None
            if debug:
                with print_lock:
                    print(f"\n  [!] {ip} timed out")
        except Exception as e:
            result_path = None
            if debug:
                with print_lock:
                    print(f"\n  [!] {ip} error: {e}")

        with print_lock:
            _print_bar(n, total)
            if debug:
                status = f"✓ {len(ports)} ports" if result_path else "✗ timeout"
                print(f"\n  {ip:<20} {status}")

        return ip, result_path

    results: list[tuple[str, Path | None]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in sorted_hosts}
        for future in as_completed(futures):
            results.append(future.result())

    successful = [(ip, p) for ip, p in results if p is not None]
    failed     = [ip for ip, p in results if p is None]

    combined_xml = outdir / "nmap_combined.xml"
    _merge_nmap_xmls([p for _, p in successful], combined_xml)

    _end_bar(total)
    print(f"  [+] nmap: {len(successful)}/{total} complete"
          + (f", {len(failed)} timed out" if failed else ""))

    # Write timed-out hosts to debug dir for reference
    if failed:
        debug_dir = outdir / "debug"
        debug_dir.mkdir(exist_ok=True)
        with open(debug_dir / "nmap_timed_out.txt", "w") as f:
            for ip in sort_ips(failed):
                f.write(ip + "\n")

    return combined_xml, failed


# ----------------------------------------------------------------------------- #
# Stage 5: EyeWitness
# ----------------------------------------------------------------------------- #
def run_eyewitness(combined_xml: Path, outdir: Path) -> Path | None:
    """
    Run EyeWitness against the merged nmap XML.
    Returns path to report.html if successful, None otherwise.
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

    print(f"  [*] running EyeWitness...", end="", flush=True)
    result = subprocess.run(cmd, capture_output=True)
    report = ew_dir / "report.html"

    if result.returncode != 0 or not report.exists():
        print(f"\r  [!] EyeWitness failed (exit {result.returncode})")
        return None

    print(f"\r  [+] EyeWitness done")
    return report


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
    dev_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Show verbose per-host output during confirm and nmap stages"
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

    debug = args.debug

    optional             = check_dependencies(skip_masscan=args.from_xml is not None)
    run_eyewitness_stage = optional.get("eyewitness", False)

    scan_start = datetime.now()

    if args.from_xml:
        if not os.path.isfile(args.from_xml):
            print(f"[!] XML file not found: {args.from_xml}")
            sys.exit(1)
        masscan_xml    = Path(args.from_xml)
        outdir         = Path(args.outdir) if args.outdir else masscan_xml.parent
        display_target = str(masscan_xml)
        outdir.mkdir(parents=True, exist_ok=True)
        print(f"[*] --from-xml mode  : skipping masscan, using {masscan_xml}")
        print(f"[*] Output dir       : {outdir}/")
        print()

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

        print(f"  target   : {display_target}")
        print(f"  profile  : {args.profile} — {profile['desc']}")
        print(f"  rate     : {profile['rate']:,} pps  ({profile['bw']})")
        print(f"  ports    : {args.ports}")
        print(f"  est. time: ~{format_time(est_secs)}")
        print(f"  output   : {outdir}/")
        if args.exclude:
            print(f"  exclude  : {args.exclude}")
        if debug:
            print(f"  debug    : enabled")
        print()

        if profile["confirm"]:
            confirm_safe_profile()

        print("[1/5] masscan — full port discovery")
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

    print("[2/5] parse   — extracting hosts and ports")
    portmap = parse_masscan_xml(masscan_xml)

    if not portmap:
        print("[!] No open TCP ports found.")
        sys.exit(0)

    portmap_path, debug_dir = write_parse_outputs(portmap, outdir)

    print("[3/5] confirm — filtering false positives")
    confirmed_map = confirm_hosts(portmap, profile, outdir, debug=debug)

    if not confirmed_map:
        print("[!] No hosts survived confirmation.")
        sys.exit(0)

    print("[4/5] nmap    — deep dive fingerprinting")
    combined_xml, timed_out = run_nmap_deep_dive(confirmed_map, profile, outdir, debug=debug)

    ew_report = None
    if run_eyewitness_stage:
        print("[5/5] eyewitness — web screenshots")
        ew_report = run_eyewitness(combined_xml, outdir)
    else:
        print("[5/5] eyewitness — skipped (not installed)")

    elapsed = datetime.now() - scan_start

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        subprocess.run(["chown", "-R", f"{sudo_user}:{sudo_user}", str(outdir)],
                       capture_output=True)

    # ── Final summary ────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  target          : {display_target}")
    print(f"  elapsed         : {str(elapsed).split('.')[0]}")
    print(f"  hosts alive     : {len(confirmed_map)}")
    if timed_out:
        print(f"  timed out       : {len(timed_out)}  (see debug/nmap_timed_out.txt)")
    print()
    print("  --- important files ---")
    print(f"  confirmed ports : {portmap_path}")
    print(f"  nmap XML        : {combined_xml}")
    print(f"  nmap per-host   : {outdir}/nmap/  (.xml .nmap .gnmap)")
    if ew_report:
        print(f"  eyewitness      : {ew_report}")
    elif run_eyewitness_stage:
        print(f"  eyewitness      : failed — check {outdir}/eyewitness/")
    else:
        print(f"  eyewitness      : run manually:")
        print(f"                    eyewitness -x {combined_xml} --web --no-prompt -d {outdir}/eyewitness")
    print()
    print("  --- debug / raw data ---")
    print(f"  {outdir}/debug/")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
