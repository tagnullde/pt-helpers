#!/usr/bin/env python3

import argparse
import xmltodict
import openpyxl


def parse_nmap_xml(xml_file):
    """Parst die Nmap-XML-Datei mit xmltodict."""
    with open(xml_file, "r", encoding="utf-8") as f:
        return xmltodict.parse(f.read())


def ensure_list(value):
    """Sorgt dafür, dass value immer eine Liste ist (None, Dict oder Einzelwert -> Liste)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def extract_addresses(host):
    """
    Extrahiert IPv4/IPv6 und MAC getrennt aus <address>.
    Nmap liefert z.B.:
      <address addr="192.168.0.10" addrtype="ipv4"/>
      <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="..."/>
    """
    ip_address = "Unknown"
    mac_address = "N/A"

    addresses = host.get("address")

    if isinstance(addresses, list):
        for addr in addresses:
            if not isinstance(addr, dict):
                continue
            atype = addr.get("@addrtype", "")
            aval = addr.get("@addr")
            if not aval:
                continue
            if atype in ("ipv4", "ipv6") and ip_address == "Unknown":
                ip_address = aval
            elif atype == "mac" and mac_address == "N/A":
                mac_address = aval

        # Fallback: falls addrtype fehlt, nimm ersten Wert als IP
        if ip_address == "Unknown":
            for addr in addresses:
                if isinstance(addr, dict) and addr.get("@addr"):
                    ip_address = addr.get("@addr")
                    break

    elif isinstance(addresses, dict):
        atype = addresses.get("@addrtype", "")
        aval = addresses.get("@addr")
        if aval:
            if atype == "mac":
                mac_address = aval
            else:
                ip_address = aval

    return ip_address, mac_address


def write_to_excel(data, output_file):
    """Schreibt relevante Nmap-Infos in eine Excel-Datei."""
    wb = openpyxl.Workbook()
    ws_summary = wb.active
    ws_summary.title = "Summary"
    ws_summary.append(["IP Address", "MAC Address", "Hostname", "Port", "State", "Service", "Version", "Description"])

    nmaprun = data.get("nmaprun", {})
    hosts = ensure_list(nmaprun.get("host", []))

    for host in hosts:
        if not isinstance(host, dict):
            continue

        ip_address, mac_address = extract_addresses(host)

        hostname = "N/A"
        hostnames_data = host.get("hostnames")
        if isinstance(hostnames_data, dict):
            hostname_entry = hostnames_data.get("hostname")
            hostname_list = ensure_list(hostname_entry)
            if hostname_list:
                first_hostname = hostname_list[0]
                if isinstance(first_hostname, dict):
                    hostname = first_hostname.get("@name", "N/A")

        ports_section = host.get("ports", {}) or {}
        ports = ensure_list(ports_section.get("port", []))

        for port in ports:
            if not isinstance(port, dict):
                continue

            port_id = port.get("@portid", "Unknown")

            state_info = port.get("state", {}) or {}
            if not isinstance(state_info, dict):
                state_info = {}
            state = state_info.get("@state", "Unknown")

            service_info = port.get("service", {}) or {}
            if not isinstance(service_info, dict):
                service_info = {}

            service_name = service_info.get("@name", "Unknown")
            service_version = service_info.get("@version", "Unknown")
            service_description = service_info.get("@product", "Unknown")

            ws_summary.append([
                ip_address,
                mac_address,
                hostname,
                port_id,
                state,
                service_name,
                service_version,
                service_description
            ])

    wb.save(output_file)
    print(f"Data written to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Nmap XML output to Excel format.")
    parser.add_argument("-f", "--file", required=True, help="Path to the Nmap XML file")
    parser.add_argument("-o", "--output", default="nmap_output.xlsx",
                        help="Output Excel file (default: nmap_output.xlsx)")

    args = parser.parse_args()

    nmap_data = parse_nmap_xml(args.file)
    write_to_excel(nmap_data, args.output)
