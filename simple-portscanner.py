import socket
import ipaddress
import argparse

def is_port_open(ip, port, timeout=1):
    """
    Check if a specific port is open on a given IP address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0  # Port is open if result is 0
    except socket.error:
        return False

def get_domain_name(ip):
    """
    Get the domain name of an IP address if it exists.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None

def resolve_dns_to_ip(dns_name):
    """
    Resolve a DNS name to its corresponding IP address.
    """
    try:
        return socket.gethostbyname(dns_name)
    except (socket.gaierror, socket.herror):
        return None

def scan_ip(ip, ports, query_dns=False):
    """
    Scan a single IP address for a list of ports and optionally query its domain name.
    """
    domain = f" ({get_domain_name(ip)})" if query_dns else ""
    for port in ports:
        if is_port_open(ip, port):
            print(f"[+] {ip}{domain}: Port {port} is open")
        else:
            print(f"[-] {ip}{domain}: Port {port} is closed or system is offline")

def scan_subnet(subnet, ports, query_dns=False):
    """
    Scan all IP addresses in a subnet for a list of ports and optionally query their domain names.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        print(f"Scanning subnet: {subnet}")
        for ip in network.hosts():
            scan_ip(str(ip), ports, query_dns)
    except ValueError as e:
        print(f"[!] Invalid subnet: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IP or Subnet for specified ports")
    parser.add_argument("target", help="IP address, DNS name, or subnet (e.g., 192.168.1.1, example.com, or 192.168.1.0/24)")
    parser.add_argument(
        "-p", "--ports", 
        help="Comma-separated list of ports to scan (e.g., 445,80,443). Default is 445.", 
        default="445"
    )
    parser.add_argument(
        "-dns", 
        action="store_true", 
        help="Query the domain name of each IP address"
    )
    args = parser.parse_args()

    target = args.target
    ports = [int(port.strip()) for port in args.ports.split(",")]
    query_dns = args.dns

    try:
        # Resolve DNS name to IP if target is a domain name
        try:
            ip = ipaddress.ip_address(target)
            print(f"Scanning single IP: {target}")
            scan_ip(str(ip), ports, query_dns)
        except ValueError:
            resolved_ip = resolve_dns_to_ip(target)
            if resolved_ip:
                print(f"DNS name {target} resolved to IP: {resolved_ip}")
                scan_ip(resolved_ip, ports, query_dns)
            else:
                print(f"[!] Unable to resolve DNS name: {target}")
    except ValueError:
        # Otherwise, treat input as a subnet
        scan_subnet(target, ports, query_dns)
