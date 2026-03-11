#!/usr/bin/env python3
# UNTESTED in production - don't use it yet.
"""
laps.py — query LAPS passwords from Active Directory via LDAP.
Supports both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS
(msLAPS-Password, msLAPS-EncryptedPassword).

Examples:
    python3 laps.py -d corp.local -u 'CORP\\admin' -p 'P@ss'
    python3 laps.py -d corp.local -u 'CORP\\admin' -p 'P@ss' -c FILESERVER
    python3 laps.py -d corp.local -u 'CORP\\admin' -p 'P@ss' -o laps_dump.txt
    python3 laps.py -d corp.local -u 'CORP\\admin' -p 'P@ss' --use-ssl

Requires: pip install ldap3
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, NTLM
except ImportError:
    print("[!] ldap3 not installed — pip install ldap3")
    sys.exit(1)


# Legacy LAPS (pre-2023): cleartext password in a single attribute
ATTR_LEGACY = "ms-Mcs-AdmPwd"

# Windows LAPS (2023+): JSON blob with account name, password, and expiry
ATTR_NEW_CLEARTEXT = "msLAPS-Password"

# Windows LAPS encrypted: only decryptable by authorized principals
ATTR_NEW_ENCRYPTED = "msLAPS-EncryptedPassword"

ALL_LAPS_ATTRS = [ATTR_LEGACY, ATTR_NEW_CLEARTEXT, ATTR_NEW_ENCRYPTED]


def build_base_dn(domain: str) -> str:
    """corp.local → DC=corp,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def _read_attr(entry, attr: str) -> str | None:
    """Safely read a string attribute from an ldap3 entry."""
    if not hasattr(entry, attr.replace("-", "_")):
        return None
    raw = getattr(entry, attr.replace("-", "_"), None)
    if raw is None:
        return None
    val = str(raw)
    if val in ("[]", ""):
        return None
    return val


def _parse_new_laps_json(raw: str) -> dict[str, str] | None:
    """
    Windows LAPS stores a JSON blob in msLAPS-Password:
        {"n":"Administrator","t":"...", "p":"ThePassword"}
    Returns parsed dict or None.
    """
    try:
        data = json.loads(raw)
        return {
            "account":  data.get("n", ""),
            "password": data.get("p", ""),
        }
    except (json.JSONDecodeError, TypeError):
        return None


def query_laps(
    domain:   str,
    username: str,
    password: str,
    computer: str | None = None,
    use_ssl:  bool = False,
    dc_host:  str | None = None,
) -> list[dict]:
    """
    Query AD for LAPS passwords (legacy + new).
    Returns list of dicts with name, source, and credential info.
    """
    host = dc_host or domain
    port = 636 if use_ssl else 389

    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
    conn = Connection(
        server,
        user=username,
        password=password,
        authentication=NTLM,
        auto_bind=True,
    )

    base_dn = build_base_dn(domain)

    if computer:
        ldap_filter = f"(&(objectClass=computer)(name={computer}))"
    else:
        # Any computer that has at least one LAPS attribute populated
        ldap_filter = (
            "(&(objectClass=computer)"
            f"(|({ATTR_LEGACY}=*)({ATTR_NEW_CLEARTEXT}=*)({ATTR_NEW_ENCRYPTED}=*)))"
        )

    conn.search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=SUBTREE,
        attributes=["name"] + ALL_LAPS_ATTRS,
    )

    results = []
    for entry in conn.entries:
        name = str(entry.name) if hasattr(entry, "name") else "unknown"

        record = {"name": name, "credentials": []}

        # Legacy LAPS
        legacy = _read_attr(entry, ATTR_LEGACY)
        if legacy:
            record["credentials"].append({
                "source":   "legacy",
                "account":  "Administrator",
                "password": legacy,
            })

        # Windows LAPS — cleartext JSON
        new_clear = _read_attr(entry, ATTR_NEW_CLEARTEXT)
        if new_clear:
            parsed = _parse_new_laps_json(new_clear)
            if parsed and parsed["password"]:
                record["credentials"].append({
                    "source":   "winlaps",
                    "account":  parsed["account"] or "Administrator",
                    "password": parsed["password"],
                })
            else:
                record["credentials"].append({
                    "source":   "winlaps",
                    "account":  "",
                    "password": None,
                    "note":     f"attribute present but unparseable: {new_clear[:80]}",
                })

        # Windows LAPS — encrypted
        encrypted = _read_attr(entry, ATTR_NEW_ENCRYPTED)
        if encrypted:
            record["credentials"].append({
                "source":   "winlaps-encrypted",
                "account":  "",
                "password": None,
                "note":     "encrypted blob present — requires authorized principal to decrypt",
            })

        results.append(record)

    conn.unbind()
    return results


SOURCE_LABELS = {
    "legacy":            "legacy LAPS (ms-Mcs-AdmPwd)",
    "winlaps":           "Windows LAPS (msLAPS-Password)",
    "winlaps-encrypted": "Windows LAPS (msLAPS-EncryptedPassword)",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="laps.py — query LAPS passwords from Active Directory",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-d", "--domain",   required=True, help="Domain name (e.g. corp.local)")
    parser.add_argument("-u", "--username", required=True, help="Auth user (e.g. CORP\\\\admin)")
    parser.add_argument("-p", "--password", required=True, help="Auth password")
    parser.add_argument("-c", "--computer", default=None,  help="Specific computer name (default: all with LAPS)")
    parser.add_argument("--dc",            default=None,  help="Domain controller IP/hostname (default: domain)")
    parser.add_argument("--use-ssl",       action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("-o", "--output",   default=None,  help="Write results to file (one entry per line)")

    args = parser.parse_args()

    target = args.computer or "all computers"
    print(f"[*] Querying LAPS — domain: {args.domain}  target: {target}")

    try:
        results = query_laps(
            domain=args.domain,
            username=args.username,
            password=args.password,
            computer=args.computer,
            use_ssl=args.use_ssl,
            dc_host=args.dc,
        )
    except Exception as e:
        print(f"[!] LDAP error: {e}")
        sys.exit(1)

    if not results:
        print("[!] No computers found. Check your search parameters and permissions.")
        sys.exit(0)

    found = 0
    lines = []

    for record in results:
        name  = record["name"]
        creds = record["credentials"]

        if not creds:
            print(f"  {name:<25} (no LAPS attributes — check permissions or config)")
            continue

        for cred in creds:
            source = SOURCE_LABELS.get(cred["source"], cred["source"])
            pw     = cred.get("password")
            acct   = cred.get("account", "")
            note   = cred.get("note", "")

            if pw:
                found += 1
                label = f"{acct}:{pw}" if acct else pw
                print(f"  {name:<25} {label:<40} [{source}]")
                out_label = f"{acct}@" if acct else ""
                lines.append(f"{name}:{out_label}{pw}  # {source}")
            elif note:
                print(f"  {name:<25} {'—':<40} [{source}] {note}")
            else:
                print(f"  {name:<25} {'(no password)':<40} [{source}]")

    print(f"\n[+] {found} password(s) retrieved from {len(results)} computer(s)")

    if args.output and lines:
        Path(args.output).write_text("\n".join(lines) + "\n")
        print(f"[+] Written to {args.output}")


if __name__ == "__main__":
    main()
