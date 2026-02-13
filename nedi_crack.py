from __future__ import annotations

import argparse
import os
import sys

DEFAULT_KEY = "change for more security"


# ---------- ANSI helpers (auto-disable if not a TTY) ----------
def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    if not _use_color():
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


def info(s: str) -> str:
    return _c("92", f"[+] {s}")  # green


def warn(s: str) -> str:
    return _c("93", f"[!] {s}")  # yellow


def err(s: str) -> str:
    return _c("91", f"[-] {s}")  # red


def bold(s: str) -> str:
    return _c("1", s)


# ---------- crypto core ----------
def xorpass(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must be non-empty")

    k = bytearray(key)
    out = bytearray(len(data))

    for idx, b in enumerate(data):
        i = k.pop()
        out[idx] = b ^ i
        k.insert(0, i)

    return bytes(out)


def encode_hex(plaintext: str, key: str) -> str:
    pt = plaintext.encode("latin1", errors="strict")
    ct = xorpass(pt, key.encode("latin1", errors="strict"))
    return ct.hex()


def decode_hex(ciphertext_hex: str, key: str) -> str:
    ct = bytes.fromhex(ciphertext_hex)
    pt = xorpass(ct, key.encode("latin1", errors="strict"))
    return pt.decode("latin1", errors="strict")


def recover_key_part(ciphertext_hex: str, plaintext: str) -> str:
    ct = bytes.fromhex(ciphertext_hex)
    pt = plaintext.encode("latin1", errors="strict")

    if len(ct) != len(pt):
        raise ValueError("ciphertext and plaintext must have same length")

    # keystream = c ^ p ; your xorpass uses key reversed => key_part = reverse(keystream)
    keystream = bytes(c ^ p for c, p in zip(ct, pt))
    key_part = keystream[::-1]
    return key_part.decode("latin1", errors="strict")


# ---------- CLI ----------
def build_argparser() -> argparse.ArgumentParser:
    script = os.path.basename(sys.argv[0])

    epilog = f"""
Examples:

  Encode with default key:
    python3 {script} -e 'Password'

  Decode with default key:
    python3 {script} -d 29151a01020c1717

  Encode with custom key:
    python3 {script} -e 'mykey' 'Password'

  Decode with custom key:
    python3 {script} -d 'mykey' 2904180a1a16170f

  Recover key-stream from known plaintext + ciphertext:
    python3 {script} -r 29151a01020c1717 'Password'
    python3 {script} -r 2904180a1a16170f 'Password'
"""

    p = argparse.ArgumentParser(
        description="Rotating XOR utility (minimal syntax)",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = p.add_mutually_exclusive_group(required=True)

    mode.add_argument(
        "-e", "--encode",
        nargs="+",
        metavar=("KEY", "PLAINTEXT"),
        help="Encode:  -e <key> <plaintext>   (if key omitted: default key)",
    )
    mode.add_argument(
        "-d", "--decode",
        nargs="+",
        metavar=("KEY", "CIPHERHEX"),
        help="Decode:  -d <key> <cipherhex>  (if key omitted: default key)",
    )
    mode.add_argument(
        "-r", "--recover",
        nargs=2,
        metavar=("CIPHERHEX", "PLAINTEXT"),
        help="Recover key-part: -r <cipherhex> <plaintext>  (outputs recovered key part for -k)",
    )

    return p


def main() -> int:
    args = build_argparser().parse_args()

    try:
        if args.encode is not None:
            if len(args.encode) == 1:
                key = DEFAULT_KEY
                plaintext = args.encode[0]
                print(info(f"Mode     : encode (default key)"))
            else:
                key, plaintext = args.encode[0], " ".join(args.encode[1:])
                print(info(f"Mode     : encode (custom key)"))

            out = encode_hex(plaintext, key)
            print(info(f"Plaintext: {bold(plaintext)}"))
            print(info(f"Cipher   : {bold(out)}"))
            return 0

        if args.decode is not None:
            if len(args.decode) == 1:
                key = DEFAULT_KEY
                cipherhex = args.decode[0]
                print(info(f"Mode     : decode (default key)"))
            else:
                key, cipherhex = args.decode[0], args.decode[1]
                print(info(f"Mode     : decode (custom key)"))

            pt = decode_hex(cipherhex, key)
            print(info(f"Cipher   : {bold(cipherhex)}"))
            print(info(f"Plaintext: {bold(pt)}"))
            return 0

        if args.recover is not None:
            cipherhex, plaintext = args.recover
            key_part = recover_key_part(cipherhex, plaintext)
            print(info("Mode     : recover"))
            print(info(f"Cipher   : {bold(cipherhex)}"))
            print(info(f"Plaintext: {bold(plaintext)}"))
            print(info(f"Key part : {bold(key_part)}"))
            return 0

        raise SystemExit(2)

    except ValueError as e:
        print(err(str(e)))
        return 2
    except UnicodeDecodeError as e:
        print(err(f"latin1 decode/encode error: {e}"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
