from __future__ import annotations

import argparse
import os
import sys
from functools import lru_cache
from itertools import cycle

DEFAULT_KEY = "change for more security"

# ---------- ANSI helpers (auto-disable if not a TTY) ----------
@lru_cache(maxsize=1)
def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _use_color() else s


def info(s: str) -> str:
    return _c("92", f"[+] {s}")  # green


def err(s: str) -> str:
    return _c("91", f"[-] {s}")  # red


def bold(s: str) -> str:
    return _c("1", s)


# ---------- crypto core ----------
def xorpass(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must be non-empty")

    k = key[::-1]
    klen = len(k)

    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ k[i % klen]
    return bytes(out)


def _b_latin1(s: str) -> bytes:
    return s.encode("latin1", errors="strict")


def encode_hex(plaintext: str, key: str) -> str:
    return xorpass(_b_latin1(plaintext), _b_latin1(key)).hex()


def decode_hex(ciphertext_hex: str, key: str) -> str:
    return xorpass(bytes.fromhex(ciphertext_hex), _b_latin1(key)).decode("latin1", errors="strict")


def recover_key_part(ciphertext_hex: str, plaintext: str) -> str:
    ct = bytes.fromhex(ciphertext_hex)
    pt = _b_latin1(plaintext)

    if len(ct) != len(pt):
        raise ValueError("ciphertext and plaintext must have same length")

    # keystream = c ^ p ; xorpass cycles reversed(key) => key_part = reverse(keystream)
    key_part = bytes(c ^ p for c, p in zip(ct, pt))[::-1]
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


def _split_optional_key(parts: list[str], *, join_rest: bool) -> tuple[str, str, bool]:
    """
    Returns: (key, text, used_default_key)
    - If one arg: default key + that arg as text
    - If >=2: first is key, rest is text (optionally joined)
    """
    if len(parts) == 1:
        return DEFAULT_KEY, parts[0], True
    if join_rest:
        return parts[0], " ".join(parts[1:]), False
    return parts[0], parts[1], False


def main() -> int:
    args = build_argparser().parse_args()

    try:
        if args.encode is not None:
            key, plaintext, used_default = _split_optional_key(args.encode, join_rest=True)
            print(info(f"Mode     : encode ({'default' if used_default else 'custom'} key)"))
            out = encode_hex(plaintext, key)
            print(info(f"Plaintext: {bold(plaintext)}"))
            print(info(f"Cipher   : {bold(out)}"))
            return 0

        if args.decode is not None:
            key, cipherhex, used_default = _split_optional_key(args.decode, join_rest=False)
            print(info(f"Mode     : decode ({'default' if used_default else 'custom'} key)"))
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
