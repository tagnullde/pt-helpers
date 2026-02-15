from __future__ import annotations

import argparse
import os
import re
import sys
from functools import lru_cache

DEFAULT_KEY = "change for more security"

# ---------- ANSI helpers (auto-disable if not a TTY) ----------
@lru_cache(maxsize=1)
def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if _use_color() else s


def bold(s: str) -> str:
    return _c("1", s)


# ---------- output formatting ----------
MODE_COLORS = {
    "encode": "96",        # bright cyan
    "decode": "95",        # bright magenta/purple
    "recover": "38;5;39",  # bright azure (distinct from orange/yellow)
}

RESULT_COLOR = "38;5;208"  # bright orange for ALL [>] result lines
ERR_COLOR = "91"           # bright red

PREFIX_INFO = "[+]"
PREFIX_RESULT = "[>]"
PREFIX_ERR = "[-]"

LABEL_W = 11  # fits: "plaintext:" "secret key:"


def _mode_color(mode: str) -> str:
    return MODE_COLORS.get(mode, "97")


def _prefix(mode: str, kind: str) -> str:
    if kind == "result":
        return _c(RESULT_COLOR, PREFIX_RESULT)
    if kind == "err":
        return _c(ERR_COLOR, PREFIX_ERR)
    return _c(_mode_color(mode), PREFIX_INFO)


def _label(mode: str, s: str, *, is_result: bool) -> str:
    color = RESULT_COLOR if is_result else _mode_color(mode)
    txt = f"{s:<{LABEL_W}}"
    return bold(_c(color, txt)) if is_result else _c(color, txt)


def _value(mode: str, s: str, *, is_result: bool) -> str:
    if is_result:
        # Entire last line is bold (label+value are bolded; prefix is colored)
        return bold(_c(RESULT_COLOR, s))
    return _c(_mode_color(mode), s)


def line(mode: str, label: str, value: str, *, is_result: bool = False) -> str:
    pfx = _prefix(mode, "result" if is_result else "info")
    lab = _label(mode, label, is_result=is_result)
    val = _value(mode, value, is_result=is_result)
    # If result: also bold the whole remainder (label + space + value)
    if is_result:
        rest = bold(_c(RESULT_COLOR, f"{label:<{LABEL_W}} {value}"))
        return f"{_c(RESULT_COLOR, PREFIX_RESULT)}  {rest}"
    return f"{pfx}  {lab} {val}"


def errline(msg: str) -> str:
    return f"{_c(ERR_COLOR, PREFIX_ERR)}  {_c(ERR_COLOR, 'error:'):<{LABEL_W}} {_c(ERR_COLOR, msg)}"


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

    key_part = bytes(c ^ p for c, p in zip(ct, pt))[::-1]
    return key_part.decode("latin1", errors="strict")


# ---------- colored help ----------
def _colorize_help_text(s: str) -> str:
    if not _use_color():
        return s

    encode_flags = _c(MODE_COLORS["encode"], "-e") + ", " + _c(MODE_COLORS["encode"], "--encode")
    decode_flags = _c(MODE_COLORS["decode"], "-d") + ", " + _c(MODE_COLORS["decode"], "--decode")
    recover_flags = _c(MODE_COLORS["recover"], "-r") + ", " + _c(MODE_COLORS["recover"], "--recover")

    s = s.replace("-e, --encode", encode_flags)
    s = s.replace("-d, --decode", decode_flags)
    s = s.replace("-r, --recover", recover_flags)

    s = re.sub(r"^(usage: .+)$", lambda m: bold(m.group(1)), s, flags=re.M)
    s = re.sub(r"^([A-Za-z ].+?:)$", lambda m: bold(m.group(1)), s, flags=re.M)

    def color_example_line(m: re.Match) -> str:
        line0 = m.group(0)
        if " -e " in line0:
            return _c(MODE_COLORS["encode"], line0)
        if " -d " in line0:
            return _c(MODE_COLORS["decode"], line0)
        if " -r " in line0:
            return _c(MODE_COLORS["recover"], line0)
        return line0

    s = re.sub(r"(?m)^\s{4}python3 .+$", color_example_line, s)
    return s


class ColoredHelpArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return _colorize_help_text(super().format_help())


# ---------- CLI ----------
def build_argparser() -> argparse.ArgumentParser:
    script = os.path.basename(sys.argv[0])

    epilog = f"""
Examples (consistent order: data first, optional key last):

  Encode with default NeDi Secret:
    python3 {script} -e 'Password'

  Encode with custom key:
    python3 {script} -e 'Password' 'mykey'

  Decode with default NeDi Secret:
    python3 {script} -d 29151a01020c1717

  Decode with custom key:
    python3 {script} -d 2904180a1a16170f 'mykey'

  Recover secret key from known plaintext + ciphertext:
    python3 {script} -r 29151a01020c1717 'Password'
"""

    p = ColoredHelpArgumentParser(
        description="NeDi Decoder by x41",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = p.add_mutually_exclusive_group(required=True)

    mode.add_argument(
        "-e", "--encode",
        nargs="+",
        metavar=("PLAINTEXT", "KEY"),
        help="Encode:  -e <plaintext> [key]   (key omitted: default NeDi Secret)",
    )
    mode.add_argument(
        "-d", "--decode",
        nargs="+",
        metavar=("CIPHERHEX", "KEY"),
        help="Decode:  -d <cipherhex> [key]  (key omitted: default NeDi Secret)",
    )
    mode.add_argument(
        "-r", "--recover",
        nargs=2,
        metavar=("CIPHERHEX", "PLAINTEXT"),
        help="Recover secret key: -r <cipherhex> <plaintext>  (use sufficiently long password in NeDi to extract the entire secret key)",
    )
    return p


def _split_text_optional_key(parts: list[str], what: str) -> tuple[str, str, bool]:
    if len(parts) == 1:
        return parts[0], DEFAULT_KEY, True
    if len(parts) == 2:
        return parts[0], parts[1], False
    raise ValueError(f"{what}: expected 1 or 2 args, got {len(parts)}")


def main() -> int:
    args = build_argparser().parse_args()

    print()

    try:
        if args.encode is not None:
            plaintext, key, used_default = _split_text_optional_key(args.encode, "encode")
            mode = "encode"

            print(line(mode, "mode:", f"encode ({'default NeDi Secret' if used_default else 'custom'} key)"))
            print(line(mode, "plaintext:", plaintext))
            out = encode_hex(plaintext, key)
            print(line(mode, "cipher:", out, is_result=True))

            print()
            return 0

        if args.decode is not None:
            cipherhex, key, used_default = _split_text_optional_key(args.decode, "decode")
            mode = "decode"

            print(line(mode, "mode:", f"decode ({'default NeDi Secret' if used_default else 'custom'} key)"))
            print(line(mode, "cipher:", cipherhex))
            pt = decode_hex(cipherhex, key)
            print(line(mode, "plaintext:", pt, is_result=True))

            print()
            return 0

        if args.recover is not None:
            cipherhex, plaintext = args.recover
            mode = "recover"

            print(line(mode, "mode:", "recover"))
            print(line(mode, "cipher:", cipherhex))
            print(line(mode, "plaintext:", plaintext))
            secret_key = recover_key_part(cipherhex, plaintext)
            print(line(mode, "secret key:", secret_key, is_result=True))

            print()
            return 0

        raise SystemExit(2)

    except ValueError as e:
        print(errline(str(e)))
        print()
        return 2
    except UnicodeDecodeError as e:
        print(errline(f"latin1 decode/encode error: {e}"))
        print()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
