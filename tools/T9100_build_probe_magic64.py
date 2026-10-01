#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T9100_build_probe_magic64.py
============================

OFFLINE ONLY.  Builds a **mechanism probe** magic64 image for the T9100 / VN300E.

Why a probe?
------------
The magic64 delivery mechanism (entry jump -> shellcode -> payload relocation ->
patch table) has one property that the full 4-patch unlock image cannot test in
isolation: *did our code actually run at all?*  If it did not run, the device
boots exactly like stock and looks identical - you learn nothing.

This tool patches something that is:

  * **observable** on a LOCKED device (your current state),
  * **functionally inert** - it only removes one UART log line,

so that a single flash answers "does magic64 execute on this build?" with
**zero functional side effects**:

    probe patch (code 0xB520) :  bl 0x32E44  ->  nop

0xB520 is the UART print of `INFO: LOCK FLAG IS : LOCK!!!` inside the LOCK arm
of the boot-time lock-warning function (fn 0xB4E0).  A locked device takes that
arm on every boot (confirmed in this device's uboot_log: 51 occurrences).

    magic64 ran      -> that line disappears from the UART log   (observable)
    magic64 did not  -> boot output is byte-identical to stock   (safe no-op)

It does NOT touch the lock state, verification, or anything else.

Guarantees (identical to the main patcher):
  * input opened "rb" only; output is a NEW file; refuses in == out
  * SHA256 of the stock image must match the pinned T9100 hash
  * the patch word must match exactly, else abort before writing anything
  * reuses the official repository's magic_pack_ums9620.pack()
  * no re-signing, no device access, no flashing

Usage
-----
    python T9100_build_probe_magic64.py
    python T9100_build_probe_magic64.py --patch 0xb520=0x94009e49
    python T9100_build_probe_magic64.py --dry-run
"""

import argparse
import hashlib
import os
import struct
import sys

sys.dont_write_bytecode = True

REPO_TOOLS = r"C:\Users\admin\Desktop\B\T9100\UnisocBypass-main\tools"
if REPO_TOOLS not in sys.path:
    sys.path.insert(0, REPO_TOOLS)
try:
    import magic_pack_ums9620 as MP
except ImportError as e:  # pragma: no cover
    sys.exit(f"cannot import magic_pack_ums9620 from {REPO_TOOLS}: {e}")

DEFAULT_INPUT = r"C:\Users\admin\Desktop\B\T9100\backup\T9100_back\uboot_b.bin"
DEFAULT_OUTPUT = "T9100_uboot_b_probe_lockmsg_magic64.img"

STOCK_SHA256 = "5935075bed5b12d35b961d0e39a4e95154b8cfb94ac177f96919700a24b8e321"
PARTITION_SIZE = 0x300000
DHTB_HDR = 0x200
NOP = 0xD503201F
LOAD_BASE = 0xB5000000

# code offset = expected stock word,  description
DEFAULT_PROBES = [
    (0x0B520, 0x94009E49,
     "UART print of 'INFO: LOCK FLAG IS : LOCK!!!' (LOCK arm of fn 0xB4E0)"),
]


def parse_spec(s):
    """CODE_OFF=EXPECTED[:TARGET]
    TARGET 省略时写 nop（0xD503201F）。
    """
    off, _, rest = s.partition("=")
    if ":" in rest:
        exp, _, tgt = rest.partition(":")
    else:
        exp, tgt = rest, hex(NOP)
    return int(off, 0), int(exp, 0), int(tgt, 0)


def main():
    ap = argparse.ArgumentParser(
        description="Build a zero-side-effect magic64 mechanism probe (offline).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=DEFAULT_INPUT)
    ap.add_argument("--output", default=DEFAULT_OUTPUT)
    ap.add_argument("--load-base", type=lambda x: int(x, 0), default=LOAD_BASE)
    ap.add_argument("--patch", action="append", metavar="CODE_OFF=EXPECTED_WORD",
                    help="override the probe set (repeatable)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    print("=" * 74)
    print("  T9100 / VN300E  magic64 MECHANISM PROBE builder  (offline, read-only input)")
    print("=" * 74)

    if not os.path.isfile(args.input):
        sys.exit(f"input not found: {args.input}")
    if os.path.abspath(args.input).lower() == os.path.abspath(args.output).lower():
        sys.exit("output path equals input path - refusing to overwrite the stock image")

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    if data[0:4] != b"DHTB":
        sys.exit("not a DHTB image")
    sha = hashlib.sha256(data).hexdigest()
    print(f"input   : {args.input}")
    print(f"sha256  : {sha}")
    if sha != STOCK_SHA256:
        sys.exit("sha256 mismatch - aborting, nothing written")
    print("sha256  : MATCH")
    if len(data) != PARTITION_SIZE:
        sys.exit(f"unexpected size 0x{len(data):x}")

    size = struct.unpack_from("<I", data, 0x30)[0]
    foot = DHTB_HDR + size
    if data[foot:foot + 7] != b"SIMGHDR":
        sys.exit("SIMGHDR footer not found")
    if struct.unpack_from("<Q", data, foot + 0x18)[0] != 0x200:
        sys.exit("footer payload_offset != 0x200 - already magic-patched?")

    probes = ([parse_spec(p) for p in args.patch] if args.patch
              else [(o, w, NOP) for o, w, _ in DEFAULT_PROBES])

    print()
    print("--- probe point verification ---")
    ok = True
    for code_off, want, tgt in probes:
        file_off = DHTB_HDR + code_off
        got = struct.unpack_from("<I", data, file_off)[0]
        m = (got == want)
        ok &= m
        desc = next((d for o, _, d in DEFAULT_PROBES if o == code_off), "")
        print(f"  code 0x{code_off:06x}  file 0x{file_off:07x}  "
              f"found 0x{got:08x}  expected 0x{want:08x}  "
              f"{'OK' if m else 'MISMATCH'}  -> 0x{tgt:08x}  {desc}")
    if not ok:
        sys.exit("probe word mismatch - aborting, nothing written")

    print()
    print("--- magic64 packing ---")
    print(f"  LOAD_BASE 0x{args.load_base:08x}")
    for code_off, _, tgt in probes:
        print(f"  runtime 0x{args.load_base + code_off:08x} <- 0x{tgt:08x}")
    try:
        out = MP.pack(data, [(o, t) for o, _, t in probes], args.load_base)
    except ValueError as e:
        sys.exit(f"packing failed: {e}")

    if len(out) != PARTITION_SIZE:
        sys.exit("packed size != partition size")
    if out[0x210:0x210 + size] != data[DHTB_HDR:DHTB_HDR + size]:
        sys.exit("packed payload is not byte-identical to stock")

    if args.dry_run:
        print("\nDRY RUN - nothing written.")
        return 0

    with open(args.output, "wb") as f:
        f.write(out)
    print()
    print("=" * 74)
    print(f"wrote : {os.path.abspath(args.output)}")
    print(f"size  : {len(out)} (0x{len(out):x})")
    print(f"sha256: {hashlib.sha256(out).hexdigest()}")
    print()
    print("HOW TO READ THE RESULT (UART console, 921600n8):")
    print("  * 'INFO: LOCK FLAG IS : LOCK!!!' gone  -> magic64 executed; proceed")
    print("  * output identical to stock             -> magic64 did not execute;")
    print("                                             device is unharmed, stop here")
    print("  * device hangs                          -> restore stock uboot_b")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
